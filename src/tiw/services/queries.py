"""Read models for the UI, REST API and exports. GET paths never modify data."""

from __future__ import annotations

import base64
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tiw.domain.vocab import DELTA_LABELS, REASON_TEXT, URGENCY_RANK
from tiw.services.pipeline import (
    effective_review_states,
    latest_applicability,
    latest_asset_revision,
    latest_assessment,
    latest_decision,
    load_claims,
)
from tiw.storage import db
from tiw.storage.models import (
    Asset,
    Claim,
    ClaimRelation,
    ClaimReview,
    Decision,
    Finding,
    GraphInput,
    ImportRun,
    IntelligenceDelta,
    InvestigationTask,
    Observation,
    SensorWindow,
    Source,
    SourceRevision,
    ThreatAssessment,
    Vulnerability,
)

PERIODS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "all": None}
PERIOD_LABELS = {"24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days", "all": "All time"}
FRESHNESS = {"kev": timedelta(days=7), "epss": timedelta(hours=72)}
ADAPTER_SOURCE_KIND = {
    "kev": "kev",
    "epss": "epss",
    "observations": "sensor",
    "assets": "asset_inventory",
    "findings": "scanner",
    "claims": "advisory",
    "topology": "topology",
    "exploit_conditions": "exploit_conditions",
    "remediations": "remediations",
}
RULE_TITLES = {
    1: "Rule 1: Reviewed compromise on asset",
    2: "Rule 2: not_affected contradicted by local attempt",
    3: "Rule 3: Valid reviewed not_affected",
    4: "Rule 4: Applicability unknown or expired",
    5: "Rule 5: Confirmed local exploit attempt",
    6: "Rule 6: Confirmed exploitation + exposed/critical",
    7: "Rule 7: Confirmed exploitation",
    8: "Rule 8: Exposure unknown or expired",
    9: "Rule 9: Affected, no further signal",
}
EVIDENCE_STATUS_ORDER = ("conflict", "confirmed", "reported", "unknown")


@dataclass
class Period:
    key: str
    start: datetime | None
    end: datetime

    @property
    def label(self) -> str:
        return PERIOD_LABELS[self.key]

    def contains(self, t: datetime | None) -> bool:
        return t is not None and (self.start is None or t >= self.start) and t <= self.end


def parse_period(s: Session, key: str | None) -> Period:
    k = key if key in PERIODS else "7d"
    now = db.now(s)
    span = PERIODS[k]
    return Period(k, now - span if span else None, now)


def display_tz(s: Session) -> ZoneInfo:
    try:
        return ZoneInfo(db.get_meta(s, "timezone") or db.DEFAULT_TIMEZONE)
    except Exception:  # noqa: BLE001 - invalid setting falls back to UTC
        return ZoneInfo("UTC")


# --------------------------------------------------------------------------- shared helpers


def evidence_status(state: dict[str, Any] | None) -> str:
    if not state:
        return "unknown"
    if state.get("conflict"):
        return "conflict"
    return state.get("public_exploitation", "unknown")


def current_decisions(s: Session) -> dict[str, Decision]:
    sub = select(Decision.finding_id, func.max(Decision.seq).label("m")).group_by(Decision.finding_id).subquery()
    rows = s.execute(select(Decision).join(sub, (Decision.finding_id == sub.c.finding_id) & (Decision.seq == sub.c.m))).scalars()
    return {d.finding_id: d for d in rows}


def latest_assessments(s: Session) -> dict[str, ThreatAssessment]:
    sub = (
        select(ThreatAssessment.vulnerability_id, func.max(ThreatAssessment.seq).label("m"))
        .group_by(ThreatAssessment.vulnerability_id)
        .subquery()
    )
    rows = s.execute(
        select(ThreatAssessment).join(
            sub, (ThreatAssessment.vulnerability_id == sub.c.vulnerability_id) & (ThreatAssessment.seq == sub.c.m)
        )
    ).scalars()
    return {a.vulnerability_id: a for a in rows}


def source_health(s: Session) -> list[dict[str, Any]]:
    now = db.now(s)
    out = []
    runs = list(s.execute(select(ImportRun).order_by(ImportRun.started_at)).scalars())
    for src in s.execute(select(Source).order_by(Source.kind, Source.name)).scalars():
        last_rev = s.execute(
            select(SourceRevision).where(SourceRevision.source_id == src.id).order_by(SourceRevision.seq.desc()).limit(1)
        ).scalar_one_or_none()
        revs = s.execute(select(func.count(SourceRevision.id)).where(SourceRevision.source_id == src.id)).scalar_one()
        last_ok = last_rev.fetched_at if last_rev else None
        kind_runs = [r for r in runs if ADAPTER_SOURCE_KIND.get(r.adapter) == src.kind]
        last_failed = next((r for r in reversed(kind_runs) if r.status == "failed"), None)
        failed_after_ok = last_failed is not None and (last_ok is None or last_failed.started_at >= last_ok)
        limit = FRESHNESS.get(src.kind)
        stale = bool(limit and last_ok and now - last_ok > limit)
        if failed_after_ok:
            status = "failed"
        elif stale:
            status = "stale"
        else:
            status = "ok"
        out.append(
            {
                "id": src.id,
                "name": src.name,
                "kind": src.kind,
                "status": status,
                "stale": stale,
                "freshness_limit": _fmt_td(limit) if limit else "n/a (no freshness policy)",
                "last_successful_update": last_ok,
                "last_failure": last_failed.started_at if failed_after_ok and last_failed else None,
                "last_failure_reason": (last_failed.errors_json[0]["reason"] if failed_after_ok and last_failed and last_failed.errors_json else None),
                "revisions": revs,
                "synthetic": bool(last_rev and last_rev.synthetic),
            }
        )
    # Failed imports for an adapter that has never succeeded have no Source row yet.
    known = {o["kind"] for o in out}
    for adapter, kind in ADAPTER_SOURCE_KIND.items():
        if kind in known:
            continue
        failed = [r for r in runs if r.adapter == adapter and r.status == "failed"]
        if failed:
            out.append(
                {
                    "id": None,
                    "name": f"{adapter} import (no successful import yet)",
                    "kind": kind,
                    "status": "failed",
                    "stale": False,
                    "freshness_limit": _fmt_td(FRESHNESS[kind]) if kind in FRESHNESS else "n/a",
                    "last_successful_update": None,
                    "last_failure": failed[-1].started_at,
                    "last_failure_reason": failed[-1].errors_json[0]["reason"] if failed[-1].errors_json else None,
                    "revisions": 0,
                    "synthetic": False,
                }
            )
    return out


def _fmt_td(td: timedelta) -> str:
    hours = int(td.total_seconds() // 3600)
    return f"{hours // 24} days" if hours % 24 == 0 and hours >= 48 else f"{hours} h"


def stale_source_kinds(s: Session) -> set[str]:
    return {h["kind"] for h in source_health(s) if h["status"] in ("stale", "failed")}


def workspace_info(s: Session) -> dict[str, Any]:
    has_data = s.execute(select(func.count(Vulnerability.id))).scalar_one() > 0 or s.execute(
        select(func.count(ImportRun.id))
    ).scalar_one() > 0
    return {
        "synthetic": db.is_synthetic_workspace(s),
        "now": db.now(s),
        "clock_fixed": db.get_meta(s, "clock_fixed"),
        "timezone": db.get_meta(s, "timezone") or db.DEFAULT_TIMEZONE,
        "brand_name": db.get_meta(s, "brand_name") or db.DEFAULT_BRAND,
        "has_data": has_data,
        "last_update": s.execute(select(func.max(ImportRun.completed_at))).scalar_one(),
        # v2: telemetry is optional; sensor widgets are labelled/hidden when none exists
        "has_telemetry": s.execute(select(func.count(Observation.id))).scalar_one() > 0
        or s.execute(select(func.count(SensorWindow.id))).scalar_one() > 0,
        "has_graph": s.execute(select(func.count(GraphInput.id)).where(GraphInput.kind == "topology")).scalar_one() > 0,
        "demo_scenarios": list(db.get_meta_json(s, "demo_scenarios", [])),  # type: ignore[arg-type]
    }


# --------------------------------------------------------------------------- home


def relevant_vulnerabilities(s: Session) -> set[str]:
    """Vulnerabilities that touch your environment: findings or confirmed local activity."""
    ids = set(s.execute(select(Finding.vulnerability_id)).scalars())
    ids |= set(
        s.execute(
            select(Observation.cve_id).where(
                Observation.status == "accepted", Observation.cve_id.is_not(None), Observation.mapping_status != "unconfirmed"
            )
        ).scalars()
    )
    return ids


def setup_status(s: Session) -> dict[str, Any]:
    """What has been loaded so far; drives the getting-started checklist."""
    kinds = {k for (k,) in s.execute(select(Source.kind).join(SourceRevision, SourceRevision.source_id == Source.id).distinct()).all()}
    steps = [
        {"key": "assets", "done": s.execute(select(func.count(Asset.id))).scalar_one() > 0,
         "title": "Add your assets", "text": "A CSV of systems with criticality and whether they face the internet.", "href": "/import?kind=assets", "action": "Import assets"},
        {"key": "findings", "done": s.execute(select(func.count(Finding.id))).scalar_one() > 0,
         "title": "Map vulnerabilities to assets", "text": "A CSV from your scanner: which CVE affects which asset.", "href": "/import?kind=findings", "action": "Import findings"},
        {"key": "kev", "done": "kev" in kinds,
         "title": "Load known-exploited vulnerabilities", "text": "Fetch the official CISA KEV catalog (one explicit download).", "href": "/sources#fetch", "action": "Fetch KEV"},
        {"key": "epss", "done": "epss" in kinds,
         "title": "Add exploit likelihood (optional)", "text": "Fetch FIRST EPSS scores for the CVEs you track. Used for ordering only.", "href": "/sources#fetch", "action": "Fetch EPSS"},
        {"key": "observations", "done": "sensor" in kinds,
         "title": "Add what your sensors saw (optional)", "text": "IDS/WAF events as JSONL. Attacks on your own assets change decisions first.", "href": "/import?kind=observations", "action": "Import observations"},
    ]
    return {"steps": steps, "done": sum(1 for x in steps if x["done"]), "core_done": all(x["done"] for x in steps[:3])}


def home(s: Session, period_key: str | None, scope: str = "mine") -> dict[str, Any]:
    p = parse_period(s, period_key)
    mine = scope != "all"
    relevant = relevant_vulnerabilities(s)
    deltas = list(s.execute(select(IntelligenceDelta).order_by(IntelligenceDelta.seq.desc())).scalars())
    if mine:
        deltas = [d for d in deltas if d.vulnerability_id in relevant]
    in_period = [d for d in deltas if p.contains(d.created_at)]
    attempts = list(
        s.execute(
            select(Observation).where(Observation.status == "accepted", Observation.event_type == "exploit_attempt")
        ).scalars()
    )
    attempts_in = [o for o in attempts if p.contains(o.observed_at)]
    decisions = current_decisions(s)
    findings = {f.id: f for f in s.execute(select(Finding)).scalars()}
    reassess_assets = {findings[fid].asset_id for fid, d in decisions.items() if d.action == "investigate"}
    open_tasks = s.execute(select(func.count(InvestigationTask.id)).where(InvestigationTask.status == "open")).scalar_one()

    comparison = None
    if p.start is not None:
        span = p.end - p.start
        prev_start = p.start - span
        earliest_candidates = [x for x in (
            s.execute(select(func.min(IntelligenceDelta.created_at))).scalar_one(),
            s.execute(select(func.min(Observation.observed_at))).scalar_one(),
        ) if x is not None]
        earliest = min(earliest_candidates) if earliest_candidates else None
        if earliest is not None and earliest <= prev_start:
            comparison = {
                "label": f"previous {p.key}",
                "changes": sum(1 for d in deltas if prev_start <= d.created_at < p.start),
                "attempts": sum(1 for o in attempts if prev_start <= o.observed_at < p.start),
            }

    kpis = [
        {
            "key": "changes",
            "label": "Threat changes",
            "value": len(in_period),
            "definition": ("For threats that touch your assets" if mine else "Across all tracked threats") + ". Reposts and refetches are not counted",
            "href": f"/threats?period={p.key}&changed=1&scope={'mine' if mine else 'all'}",
            "previous": comparison["changes"] if comparison else None,
        },
        {
            "key": "attempts",
            "label": "Attacks on your sensors",
            "value": len(attempts_in),
            "definition": f"Exploit attempts, deduplicated ({sum(1 for o in attempts_in if o.mapping_status != 'unconfirmed')} tied to a known CVE). Scans not counted",
            "href": f"/observations?period={p.key}&event_type=exploit_attempt",
            "previous": comparison["attempts"] if comparison else None,
        },
        {
            "key": "reassess",
            "label": "Assets to check",
            "value": len(reassess_assets),
            "definition": "Assets where something must be confirmed before deciding",
            "href": "/assets?action=investigate",
            "previous": None,
        },
        {
            "key": "questions",
            "label": "Open questions",
            "value": open_tasks,
            "definition": "Specific checks that would settle undecided cases",
            "href": "/investigations",
            "previous": None,
        },
    ]

    assessments = latest_assessments(s)
    if mine:
        assessments = {k: v for k, v in assessments.items() if k in relevant}
    status_counts = Counter(evidence_status(a.state_json) for a in assessments.values())
    evidence = [{"status": k, "count": status_counts.get(k, 0)} for k in EVIDENCE_STATUS_ORDER]

    latest_changes = [delta_row(s, d, findings, decisions) for d in in_period[:10]]
    changed_decisions = []
    for d in s.execute(
        select(Decision).where(Decision.previous_id.is_not(None)).order_by(Decision.seq.desc()).limit(60)
    ).scalars():
        if not p.contains(d.created_at):
            continue
        prev = s.get(Decision, d.previous_id)
        if prev and (prev.action, prev.urgency) != (d.action, d.urgency):
            f = findings[d.finding_id]
            changed_decisions.append(
                {"decision": d, "previous": prev, "finding": f, "asset_id": f.asset_id, "vulnerability_id": f.vulnerability_id}
            )
        if len(changed_decisions) >= 8:
            break

    return {
        "period": p,
        "scope": "mine" if mine else "all",
        "relevant_count": len(relevant),
        "setup": setup_status(s),
        "kpis": kpis,
        "comparison": comparison,
        "activity": activity_series(s, p),
        "evidence_status": evidence,
        "evidence_total": sum(e["count"] for e in evidence),
        "latest_changes": latest_changes,
        "sources": source_health(s),
        "tasks": investigations(s)[:5],
        "decision_changes": changed_decisions,
    }


def delta_row(
    s: Session, d: IntelligenceDelta, findings: dict[str, Finding], decisions: dict[str, Decision]
) -> dict[str, Any]:
    r = d.reasons_json
    affected = r.get("affected_finding_ids", [])
    assets = sorted({findings[f].asset_id for f in affected if f in findings})
    dec_ids = r.get("decision_ids", [])
    return {
        "delta": d,
        "label": DELTA_LABELS.get(d.change_type, d.change_type),
        "summary": r.get("summary", ""),
        "evidence_count": len(r.get("evidence_ids", [])),
        "assets": assets,
        "decision_ids": dec_ids,
        "first_decision_id": dec_ids[0] if dec_ids else None,
    }


def activity_series(s: Session, p: Period) -> dict[str, Any]:
    tz = display_tz(s)
    end = p.end
    start = p.start
    if start is None:
        firsts = [
            x
            for x in (
                s.execute(select(func.min(SourceRevision.published_at))).scalar_one(),
                s.execute(select(func.min(Observation.observed_at))).scalar_one(),
            )
            if x is not None
        ]
        start = max(min(firsts), end - timedelta(days=90)) if firsts else end - timedelta(days=30)
    hourly = (end - start) <= timedelta(hours=48)
    step = timedelta(hours=1) if hourly else timedelta(days=1)
    # Buckets aligned to the display timezone.
    local_start = start.astimezone(tz)
    if hourly:
        b0 = local_start.replace(minute=0, second=0, microsecond=0)
    else:
        b0 = local_start.replace(hour=0, minute=0, second=0, microsecond=0)
    buckets: list[tuple[datetime, datetime]] = []
    cur = b0
    while cur < end.astimezone(tz) and len(buckets) < 400:
        nxt = (cur + step) if hourly else (cur + timedelta(days=1)).replace(hour=0)
        buckets.append((cur.astimezone(timezone.utc), nxt.astimezone(timezone.utc)))
        cur = nxt

    pub_times = [
        r.published_at or r.fetched_at
        for r, src in s.execute(
            select(SourceRevision, Source).join(Source, SourceRevision.source_id == Source.id).where(Source.kind.in_(("kev", "advisory")))
        ).all()
    ]
    obs_times = [
        o for o in s.execute(select(Observation.observed_at).where(Observation.status == "accepted")).scalars()
    ]
    windows = list(s.execute(select(SensorWindow)).scalars())
    ok_windows = [(w.start, w.end) for w in windows if w.status == "ok"]
    outages = [(w.start, w.end, w.sensor_id) for w in windows if w.status == "outage"]

    def covered_fraction(a: datetime, b: datetime) -> float:
        total = 0.0
        for ws_, we in ok_windows:
            lo, hi = max(a, ws_), min(b, we)
            if hi > lo:
                total += (hi - lo).total_seconds()
        for os_, oe, _ in outages:
            lo, hi = max(a, os_), min(b, oe)
            if hi > lo:
                total -= (hi - lo).total_seconds()
        return max(0.0, min(1.0, total / (b - a).total_seconds()))

    points = []
    for a, b in buckets:
        pub = sum(1 for t in pub_times if a <= t < b)
        local_count = sum(1 for t in obs_times if a <= t < b)
        gap = bool(windows) and covered_fraction(a, b) < 0.5
        points.append(
            {
                "start": a,
                "label": a.astimezone(tz).strftime("%H:%M" if hourly else "%m-%d"),
                "public": pub,
                "local": None if gap else local_count,
                "gap": gap,
            }
        )
    notes = []
    if not windows:
        notes.append("Sensor coverage not recorded; zero local observations are not evidence of no activity.")
    for os_, oe, sid in outages:
        if oe >= start and os_ <= end:
            notes.append(
                f"Sensor {sid} outage {os_.astimezone(tz).strftime('%m-%d %H:%M')}–{oe.astimezone(tz).strftime('%m-%d %H:%M')}: local series is broken, not zero."
            )
    return {
        "points": points,
        "granularity": "hour" if hourly else "day",
        "timezone": str(tz),
        "notes": notes,
        "max": max([1] + [pt["public"] for pt in points] + [pt["local"] or 0 for pt in points]),
        "has_data": any(pt["public"] or pt["local"] for pt in points),
    }


# --------------------------------------------------------------------------- threats


def _encode_cursor(v: str) -> str:
    return base64.urlsafe_b64encode(v.encode()).decode().rstrip("=")


def _decode_cursor(c: str) -> str:
    pad = "=" * (-len(c) % 4)
    return base64.urlsafe_b64decode(c + pad).decode()


def threats(
    s: Session,
    *,
    status: str | None = None,
    period_key: str | None = None,
    q: str | None = None,
    changed_only: bool = False,
    cursor: str | None = None,
    limit: int = 50,
    scope: str = "mine",
) -> dict[str, Any]:
    p = parse_period(s, period_key)
    relevant = relevant_vulnerabilities(s) if scope != "all" else None
    assessments = latest_assessments(s)
    decisions = current_decisions(s)
    findings_by_vuln: dict[str, list[Finding]] = defaultdict(list)
    for f in s.execute(select(Finding)).scalars():
        findings_by_vuln[f.vulnerability_id].append(f)
    last_delta = dict(
        s.execute(select(IntelligenceDelta.vulnerability_id, func.max(IntelligenceDelta.created_at)).group_by(IntelligenceDelta.vulnerability_id)).all()
    )
    deltas_in_period = Counter(
        d.vulnerability_id for d in s.execute(select(IntelligenceDelta)).scalars() if p.contains(d.created_at)
    )
    stale_kinds = stale_source_kinds(s)
    after = _decode_cursor(cursor) if cursor else None
    rows = []
    for v in s.execute(select(Vulnerability).order_by(Vulnerability.id)).scalars():
        if after and v.id <= after:
            continue
        if relevant is not None and v.id not in relevant:
            continue
        a = assessments.get(v.id)
        st = a.state_json if a else None
        es = evidence_status(st)
        if status and status != es:
            continue
        if q and q.lower() not in v.id.lower() and q.lower() not in (v.title or "").lower():
            continue
        if changed_only and not deltas_in_period.get(v.id):
            continue
        fs = findings_by_vuln.get(v.id, [])
        decs = [decisions[f.id] for f in fs if f.id in decisions]
        top = min(decs, key=lambda d: URGENCY_RANK[d.urgency]) if decs else None
        rows.append(
            {
                "id": v.id,
                "title": v.title,
                "synthetic": v.synthetic,
                "status": es,
                "state": st,
                "assets": len({f.asset_id for f in fs}),
                "top_urgency": top.urgency if top else None,
                "top_action": top.action if top else None,
                "changes_in_period": deltas_in_period.get(v.id, 0),
                "last_change": last_delta.get(v.id),
                "kev_source_stale": bool(st and st["kev"]["listed_ever"] and "kev" in stale_kinds),
            }
        )
        if len(rows) > limit:
            break
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = _encode_cursor(rows[-1]["id"])
    return {"items": rows, "next_cursor": next_cursor, "period": p, "scope": "all" if relevant is None else "mine"}


def claim_rows(s: Session, vid: str) -> list[dict[str, Any]]:
    claims, rels = load_claims(s, vid)
    from tiw.domain.claims import mark_inactive

    mark_inactive(claims, rels)
    a = latest_assessment(s, vid)
    derived = set((a.state_json.get("independence") or {}).get("derived_from_inactive", [])) if a else set()
    by_id = {c.id: c for c in claims}
    reviews = defaultdict(list)
    if claims:
        for r in s.execute(
            select(ClaimReview).where(ClaimReview.claim_id.in_(list(by_id))).order_by(ClaimReview.seq)
        ).scalars():
            reviews[r.claim_id].append(r)
    out = []
    for c in sorted(claims, key=lambda c: (c.evidence_time, c.id), reverse=True):
        rel_out = [
            {"kind": r.kind, "verification": r.verification, "to": r.to_id, "to_key": by_id[r.to_id].key if r.to_id in by_id else r.to_id}
            for r in rels
            if r.from_id == c.id
        ]
        rel_in = sum(1 for r in rels if r.to_id == c.id and r.kind in ("cites", "duplicates"))
        out.append(
            {
                "claim": c,
                "relations": rel_out,
                "cited_by": rel_in,
                "reviews": reviews.get(c.id, []),
                "inactive_reason": c.inactive_reason or ("cited source retracted" if c.id in derived else None),
            }
        )
    return out


def threat_detail(s: Session, vid: str) -> dict[str, Any] | None:
    v = s.get(Vulnerability, vid)
    if v is None:
        return None
    a = latest_assessment(s, vid)
    history = list(
        s.execute(select(ThreatAssessment).where(ThreatAssessment.vulnerability_id == vid).order_by(ThreatAssessment.seq)).scalars()
    )
    deltas = list(
        s.execute(select(IntelligenceDelta).where(IntelligenceDelta.vulnerability_id == vid).order_by(IntelligenceDelta.seq.desc())).scalars()
    )
    findings = list(s.execute(select(Finding).where(Finding.vulnerability_id == vid).order_by(Finding.id)).scalars())
    decisions = current_decisions(s)
    asset_rows = [finding_row(s, f, decisions.get(f.id)) for f in findings]
    asset_ids = {f.asset_id for f in findings}
    obs = list(s.execute(select(Observation).where(Observation.cve_id == vid).order_by(Observation.observed_at.desc())).scalars())
    unmapped_on_assets = [
        o
        for o in s.execute(
            select(Observation).where(Observation.asset_id.in_(asset_ids), Observation.cve_id.is_(None)).order_by(Observation.observed_at.desc())
        ).scalars()
    ] if asset_ids else []
    decision_history = list(
        s.execute(
            select(Decision).where(Decision.finding_id.in_([f.id for f in findings])).order_by(Decision.seq.desc())
        ).scalars()
    ) if findings else []
    timeline: list[dict[str, Any]] = []
    for d in deltas:
        timeline.append({"time": d.created_at, "kind": "delta", "label": DELTA_LABELS.get(d.change_type, d.change_type), "text": d.reasons_json.get("summary", ""), "obj": d})
    for c in claim_rows(s, vid):
        cl = c["claim"]
        if cl.predicate == "epss_score":
            continue
        timeline.append({"time": cl.evidence_time, "kind": "public", "label": f"{cl.source_name}", "text": f"{cl.predicate} = {cl.value.get('value', '')} ({cl.effective_state})", "obj": cl})
    for o in obs:
        timeline.append({"time": o.observed_at, "kind": "local", "label": f"{o.event_type} · {o.sensor_id}", "text": f"asset {o.asset_id or 'n/a'} · mapping {o.mapping_status}", "obj": o})
    timeline.sort(key=lambda x: x["time"], reverse=True)
    stale_kinds = stale_source_kinds(s)
    return {
        "vulnerability": v,
        "assessment": a,
        "state": a.state_json if a else None,
        "status": evidence_status(a.state_json if a else None),
        "history": history,
        "deltas": deltas,
        "claims": claim_rows(s, vid),
        "observations": obs,
        "unmapped_on_assets": unmapped_on_assets,
        "assets": asset_rows,
        "decisions": decision_history,
        "timeline": timeline[:60],
        "kev_source_stale": bool(a and a.state_json["kev"]["listed_ever"] and "kev" in stale_kinds),
        "stale_kinds": stale_kinds,
    }


def finding_row(s: Session, f: Finding, d: Decision | None) -> dict[str, Any]:
    asset = s.get(Asset, f.asset_id)
    return {
        "finding": f,
        "asset": asset,
        "decision": d,
        "asset_revision": latest_asset_revision(s, f.asset_id),
        "applicability": latest_applicability(s, f.id),
        "reasons": [(c, REASON_TEXT.get(c, c)) for c in (d.reason_codes if d else [])],
    }


def affected_assets(
    s: Session, *, urgency: str | None = None, action: str | None = None, q: str | None = None, vulnerability_id: str | None = None
) -> list[dict[str, Any]]:
    decisions = current_decisions(s)
    rows = []
    from tiw.domain.decisions import sort_key

    for f in s.execute(select(Finding).order_by(Finding.id)).scalars():
        d = decisions.get(f.id)
        if urgency and (not d or d.urgency != urgency):
            continue
        if action and (not d or d.action != action):
            continue
        if vulnerability_id and f.vulnerability_id != vulnerability_id:
            continue
        if q and q.lower() not in f"{f.id} {f.asset_id} {f.vulnerability_id}".lower():
            continue
        rows.append(finding_row(s, f, d))
    rows.sort(
        key=lambda r: sort_key(
            r["decision"].inputs_json["criticality"] if r["decision"] else "normal",
            r["decision"].inputs_json.get("epss") if r["decision"] else None,
            r["decision"].urgency if r["decision"] else "low",
            r["finding"].id,
        )
    )
    return rows


def observations(
    s: Session, *, period_key: str | None = None, event_type: str | None = None, q: str | None = None
) -> dict[str, Any]:
    p = parse_period(s, period_key)
    rows = [
        o
        for o in s.execute(select(Observation).order_by(Observation.observed_at.desc())).scalars()
        if p.contains(o.observed_at) or o.status == "quarantined"
    ]
    if event_type:
        rows = [o for o in rows if o.event_type == event_type]
    if q:
        ql = q.lower()
        rows = [o for o in rows if ql in f"{o.asset_id} {o.cve_id} {o.sensor_id} {o.external_event_id}".lower()]
    mapped = [o for o in rows if o.status == "accepted" and o.cve_id and o.mapping_status != "unconfirmed"]
    unmapped = [o for o in rows if o.status == "accepted" and (not o.cve_id or o.mapping_status == "unconfirmed")]
    quarantined = [o for o in rows if o.status == "quarantined"]
    windows = list(s.execute(select(SensorWindow).order_by(SensorWindow.sensor_id, SensorWindow.start)).scalars())
    return {"period": p, "mapped": mapped, "unmapped": unmapped, "quarantined": quarantined, "windows": windows}


# --------------------------------------------------------------------------- decisions


def decision_diff(s: Session, decision_id: str) -> dict[str, Any] | None:
    d = s.get(Decision, decision_id)
    if d is None:
        return None
    prev = s.get(Decision, d.previous_id) if d.previous_id else None
    f = s.get(Finding, d.finding_id)
    rows = []

    def row(label: str, before: Any, after: Any) -> None:
        rows.append({"label": label, "before": before, "after": after, "changed": before != after})

    pi = prev.inputs_json if prev else None
    ni = d.inputs_json
    row("Action", prev.action if prev else None, d.action)
    row("Urgency", prev.urgency if prev else None, d.urgency)
    row("Matched rule", RULE_TITLES[prev.rule] if prev else None, RULE_TITLES[d.rule])
    row("Public exploitation", pi["public_exploitation"] if pi else None, ni["public_exploitation"])
    row("Local activity on asset", pi["local_activity_on_asset"] if pi else None, ni["local_activity_on_asset"])
    row("Applicability", pi["applicability"]["effective"] if pi else None, ni["applicability"]["effective"])
    row("Internet exposure", pi["exposure"]["effective"] if pi else None, ni["exposure"]["effective"])
    row("Asset criticality", pi["criticality"] if pi else None, ni["criticality"])
    row("Evidence conflict", pi["conflict"] if pi else None, ni["conflict"])
    row(
        "Reports / independent roots / unresolved",
        _indep(pi) if pi else None,
        _indep(ni),
    )
    row("EPSS", _epss(pi) if pi else None, _epss(ni))
    row("Reason codes", ", ".join(prev.reason_codes) if prev else None, ", ".join(d.reason_codes))
    row("Unconfirmed conditions", len(prev.unknowns_json) if prev else None, len(d.unknowns_json))
    row("Policy version", prev.policy_version if prev else None, d.policy_version)

    triggers = [s.get(IntelligenceDelta, t) for t in d.trigger_delta_ids]
    triggers = [t for t in triggers if t is not None]
    prev_ev = set(prev.evidence_ids) if prev else set()
    new_ev = set(d.evidence_ids)
    added = [_evidence_ref(s, e) for e in sorted(new_ev - prev_ev)]
    removed = [_evidence_ref(s, e) for e in sorted(prev_ev - new_ev)]
    why = why_changed(prev, d, triggers)
    chain = []
    cur: Decision | None = d
    while cur is not None and len(chain) < 50:
        chain.append(cur)
        cur = s.get(Decision, cur.previous_id) if cur.previous_id else None
    return {
        "decision": d,
        "previous": prev,
        "finding": f,
        "asset": s.get(Asset, f.asset_id) if f else None,
        "rows": rows,
        "changed_rows": [r for r in rows if r["changed"]],
        "unchanged_rows": [r for r in rows if not r["changed"]],
        "triggers": triggers,
        "evidence_added": added,
        "evidence_removed": removed,
        "why": why,
        "history": chain,
        "reason_text": [(c, REASON_TEXT.get(c, c)) for c in d.reason_codes],
        "prev_reason_text": [(c, REASON_TEXT.get(c, c)) for c in (prev.reason_codes if prev else [])],
    }


def _indep(i: dict[str, Any]) -> str:
    ind = i.get("independence") or {}
    return f"{ind.get('report_count', 0)} / {ind.get('confirmed_root_count', 0)} / {ind.get('unresolved_source_count', 0)}"


def _epss(i: dict[str, Any]) -> str:
    e = i.get("epss")
    if not e:
        return "missing"
    return f"{e['probability']:.2f} ({e['score_date']}{', stale' if e['stale'] else ''})"


def _evidence_ref(s: Session, eid: str) -> dict[str, Any]:
    c = s.get(Claim, eid)
    if c is not None:
        rev = s.get(SourceRevision, c.revision_id)
        src = s.get(Source, rev.source_id) if rev else None
        return {"id": eid, "type": "claim", "label": f"{src.name if src else '?'} · {c.predicate}", "quote": c.quote}
    o = s.get(Observation, eid)
    if o is not None:
        return {"id": eid, "type": "observation", "label": f"{o.event_type} on {o.asset_id} · {o.sensor_id}", "quote": None}
    return {"id": eid, "type": "unknown", "label": eid, "quote": None}


def why_changed(prev: Decision | None, d: Decision, triggers: list[IntelligenceDelta]) -> list[str]:
    if prev is None:
        return [f"Initial decision under {d.policy_version}: {RULE_TITLES[d.rule]}."]
    out = [t.reasons_json.get("summary", "") for t in triggers if t.reasons_json.get("summary")]
    pi, ni = prev.inputs_json, d.inputs_json
    if pi["public_exploitation"] != ni["public_exploitation"] and not any(t.change_type in ("exploitation_confirmed", "claim_retracted", "exploitation_reported") for t in triggers):
        out.append(f"Public exploitation changed from {pi['public_exploitation']} to {ni['public_exploitation']}.")
    if pi["exposure"]["effective"] != ni["exposure"]["effective"] and not any(t.change_type in ("asset_exposure_changed", "evidence_expired") for t in triggers):
        out.append(f"Internet exposure changed from {pi['exposure']['effective']} to {ni['exposure']['effective']}.")
    if pi["applicability"]["effective"] != ni["applicability"]["effective"] and not any(t.change_type in ("applicability_changed", "evidence_expired") for t in triggers):
        out.append(f"Applicability changed from {pi['applicability']['effective']} to {ni['applicability']['effective']}.")
    if (prev.action, prev.urgency) != (d.action, d.urgency):
        out.append(
            f"{d.policy_version} now matches {RULE_TITLES[d.rule]} (was {RULE_TITLES[prev.rule]}), so the decision moved from {prev.action}/{prev.urgency} to {d.action}/{d.urgency}."
        )
    else:
        added = sorted(set(d.reason_codes) - set(prev.reason_codes))
        removed = sorted(set(prev.reason_codes) - set(d.reason_codes))
        out.append(
            f"Action and urgency are unchanged ({d.action}/{d.urgency}); only context changed"
            + (f" (added: {', '.join(added)})" if added else "")
            + (f" (removed: {', '.join(removed)})" if removed else "")
            + "."
        )
    return out


def decisions_for_finding(s: Session, finding_id: str) -> list[Decision]:
    return list(s.execute(select(Decision).where(Decision.finding_id == finding_id).order_by(Decision.seq.desc())).scalars())


# --------------------------------------------------------------------------- tasks, imports, evidence


def investigations(s: Session, include_resolved: bool = False) -> list[dict[str, Any]]:
    q = select(InvestigationTask)
    if not include_resolved:
        q = q.where(InvestigationTask.status == "open")
    tasks = list(s.execute(q).scalars())
    tasks.sort(key=lambda t: (t.status != "open", -t.urgent_high_count, -len(t.affected_finding_ids), t.estimated_effort, t.task_key))
    decisions = current_decisions(s)
    findings = {f.id: f for f in s.execute(select(Finding)).scalars()}
    out = []
    for t in tasks:
        items = []
        for fid in t.affected_finding_ids:
            f = findings.get(fid)
            dd = decisions.get(fid)
            items.append({"finding_id": fid, "asset_id": f.asset_id if f else None, "vulnerability_id": f.vulnerability_id if f else None, "decision": dd})
        out.append({"task": t, "items": items, "manual": t.check_type == "correction"})
    return out


def import_runs(s: Session, limit: int = 50) -> list[ImportRun]:
    return list(s.execute(select(ImportRun).order_by(ImportRun.started_at.desc(), ImportRun.id).limit(limit)).scalars())


def evidence(s: Session, eid: str) -> dict[str, Any] | None:
    c = s.get(Claim, eid)
    if c is not None:
        rev = s.get(SourceRevision, c.revision_id)
        src = s.get(Source, rev.source_id) if rev else None
        state = effective_review_states(s, [c.id]).get(c.id, c.review_state)
        rels = list(
            s.execute(select(ClaimRelation).where((ClaimRelation.from_claim_id == c.id) | (ClaimRelation.to_claim_id == c.id))).scalars()
        )
        reviews = list(s.execute(select(ClaimReview).where(ClaimReview.claim_id == c.id).order_by(ClaimReview.seq)).scalars())
        return {
            "type": "claim",
            "id": c.id,
            "claim_key": c.claim_key,
            "subject_id": c.subject_id,
            "predicate": c.predicate,
            "value": c.value_json,
            "quote": c.quote,  # returned as plain text; renderers must escape
            "locator": c.locator,
            "origin": c.origin,
            "review_state": state,
            "source": {"name": src.name if src else None, "kind": src.kind if src else None},
            "revision": {
                "id": rev.id if rev else None,
                "external_id": rev.external_id if rev else None,
                "sha256": rev.sha256 if rev else None,
                "published_at": rev.published_at.isoformat() if rev and rev.published_at else None,
                "fetched_at": rev.fetched_at.isoformat() if rev else None,
                "synthetic": rev.synthetic if rev else None,
                "supersedes_id": rev.supersedes_id if rev else None,
            },
            "relations": [{"from": r.from_claim_id, "to": r.to_claim_id, "kind": r.kind, "verification": r.verification} for r in rels],
            "reviews": [{"reviewer": r.reviewer, "state": r.state, "reason": r.reason, "recorded_at": r.recorded_at.isoformat()} for r in reviews],
        }
    o = s.get(Observation, eid)
    if o is not None:
        return {
            "type": "observation",
            "id": o.id,
            "sensor_id": o.sensor_id,
            "external_event_id": o.external_event_id,
            "observed_at": o.observed_at.isoformat(),
            "observed_precision": o.observed_precision,
            "ingested_at": o.ingested_at.isoformat(),
            "asset_id": o.asset_id,
            "vulnerability_id": o.cve_id,
            "event_type": o.event_type,
            "mapping_status": o.mapping_status,
            "status": o.status,
            "quarantine_reason": o.quarantine_reason,
            "evidence": o.evidence_json,
            "synthetic": o.synthetic,
        }
    return None

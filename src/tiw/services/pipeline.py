"""Recompute pipeline: evidence → assessment → deltas → decisions → investigation tasks.

Idempotent: if inputs and the clock are unchanged, nothing new is written.
Past assessments and decisions are never modified; new records point to their predecessors.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from tiw.domain.assessments import (
    ENGINE_VERSION,
    KevContext,
    ObservationView,
    assess,
    canonical_hash,
    derive_deltas,
)
from tiw.domain.claims import ClaimView, RelationView
from tiw.domain.decisions import POLICY_VERSION, TriageInput, evaluate
from tiw.domain.vocab import CONFIRMED_MAPPING, URGENCY_RANK
from tiw.services.ingest import audit, next_seq
from tiw.storage import db
from tiw.storage.models import (
    ApplicabilityReview,
    Asset,
    AssetRevision,
    Claim,
    ClaimRelation,
    ClaimReview,
    Decision,
    Finding,
    IntelligenceDelta,
    InvestigationTask,
    Observation,
    Source,
    SourceRevision,
    ThreatAssessment,
    Vulnerability,
)

TASK_EFFORT = {"exposure": 1, "kev_missing": 1, "epss_refresh": 1, "correction": 1, "applicability": 2, "conflict": 3}
MANUAL_TASK_TYPES = ("correction",)


# --------------------------------------------------------------------------- loaders


def effective_review_states(s: Session, claim_ids: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    if not claim_ids:
        return out
    rows = s.execute(
        select(ClaimReview.claim_id, ClaimReview.state).where(ClaimReview.claim_id.in_(claim_ids)).order_by(ClaimReview.seq)
    ).all()
    for cid, state in rows:
        out[cid] = state
    return out


def load_claims(s: Session, vid: str) -> tuple[list[ClaimView], list[RelationView]]:
    rows = s.execute(
        select(Claim, SourceRevision, Source)
        .join(SourceRevision, Claim.revision_id == SourceRevision.id)
        .join(Source, SourceRevision.source_id == Source.id)
        .where(Claim.subject_id == vid)
    ).all()
    latest_rev: dict[tuple[str, str], int] = {}
    for _c, rev, _src in rows:
        k = (rev.source_id, rev.external_id)
        latest_rev[k] = max(latest_rev.get(k, 0), rev.seq)
    # also account for newer revisions of the same document that no longer mention this subject
    doc_keys = list(latest_rev)
    for source_id, external_id in doc_keys:
        newest = s.execute(
            select(SourceRevision.seq)
            .where(SourceRevision.source_id == source_id, SourceRevision.external_id == external_id)
            .order_by(SourceRevision.seq.desc())
            .limit(1)
        ).scalar_one()
        latest_rev[(source_id, external_id)] = newest
    states = effective_review_states(s, [c.id for c, _, _ in rows])
    views = [
        ClaimView(
            id=c.id,
            key=c.claim_key,
            subject_id=c.subject_id,
            predicate=c.predicate,
            value=c.value_json,
            origin=c.origin,
            initial_state=c.review_state,
            effective_state=states.get(c.id, c.review_state),
            revision_id=rev.id,
            revision_is_latest=rev.seq == latest_rev[(rev.source_id, rev.external_id)],
            source_name=src.name,
            source_kind=src.kind,
            published_at=rev.published_at,
            fetched_at=rev.fetched_at,
            quote=c.quote,
            locator=c.locator,
        )
        for c, rev, src in rows
    ]
    ids = [v.id for v in views]
    rels: list[RelationView] = []
    if ids:
        rels = [
            RelationView(r.from_claim_id, r.to_claim_id, r.kind, r.verification)
            for r in s.execute(
                select(ClaimRelation).where(
                    or_(ClaimRelation.from_claim_id.in_(ids), ClaimRelation.to_claim_id.in_(ids))
                )
            ).scalars()
        ]
    return views, rels


def load_observations(s: Session, vid: str) -> list[ObservationView]:
    return [
        ObservationView(o.id, o.asset_id, o.event_type, o.mapping_status, o.observed_at, o.sensor_id, o.reviewer)
        for o in s.execute(
            select(Observation)
            .where(Observation.cve_id == vid, Observation.status == "accepted")
            .order_by(Observation.observed_at, Observation.id)
        ).scalars()
    ]


def kev_snapshots(s: Session) -> tuple[SourceRevision | None, dict[str, set[str]]]:
    """Return (latest snapshot by release date, revision_id -> listed vulnerability ids)."""
    revs = list(
        s.execute(
            select(SourceRevision)
            .join(Source, SourceRevision.source_id == Source.id)
            .where(Source.kind == "kev")
        ).scalars()
    )
    if not revs:
        return None, {}
    latest = max(revs, key=lambda r: (r.published_at or r.fetched_at, r.seq))
    listed: dict[str, set[str]] = defaultdict(set)
    for rid, subj in s.execute(
        select(Claim.revision_id, Claim.subject_id).where(Claim.revision_id.in_([r.id for r in revs]))
    ).all():
        listed[rid].add(subj)
    return latest, listed


def kev_context(vid: str, latest: SourceRevision | None, listed: dict[str, set[str]], claims: list[ClaimView]) -> KevContext:
    kev_claims = [c for c in claims if c.origin == "kev"]
    ever = bool(kev_claims)
    date_added = min((c.value.get("date_added", "") for c in kev_claims), default=None) or None
    if latest is None:
        return KevContext(ever, None, None, date_added)
    released = (latest.published_at or latest.fetched_at).date().isoformat()
    return KevContext(ever, vid in listed.get(latest.id, set()), released, date_added)


def latest_asset_revision(s: Session, asset_id: str) -> AssetRevision | None:
    return s.execute(
        select(AssetRevision).where(AssetRevision.asset_id == asset_id).order_by(AssetRevision.seq.desc()).limit(1)
    ).scalar_one_or_none()


def latest_applicability(s: Session, finding_id: str) -> ApplicabilityReview | None:
    return s.execute(
        select(ApplicabilityReview)
        .where(ApplicabilityReview.finding_id == finding_id)
        .order_by(ApplicabilityReview.seq.desc())
        .limit(1)
    ).scalar_one_or_none()


def latest_decision(s: Session, finding_id: str) -> Decision | None:
    return s.execute(
        select(Decision).where(Decision.finding_id == finding_id).order_by(Decision.seq.desc()).limit(1)
    ).scalar_one_or_none()


def latest_assessment(s: Session, vid: str) -> ThreatAssessment | None:
    return s.execute(
        select(ThreatAssessment)
        .where(ThreatAssessment.vulnerability_id == vid)
        .order_by(ThreatAssessment.seq.desc())
        .limit(1)
    ).scalar_one_or_none()


# --------------------------------------------------------------------------- bulk snapshot


class Snapshot:
    """All evidence needed for one recompute, loaded with a handful of queries.

    Keeps recompute time roughly linear in data size instead of issuing per-vulnerability
    queries (a full live KEV catalog has well over a thousand entries).
    """

    def __init__(self, s: Session):
        rows = s.execute(
            select(Claim, SourceRevision, Source)
            .join(SourceRevision, Claim.revision_id == SourceRevision.id)
            .join(Source, SourceRevision.source_id == Source.id)
        ).all()
        latest_rev: dict[tuple[str, str], int] = {}
        for rev in s.execute(select(SourceRevision)).scalars():
            k = (rev.source_id, rev.external_id)
            latest_rev[k] = max(latest_rev.get(k, 0), rev.seq)
        states: dict[str, str] = {}
        for cid, state in s.execute(select(ClaimReview.claim_id, ClaimReview.state).order_by(ClaimReview.seq)).all():
            states[cid] = state
        self.claims: dict[str, list[ClaimView]] = defaultdict(list)
        claim_subject: dict[str, str] = {}
        for c, rev, src in rows:
            claim_subject[c.id] = c.subject_id
            self.claims[c.subject_id].append(
                ClaimView(
                    id=c.id, key=c.claim_key, subject_id=c.subject_id, predicate=c.predicate, value=c.value_json,
                    origin=c.origin, initial_state=c.review_state, effective_state=states.get(c.id, c.review_state),
                    revision_id=rev.id, revision_is_latest=rev.seq == latest_rev[(rev.source_id, rev.external_id)],
                    source_name=src.name, source_kind=src.kind, published_at=rev.published_at, fetched_at=rev.fetched_at,
                    quote=c.quote, locator=c.locator,
                )
            )
        self.relations: dict[str, list[RelationView]] = defaultdict(list)
        for r in s.execute(select(ClaimRelation)).scalars():
            rv = RelationView(r.from_claim_id, r.to_claim_id, r.kind, r.verification)
            subjects = {claim_subject.get(r.from_claim_id), claim_subject.get(r.to_claim_id)} - {None}
            for subj in subjects:
                self.relations[subj].append(rv)
        self.observations: dict[str, list[ObservationView]] = defaultdict(list)
        for o in s.execute(
            select(Observation).where(Observation.status == "accepted", Observation.cve_id.is_not(None)).order_by(Observation.observed_at, Observation.id)
        ).scalars():
            self.observations[o.cve_id].append(
                ObservationView(o.id, o.asset_id, o.event_type, o.mapping_status, o.observed_at, o.sensor_id, o.reviewer)
            )
        self.assessment: dict[str, ThreatAssessment] = {}
        for a in s.execute(select(ThreatAssessment).order_by(ThreatAssessment.seq)).scalars():
            self.assessment[a.vulnerability_id] = a
        self.findings: dict[str, list[Finding]] = defaultdict(list)
        for f in s.execute(select(Finding).order_by(Finding.id)).scalars():
            self.findings[f.vulnerability_id].append(f)
        self.assets = {a.id: a for a in s.execute(select(Asset)).scalars()}
        self.asset_rev: dict[str, AssetRevision] = {}
        for ar in s.execute(select(AssetRevision).order_by(AssetRevision.seq)).scalars():
            self.asset_rev[ar.asset_id] = ar
        self.applicability: dict[str, ApplicabilityReview] = {}
        for ap in s.execute(select(ApplicabilityReview).order_by(ApplicabilityReview.seq)).scalars():
            self.applicability[ap.finding_id] = ap
        self.decision: dict[str, Decision] = {}
        for d in s.execute(select(Decision).order_by(Decision.seq)).scalars():
            self.decision[d.finding_id] = d
        self.decision_seq = next_seq(s, Decision)
        self.delta_seq = next_seq(s, IntelligenceDelta)


# --------------------------------------------------------------------------- main


def recompute(
    ws: db.Workspace,
    vulnerability_ids: list[str] | None = None,
    *,
    actor: str = "system",
    trigger: str = "manual",
) -> dict[str, Any]:
    with db.session_scope(ws) as s:
        return recompute_in_session(s, vulnerability_ids, actor=actor, trigger=trigger)


def recompute_in_session(
    s: Session, vulnerability_ids: list[str] | None, *, actor: str, trigger: str
) -> dict[str, Any]:
    now = db.now(s)
    vids = vulnerability_ids or list(s.execute(select(Vulnerability.id).order_by(Vulnerability.id)).scalars())
    latest_kev, kev_listed = kev_snapshots(s)
    summary = {"assessments": 0, "deltas": 0, "decisions": 0, "vulnerabilities": len(vids)}
    run_deltas: list[IntelligenceDelta] = []
    snap = Snapshot(s)

    for vid in vids:
        claims, rels = snap.claims.get(vid, []), snap.relations.get(vid, [])
        obs = snap.observations.get(vid, [])
        state, evidence = assess(vid, claims, rels, obs, kev_context(vid, latest_kev, kev_listed, claims), now)
        h = canonical_hash(state)
        prev = snap.assessment.get(vid)
        if prev is not None and prev.state_hash == h:
            assessment, vuln_changes = prev, []
        else:
            assessment = ThreatAssessment(
                id=str(uuid.uuid4()),
                vulnerability_id=vid,
                created_at=now,
                evidence_cutoff=now,
                engine_version=ENGINE_VERSION,
                state_json=state,
                state_hash=h,
                evidence_ids=evidence,
                seq=(prev.seq + 1) if prev else 1,
            )
            s.add(assessment)
            s.flush()
            snap.assessment[vid] = assessment
            summary["assessments"] += 1
            vuln_changes = derive_deltas(prev.state_json if prev else None, state)

        findings = snap.findings.get(vid, [])
        obs_by_asset: dict[str, list[str]] = defaultdict(list)
        for o in obs:
            if o.asset_id and o.mapping_status in CONFIRMED_MAPPING:
                obs_by_asset[o.asset_id].append(o.id)

        pending: list[dict[str, Any]] = []  # delta dicts with pre-assigned ids
        for ch in vuln_changes:
            affected = [f.id for f in findings if "asset_id" not in ch or f.asset_id == ch["asset_id"]]
            if ch["change_type"] in ("local_attempt_observed", "local_compromise_confirmed"):
                ch["evidence_ids"] = obs_by_asset.get(ch["asset_id"], [])
            pending.append({"id": str(uuid.uuid4()), **ch, "affected_finding_ids": affected, "decision_ids": []})

        new_decisions: list[Decision] = []
        for f in findings:
            asset = snap.assets.get(f.asset_id)
            arev = snap.asset_rev.get(f.asset_id)
            app = snap.applicability.get(f.id)
            criticality = (arev.context_json.get("criticality") if arev else None) or (asset.criticality if asset else "normal")
            inp = TriageInput(
                finding_id=f.id,
                asset_id=f.asset_id,
                vulnerability_id=vid,
                criticality=criticality,
                exposure_value=arev.internet_exposed if arev else "unknown",
                exposure_expires_at=arev.expires_at if arev else None,
                exposure_observed_at=arev.observed_at if arev else None,
                applicability=app.status if app else "unknown",
                applicability_expires_at=app.expires_at if app else None,
                applicability_reviewer=app.reviewer if app else None,
                applicability_rationale=app.rationale if app else None,
                state=state,
                now=now,
            )
            res = evaluate(inp)
            prev_dec = snap.decision.get(f.id)

            finding_changes: list[dict[str, Any]] = []
            if prev_dec is not None:
                pi = prev_dec.inputs_json
                pe, ne = pi["exposure"]["effective"], res.inputs["exposure"]["effective"]
                if pe != ne:
                    finding_changes.append(
                        {
                            "change_type": "evidence_expired" if ne == "expired" else "asset_exposure_changed",
                            "summary": (
                                f"Exposure evidence for {f.asset_id} expired"
                                if ne == "expired"
                                else f"Internet exposure of {f.asset_id}: {pe} → {ne}"
                            ),
                            "before": {"exposure": pe},
                            "after": {"exposure": ne},
                            "evidence_kind": "asset_exposure",
                            "asset_id": f.asset_id,
                            "evidence_ids": [arev.id] if arev else [],
                        }
                    )
                pa, na = pi["applicability"]["effective"], res.inputs["applicability"]["effective"]
                if pa != na:
                    finding_changes.append(
                        {
                            "change_type": "evidence_expired" if na == "not_affected_expired" else "applicability_changed",
                            "summary": (
                                f"Reviewed not_affected for {f.id} expired"
                                if na == "not_affected_expired"
                                else f"Applicability of {f.id}: {pa} → {na}"
                            ),
                            "before": {"applicability": pa},
                            "after": {"applicability": na},
                            "evidence_kind": "applicability",
                            "asset_id": f.asset_id,
                            "evidence_ids": [app.id] if app else [],
                        }
                    )
            for ch in finding_changes:
                pending.append({"id": str(uuid.uuid4()), **ch, "affected_finding_ids": [f.id], "decision_ids": []})

            if prev_dec is not None and prev_dec.outcome_hash == res.outcome_hash():
                continue
            triggers = [p["id"] for p in pending if f.id in p["affected_finding_ids"]]
            dec = Decision(
                finding_id=f.id,
                assessment_id=assessment.id,
                asset_revision_id=arev.id if arev else None,
                applicability_review_id=app.id if app else None,
                policy_version=POLICY_VERSION,
                action=res.action,
                urgency=res.urgency,
                rule=res.rule,
                reason_codes=res.reason_codes,
                evidence_ids=sorted(set(res.evidence_claim_ids) | set(obs_by_asset.get(f.asset_id, []))),
                unknowns_json=res.unknowns,
                inputs_json=res.inputs,
                outcome_hash=res.outcome_hash(),
                previous_id=prev_dec.id if prev_dec else None,
                created_at=now,
                trigger_delta_ids=triggers,
                seq=snap.decision_seq,
            )
            snap.decision_seq += 1
            s.add(dec)
            s.flush()
            snap.decision[f.id] = dec
            new_decisions.append(dec)
            for p in pending:
                if f.id in p["affected_finding_ids"]:
                    p["decision_ids"].append(dec.id)

        for p in pending:
            reasons = {k: v for k, v in p.items() if k not in ("id", "change_type")}
            d = IntelligenceDelta(
                id=p["id"],
                vulnerability_id=vid,
                old_assessment_id=prev.id if prev is not None and assessment is not prev else (prev.id if prev else None),
                new_assessment_id=assessment.id,
                change_type=p["change_type"],
                reasons_json=reasons,
                created_at=now,
                seq=snap.delta_seq,
            )
            snap.delta_seq += 1
            s.add(d)
            run_deltas.append(d)
        summary["deltas"] += len(pending)
        summary["decisions"] += len(new_decisions)

    _create_correction_tasks(s, run_deltas, now)
    rebuild_tasks(s, now)
    if summary["assessments"] or summary["deltas"] or summary["decisions"]:
        audit(s, actor, "recompute", "workspace", "*", {"trigger": trigger, **summary})
    return summary


# --------------------------------------------------------------------------- tasks


def _current_decisions(s: Session) -> list[Decision]:
    out = []
    for fid in s.execute(select(Finding.id).order_by(Finding.id)).scalars():
        d = latest_decision(s, fid)
        if d is not None:
            out.append(d)
    return out


def _upsert_task(
    s: Session,
    now: datetime,
    key: str,
    check_type: str,
    question: str,
    required: str,
    finding_ids: list[str],
    decisions: dict[str, Decision],
    vulnerability_id: str | None,
) -> None:
    uh = sum(1 for fid in finding_ids if fid in decisions and URGENCY_RANK[decisions[fid].urgency] <= 1)
    t = s.execute(select(InvestigationTask).where(InvestigationTask.task_key == key)).scalar_one_or_none()
    first_dec = decisions.get(finding_ids[0]) if finding_ids else None
    if t is None:
        s.add(
            InvestigationTask(
                task_key=key,
                finding_id=finding_ids[0] if len(finding_ids) == 1 else None,
                vulnerability_id=vulnerability_id,
                question=question,
                affected_finding_ids=sorted(finding_ids),
                required_evidence=required,
                check_type=check_type,
                estimated_effort=TASK_EFFORT[check_type],
                urgent_high_count=uh,
                status="open",
                decision_id=first_dec.id if first_dec else None,
                created_at=now,
                updated_at=now,
            )
        )
        s.flush()
        return
    changed = (
        t.status != "open"
        or t.affected_finding_ids != sorted(finding_ids)
        or t.urgent_high_count != uh
        or t.question != question
    )
    if changed:
        t.status = "open"
        t.question = question
        t.affected_finding_ids = sorted(finding_ids)
        t.urgent_high_count = uh
        t.decision_id = first_dec.id if first_dec else t.decision_id
        t.updated_at = now


def rebuild_tasks(s: Session, now: datetime) -> None:
    decisions = {d.finding_id: d for d in _current_decisions(s)}
    findings = {f.id: f for f in s.execute(select(Finding)).scalars()}
    groups: dict[str, dict[str, Any]] = {}

    def add(key: str, check_type: str, question: str, required: str, fid: str, vid: str | None) -> None:
        g = groups.setdefault(key, {"check_type": check_type, "question": question, "required": required, "fids": [], "vid": vid})
        g["fids"].append(fid)

    for fid, d in decisions.items():
        f = findings[fid]
        codes = set(d.reason_codes)
        if codes & {"APPLICABILITY_UNKNOWN", "NOT_AFFECTED_EXPIRED"}:
            add(
                f"applicability:{f.vulnerability_id}",
                "applicability",
                f"Which assets run an affected version or configuration of {f.vulnerability_id}?",
                "Installed version, enabled modules/configuration, vendor applicability statement; re-confirm expired not_affected reviews",
                fid,
                f.vulnerability_id,
            )
        if "NOT_AFFECTED_CONTRADICTED" in codes:
            add(
                f"conflict:{f.vulnerability_id}:{f.asset_id}",
                "conflict",
                f"A confirmed exploit attempt hit {f.asset_id} although {f.vulnerability_id} was reviewed not_affected. Is the review still valid?",
                "Verify the rule-to-vulnerability mapping, the installed version, and the actual request target",
                fid,
                f.vulnerability_id,
            )
        if codes & {"EXPOSURE_UNKNOWN", "EVIDENCE_EXPIRED"}:
            add(
                f"exposure:{f.asset_id}",
                "exposure",
                f"Is {f.asset_id} currently reachable from the internet?",
                "Current firewall/load-balancer/configuration evidence with an observation time and expiry",
                fid,
                None,
            )
        if "KEV_RECORD_MISSING" in codes:
            add(
                f"kev_missing:{f.vulnerability_id}",
                "kev_missing",
                f"Why is {f.vulnerability_id} missing from the latest KEV snapshot?",
                "Check the KEV changelog or a newer snapshot; a missing record is not a retraction",
                fid,
                f.vulnerability_id,
            )
        if "EPSS_STALE" in codes:
            add(
                "epss_refresh",
                "epss_refresh",
                "EPSS scores used by current decisions are older than 72 h. Import a current EPSS response.",
                "A saved EPSS API response dated within the last 72 hours",
                fid,
                None,
            )

    for key, g in groups.items():
        _upsert_task(s, now, key, g["check_type"], g["question"], g["required"], g["fids"], decisions, g["vid"])
    for t in s.execute(select(InvestigationTask).where(InvestigationTask.status == "open")).scalars():
        if t.task_key not in groups and t.check_type not in MANUAL_TASK_TYPES:
            t.status = "resolved"
            t.updated_at = now
    s.flush()


def _create_correction_tasks(s: Session, deltas: list[IntelligenceDelta], now: datetime) -> None:
    decisions = {d.finding_id: d for d in _current_decisions(s)}
    for d in deltas:
        if d.change_type != "claim_retracted":
            continue
        claim_ids = d.reasons_json.get("evidence_ids") or []
        dependent: set[str] = set()
        for cid in claim_ids:
            for fid, ev in s.execute(select(Decision.finding_id, Decision.evidence_ids)).all():
                if cid in (ev or []):
                    dependent.add(fid)
        dependent |= set(d.reasons_json.get("affected_finding_ids", []))
        if not dependent:
            continue
        key = f"correction:{d.vulnerability_id}:{','.join(sorted(claim_ids)) or d.id}"
        _upsert_task(
            s,
            now,
            key,
            "correction",
            f"A source corrected evidence for {d.vulnerability_id}. Review the decisions that relied on it.",
            "Compare the dependent decisions' Before/After and confirm no other evidence supports the old conclusion",
            sorted(dependent),
            decisions,
            d.vulnerability_id,
        )


def resolve_task(s: Session, task_id: str, actor: str, reason: str) -> InvestigationTask:
    t = s.get(InvestigationTask, task_id)
    if t is None:
        raise LookupError("investigation task not found")
    if t.status != "resolved":
        t.status = "resolved"
        t.updated_at = db.now(s)
        audit(s, actor, "resolve_task", "investigation_task", t.id, {"reason": reason})
    return t

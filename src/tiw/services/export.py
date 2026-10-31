"""Local JSON / Markdown exports for one threat. Nothing is sent anywhere."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from tiw.domain.vocab import DELTA_LABELS, REASON_TEXT
from tiw.services import queries
from tiw.storage import db

EXPORT_VERSION = "export-1"


def _iso(v: Any) -> Any:
    return v.isoformat() if isinstance(v, datetime) else v


def threat_document(s: Session, vid: str) -> dict[str, Any] | None:
    det = queries.threat_detail(s, vid)
    if det is None:
        return None
    st = det["state"] or {}
    return {
        "export_version": EXPORT_VERSION,
        "generated_at": db.utc_iso(db.now(s)),
        "synthetic": db.is_synthetic_workspace(s) or det["vulnerability"].synthetic,
        "vulnerability_id": vid,
        "title": det["vulnerability"].title,
        "assessment": {
            "id": det["assessment"].id if det["assessment"] else None,
            "engine_version": det["assessment"].engine_version if det["assessment"] else None,
            "evidence_cutoff": _iso(det["assessment"].evidence_cutoff) if det["assessment"] else None,
            "evidence_status": det["status"],
            "state": st,
            "evidence_ids": det["assessment"].evidence_ids if det["assessment"] else [],
        },
        "deltas": [
            {
                "id": d.id,
                "change_type": d.change_type,
                "label": DELTA_LABELS.get(d.change_type, d.change_type),
                "created_at": _iso(d.created_at),
                "reasons": d.reasons_json,
            }
            for d in det["deltas"]
        ],
        "evidence": [
            {
                "id": r["claim"].id,
                "claim_key": r["claim"].key,
                "source": r["claim"].source_name,
                "predicate": r["claim"].predicate,
                "value": r["claim"].value,
                "origin": r["claim"].origin,
                "review_state": r["claim"].effective_state,
                "inactive_reason": r["inactive_reason"],
                "published_at": _iso(r["claim"].published_at),
                "quote_excerpt": (r["claim"].quote or "")[:300] or None,
                "relations": r["relations"],
            }
            for r in det["claims"]
        ],
        "assets": [
            {
                "finding_id": a["finding"].id,
                "asset_id": a["finding"].asset_id,
                "decision": None
                if a["decision"] is None
                else {
                    "id": a["decision"].id,
                    "policy_version": a["decision"].policy_version,
                    "action": a["decision"].action,
                    "urgency": a["decision"].urgency,
                    "rule": a["decision"].rule,
                    "reason_codes": a["decision"].reason_codes,
                    "unknowns": a["decision"].unknowns_json,
                    "inputs": a["decision"].inputs_json,
                    "evidence_ids": a["decision"].evidence_ids,
                    "previous_id": a["decision"].previous_id,
                    "created_at": _iso(a["decision"].created_at),
                },
            }
            for a in det["assets"]
        ],
        "decision_history": [
            {
                "id": d.id,
                "finding_id": d.finding_id,
                "action": d.action,
                "urgency": d.urgency,
                "rule": d.rule,
                "reason_codes": d.reason_codes,
                "previous_id": d.previous_id,
                "created_at": _iso(d.created_at),
            }
            for d in det["decisions"]
        ],
    }


_MD_SPECIAL = re.compile(r"([\\`*_\[\]|#])")


def md_escape(text: Any) -> str:
    """Escape untrusted text for Markdown: neutralise HTML and Markdown syntax, keep one line."""
    t = str(text if text is not None else "")
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"[\r\n\t]+", " ", t)
    return _MD_SPECIAL.sub(r"\\\1", t)


def to_markdown(doc: dict[str, Any]) -> str:
    st = doc["assessment"]["state"] or {}
    L: list[str] = []
    L.append(f"# Threat report: {md_escape(doc['vulnerability_id'])}")
    L.append("")
    if doc["synthetic"]:
        L.append("> **SYNTHETIC DATA** — generated from demo fixtures; not real threat intelligence.")
        L.append("")
    L.append(f"- Generated: {doc['generated_at']} ({doc['export_version']})")
    L.append(f"- Assessment engine: {md_escape(doc['assessment']['engine_version'])}, evidence cutoff {md_escape(doc['assessment']['evidence_cutoff'])}")
    L.append(f"- Evidence status: **{md_escape(doc['assessment']['evidence_status'])}**")
    if st:
        ind = st.get("independence", {})
        L.append(f"- Public exploitation: {md_escape(st['public_exploitation'])} (basis: {md_escape(', '.join(st['public_basis_kinds']) or 'none')})")
        L.append(f"- Local activity: {md_escape(st['local_activity'])} (observations without a confirmed mapping: {st['unmapped_observation_count']})")
        L.append(f"- Reports: {ind.get('report_count', 0)}, independent known roots: {ind.get('confirmed_root_count', 0)}, unresolved roots: {ind.get('unresolved_source_count', 0)}")
        L.append(f"- Recency: {md_escape(st['recency'])}; conflict: {st['conflict']}")
        e = st.get("epss")
        L.append(f"- EPSS: {md_escape(f'{e['probability']} (score date {e['score_date']}, stale={e['stale']})') if e else 'missing'}")
    L.append("")
    L.append("## Asset decisions")
    L.append("")
    L.append("| Finding | Asset | Action | Urgency | Rule | Reason codes |")
    L.append("|---|---|---|---|---|---|")
    for a in doc["assets"]:
        d = a["decision"]
        if d is None:
            L.append(f"| {md_escape(a['finding_id'])} | {md_escape(a['asset_id'])} | — | — | — | not yet evaluated |")
        else:
            L.append(
                f"| {md_escape(a['finding_id'])} | {md_escape(a['asset_id'])} | {d['action']} | {d['urgency']} | {d['rule']} | {md_escape(', '.join(d['reason_codes']))} |"
            )
    L.append("")
    for a in doc["assets"]:
        d = a["decision"]
        if d and d["unknowns"]:
            L.append(f"Unconfirmed conditions for {md_escape(a['finding_id'])}:")
            for u in d["unknowns"]:
                L.append(f"- {md_escape(u['detail'])} — check: {md_escape(u['check'])}")
            L.append("")
    L.append("## Intelligence changes")
    L.append("")
    if not doc["deltas"]:
        L.append("No meaningful changes recorded.")
    for d in doc["deltas"]:
        L.append(f"- {md_escape(d['created_at'])} — **{md_escape(d['label'])}**: {md_escape(d['reasons'].get('summary', ''))}")
    L.append("")
    L.append("## Evidence")
    L.append("")
    for e in doc["evidence"]:
        status = e["review_state"] + (f", inactive: {e['inactive_reason']}" if e["inactive_reason"] else "")
        L.append(f"- `{e['id'][:8]}` {md_escape(e['source'])} · {md_escape(e['predicate'])} · origin {md_escape(e['origin'])} · {md_escape(status)}")
        if e["quote_excerpt"]:
            L.append(f"  - excerpt: {md_escape(e['quote_excerpt'])}")
    L.append("")
    L.append("## Reason code glossary")
    L.append("")
    used = sorted({c for a in doc["assets"] if a["decision"] for c in a["decision"]["reason_codes"]})
    for c in used:
        L.append(f"- `{c}`: {md_escape(REASON_TEXT.get(c, c))}")
    L.append("")
    return "\n".join(L)


def export_threat(ws: db.Workspace, vid: str, fmt: str) -> tuple[str, str]:
    """Write the export under <data_dir>/exports and return (path, content)."""
    if fmt not in ("json", "markdown"):
        raise ValueError("format must be json or markdown")
    with db.session_scope(ws) as s:
        doc = threat_document(s, vid)
        if doc is None:
            raise LookupError(f"unknown vulnerability {vid}")
        content = json.dumps(doc, indent=2, default=str) if fmt == "json" else to_markdown(doc)
        safe_id = re.sub(r"[^A-Za-z0-9-]", "_", vid)
        digest = hashlib.sha256(content.encode()).hexdigest()[:12]
        ext = "json" if fmt == "json" else "md"
        ws.exports_dir.mkdir(parents=True, exist_ok=True)
        path = ws.exports_dir / f"{safe_id}-{digest}.{ext}"
        path.write_text(content, encoding="utf-8")
        from tiw.services.ingest import audit

        audit(s, "export", "export", "vulnerability", vid, {"format": fmt, "file": path.name})
    return str(path), content

"""Draft v2 inputs generated from data the workspace already has (assets and findings).

Drafts never invent evidence. Anything that cannot be derived is left explicitly unknown:
service ports become ``any`` (which adds an unknown "service port" fact to every hop), nothing
is marked reviewed, CVSS is omitted, and every remediation effort is a placeholder of 1 that
the README and the file itself tell the analyst to replace. Drafts are plain JSON in the
documented import formats, so they can be edited and re-imported.
"""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from tiw.services.graph import latest_input
from tiw.storage import db
from tiw.storage.models import Asset, Finding, Vulnerability

DRAFT_KINDS = ("exploit_conditions", "remediations")
DRAFT_NOTE = "DRAFT generated from imported findings. Nothing here is reviewed; edit and re-import."


class DraftError(LookupError):
    pass


def _findings(s: Session) -> list[Finding]:
    rows = list(s.execute(select(Finding).join(Asset, Finding.asset_id == Asset.id).where(Asset.active.is_(True)).order_by(Finding.id)).scalars())
    if not rows:
        raise DraftError("no findings imported yet: import assets.csv and findings.csv first")
    return rows


def draft_exploit_conditions(s: Session) -> dict[str, Any]:
    """One entry per vulnerability with findings. Existing entries (if any) are kept as they are."""
    existing = {}
    cur = latest_input(s, "exploit_conditions")
    if cur is not None:
        existing = {v["vulnerability_id"]: v for v in cur.content_json["vulnerabilities"]}
    with_findings = {f.vulnerability_id for f in _findings(s)}
    # curated entries first, in their recorded order; new vulnerabilities appended in id order
    vids = [v for v in existing if v in with_findings] + sorted(with_findings - set(existing))
    out = []
    for vid in vids:
        if vid in existing:
            v = dict(existing[vid])
            v = {k: val for k, val in v.items() if val is not None or k in ("cvss",)}
            if v.get("cvss") is None:
                v.pop("cvss", None)
            for c in v.get("conditions", []):
                for k in [k for k, val in c.items() if val is None]:
                    c.pop(k)
            out.append(v)
            continue
        vul = s.get(Vulnerability, vid)
        out.append({
            "vulnerability_id": vid,
            "title": (vul.title if vul and vul.title else None) or vid,
            "service_ports": ["any"],
            "requires_capability": "network_access",
            "grants_capability": "code_execution",
            "citation": "draft: not yet researched (replace with the advisory section that states the preconditions)",
            "review_state": "unreviewed",
            "conditions": [],
            "notes": "Draft defaults: reachable on any open port, needs only network access, grants code execution. "
                     "Replace service_ports and capabilities from the advisory; add conditions.",
        })
    for v in out:
        if v.get("title") is None:
            v.pop("title", None)
    description = (cur.content_json.get("description") if cur is not None else None) or DRAFT_NOTE
    return {"schema_version": "1.0", "synthetic": db.is_synthetic_workspace(s), "description": description,
            "source": {"name": "draft generated from findings"}, "vulnerabilities": out}


def draft_remediations(s: Session) -> dict[str, Any]:
    """A patch action per finding. Existing actions are kept; effort 1 is a placeholder."""
    existing: list[dict[str, Any]] = []
    cur = latest_input(s, "remediations")
    if cur is not None:
        existing = [{k: v for k, v in a.items() if v not in (None, [], "")} for a in cur.content_json["actions"]]
    covered = {a.get("finding_id") for a in existing if a.get("type") == "patch_finding"}
    ids = {a["id"] for a in existing}
    actions = list(existing)
    for f in _findings(s):
        if f.id in covered:
            continue
        aid = f"A-patch-{f.id}"[:58]
        n = 2
        while aid in ids:
            aid = f"A-patch-{f.id}"[:54] + f"-{n}"
            n += 1
        ids.add(aid)
        actions.append({"id": aid, "type": "patch_finding", "finding_id": f.id,
                        "label": f"Patch {f.vulnerability_id} on {f.asset_id}", "cost": 1, "downtime": "low",
                        "verification_status": "unverified", "notes": "draft: effort 1 is a placeholder; replace with a real estimate"})
    description = (cur.content_json.get("description") if cur is not None else None) or DRAFT_NOTE
    return {"schema_version": "1.0", "synthetic": db.is_synthetic_workspace(s), "description": description,
            "cost_unit": "effort units (draft placeholders = 1)" if cur is None else (cur.content_json.get("cost_unit") or "effort units"),
            "source": {"name": "draft generated from findings"}, "actions": actions}


def draft(s: Session, kind: str) -> dict[str, Any]:
    if kind == "exploit_conditions":
        return draft_exploit_conditions(s)
    if kind == "remediations":
        return draft_remediations(s)
    raise DraftError(f"no draft for {kind}; choose one of {', '.join(DRAFT_KINDS)}")


def draft_bytes(ws: db.Workspace, kind: str) -> bytes:
    with db.session_scope(ws) as s:
        return (json.dumps(draft(s, kind), indent=1, ensure_ascii=False) + "\n").encode()


def draft_and_import(ws: db.Workspace, kinds: tuple[str, ...] = DRAFT_KINDS, actor: str = "cli") -> list[dict[str, Any]]:
    """Generate and import drafts in order. Identical drafts are no-ops (idempotent import)."""
    from tiw.services.ingest import run_import

    out = []
    for k in kinds:
        res = run_import(ws, k, draft_bytes(ws, k), actor=actor, recompute=False)
        out.append({"kind": k, **{x: res.as_dict()[x] for x in ("status", "accepted", "duplicates", "rejected", "errors")}})
        if res.status == "failed":
            break
    return out

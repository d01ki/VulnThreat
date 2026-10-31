from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tiw.services.ingest import run_import
from tiw.storage import db


def set_clock(ws: db.Workspace, iso: str) -> None:
    with db.session_scope(ws) as s:
        db.set_meta(s, "clock_fixed", iso)


@pytest.fixture
def ws(tmp_path: Path) -> db.Workspace:
    w = db.resolve_workspace(tmp_path / "syn")
    db.init_workspace(w, synthetic=True)
    set_clock(w, "2026-10-01T09:00:00Z")
    yield w
    db.dispose_engine(w)


@pytest.fixture
def live_ws(tmp_path: Path) -> db.Workspace:
    w = db.resolve_workspace(tmp_path / "live")
    db.init_workspace(w, synthetic=False)
    set_clock(w, "2026-10-01T09:00:00Z")
    yield w
    db.dispose_engine(w)


def imp(ws: db.Workspace, kind: str, data: str | bytes | dict | list, **kw: Any):
    if isinstance(data, (dict, list)):
        data = json.dumps(data)
    if isinstance(data, str):
        data = data.encode()
    return run_import(ws, kind, data, **kw)


ASSET_HDR = "asset_id,name,criticality,internet_exposed,observed_at,expires_at\n"
FINDING_HDR = "finding_id,asset_id,vulnerability_id,applicability,observed_at,rationale,evidence_ref,reviewer,expires_at\n"


def asset_row(aid: str, crit: str = "normal", exposed: str = "true", expires: str = "2026-12-31T00:00:00Z") -> str:
    return f"{aid},{aid}-name,{crit},{exposed},2026-10-01T00:00:00Z,{expires}\n"


def finding_row(fid: str, aid: str, vid: str, app: str = "affected", expires: str = "") -> str:
    if app == "not_affected":
        return f"{fid},{aid},{vid},not_affected,2026-10-01T00:00:00Z,module disabled,cfg:1,analyst,{expires or '2026-12-31T00:00:00Z'}\n"
    return f"{fid},{aid},{vid},{app},2026-10-01T00:00:00Z,,,,\n"


def obs(ext: str, asset: str | None, vid: str | None, etype: str = "exploit_attempt", mapping: str = "reviewer_confirmed", at: str = "2026-10-01T08:00:00Z", **extra: Any) -> str:
    r = {"schema_version": "1.0", "sensor_id": "s1", "external_event_id": ext, "observed_at": at, "asset_id": asset,
         "event_type": etype, "mapping_status": mapping, "evidence": {"rule_id": "r"}, "synthetic": True, **extra}
    if vid:
        r["vulnerability_id"] = vid
    return json.dumps(r) + "\n"


def kev(version: str, released: str, vids: list[str]) -> dict:
    return {"catalogVersion": version, "dateReleased": released, "synthetic": True,
            "vulnerabilities": [{"cveID": v, "dateAdded": released[:10], "shortDescription": "x"} for v in vids]}


def claims(source: str, docs: list[dict]) -> dict:
    return {"schema_version": "1.0", "synthetic": True, "source": {"name": source}, "documents": docs}


def claim(key: str, vid: str, origin: str = "secondary", state: str = "unreviewed", value: bool = True, **extra: Any) -> dict:
    c = {"claim_key": key, "subject_id": vid, "predicate": "exploited_in_wild", "value": value, "origin": origin, "review_state": state, **extra}
    if state == "reviewed":
        c.setdefault("reviewer", "analyst")
        c.setdefault("review_reason", "checked")
    return c


def current(ws: db.Workspace) -> dict[str, tuple[str, str, list[str]]]:
    from tiw.services.queries import current_decisions

    with db.session_scope(ws) as s:
        return {fid: (d.action, d.urgency, list(d.reason_codes)) for fid, d in current_decisions(s).items()}


def counts(ws: db.Workspace) -> dict[str, int]:
    from sqlalchemy import func, select

    from tiw.storage import models as M

    with db.session_scope(ws) as s:
        return {
            name: s.execute(select(func.count()).select_from(cls)).scalar_one()
            for name, cls in {
                "assessments": M.ThreatAssessment, "deltas": M.IntelligenceDelta, "decisions": M.Decision,
                "observations": M.Observation, "claims": M.Claim, "revisions": M.SourceRevision, "asset_revisions": M.AssetRevision,
                "applicability": M.ApplicabilityReview, "import_runs": M.ImportRun,
            }.items()
        }

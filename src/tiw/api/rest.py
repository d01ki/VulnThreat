"""REST API /api/v1 (DESIGN §14). Every request needs the local bearer token."""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field

from tiw.adapters.common import MAX_FILE_BYTES, InputMalformed, InputTooLarge
from tiw.api.security import check_token
from tiw.services import queries
from tiw.services.export import export_threat
from tiw.services.ingest import KINDS, run_import
from tiw.services.pipeline import recompute, resolve_task
from tiw.services.review import ReviewError, add_review
from tiw.storage import db
from tiw.storage.models import ImportRun


class ApiError(HTTPException):
    def __init__(self, status: int, code: str, message: str, details: list | None = None):
        super().__init__(status_code=status, detail={"code": code, "message": message, "details": details or []})


class ErrorBody(BaseModel):
    code: str
    message: str
    details: list[Any] = []


class ErrorEnvelope(BaseModel):
    error: ErrorBody


class ImportResult(BaseModel):
    id: Optional[str]
    kind: str
    status: Literal["succeeded", "failed", "duplicate", "validated"]
    accepted: int
    rejected: int
    duplicates: int
    quarantined: int
    errors: list[dict[str, Any]]
    affected_vulnerabilities: list[str] = []
    recompute: dict[str, Any] = {}
    input_sha256: str = ""


class RelationConfirm(BaseModel):
    to_claim_id: str
    kind: Literal["cites", "duplicates", "supports", "contradicts", "supersedes"]


class ReviewRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=120)
    state: Literal["reviewed", "rejected", "retracted", "unreviewed"]
    reason: str = Field(min_length=1, max_length=2000)
    relation: Optional[RelationConfirm] = None


class RecomputeRequest(BaseModel):
    vulnerability_ids: Optional[list[str]] = None


class ExportRequest(BaseModel):
    vulnerability_id: str
    format: Literal["json", "markdown"] = "markdown"


class ResolveRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)
    actor: str = Field(default="local-analyst", max_length=120)


def _iso(v: Any) -> Any:
    return v.isoformat() if hasattr(v, "isoformat") else v


def _decision(d: Any) -> dict[str, Any] | None:
    if d is None:
        return None
    return {
        "id": d.id,
        "finding_id": d.finding_id,
        "assessment_id": d.assessment_id,
        "asset_revision_id": d.asset_revision_id,
        "applicability_review_id": d.applicability_review_id,
        "policy_version": d.policy_version,
        "action": d.action,
        "urgency": d.urgency,
        "rule": d.rule,
        "reason_codes": d.reason_codes,
        "evidence_ids": d.evidence_ids,
        "unknowns": d.unknowns_json,
        "inputs": d.inputs_json,
        "previous_id": d.previous_id,
        "trigger_delta_ids": d.trigger_delta_ids,
        "created_at": _iso(d.created_at),
    }


def build_router(ws: db.Workspace) -> APIRouter:
    token = ws.token_path.read_text(encoding="utf-8").strip()

    def auth(request: Request) -> None:
        if not check_token(request, token):
            raise ApiError(401, "unauthorized", "Missing or invalid bearer token (see the api_token file in the workspace)")

    r = APIRouter(prefix="/api/v1", dependencies=[Depends(auth)], responses={401: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope}})

    @r.post("/imports/{kind}", response_model=ImportResult, status_code=201, responses={413: {"model": ErrorEnvelope}})
    async def post_import(kind: str, file: UploadFile = File(...), allow_partial: bool = Query(False), dry_run: bool = Query(False)) -> Any:
        if kind not in KINDS:
            raise ApiError(404, "unknown_kind", f"kind must be one of {', '.join(KINDS)}")
        data = await file.read(MAX_FILE_BYTES + 1)
        try:
            out = run_import(ws, kind, data, actor="api", allow_partial=allow_partial, dry_run=dry_run)
        except InputTooLarge as exc:
            raise ApiError(413, "too_large", str(exc)) from None
        except InputMalformed as exc:
            raise ApiError(422, "malformed", str(exc)) from None
        if out.status == "failed":
            raise ApiError(422, "validation_failed", "Import rejected; nothing was written", out.errors)
        return out.as_dict()

    @r.get("/imports/{run_id}")
    def get_import(run_id: str) -> Any:
        with db.session_scope(ws) as s:
            run = s.get(ImportRun, run_id)
            if run is None:
                raise ApiError(404, "not_found", "import run not found")
            return {
                "id": run.id, "adapter": run.adapter, "adapter_version": run.adapter_version, "input_sha256": run.input_sha256,
                "status": run.status, "accepted": run.accepted, "rejected": run.rejected, "duplicates": run.duplicates,
                "quarantined": run.quarantined, "errors": run.errors_json, "started_at": _iso(run.started_at), "completed_at": _iso(run.completed_at),
            }

    @r.get("/threats")
    def get_threats(
        status: Optional[Literal["conflict", "confirmed", "reported", "unknown"]] = None,
        period: Literal["24h", "7d", "30d", "all"] = "all",
        q: Optional[str] = Query(None, max_length=100),
        cursor: Optional[str] = None,
        limit: int = Query(50, ge=1, le=200),
    ) -> Any:
        with db.session_scope(ws) as s:
            try:
                res = queries.threats(s, status=status, period_key=period, q=q, cursor=cursor, limit=limit)
            except (ValueError, UnicodeDecodeError):
                raise ApiError(422, "bad_cursor", "invalid cursor") from None
            return {
                "items": [
                    {k: _iso(v) for k, v in row.items() if k != "state"} | {"state": row["state"]} for row in res["items"]
                ],
                "next_cursor": res["next_cursor"],
                "synthetic": db.is_synthetic_workspace(s),
            }

    @r.get("/threats/{vid}")
    def get_threat(vid: str) -> Any:
        with db.session_scope(ws) as s:
            det = queries.threat_detail(s, vid)
            if det is None:
                raise ApiError(404, "not_found", "unknown vulnerability")
            return {
                "id": vid,
                "title": det["vulnerability"].title,
                "synthetic": det["vulnerability"].synthetic,
                "evidence_status": det["status"],
                "assessment": None if det["assessment"] is None else {
                    "id": det["assessment"].id, "engine_version": det["assessment"].engine_version,
                    "evidence_cutoff": _iso(det["assessment"].evidence_cutoff), "state": det["state"], "evidence_ids": det["assessment"].evidence_ids,
                },
                "evidence": [queries.evidence(s, c["claim"].id) | {"inactive_reason": c["inactive_reason"]} for c in det["claims"]],
                "observations": [queries.evidence(s, o.id) for o in det["observations"]],
                "assets": [
                    {"finding_id": a["finding"].id, "asset_id": a["finding"].asset_id, "decision": _decision(a["decision"])} for a in det["assets"]
                ],
                "kev_source_stale": det["kev_source_stale"],
            }

    @r.get("/threats/{vid}/timeline")
    def get_timeline(vid: str) -> Any:
        with db.session_scope(ws) as s:
            det = queries.threat_detail(s, vid)
            if det is None:
                raise ApiError(404, "not_found", "unknown vulnerability")
            return {
                "assessments": [
                    {"id": a.id, "seq": a.seq, "created_at": _iso(a.created_at), "engine_version": a.engine_version, "state": a.state_json}
                    for a in det["history"]
                ],
                "deltas": [
                    {"id": d.id, "change_type": d.change_type, "created_at": _iso(d.created_at), "old_assessment_id": d.old_assessment_id,
                     "new_assessment_id": d.new_assessment_id, "reasons": d.reasons_json}
                    for d in det["deltas"]
                ],
            }

    @r.get("/evidence/{eid}")
    def get_evidence(eid: str) -> Any:
        with db.session_scope(ws) as s:
            ev = queries.evidence(s, eid)
            if ev is None:
                raise ApiError(404, "not_found", "evidence not found")
            return ev

    @r.post("/claims/{claim_id}/reviews", status_code=201)
    def post_review(claim_id: str, body: ReviewRequest) -> Any:
        try:
            return add_review(
                ws, claim_id, reviewer=body.reviewer, state=body.state, reason=body.reason,
                relation=body.relation.model_dump() if body.relation else None,
            )
        except LookupError:
            raise ApiError(404, "not_found", "claim not found") from None
        except ReviewError as exc:
            raise ApiError(422, "invalid_review", str(exc)) from None

    @r.get("/findings/{finding_id}/decisions")
    def get_decisions(finding_id: str) -> Any:
        with db.session_scope(ws) as s:
            decs = queries.decisions_for_finding(s, finding_id)
            if not decs:
                raise ApiError(404, "not_found", "no decisions for this finding")
            return {"finding_id": finding_id, "decisions": [_decision(d) for d in decs]}

    @r.get("/decisions/{decision_id}/diff")
    def get_diff(decision_id: str) -> Any:
        with db.session_scope(ws) as s:
            diff = queries.decision_diff(s, decision_id)
            if diff is None:
                raise ApiError(404, "not_found", "decision not found")
            return {
                "decision": _decision(diff["decision"]),
                "previous": _decision(diff["previous"]),
                "changes": [{"field": x["label"], "before": x["before"], "after": x["after"]} for x in diff["changed_rows"]],
                "unchanged": [{"field": x["label"], "value": x["after"]} for x in diff["unchanged_rows"]],
                "why": diff["why"],
                "trigger_deltas": [{"id": t.id, "change_type": t.change_type, "summary": t.reasons_json.get("summary")} for t in diff["triggers"]],
                "evidence_added": diff["evidence_added"],
                "evidence_removed": diff["evidence_removed"],
            }

    @r.post("/assessments/recompute")
    def post_recompute(body: RecomputeRequest) -> Any:
        return recompute(ws, vulnerability_ids=body.vulnerability_ids, actor="api", trigger="api")

    @r.get("/investigations")
    def get_investigations(include_resolved: bool = False) -> Any:
        with db.session_scope(ws) as s:
            return {
                "items": [
                    {
                        "id": t["task"].id, "question": t["task"].question, "check_type": t["task"].check_type,
                        "required_evidence": t["task"].required_evidence, "affected_finding_ids": t["task"].affected_finding_ids,
                        "urgent_high_count": t["task"].urgent_high_count, "estimated_effort": t["task"].estimated_effort,
                        "status": t["task"].status, "manual_resolution": t["manual"],
                    }
                    for t in queries.investigations(s, include_resolved)
                ]
            }

    @r.post("/investigations/{task_id}/resolve")
    def post_resolve(task_id: str, body: ResolveRequest) -> Any:
        with db.session_scope(ws) as s:
            try:
                t = resolve_task(s, task_id, body.actor, body.reason)
            except LookupError:
                raise ApiError(404, "not_found", "task not found") from None
            if t.check_type != "correction":
                raise ApiError(409, "auto_task", "this task resolves automatically when its evidence is updated")
            return {"id": t.id, "status": t.status}

    @r.post("/exports", status_code=201)
    def post_export(body: ExportRequest) -> Any:
        try:
            path, content = export_threat(ws, body.vulnerability_id, body.format)
        except LookupError:
            raise ApiError(404, "not_found", "unknown vulnerability") from None
        return {"path": path, "format": body.format, "content": content}

    @r.post("/fetch/{feed}", response_model=ImportResult)
    def post_fetch(feed: Literal["kev", "epss"]) -> Any:
        from tiw.services.fetch import FetchError, fetch_epss, fetch_kev

        try:
            out = fetch_kev(ws, actor="api") if feed == "kev" else fetch_epss(ws, actor="api")
        except FetchError as exc:
            raise ApiError(409, "fetch_refused", str(exc)) from None
        if out.status == "failed":
            raise ApiError(502, "fetch_failed", "Retrieval failed; existing evidence was kept", out.errors)
        return out.as_dict()

    @r.get("/health/sources")
    def get_health() -> Any:
        with db.session_scope(ws) as s:
            return {"sources": [{k: _iso(v) for k, v in h.items()} for h in queries.source_health(s)], "now": _iso(db.now(s))}

    return r

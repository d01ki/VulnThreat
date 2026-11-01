"""REST endpoints for v2 attack-path triage (same /api/v1 prefix, bearer auth and error envelope)."""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from tiw.services import triage
from tiw.services.graph import GraphNotReady
from tiw.storage import db


class OptimizeRequest(BaseModel):
    budget: int = Field(ge=0, le=100_000)
    objective: Literal["weighted-paths", "reachable-targets"] = "weighted-paths"
    downtime_cap: Optional[Literal["none", "low", "high"]] = None
    inclusion: Literal["as_recorded", "pessimistic", "optimistic"] = "as_recorded"
    record: bool = True


class RobustnessRequest(BaseModel):
    budget: int = Field(ge=0, le=100_000)
    objective: Literal["weighted-paths", "reachable-targets"] = "weighted-paths"
    downtime_cap: Optional[Literal["none", "low", "high"]] = None
    scenario_set: Literal["default"] = "default"
    stale_days: int = Field(90, ge=1, le=3650)
    record: bool = True


class HypothesisRequest(BaseModel):
    candidates: list[Any] = Field(default_factory=list, max_length=500)


def add_routes(r: APIRouter, ws: db.Workspace, api_error: Any) -> None:
    def guarded(fn: Any, **kw: Any) -> Any:
        with db.session_scope(ws) as s:
            try:
                return fn(s=s, **kw)
            except GraphNotReady as exc:
                raise api_error(409, "graph_not_ready", str(exc)) from None
            except triage.AnalysisError as exc:
                raise api_error(422, "invalid_input", str(exc)) from None

    @r.get("/graph")
    def get_graph() -> Any:
        """Attack graph, bounded model paths and their evidence states (read-only, not recorded)."""
        out = guarded(triage.analyze_graph)
        return {"result": out["result"], "layout": out["layout"]}

    @r.post("/graph/build", status_code=201)
    def post_graph_build() -> Any:
        payload = guarded(triage.analyze_graph)
        run, created, _ = triage.record(ws, "graph", "graph", payload, actor="api")
        return {"run": triage.run_meta(run), "created": created, "result": payload["result"]}

    @r.get("/graph/paths/{path_id}")
    def get_path(path_id: str) -> Any:
        if len(path_id) > 40:
            raise api_error(422, "invalid_input", "path id too long")
        x = guarded(triage.explain_path, path_id=path_id)
        if x is None:
            raise api_error(404, "not_found", "unknown path")
        return x

    @r.post("/graph/hypotheses")
    def post_hypotheses(body: HypothesisRequest) -> Any:
        """Verify untrusted candidates against recorded facts. Nothing is persisted or executed."""
        return guarded(triage.hypotheses, external=body.candidates)

    @r.post("/triage/optimize")
    def post_optimize(body: OptimizeRequest) -> Any:
        payload = guarded(triage.optimize_analysis, budget=body.budget, objective=body.objective,
                          downtime_cap=body.downtime_cap, inclusion=body.inclusion)
        out: dict[str, Any] = {"result": payload["result"], "diagnostics": payload["diagnostics"], "run": None, "diff": None}
        if body.record:
            run, created, diff = triage.record(ws, "optimize", triage.run_key("optimize", payload["result"]["params"]), payload, actor="api")
            out |= {"run": triage.run_meta(run), "created": created, "diff": diff}
        return out

    @r.post("/triage/robustness")
    def post_robustness(body: RobustnessRequest) -> Any:
        payload = guarded(triage.robustness_analysis, budget=body.budget, objective=body.objective, downtime_cap=body.downtime_cap,
                          scenario_set=body.scenario_set, stale_days=body.stale_days)
        out: dict[str, Any] = {"result": payload["result"], "run": None}
        if body.record:
            run, created, _ = triage.record(ws, "robustness", triage.run_key("robustness", payload["result"]["params"]), payload, actor="api")
            out |= {"run": triage.run_meta(run), "created": created}
        return out

    @r.get("/drafts/{kind}")
    def get_draft(kind: Literal["exploit_conditions", "remediations"]) -> Any:
        """Editable draft built from imported findings (read-only)."""
        import json

        from tiw.services import drafts

        try:
            return json.loads(drafts.draft_bytes(ws, kind))
        except drafts.DraftError as exc:
            raise api_error(409, "no_findings", str(exc)) from None

    @r.post("/drafts/import", status_code=201)
    def post_draft_import() -> Any:
        from tiw.services import drafts

        try:
            results = drafts.draft_and_import(ws, actor="api")
        except drafts.DraftError as exc:
            raise api_error(409, "no_findings", str(exc)) from None
        if any(x["status"] == "failed" for x in results):
            raise api_error(422, "validation_failed", "draft import rejected; nothing was written", results)
        return {"results": results}

    @r.get("/analysis-runs")
    def get_runs(limit: int = Query(50, ge=1, le=500)) -> Any:
        with db.session_scope(ws) as s:
            return {"items": [triage.run_meta(x) for x in triage.latest_runs(s, limit)]}

    @r.get("/analysis-runs/{run_id}")
    def get_run(run_id: str, format: Literal["json", "markdown", "normalized"] = "json") -> Any:
        from tiw.services.analysis_export import analysis_document, to_markdown

        try:
            doc = analysis_document(ws, run_id)
        except LookupError:
            raise api_error(404, "not_found", "analysis run not found") from None
        if format == "markdown":
            return {"format": "markdown", "content": to_markdown(doc)}
        if format == "normalized":
            return doc["result"]
        return doc

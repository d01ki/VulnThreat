"""Server-rendered v2 screens: Attack Paths -> Evidence -> Remediation Lab -> Decision Robustness.

GET requests never write. Recording an analysis run and the demo reset are CSRF-protected POSTs.
Imported labels, claim text and identifiers are hostile input and are only ever autoescaped.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from tiw.api.security import check_csrf
from tiw.domain.attack_graph import FactOverride
from tiw.domain.robustness import SCENARIO_TEXT
from tiw.services import triage
from tiw.services.graph import GraphNotReady
from tiw.storage import db

PATH_ID_RE = re.compile(r"^PATH-[0-9A-F]{1,10}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_.:#-]{1,120}$")
DOWNTIME = ("none", "low", "high")
OBJECTIVES = ("weighted-paths", "reachable-targets")
STATUSES = ("supported", "conditional", "insufficient_evidence", "contradicted")


def _int(v: str | None, default: int, lo: int = 0, hi: int = 1000) -> int:
    try:
        return max(lo, min(hi, int(v))) if v not in (None, "") else default
    except ValueError:
        return default


def _safe(v: str | None) -> str | None:
    return v if v and SAFE_ID_RE.match(v) else None


def add_routes(r: APIRouter, ws: db.Workspace, render: Callable[..., Response], forbidden: Callable[[Request], Response]) -> None:
    def not_ready(request: Request, exc: Exception, nav: str) -> Response:
        return render(request, "v2_not_ready.html", {"title": "Attack paths not set up", "nav": nav, "message": str(exc)}, 200)

    @r.get("/attack-paths", response_class=HTMLResponse)
    def attack_paths(request: Request, target: str | None = None, status: str | None = None, path: str | None = None, edge: str | None = None) -> Response:
        with db.session_scope(ws) as s:
            try:
                out = triage.analyze_graph(s)
            except GraphNotReady as exc:
                return not_ready(request, exc, "attack_paths")
            latest = triage.latest_run_for(s, "graph")
        res, lay = out["result"], out["layout"]
        tgt = target if target in {o["id"] for o in res["objectives"]} else None
        st = status if status in STATUSES else None
        sel_path = path if path and PATH_ID_RE.match(path) else None
        sel_edge = _safe(edge)
        rows = [p for p in res["paths"] if (not tgt or p["objective_id"] == tgt) and (not st or p["status"] == st)]
        visible_edges = {h["edge_id"] for p in rows for h in p["hops"]}
        hl_edges: set[str] = set()
        if sel_path:
            hl_edges = {h["edge_id"] for p in res["paths"] if p["id"] == sel_path for h in p["hops"]}
        elif sel_edge:
            hl_edges = {sel_edge}
        edge_fact = next((f for f in res["facts"] if f["fact_id"] == f"edge:{sel_edge}"), None) if sel_edge else None
        edge_paths = [p for p in res["paths"] if sel_edge and any(h["edge_id"] == sel_edge for h in p["hops"])]
        return render(request, "attack_paths.html", {
            "title": "Attack Paths", "nav": "attack_paths", "g": res, "lay": lay, "rows": rows, "target": tgt, "status": st,
            "statuses": STATUSES, "visible_edges": visible_edges, "hl_edges": hl_edges, "sel_path": sel_path, "sel_edge": sel_edge,
            "edge_fact": edge_fact, "edge_paths": edge_paths, "latest": latest,
        })

    @r.get("/attack-paths/{path_id}", response_class=HTMLResponse)
    def path_detail(request: Request, path_id: str) -> Response:
        if not PATH_ID_RE.match(path_id):
            return render(request, "error.html", {"title": "Path not found", "message": "Unknown path identifier.", "nav": "attack_paths"}, 404)
        with db.session_scope(ws) as s:
            try:
                x = triage.explain_path(s, path_id)
            except GraphNotReady as exc:
                return not_ready(request, exc, "attack_paths")
        if x is None:
            return render(request, "error.html", {"title": "Path not found", "message": "This path is not in the current graph.", "nav": "attack_paths"}, 404)
        return render(request, "path_detail.html", {"title": f"Evidence · {x['path']['id']}", "nav": "attack_paths", "x": x})

    @r.get("/remediation-lab", response_class=HTMLResponse)
    def lab(request: Request, budget: str | None = None, objective: str | None = None, downtime_cap: str | None = None, compare: str | None = None) -> Response:
        b = _int(budget, 2)
        obj = objective if objective in OBJECTIVES else "weighted-paths"
        cap = downtime_cap if downtime_cap in DOWNTIME else None
        with db.session_scope(ws) as s:
            try:
                out = triage.optimize_analysis(s, budget=b, objective=obj, downtime_cap=cap)
            except GraphNotReady as exc:
                return not_ready(request, exc, "lab")
            except triage.AnalysisError as exc:
                return render(request, "error.html", {"title": "Cannot optimise", "message": str(exc), "nav": "lab"}, 422)
            key = triage.run_key("optimize", out["result"]["params"])
            latest = triage.latest_run_for(s, key)
            history = triage.run_with_diff(s, latest.id) if latest else None
        res = out["result"]
        cmp_name = compare if compare in {x["name"] for x in res["baselines"]} else "cvss_desc"
        cmp = next(x for x in res["baselines"] if x["name"] == cmp_name)
        recorded_same = latest is not None and latest.result_hash == triage.canonical_hash(res)
        return render(request, "remediation_lab.html", {
            "title": "Remediation Lab", "nav": "lab", "o": res, "budget": b, "objective": obj, "downtime_cap": cap,
            "cmp": cmp, "cmp_name": cmp_name, "latest": latest, "history": history, "recorded_same": recorded_same,
            "runtime_ms": out["diagnostics"]["runtime_ms"],
        })

    @r.post("/remediation-lab/record")
    def lab_record(request: Request, csrf_token: str = Form(""), budget: str = Form("2"), objective: str = Form("weighted-paths"), downtime_cap: str = Form("")) -> Response:
        if not check_csrf(request, csrf_token):
            return forbidden(request)
        b = _int(budget, 2)
        obj = objective if objective in OBJECTIVES else "weighted-paths"
        cap = downtime_cap if downtime_cap in DOWNTIME else None
        with db.session_scope(ws) as s:
            try:
                payload = triage.optimize_analysis(s, budget=b, objective=obj, downtime_cap=cap)
            except (GraphNotReady, triage.AnalysisError) as exc:
                return render(request, "error.html", {"title": "Not recorded", "message": str(exc), "nav": "lab"}, 422)
        run, _created, _ = triage.record(ws, "optimize", triage.run_key("optimize", payload["result"]["params"]), payload, actor="ui")
        return RedirectResponse(f"/analysis-runs/{run.id}", status_code=303)

    @r.get("/robustness", response_class=HTMLResponse)
    def robustness(request: Request, budget: str | None = None, objective: str | None = None, withdraw: str | None = None,
                   unknown_edge: str | None = None, unknown_app: str | None = None) -> Response:
        b = _int(budget, 2)
        obj = objective if objective in OBJECTIVES else "weighted-paths"
        wd, ue, ua = _safe(withdraw), _safe(unknown_edge), _safe(unknown_app)
        with db.session_scope(ws) as s:
            try:
                rb = triage.robustness_analysis(s, budget=b, objective=obj)["result"]
                base = triage.optimize_analysis(s, budget=b, objective=obj)["result"]
                whatif = None
                if wd or ue or ua:
                    overrides = []
                    if ue:
                        overrides.append(FactOverride(f"edge:{ue}", "unknown", f"what-if reachability_unknown:{ue}"))
                    if ua:
                        overrides.append(FactOverride(f"applicability:{ua}", "unknown", f"what-if applicability_unknown:{ua}"))
                    whatif = triage.optimize_analysis(s, budget=b, objective=obj, overrides=overrides, withdraw=[wd] if wd else None)["result"]
            except GraphNotReady as exc:
                return not_ready(request, exc, "robustness")
            except triage.AnalysisError as exc:
                return render(request, "error.html", {"title": "Cannot analyse", "message": str(exc), "nav": "robustness"}, 422)
        claims = sorted({e["id"] for f in base["facts"] for e in f["evidence"] if e["kind"] == "claim" and e["active"]})
        edges = sorted({f["fact_id"][5:] for f in base["facts"] if f["fact_id"].startswith("edge:") and f["status"] == "satisfied"})
        apps = sorted({f["fact_id"][14:] for f in base["facts"] if f["fact_id"].startswith("applicability:") and f["status"] == "satisfied"})
        diff = triage.run_diff(base, whatif) if whatif else None
        return render(request, "robustness.html", {
            "title": "Decision Robustness", "nav": "robustness", "rb": rb, "base": base, "whatif": whatif, "diff": diff,
            "budget": b, "objective": obj, "withdraw": wd, "unknown_edge": ue, "unknown_app": ua,
            "claims": claims, "edges": edges, "apps": apps, "scenario_text": SCENARIO_TEXT,
        })

    @r.get("/analysis-runs", response_class=HTMLResponse)
    def runs(request: Request) -> Response:
        with db.session_scope(ws) as s:
            items = [triage.run_meta(x) for x in triage.latest_runs(s, 100)]
        return render(request, "analysis_runs.html", {"title": "Analysis Runs", "nav": "runs", "items": items})

    @r.get("/analysis-runs/{run_id}", response_class=HTMLResponse)
    def run_detail(request: Request, run_id: str) -> Response:
        if not _safe(run_id):
            return render(request, "error.html", {"title": "Run not found", "message": "Unknown run.", "nav": "runs"}, 404)
        with db.session_scope(ws) as s:
            doc = triage.run_with_diff(s, run_id)
        if doc is None:
            return render(request, "error.html", {"title": "Run not found", "message": "This analysis run does not exist.", "nav": "runs"}, 404)
        return render(request, "analysis_run.html", {"title": "Analysis Run", "nav": "runs", "doc": doc})

    @r.get("/analysis-runs/{run_id}/export")
    def run_export(request: Request, run_id: str, format: str = "markdown") -> Response:
        from tiw.services.analysis_export import analysis_document, normalized_json, to_markdown

        if not _safe(run_id):
            return Response("unknown run", status_code=404, media_type="text/plain")
        try:
            doc = analysis_document(ws, run_id)
        except LookupError:
            return Response("unknown run", status_code=404, media_type="text/plain")
        safe = re.sub(r"[^A-Za-z0-9-]", "_", run_id)[:40]
        if format == "json":
            import json

            return Response(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False), media_type="application/json",
                            headers={"Content-Disposition": f'attachment; filename="analysis-{safe}.json"'})
        if format == "normalized":
            return Response(normalized_json(doc["result"]), media_type="application/json",
                            headers={"Content-Disposition": f'attachment; filename="analysis-{safe}-normalized.json"'})
        return Response(to_markdown(doc), media_type="text/markdown; charset=utf-8",
                        headers={"Content-Disposition": f'attachment; filename="analysis-{safe}.md"'})

    @r.get("/import/draft/{kind}")
    def draft_download(request: Request, kind: str) -> Response:
        """Download an editable draft built from imported findings (read-only)."""
        from tiw.services import drafts

        if kind not in drafts.DRAFT_KINDS:
            return Response("unknown draft", status_code=404, media_type="text/plain")
        try:
            body = drafts.draft_bytes(ws, kind)
        except drafts.DraftError as exc:
            return render(request, "error.html", {"title": "Nothing to draft", "message": str(exc), "nav": "import"}, 409)
        return Response(body, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="{kind}-draft.json"'})

    @r.post("/import/drafts")
    def draft_import(request: Request, csrf_token: str = Form("")) -> Response:
        """Generate exploit-condition and remediation drafts from findings and import them."""
        from tiw.services import drafts

        if not check_csrf(request, csrf_token):
            return forbidden(request)
        try:
            results = drafts.draft_and_import(ws, actor="ui")
        except drafts.DraftError as exc:
            return render(request, "error.html", {"title": "Nothing to draft", "message": str(exc), "nav": "import"}, 409)
        failed = next((x for x in results if x["status"] == "failed"), None)
        if failed:
            msg = "; ".join(f"{e['field']}: {e['reason']}" for e in failed["errors"][:5])
            return render(request, "error.html", {"title": "Draft not imported", "message": f"{failed['kind']}: {msg}", "nav": "import"}, 422)
        with db.session_scope(ws) as s:
            has_topology = triage.graph_svc.latest_input(s, "topology") is not None
        target = "/attack-paths" if has_topology else "/import?kind=topology"
        return RedirectResponse(f"{target}{'&' if '?' in target else '?'}notice=drafts_imported", status_code=303)

    @r.post("/demo/attack-path/reset")
    def demo_reset(request: Request, csrf_token: str = Form(""), step: str = Form("1")) -> Response:
        """One-click reproducible reset of the synthetic attack-path demo (refuses live workspaces)."""
        from tiw.services import demo

        if not check_csrf(request, csrf_token):
            return forbidden(request)
        st = _int(step, 1, 1, 2)
        try:
            with db.session_scope(ws) as s:
                synthetic = db.is_synthetic_workspace(s)
            seeded = demo.seeded(ws)
            if not synthetic or (seeded and "attack-path" not in seeded):
                raise demo.DemoError("Reset is only available in a synthetic attack-path demo workspace.")
            demo.reseed(ws, "attack-path", st)
        except demo.DemoError as exc:
            return render(request, "error.html", {"title": "Reset refused", "message": str(exc), "nav": "attack_paths"}, 409)
        return RedirectResponse(f"/attack-paths?notice=demo_reset_{st}", status_code=303)

    @r.post("/demo/attack-path/advance")
    def demo_advance(request: Request, csrf_token: str = Form("")) -> Response:
        from tiw.services import demo

        if not check_csrf(request, csrf_token):
            return forbidden(request)
        if "attack-path" not in demo.seeded(ws):
            return render(request, "error.html", {"title": "Not available", "message": "Only the synthetic attack-path demo can be advanced here.", "nav": "attack_paths"}, 409)
        demo.advance(ws, 2, "attack-path")
        return RedirectResponse("/remediation-lab?notice=demo_step_2", status_code=303)


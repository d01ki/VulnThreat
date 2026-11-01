"""Server-rendered UI (Jinja2, autoescaped). State-changing forms require a CSRF token."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from zoneinfo import ZoneInfo, available_timezones

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from markupsafe import Markup
from sqlalchemy import func, select

from tiw.adapters.common import MAX_FILE_BYTES, InputMalformed, InputTooLarge
from tiw.api import charts
from tiw.api.security import CSRF_FIELD, check_csrf, csrf_token_for, set_csrf_cookie
from tiw.domain.vocab import DELTA_LABELS, REASON_TEXT
from tiw.services import queries
from tiw.services.export import export_threat
from tiw.services.ingest import KINDS, run_import
from tiw.services.pipeline import resolve_task
from tiw.services.review import ReviewError, add_review
from tiw.storage import db
from tiw.storage.models import Finding

TEMPLATES = Path(__file__).resolve().parent.parent / "templates"
KIND_HELP = {
    "assets": "Asset CSV — asset_id, name, criticality, internet_exposed, observed_at, expires_at",
    "findings": "Finding CSV — finding_id, asset_id, vulnerability_id, applicability, observed_at (+ rationale, evidence_ref, reviewer, expires_at for not_affected)",
    "observations": "Observation JSONL — one event or sensor_window per line (schema_version 1.0)",
    "claims": "Reviewed advisory claims JSON (schema_version 1.0); also graph evidence (predicates reachability / precondition)",
    "topology_csv": "Network paths CSV — one row per path: source (internet or an asset), target, ports (443 or tcp/443), reachability, evidence_ref, reviewer. Replaces the topology; crown jewels from assets.csv crown_jewel_weight or criticality=critical",
    "topology": "Topology JSON — entry points, asset nodes, security objectives and directed edges with evidence (schema_version 1.0)",
    "exploit_conditions": "Exploit conditions JSON — structured, non-executable preconditions per vulnerability (schema_version 1.0)",
    "remediations": "Remediation catalog JSON — actions with integer effort, downtime, dependencies and conflicts (schema_version 1.0)",
    "kev": "Saved CISA KEV catalog JSON",
    "epss": "Saved FIRST EPSS API response JSON",
}
NOTICES = {
    "review_saved": "Review recorded. Assessments and decisions were recomputed.",
    "task_resolved": "Task marked as resolved.",
    "fetch_ok": "Download finished and imported. Decisions were recomputed.",
    "fetch_failed": "Download failed. Existing data was kept; see the failure below.",
    "settings_saved": "Settings saved.",
    "demo_reset_1": "Demo reset to step 1. Every analysis below was recomputed from the synthetic fixtures.",
    "demo_reset_2": "Demo reset and advanced to step 2 (the SFTP runbook claim is retracted).",
    "topology_saved": "Network paths saved as a new topology version. Attack paths were recomputed.",
    "drafts_imported": "Drafts imported from your findings. They are unreviewed: service ports are 'any' and efforts are placeholders, so paths stay conditional until you refine them.",
    "demo_step_2": "Step 2 applied: the SFTP to API runbook claim was retracted. Compare the recommendation below with the previous run.",
}
IMPORT_TEMPLATES = {
    "assets": ("assets-template.csv", "text/csv; charset=utf-8", "".join(line + chr(10) for line in [
        "asset_id,name,criticality,internet_exposed,observed_at,expires_at,owner",
        "web-01,public-web-server,critical,true,2026-11-01T00:00:00Z,2026-12-01T00:00:00Z,web-team",
        "hr-01,internal-hr-app,high,false,2026-11-01T00:00:00Z,2026-12-01T00:00:00Z,corp-it",
    ])),
    "findings": ("findings-template.csv", "text/csv; charset=utf-8", "".join(line + chr(10) for line in [
        "finding_id,asset_id,vulnerability_id,applicability,observed_at,rationale,evidence_ref,reviewer,expires_at",
        "web-01-CVE-2021-44228,web-01,CVE-2021-44228,affected,2026-11-01T00:00:00Z,,,,",
        "hr-01-CVE-2021-44228,hr-01,CVE-2021-44228,not_affected,2026-11-01T00:00:00Z,Library not on classpath,sbom:hr-01-2026-11-01,alice,2026-12-01T00:00:00Z",
    ])),
    "observations": ("observations-template.jsonl", "application/x-ndjson", "".join(line + chr(10) for line in [
        '{"schema_version":"1.0","record_type":"sensor_window","sensor_id":"ids-1","start":"2026-11-01T00:00:00Z","end":"2026-11-08T00:00:00Z","status":"ok","coverage":{"assets":["web-01"]}}',
        '{"schema_version":"1.0","sensor_id":"ids-1","external_event_id":"alert-1001","observed_at":"2026-11-02T10:00:00Z","asset_id":"web-01","vulnerability_id":"CVE-2021-44228","event_type":"exploit_attempt","mapping_status":"reviewer_confirmed","evidence":{"rule_id":"sid-1000001"}}',
    ])),
}
_TOPOLOGY_TEMPLATE = {
    "schema_version": "1.0",
    "description": "Template. Entry points, asset nodes (imported asset ids), crown jewels and directed edges with their evidence.",
    "source": {"name": "firewall export 2026-11-01", "evidence_ref": "fw-export-2026-11-01"},
    "observed_at": "2026-11-01T00:00:00Z",
    "entry_points": [{"id": "internet", "label": "Internet", "grants": "network_access"}],
    "nodes": [{"asset_id": "web-01", "zone": "dmz"}, {"asset_id": "hr-01", "zone": "internal"}],
    "objectives": [{"id": "OBJ-hr", "asset_id": "hr-01", "label": "HR records", "weight": 3}],
    "edges": [
        {"id": "e-inet-web", "source": "internet", "target": "web-01", "kind": "network", "ports": ["tcp/443"],
         "reachability": "allowed", "review_state": "reviewed", "reviewer": "alice", "evidence_ref": "fw-export rule 10",
         "valid_until": "2026-12-31T00:00:00Z"},
        {"id": "e-web-hr", "source": "web-01", "target": "hr-01", "kind": "network", "ports": ["tcp/8080"],
         "reachability": "unknown", "review_state": "reviewed", "reviewer": "alice",
         "evidence_ref": "internal segment not covered by the export (unknown, not blocked)"},
    ],
}
_CONDITIONS_TEMPLATE = {
    "schema_version": "1.0",
    "description": "Template. Use service_ports ['any'] when the port is not known yet (paths then stay conditional).",
    "source": {"name": "advisory digest"},
    "vulnerabilities": [
        {"vulnerability_id": "CVE-2021-44228", "title": "Log4Shell", "service_ports": ["tcp/443", "tcp/8080"],
         "requires_capability": "network_access", "grants_capability": "code_execution",
         "cvss": {"version": "3.1", "base_score": 10.0, "source": "NVD"},
         "citation": "vendor advisory section 2", "review_state": "reviewed", "reviewer": "alice",
         "conditions": [{"id": "lookup", "kind": "configuration", "status": "unknown", "description": "JNDI lookups enabled"}]},
    ],
}
_REMEDIATIONS_TEMPLATE = {
    "schema_version": "1.0",
    "cost_unit": "engineer-days",
    "source": {"name": "change board"},
    "actions": [
        {"id": "A-patch-web", "type": "patch_finding", "finding_id": "web-01-CVE-2021-44228", "label": "Upgrade log4j on web-01",
         "cost": 1, "downtime": "low", "verification_status": "unverified"},
        {"id": "A-restrict-web-hr", "type": "restrict_edge", "edge_id": "e-web-hr", "label": "Block web-01 to hr-01 on 8080",
         "cost": 1, "downtime": "none", "verification_status": "unverified"},
    ],
}
for _k, _doc in (("topology", _TOPOLOGY_TEMPLATE), ("exploit_conditions", _CONDITIONS_TEMPLATE), ("remediations", _REMEDIATIONS_TEMPLATE)):
    IMPORT_TEMPLATES[_k] = (f"{_k}-template.json", "application/json", json.dumps(_doc, indent=1) + chr(10))
IMPORT_TEMPLATES["topology_csv"] = ("topology-edges-template.csv", "text/csv; charset=utf-8", "".join(line + chr(10) for line in [
    "source,target,ports,reachability,evidence_ref,reviewer",
    "internet,web-01,443,allowed,fw-export rule 10,alice",
    "web-01,hr-01,8080,unknown,internal segment not in the export (unknown - not blocked),alice",
]))
COMMON_TZ = ["Asia/Tokyo", "UTC", "Asia/Singapore", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles"]
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
ALL_TZ = frozenset(available_timezones()) | {"UTC"}


def build_router(ws: db.Workspace) -> APIRouter:
    templates = Jinja2Templates(directory=str(TEMPLATES))
    env = templates.env
    env.autoescape = True

    def tz() -> ZoneInfo:
        with db.session_scope(ws) as s:
            return queries.display_tz(s)

    def fmt_time(v: Any, fmt: str = "%Y-%m-%d %H:%M") -> str:
        if v is None:
            return "—"
        if isinstance(v, str):
            try:
                v = db.parse_utc(v) if "T" in v else datetime.fromisoformat(v + "T00:00:00+00:00")
            except ValueError:
                return v
        return v.astimezone(env.globals["_tz"]).strftime(fmt)

    def rel_time(v: Any) -> str:
        if v is None:
            return "never"
        now = env.globals["_now"]
        d = now - v
        secs = int(d.total_seconds())
        if secs < 0:
            return "in the future"
        if secs < 3600:
            return f"{max(1, secs // 60)} min ago"
        if secs < 86400:
            return f"{secs // 3600} h ago"
        return f"{secs // 86400} d ago"

    def short(v: Any, n: int = 8) -> str:
        return str(v or "")[:n]

    def icon(name: str, cls: str = "icon") -> Markup:
        safe = re.sub(r"[^a-z0-9-]", "", name)
        return Markup(f'<svg class="{cls}" aria-hidden="true" focusable="false"><use href="/static/icons.svg#i-{safe}"></use></svg>')

    env.filters["t"] = fmt_time
    env.filters["rel"] = rel_time
    env.filters["short"] = short
    env.globals["icon"] = icon
    env.globals["DELTA_LABELS"] = DELTA_LABELS
    env.globals["REASON_TEXT"] = REASON_TEXT
    env.globals["RULE_TITLES"] = queries.RULE_TITLES

    def render(request: Request, name: str, ctx: dict[str, Any], status: int = 200) -> Response:
        with db.session_scope(ws) as s:
            info = queries.workspace_info(s)
            health = queries.source_health(s)
        env.globals["_tz"] = ZoneInfo(info["timezone"]) if info["timezone"] in ALL_TZ else timezone.utc
        env.globals["_now"] = info["now"]

        def url(**changes: Any) -> str:
            params = dict(request.query_params)
            for k, v in changes.items():
                if v is None:
                    params.pop(k, None)
                else:
                    params[k] = v
            return request.url.path + ("?" + urlencode(params) if params else "")

        notice = NOTICES.get(request.query_params.get("notice", ""))
        full = {
            "request": request,
            "info": info,
            "health_problem": [h for h in health if h["status"] != "ok"],
            "csrf": csrf_token_for(request),
            "csrf_field": CSRF_FIELD,
            "path": request.url.path,
            "url": url,
            "notice": notice,
            **ctx,
        }
        resp = templates.TemplateResponse(request, name, full, status_code=status)
        set_csrf_cookie(request, resp)
        return resp

    def forbidden(request: Request) -> Response:
        return render(request, "error.html", {"title": "Request rejected", "message": "The form token was missing or expired. Reload the page and try again."}, 403)

    r = APIRouter()

    @r.get("/", response_class=HTMLResponse)
    def home(request: Request, period: str = "7d", scope: str = "mine") -> Response:
        with db.session_scope(ws) as s:
            data = queries.home(s, period, "all" if scope == "all" else "mine")
        return render(
            request,
            "home.html",
            {
                "title": "Threat Changes",
                "nav": "home",
                "d": data,
                "chart": charts.line_chart(data["activity"]),
                "donut": charts.donut(data["evidence_status"]),
            },
        )

    @r.get("/threats", response_class=HTMLResponse)
    def threats(request: Request, status: str | None = None, period: str = "all", q: str | None = None, changed: str | None = None, cursor: str | None = None, scope: str = "mine") -> Response:
        st = status if status in queries.EVIDENCE_STATUS_ORDER else None
        sc = "all" if scope == "all" else "mine"
        with db.session_scope(ws) as s:
            try:
                data = queries.threats(s, status=st, period_key=period, q=(q or "")[:100] or None, changed_only=bool(changed), cursor=cursor, scope=sc)
            except (ValueError, UnicodeDecodeError):
                data = queries.threats(s, status=st, period_key=period, q=(q or "")[:100] or None, changed_only=bool(changed), scope=sc)
        return render(request, "threats.html", {"title": "Threats", "nav": "threats", "d": data, "status": st, "q": q or "", "changed": bool(changed)})

    @r.get("/threats/{vid}", response_class=HTMLResponse)
    def threat(request: Request, vid: str, tab: str = "evidence") -> Response:
        with db.session_scope(ws) as s:
            det = queries.threat_detail(s, vid)
        if det is None:
            return render(request, "error.html", {"title": "Threat not found", "message": f"No vulnerability with ID {vid} has been imported.", "nav": "threats"}, 404)
        tab = tab if tab in ("evidence", "observations", "assets", "decisions") else "evidence"
        return render(request, "threat_detail.html", {"title": vid, "nav": "threats", "t": det, "tab": tab})

    @r.get("/observations", response_class=HTMLResponse)
    def observations(request: Request, period: str = "30d", event_type: str | None = None, q: str | None = None) -> Response:
        et = event_type if event_type in ("scan", "exploit_attempt", "compromise_confirmed") else None
        with db.session_scope(ws) as s:
            data = queries.observations(s, period_key=period, event_type=et, q=(q or "")[:100] or None)
        return render(request, "observations.html", {"title": "Observations", "nav": "observations", "d": data, "event_type": et, "q": q or ""})

    @r.get("/assets", response_class=HTMLResponse)
    def assets(request: Request, urgency: str | None = None, action: str | None = None, q: str | None = None, vulnerability: str | None = None) -> Response:
        u = urgency if urgency in ("urgent", "high", "normal", "low") else None
        a = action if action in ("incident_response", "remediate", "investigate", "monitor") else None
        with db.session_scope(ws) as s:
            rows = queries.affected_assets(s, urgency=u, action=a, q=(q or "")[:100] or None, vulnerability_id=vulnerability)
            obs = queries.observations(s, period_key="all")
        return render(request, "assets.html", {"title": "Affected Assets", "nav": "assets", "rows": rows, "urgency": u, "action": a, "q": q or "", "unmapped": obs["unmapped"][:20], "vulnerability": vulnerability})

    @r.get("/decisions/{decision_id}", response_class=HTMLResponse)
    def decision(request: Request, decision_id: str) -> Response:
        with db.session_scope(ws) as s:
            diff = queries.decision_diff(s, decision_id)
        if diff is None:
            return render(request, "error.html", {"title": "Decision not found", "message": "This decision does not exist.", "nav": "assets"}, 404)
        return render(request, "decision_diff.html", {"title": "Decision Diff", "nav": "assets", "x": diff})

    @r.get("/investigations", response_class=HTMLResponse)
    def investigations(request: Request, show: str = "open") -> Response:
        with db.session_scope(ws) as s:
            items = queries.investigations(s, include_resolved=show == "all")
        return render(request, "investigations.html", {"title": "Investigation Queue", "nav": "investigations", "items": items, "show": show})

    @r.post("/investigations/{task_id}/resolve")
    def resolve(request: Request, task_id: str, csrf_token: str = Form(""), reason: str = Form("")) -> Response:
        if not check_csrf(request, csrf_token):
            return forbidden(request)
        with db.session_scope(ws) as s:
            try:
                t = resolve_task(s, task_id, "local-analyst", reason.strip()[:1000] or "resolved in UI")
                if t.check_type != "correction":
                    raise PermissionError
            except (LookupError, PermissionError):
                s.rollback()
                return render(request, "error.html", {"title": "Cannot resolve", "message": "Only correction-review tasks are resolved manually; others close when evidence is updated.", "nav": "investigations"}, 409)
        return RedirectResponse("/investigations?notice=task_resolved", status_code=303)

    @r.get("/sources", response_class=HTMLResponse)
    def sources(request: Request) -> Response:
        with db.session_scope(ws) as s:
            health = queries.source_health(s)
            runs = queries.import_runs(s)
            obs = queries.observations(s, period_key="all")
        return render(request, "sources.html", {"title": "Sources & Health", "nav": "sources", "health": health, "runs": runs, "windows": obs["windows"], "quarantined": obs["quarantined"]})

    @r.get("/import", response_class=HTMLResponse)
    def import_form(request: Request, kind: str = "observations") -> Response:
        with db.session_scope(ws) as s:
            has_findings = s.execute(select(func.count(Finding.id))).scalar_one() > 0
        return render(request, "import.html", {"title": "Import", "nav": "import", "kinds": KINDS, "kind_help": KIND_HELP,
                                               "kind": kind if kind in KINDS else "observations", "templates": IMPORT_TEMPLATES,
                                               "has_findings": has_findings})

    @r.post("/import/validate", response_class=HTMLResponse)
    async def import_validate(request: Request, kind: str = Form(...), csrf_token: str = Form(""), allow_partial: str | None = Form(None), file: UploadFile = File(...)) -> Response:
        if not check_csrf(request, csrf_token):
            return forbidden(request)
        if kind not in KINDS:
            return render(request, "error.html", {"title": "Unknown import type", "message": "Choose one of the listed import types.", "nav": "import"}, 422)
        data = await file.read(MAX_FILE_BYTES + 1)
        ctx: dict[str, Any] = {"title": "Import · validation", "nav": "import", "kind": kind, "filename": (file.filename or "")[:120], "allow_partial": bool(allow_partial), "stage": "validate"}
        try:
            out = run_import(ws, kind, data, actor="ui", allow_partial=bool(allow_partial), dry_run=True)
        except InputTooLarge as exc:
            return render(request, "import_result.html", ctx | {"error": str(exc), "out": None}, 413)
        except InputMalformed as exc:
            return render(request, "import_result.html", ctx | {"error": str(exc), "out": None}, 422)
        sha = hashlib.sha256(data).hexdigest()
        if out.status in ("validated",):
            ws.staging_dir.mkdir(parents=True, exist_ok=True)
            (ws.staging_dir / sha).write_bytes(data)
        return render(request, "import_result.html", ctx | {"out": out, "sha": sha, "error": None}, 200 if out.status != "failed" else 422)

    @r.post("/import/commit", response_class=HTMLResponse)
    def import_commit(request: Request, kind: str = Form(...), sha: str = Form(...), csrf_token: str = Form(""), allow_partial: str | None = Form(None)) -> Response:
        if not check_csrf(request, csrf_token):
            return forbidden(request)
        if kind not in KINDS or not SHA_RE.match(sha):
            return render(request, "error.html", {"title": "Invalid request", "message": "Unknown staged file.", "nav": "import"}, 422)
        staged = ws.staging_dir / sha
        if not staged.exists():
            return render(request, "error.html", {"title": "Staged file missing", "message": "Validate the file again before importing.", "nav": "import"}, 404)
        data = staged.read_bytes()
        out = run_import(ws, kind, data, actor="ui", allow_partial=bool(allow_partial))
        staged.unlink(missing_ok=True)
        return render(request, "import_result.html", {"title": "Import · result", "nav": "import", "kind": kind, "out": out, "stage": "commit", "error": None, "filename": ""}, 200 if out.status != "failed" else 422)

    @r.post("/claims/{claim_id}/review")
    def review(request: Request, claim_id: str, csrf_token: str = Form(""), state: str = Form(...), reason: str = Form(""), reviewer: str = Form("local-analyst"), back: str = Form("/")) -> Response:
        if not check_csrf(request, csrf_token):
            return forbidden(request)
        try:
            add_review(ws, claim_id, reviewer=reviewer, state=state, reason=reason)
        except (ReviewError, LookupError) as exc:
            return render(request, "error.html", {"title": "Review not saved", "message": str(exc), "nav": "threats"}, 422)
        target = back if back.startswith("/threats/") and "//" not in back else "/threats"
        return RedirectResponse(f"{target}?tab=evidence&notice=review_saved", status_code=303)

    @r.get("/threats/{vid}/export")
    def export(request: Request, vid: str, format: str = "markdown") -> Response:
        fmt = format if format in ("json", "markdown") else "markdown"
        try:
            _path, content = export_threat(ws, vid, fmt)
        except LookupError:
            return render(request, "error.html", {"title": "Threat not found", "message": "Nothing to export.", "nav": "threats"}, 404)
        safe = re.sub(r"[^A-Za-z0-9-]", "_", vid)
        media = "application/json" if fmt == "json" else "text/markdown; charset=utf-8"
        ext = "json" if fmt == "json" else "md"
        return Response(content, media_type=media, headers={"Content-Disposition": f'attachment; filename="{safe}.{ext}"'})

    @r.post("/sources/fetch/{kind}")
    def fetch(request: Request, kind: str, csrf_token: str = Form("")) -> Response:
        from tiw.services.fetch import FetchError, fetch_epss, fetch_kev

        if not check_csrf(request, csrf_token):
            return forbidden(request)
        if kind not in ("kev", "epss"):
            return render(request, "error.html", {"title": "Unknown feed", "message": "Only KEV and EPSS can be fetched.", "nav": "sources"}, 404)
        try:
            out = fetch_kev(ws, actor="ui") if kind == "kev" else fetch_epss(ws, actor="ui")
        except FetchError as exc:
            return render(request, "error.html", {"title": "Nothing fetched", "message": str(exc), "nav": "sources"}, 409)
        return RedirectResponse(f"/sources?notice={'fetch_failed' if out.status == 'failed' else 'fetch_ok'}#fetch", status_code=303)

    @r.get("/start", response_class=HTMLResponse)
    def start(request: Request) -> Response:
        return render(request, "start.html", {"title": "What it does", "nav": "start"})

    @r.get("/guide", response_class=HTMLResponse)
    def guide(request: Request) -> Response:
        with db.session_scope(ws) as s:
            setup = queries.setup_status(s)
        return render(request, "guide.html", {"title": "How it works", "nav": "guide", "setup": setup})

    @r.get("/import/template/{kind}")
    def template(kind: str) -> Response:
        if kind not in IMPORT_TEMPLATES:
            return Response("unknown template", status_code=404, media_type="text/plain")
        name, media, body = IMPORT_TEMPLATES[kind]
        return Response(body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @r.get("/settings", response_class=HTMLResponse)
    def settings(request: Request) -> Response:
        return render(request, "settings.html", {"title": "Settings", "nav": "settings", "zones": COMMON_TZ})

    @r.post("/settings")
    def save_settings(request: Request, csrf_token: str = Form(""), timezone_name: str = Form(...)) -> Response:
        if not check_csrf(request, csrf_token):
            return forbidden(request)
        if timezone_name not in ALL_TZ:
            return render(request, "error.html", {"title": "Unknown timezone", "message": "Use an IANA timezone name such as Asia/Tokyo.", "nav": "settings"}, 422)
        with db.session_scope(ws) as s:
            db.set_meta(s, "timezone", timezone_name)
        return RedirectResponse("/settings?notice=settings_saved", status_code=303)

    from tiw.api import web_v2

    web_v2.add_routes(r, ws, render, forbidden)
    return r

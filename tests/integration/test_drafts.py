"""Templates and drafts: lowering the input burden without inventing evidence."""

from __future__ import annotations

import json
import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tiw.services import demo, drafts, triage
from tiw.services.ingest import run_import
from tiw.storage import db
from tiw.storage import models as M

HOST = "http://127.0.0.1:8787"


@pytest.fixture
def client_live(live_ws):
    from tiw.api.app import create_app

    return TestClient(create_app(live_ws), base_url=HOST)


def _tpl(client, kind) -> bytes:
    r = client.get(f"/import/template/{kind}")
    assert r.status_code == 200
    return r.content


def test_templates_import_cleanly_into_a_live_workspace(client_live, live_ws):
    for kind in ("assets", "findings", "topology", "exploit_conditions", "remediations"):
        out = run_import(live_ws, kind, _tpl(client_live, kind), actor="test")
        assert out.status == "succeeded", (kind, out.errors)
    with db.session_scope(live_ws) as s:
        g = triage.analyze_graph(s)["result"]
        o = triage.optimize_analysis(s, budget=1)["result"]
    # hr-01 is reviewed not_affected in the findings template, and web->hr is unknown: no fabricated certainty
    assert g["counts"]["objectives"] == 1
    assert o["selected"]["effort"] <= 1


def test_drafts_from_findings_only_need_a_topology(client_live, live_ws):
    for kind in ("assets", "findings"):
        assert run_import(live_ws, kind, _tpl(client_live, kind)).status == "succeeded"
    with db.session_scope(live_ws) as s:
        cond = drafts.draft_exploit_conditions(s)
        rem = drafts.draft_remediations(s)
    v = cond["vulnerabilities"][0]
    assert v["service_ports"] == ["any"] and v["review_state"] == "unreviewed" and "cvss" not in v
    assert cond["synthetic"] is False and "DRAFT" in cond["description"]
    assert {a["finding_id"] for a in rem["actions"]} == {"web-01-CVE-2021-44228", "hr-01-CVE-2021-44228"}
    assert all(a["cost"] == 1 and a["verification_status"] == "unverified" for a in rem["actions"])

    assert run_import(live_ws, "topology", _tpl(client_live, "topology")).status == "succeeded"
    res = drafts.draft_and_import(live_ws, actor="test")
    assert [r["status"] for r in res] == ["succeeded", "succeeded"]
    with db.session_scope(live_ws) as s:
        g = triage.analyze_graph(s)["result"]
    facts = {f["fact_id"]: f for f in g["facts"]}
    assert facts["cond:CVE-2021-44228:service-port"]["status"] == "unknown"
    # a path through a drafted vulnerability can never be "supported"
    assert all(p["status"] != "supported" for p in g["paths"])
    # importing the same drafts again is a no-op
    again = drafts.draft_and_import(live_ws, actor="test")
    assert all(r["status"] in ("succeeded", "duplicate") and r["accepted"] == 0 for r in again)


def test_drafts_keep_existing_curated_entries(tmp_path):
    w = db.resolve_workspace(tmp_path / "ap")
    demo.seed(w, "attack-path")
    with db.session_scope(w) as s:
        before = triage.optimize_analysis(s, budget=2)["result"]
        n_inputs = s.execute(select(func.count(M.GraphInput.id))).scalar_one()
        rem = drafts.draft_remediations(s)
    curated = json.loads(demo.fixture_bytes("attack-path", "remediations.json"))["actions"]
    by_id = {x["id"]: x for x in rem["actions"]}
    for x in curated:  # curated actions are kept verbatim
        assert {k: v for k, v in by_id[x["id"]].items() if k in x} == x
    # the demo catalogue has no patch for f-fin-103; the draft fills exactly that gap
    assert sorted(set(by_id) - {x["id"] for x in curated}) == ["A-patch-f-fin-103"]
    drafts.draft_and_import(w, actor="test")
    with db.session_scope(w) as s:
        after = triage.optimize_analysis(s, budget=2)["result"]
        # exploit conditions were already complete -> unchanged; only the remediation catalogue gains a version
        assert s.execute(select(func.count(M.GraphInput.id))).scalar_one() == n_inputs + 1
    assert after["selected"]["actions"] == before["selected"]["actions"]
    assert any(t["actions"] == ["A-patch-f-fin-103", "A-rotate-svc"] for t in after["ties"])
    db.dispose_engine(w)


def test_draft_needs_findings(ws):
    with db.session_scope(ws) as s, pytest.raises(drafts.DraftError, match="findings"):
        drafts.draft_exploit_conditions(s)


def test_ui_draft_routes(client_live, live_ws):
    assert client_live.get("/import/draft/exploit_conditions").status_code == 409
    for kind in ("assets", "findings"):
        run_import(live_ws, kind, _tpl(client_live, kind))
    page = client_live.get("/import")
    assert "Generate and import drafts" in page.text and "/import/template/topology" in page.text
    r = client_live.get("/import/draft/remediations")
    assert r.status_code == 200 and json.loads(r.content)["actions"]
    assert client_live.get("/import/draft/claims").status_code == 404
    with db.session_scope(live_ws) as s:
        assert s.execute(select(func.count(M.GraphInput.id))).scalar_one() == 0  # GET wrote nothing
    assert client_live.post("/import/drafts").status_code == 403
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    r = client_live.post("/import/drafts", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/import?kind=topology")
    with db.session_scope(live_ws) as s:
        assert s.execute(select(func.count(M.GraphInput.id))).scalar_one() == 2


def test_api_drafts(client_live, live_ws):
    h = {"Authorization": f"Bearer {live_ws.token_path.read_text().strip()}"}
    assert client_live.get("/api/v1/drafts/remediations", headers=h).status_code == 409
    for kind in ("assets", "findings"):
        run_import(live_ws, kind, _tpl(client_live, kind))
    assert client_live.get("/api/v1/drafts/remediations").status_code == 401
    assert client_live.get("/api/v1/drafts/exploit_conditions", headers=h).json()["vulnerabilities"]
    r = client_live.post("/api/v1/drafts/import", headers=h)
    assert r.status_code == 201 and len(r.json()["results"]) == 2


def test_cli_draft(tmp_path, client_live, live_ws):
    from typer.testing import CliRunner

    from tiw.cli.main import app

    for kind in ("assets", "findings"):
        run_import(live_ws, kind, _tpl(client_live, kind))
    d = str(live_ws.data_dir)
    run = CliRunner().invoke
    out = tmp_path / "draft.json"
    r = run(app, ["draft", "all", "--out", str(out), "--data-dir", d])
    assert r.exit_code == 0 and (tmp_path / "draft-exploit_conditions.json").exists()
    r = run(app, ["draft", "exploit-conditions", "--import", "--data-dir", d])
    assert r.exit_code == 0 and "succeeded" in r.output and "unreviewed" in r.output

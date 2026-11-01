"""Simplified topology input: edge CSV and the Network Paths form."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tiw.services import demo, drafts, triage
from tiw.services import topology_builder as tb
from tiw.services.ingest import run_import
from tiw.storage import db
from tiw.storage import models as M

HOST = "http://127.0.0.1:8787"
ASSETS = (
    "asset_id,name,criticality,internet_exposed,observed_at,expires_at,zone\n"
    "web-01,web,high,true,2026-10-01T00:00:00Z,2026-12-31T00:00:00Z,dmz\n"
    "app-01,app,normal,false,2026-10-01T00:00:00Z,2026-12-31T00:00:00Z,app\n"
    "db-01,db,critical,false,2026-10-01T00:00:00Z,2026-12-31T00:00:00Z,data\n"
)
FINDINGS = (
    "finding_id,asset_id,vulnerability_id,applicability,observed_at\n"
    "f-web,web-01,CVE-2024-0001,affected,2026-10-01T00:00:00Z\n"
    "f-app,app-01,CVE-2024-0002,affected,2026-10-01T00:00:00Z\n"
    "f-db,db-01,CVE-2024-0003,affected,2026-10-01T00:00:00Z\n"
)
EDGES = (
    "source,target,ports,reachability,evidence_ref,reviewer\n"
    "internet,web-01,443,allowed,fw rule 1,alice\n"
    "web-01,app-01,8443 8080,allowed,fw rule 2,alice\n"
    "app-01,db-01,tcp/5432,unknown,segment not exported,alice\n"
)


@pytest.fixture
def base(live_ws):
    assert run_import(live_ws, "assets", ASSETS.encode()).status == "succeeded"
    assert run_import(live_ws, "findings", FINDINGS.encode()).status == "succeeded"
    return live_ws


def _errs(out) -> str:
    return " | ".join(f"line {e['line']} {e['field']}: {e['reason']}" for e in out.errors)


def test_three_column_csv_to_attack_paths_with_drafts(base):
    out = run_import(base, "topology-csv", EDGES.encode())
    assert out.status == "succeeded", _errs(out)
    with db.session_scope(base) as s:
        doc = tb.current_document(s)
    assert doc["entry_points"] == [{"id": "internet", "label": "Internet", "grants": "network_access"}]
    assert [(o["asset_id"], o["weight"]) for o in doc["objectives"]] == [("db-01", 1)]
    assert "criticality=critical" in doc["description"]
    assert {e["id"] for e in doc["edges"]} == {"e-internet-web-01", "e-web-01-app-01", "e-app-01-db-01"}
    assert next(e for e in doc["edges"] if e["id"] == "e-web-01-app-01")["ports"] == ["tcp/8080", "tcp/8443"]
    assert {n["asset_id"]: n.get("zone") for n in doc["nodes"]}["db-01"] == "data"
    drafts.draft_and_import(base, actor="test")
    with db.session_scope(base) as s:
        g = triage.analyze_graph(s)["result"]
        o = triage.optimize_analysis(s, budget=1)["result"]
    assert g["counts"]["paths"] == 1 and g["paths"][0]["status"] == "conditional"  # unknown edge + 'any' ports
    assert o["selected"]["weighted_paths"] == 0


def test_crown_jewel_weight_column_wins(live_ws):
    assets = ASSETS.replace(",zone\n", ",zone,crown_jewel_weight\n", 1).replace("dmz\n", "dmz,\n").replace("app\n", "app,2\n").replace("data\n", "data,5\n")
    assert run_import(live_ws, "assets", assets.encode()).status == "succeeded"
    assert run_import(live_ws, "findings", FINDINGS.encode()).status == "succeeded"
    assert run_import(live_ws, "topology_csv", EDGES.encode()).status == "succeeded"
    with db.session_scope(live_ws) as s:
        objs = {o["asset_id"]: o["weight"] for o in tb.current_document(s)["objectives"]}
    assert objs == {"app-01": 2, "db-01": 5}


@pytest.mark.parametrize(
    "row,needle",
    [
        ("intrnet,web-01,443,allowed,x,a", "neither an imported asset"),  # typo never becomes an entry point
        ("internet,ghost,443,allowed,x,a", "not an imported asset"),
        ("internet,web-01,https,allowed,x,a", "invalid port"),
        ("internet,web-01,443,allowed,,a", "missing citation"),
        ("internet,web-01,443,open,x,a", "reachability"),
        ("web-01,web-01,443,allowed,x,a", "self-loops"),
    ],
)
def test_csv_errors_point_at_the_csv_line(base, row, needle):
    data = EDGES + row + "\n"
    out = run_import(base, "topology_csv", data.encode())
    assert out.status == "failed" and needle in _errs(out), _errs(out)
    assert any(e["line"] == 5 for e in out.errors)
    with db.session_scope(base) as s:
        assert s.execute(select(func.count(M.GraphInput.id))).scalar_one() == 0


def test_csv_rejects_unknown_columns_and_missing_crown_jewel(live_ws):
    out = run_import(live_ws, "topology_csv", b"source,target,payload\ninternet,x,1\n")
    assert out.status == "failed" and "unknown columns" in _errs(out)
    no_crit = ASSETS.replace("db,critical", "db,high")
    run_import(live_ws, "assets", no_crit.encode())
    run_import(live_ws, "findings", FINDINGS.encode())
    out = run_import(live_ws, "topology_csv", EDGES.encode())
    assert out.status == "failed" and "no crown jewel" in _errs(out)


def test_demo_topology_round_trips_through_csv(tmp_path):
    w = db.resolve_workspace(tmp_path / "ap")
    demo.seed(w, "attack-path")
    with db.session_scope(w) as s:
        before = triage.optimize_analysis(s, budget=2)["result"]
        csv_text = tb.to_csv(tb.current_document(s))
        paths_before = [(p["id"], p["status"]) for p in triage.analyze_graph(s)["result"]["paths"]]
    out = run_import(w, "topology_csv", csv_text.encode())
    assert out.status == "succeeded", _errs(out)
    with db.session_scope(w) as s:
        after = triage.optimize_analysis(s, budget=2)["result"]
        paths_after = [(p["id"], p["status"]) for p in triage.analyze_graph(s)["result"]["paths"]]
    assert paths_after == paths_before  # ids, claims, review state and validity survive the round trip
    assert after["selected"]["actions"] == before["selected"]["actions"]
    db.dispose_engine(w)


@pytest.fixture
def client(base):
    from tiw.api.app import create_app

    return TestClient(create_app(base), base_url=HOST)


def _tok(client) -> str:
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get("/topology").text).group(1)


def test_form_flow_builds_topology_without_files(client, base):
    page = client.get("/topology")
    assert page.status_code == 200 and "No paths yet" in page.text
    assert client.post("/topology/edges", data={"source": "internet", "target": "web-01", "ports": "443", "evidence_ref": "x"}).status_code == 403
    tok = _tok(client)
    for src, dst, port in (("internet", "web-01", "443"), ("web-01", "app-01", "8443"), ("app-01", "db-01", "5432")):
        r = client.post("/topology/edges", data={"csrf_token": tok, "source": src, "target": dst, "ports": port,
                                                  "reachability": "allowed", "evidence_ref": "form", "reviewer": "alice"}, follow_redirects=False)
        assert r.status_code == 303, r.text[:500]
    with db.session_scope(base) as s:
        assert len(tb.current_document(s)["edges"]) == 3
        assert s.execute(select(func.count(M.GraphInput.id))).scalar_one() == 3  # one append-only version per change
    r = client.post("/topology/objectives", data={"csrf_token": tok, "w:db-01": "4", "w:app-01": "1"}, follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/topology/objectives", data={"csrf_token": tok, "w:db-01": "abc"})
    assert r.status_code == 422
    r = client.post("/topology/objectives", data={"csrf_token": tok})
    assert r.status_code == 422 and "no crown jewel" in r.text
    r = client.post("/topology/edges/e-web-01-app-01/delete", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303
    assert client.post("/topology/edges/nope/delete", data={"csrf_token": tok}).status_code == 404
    with db.session_scope(base) as s:
        doc = tb.current_document(s)
    assert {e["id"] for e in doc["edges"]} == {"e-internet-web-01", "e-app-01-db-01"}
    assert {o["asset_id"]: o["weight"] for o in doc["objectives"]} == {"app-01": 1, "db-01": 4}
    r = client.post("/topology/edges", data={"csrf_token": tok, "source": "ghost", "target": "web-01", "ports": "443", "evidence_ref": "x"})
    assert r.status_code == 422
    csv_body = client.get("/topology.csv")
    assert csv_body.status_code == 200 and csv_body.text.startswith("source,target,ports")
    page = client.get("/topology")
    assert "e-app-01-db-01" in page.text and "Network Paths" in page.text


def test_form_escapes_hostile_input(client, base):
    tok = _tok(client)
    client.post("/topology/edges", data={"csrf_token": tok, "source": "internet", "target": "web-01", "ports": "443",
                                         "evidence_ref": "<script>alert(1)</script>", "reviewer": "alice"})
    page = client.get("/topology")
    assert "<script>alert(1)</script>" not in page.text and "&lt;script&gt;" in page.text


def test_cli_edges_export_and_csv_import(tmp_path, base):
    from typer.testing import CliRunner

    from tiw.cli.main import app

    d = str(base.data_dir)
    f = tmp_path / "edges.csv"
    f.write_text(EDGES, encoding="utf-8")
    run = CliRunner().invoke
    r = run(app, ["import", "topology-csv", str(f), "--data-dir", d])
    assert r.exit_code == 0 and "succeeded" in r.output
    out = tmp_path / "back.csv"
    r = run(app, ["graph", "edges", "--out", str(out), "--data-dir", d])
    assert r.exit_code == 0 and "e-app-01-db-01" in out.read_text(encoding="utf-8")

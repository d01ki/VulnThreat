"""v2 attack-path triage: demo acceptance criteria, imports, reproducibility, API/UI security."""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from tiw.services import demo, triage
from tiw.services.analysis_export import export_analysis_run, normalized_json
from tiw.services.demo import fixture_bytes
from tiw.services.ingest import run_import
from tiw.storage import db
from tiw.storage import models as M

AP = "attack-path"
HOST = "http://127.0.0.1:8787"


def _fixture(name: str) -> dict:
    return json.loads(fixture_bytes(AP, name))


@pytest.fixture
def ap(tmp_path: Path) -> db.Workspace:
    w = db.resolve_workspace(tmp_path / "ap")
    demo.seed(w, AP)
    yield w
    db.dispose_engine(w)


def _opt(ws: db.Workspace, budget: int = 2, **kw) -> dict:
    with db.session_scope(ws) as s:
        return triage.optimize_analysis(s, budget=budget, **kw)["result"]


def _graph(ws: db.Workspace) -> dict:
    with db.session_scope(ws) as s:
        return triage.analyze_graph(s)["result"]


# --------------------------------------------------------------------------- demo acceptance (spec §9)


def test_step1_graph_without_any_sensor_data(ap):
    g = _graph(ap)
    with db.session_scope(ap) as s:
        assert s.execute(select(func.count(M.Observation.id))).scalar_one() == 0
        assert s.execute(select(func.count(M.SensorWindow.id))).scalar_one() == 0
    assert g["counts"]["paths"] == 7 and g["counts"]["objectives"] == 2
    assert g["counts"]["by_status"] == {"conditional": 1, "contradicted": 2, "supported": 4}
    assert g["synthetic"] is True
    # rule-based hypotheses are verified; at least one is not "supported"
    statuses = {h["verification"]["status"] for h in g["hypotheses"]}
    assert {"supported", "contradicted", "conditional"} <= statuses
    # fixture minimums
    assert len(g["assets"]) >= 5 and len(g["vulnerabilities"]) >= 6


def test_step3_budget_two_graph_aware_beats_highest_severity_for_a_graph_reason(ap):
    o = _opt(ap)
    assert o["exact"] is True
    assert o["selected"]["actions"] == ["A-patch-api"]
    cvss = next(b for b in o["baselines"] if b["name"] == "cvss_desc")
    assert cvss["actions"] == ["A-patch-vpn", "A-patch-web"]
    assert cvss["effort"] <= 2 and o["selected"]["effort"] <= 2
    assert o["selected"]["objective_value"] < cvss["objective_value"]
    assert any("shared choke point" in w for w in cvss["why_optimised_differs"])
    for b in o["baselines"]:
        assert b["effort"] <= 2  # identical budget for every method


def test_step4_single_choke_point_breaks_multiple_paths_with_assumptions(ap):
    o = _opt(ap)
    eff = {e["action"]: e for e in o["single_action_effects"]}
    assert eff["A-patch-api"]["count"] >= 2
    assert len(o["surviving_paths"]) == 1 and o["resimulation"]["consistent"]
    assert any("not observed attacks" in a for a in o["assumptions"])
    assert any("EPSS" in a and "never multiplied" in a for a in o["assumptions"])


def test_step5_retraction_changes_portfolio_and_diff_explains_why(ap):
    rb = _robust(ap)
    flip = next(x for x in rb["scenarios"] if x["scenario"]["id"] == "S-withdraw-g-sftp-api")
    assert not flip["same_portfolio"]
    assert any("edge:e-sftp-api satisfied→unsupported" in r for r in flip["flip_reasons"])
    assert "not a probability" in rb["summary"]["portfolios"][0]["text"]

    demo.advance(ap, 2, AP)
    o2 = _opt(ap)
    assert o2["selected"]["actions"] == ["A-patch-vpn", "A-patch-web"]
    excluded = {p["id"]: p for p in o2["excluded_paths"]}
    assert len(excluded) == 2 and all(p["status"] == "insufficient_evidence" for p in excluded.values())
    with db.session_scope(ap) as s:
        run = triage.latest_run_for(s, triage.run_key("optimize", o2["params"]))
        doc = triage.run_with_diff(s, run.id)
    d = doc["diff"]
    assert d["portfolio_changed"] and d["actions_added"] == ["A-patch-vpn", "A-patch-web"]
    assert any("e-sftp-api" in w for w in d["why"])
    ev = [e for f in d["fact_reasons"] for e in f["evidence"] if e["id"] == "claim:g-sftp-api"]
    assert ev and ev[0]["active"] is False and ev[0]["inactive_reason"] == "retracted"
    # graph-only (no provenance) still recommends the old portfolio
    go = next(b for b in o2["baselines"] if b["name"] == "graph_only")
    assert go["actions"] == ["A-patch-api"]


def _robust(ws):
    with db.session_scope(ws) as s:
        return triage.robustness_analysis(s, budget=2)["result"]


def test_step6_repeat_demo_gives_identical_normalized_json(tmp_path):
    outs = []
    for name in ("one", "two"):
        w = db.resolve_workspace(tmp_path / name)
        demo.seed(w, AP)
        demo.advance(w, 2, AP)
        with db.session_scope(w) as s:
            runs = triage.latest_runs(s, 100)
        by_key = sorted((r.run_key, r.seq) for r in runs)
        texts = []
        for key, seq in by_key:
            with db.session_scope(w) as s:
                r = s.execute(select(M.AnalysisRun).where(M.AnalysisRun.run_key == key, M.AnalysisRun.seq == seq)).scalar_one()
            texts.append(normalized_json(r.result_json))
        outs.append(texts)
        db.dispose_engine(w)
    assert outs[0] == outs[1] and len(outs[0]) == 6


def test_reseed_is_idempotent_and_records_are_append_only(ap):
    with db.session_scope(ap) as s:
        n = s.execute(select(func.count(M.AnalysisRun.id))).scalar_one()
    demo.record_demo_analyses(ap)  # identical results -> nothing new
    with db.session_scope(ap) as s:
        assert s.execute(select(func.count(M.AnalysisRun.id))).scalar_one() == n
        run = s.execute(select(M.AnalysisRun).limit(1)).scalar_one()
        run.actor = "tamper"
        with pytest.raises(PermissionError):
            s.flush()
        s.rollback()


def test_counterfactuals_do_not_mutate_canonical_inputs(ap):
    with db.session_scope(ap) as s:
        before = {g.id: g.content_hash for g in s.execute(select(M.GraphInput)).scalars()}
        h0 = triage.analyze_graph(s)["result"]["evidence_hash"]
    _robust(ap)
    _opt(ap, withdraw=["claim:g-sftp-api"])
    with db.session_scope(ap) as s:
        after = {g.id: g.content_hash for g in s.execute(select(M.GraphInput)).scalars()}
        assert triage.analyze_graph(s)["result"]["evidence_hash"] == h0
    assert before == after


def test_stale_clock_changes_states_without_touching_data(ap):
    rb = _robust(ap)
    stale = next(x for x in rb["scenarios"] if x["scenario"]["kind"] == "stale_evidence")
    assert stale["path_changes"]  # expired firewall-export support becomes unknown / refutation wins


def test_export_markdown_and_json_carry_required_fields(ap):
    with db.session_scope(ap) as s:
        rid = next(r.id for r in triage.latest_runs(s) if r.kind == "optimize")
    _, md = export_analysis_run(ap, rid, "markdown")
    for needle in ("Evidence snapshot hash", "Algorithm / policy version", "Tie-breaking", "Equal-budget baselines",
                   "Paths excluded from the objective", "Assumptions and limitations", "SYNTHETIC DATA"):
        assert needle in md
    _, js = export_analysis_run(ap, rid, "json")
    doc = json.loads(js)
    assert doc["result"]["evidence_hash"] and doc["result"]["objective"]["tie_breaking"]
    assert doc["result"]["reasons"] and doc["run"]["id"] == rid


def test_family_separation_and_legacy_scenarios_unaffected(tmp_path, ap):
    with pytest.raises(demo.DemoError, match="own synthetic KEV"):
        demo.seed(ap, "all")
    w = db.resolve_workspace(tmp_path / "legacy")
    demo.seed(w, "all")
    with pytest.raises(demo.DemoError):
        demo.seed(w, AP)
    assert "attack-path" not in demo.seeded(w)
    db.dispose_engine(w)


def test_one_click_reset_restores_step1(ap):
    demo.advance(ap, 2, AP)
    token = ap.token_path.read_text()
    demo.reseed(ap, AP, 1)
    assert ap.token_path.read_text() == token
    assert _opt(ap)["selected"]["actions"] == ["A-patch-api"]
    with db.session_scope(ap) as s:
        assert s.execute(select(func.count(M.AnalysisRun.id))).scalar_one() == 3


# --------------------------------------------------------------------------- strict import validation


@pytest.fixture
def base(ws):
    for kind, name in (("assets", "assets.csv"), ("findings", "findings.csv"), ("claims", "claims-1.json")):
        assert run_import(ws, kind, fixture_bytes(AP, name), recompute=False).status == "succeeded"
    return ws


def _imp(ws, kind, doc):
    return run_import(ws, kind, json.dumps(doc).encode(), recompute=False)


def _errs(out) -> str:
    return " | ".join(f"{e['field']}: {e['reason']}" for e in out.errors)


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (lambda d: d["nodes"].append({"asset_id": "ghost-asset"}), "unknown asset"),
        (lambda d: d["edges"].append(copy.deepcopy(d["edges"][0])), "duplicate edge id"),
        (lambda d: d["edges"].append({**copy.deepcopy(d["edges"][0]), "id": "e-dup2"}), "duplicate edge internet -> ap-web-01"),
        (lambda d: d["edges"][0].pop("evidence_ref"), "missing citation"),
        (lambda d: d["edges"][0].update(valid_until="tomorrow"), "valid_from/valid_until"),
        (lambda d: d["edges"][0].update(valid_until="2026-10-01T00:00:00"), "timezone"),
        (lambda d: d["edges"][0].update(target="ap-web-01", source="ap-web-01"), "self-loops"),
        (lambda d: d["edges"][0].update(target="internet", source="ap-web-01"), "entry point"),
        (lambda d: d["edges"][0].update(claim_keys=["no-such-claim"]), "unknown claim_key"),
        (lambda d: d["edges"][0].update(claim_keys=["g-api-debug"]), "expected reachability"),
        (lambda d: d["edges"][0].update(payload="<script>"), "unexpected keys"),
        (lambda d: d["edges"][0].update(id="bad id with spaces"), "edge id is required"),
        (lambda d: d["objectives"][0].update(weight=-1), "weight"),
        (lambda d: d["edges"][0].update(ports=["tcp/99999"]), "ports"),
    ],
)
def test_topology_rejections(base, mutate, needle):
    doc = _fixture("topology.json")
    mutate(doc)
    out = _imp(base, "topology", doc)
    assert out.status == "failed", out.as_dict()
    assert needle in _errs(out)
    with db.session_scope(base) as s:
        assert s.execute(select(func.count(M.GraphInput.id))).scalar_one() == 0  # whole-file rollback


def test_topology_rejects_nan_and_oversize(base):
    raw = fixture_bytes(AP, "topology.json").replace(b'"weight": 3', b'"weight": NaN')
    out = run_import(base, "topology", raw, recompute=False)
    assert out.status == "failed" and "non-finite" in _errs(out)
    big = _fixture("topology.json")
    big["edges"] = [{"id": f"e{i}"} for i in range(10_001)]
    from tiw.adapters.common import InputTooLarge

    with pytest.raises(InputTooLarge):
        _imp(base, "topology", big)


def test_repeated_import_is_idempotent(base):
    assert _imp(base, "topology", _fixture("topology.json")).status == "succeeded"
    assert run_import(base, "topology", fixture_bytes(AP, "topology.json"), recompute=False).status in ("succeeded", "duplicate")
    with db.session_scope(base) as s:
        assert s.execute(select(func.count(M.GraphInput.id))).scalar_one() == 1


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (lambda d: d["vulnerabilities"].append({**copy.deepcopy(d["vulnerabilities"][0]), "vulnerability_id": "DEMO-VULN-999"}), "orphan"),
        (lambda d: d["vulnerabilities"][0].update(exploit_code="curl x | sh"), "no payloads"),
        (lambda d: d["vulnerabilities"][0].pop("citation"), "citation"),
        (lambda d: d["vulnerabilities"][0]["cvss"].update(base_score=11), "base_score"),
        (lambda d: d["vulnerabilities"][0]["cvss"].pop("source"), "provenance"),
        (lambda d: d["vulnerabilities"][0].update(vulnerability_id="CVE-2024-0001"), "invalid identifier"),
        (lambda d: d["vulnerabilities"][0]["conditions"][0].update(status="maybe"), "status"),
    ],
)
def test_exploit_condition_rejections(base, mutate, needle):
    doc = _fixture("exploit_conditions.json")
    mutate(doc)
    out = _imp(base, "exploit_conditions", doc)
    assert out.status == "failed" and needle in _errs(out), _errs(out)


@pytest.mark.parametrize(
    "mutate,needle",
    [
        (lambda d: d["actions"][0].update(cost=-1), "non-negative integer"),
        (lambda d: d["actions"][0].update(cost=1.5), "non-negative integer"),
        (lambda d: d["actions"][0].update(cost=True), "non-negative integer"),
        (lambda d: d["actions"].append(copy.deepcopy(d["actions"][0])), "duplicate action id"),
        (lambda d: d["actions"][0].update(finding_id="nope"), "unknown finding"),
        (lambda d: d["actions"][0].update(requires=["ghost"]), "unknown action ids"),
        (lambda d: d["actions"][-1].update(requires=["A-proxy"]) or d["actions"][-2].update(requires=["A-restrict-fin"]), "cycle"),
        (lambda d: d["actions"][0].update(downtime="forever"), "downtime"),
    ],
)
def test_remediation_rejections(base, mutate, needle):
    assert _imp(base, "topology", _fixture("topology.json")).status == "succeeded"
    doc = _fixture("remediations.json")
    mutate(doc)
    out = _imp(base, "remediations", doc)
    assert out.status == "failed" and needle in _errs(out), _errs(out)


def test_graph_claim_validation(base):
    doc = {"schema_version": "1.0", "synthetic": True, "source": {"name": "x"}, "documents": [{"external_id": "d", "claims": [
        {"claim_key": "bad", "subject_id": "DEMO-VULN-101", "predicate": "reachability", "value": True, "origin": "primary"}]}]}
    assert "edge:" in _errs(_imp(base, "claims", doc))
    doc["documents"][0]["claims"][0].update(subject_id="edge:e-x", value="yes")
    assert "true or false" in _errs(_imp(base, "claims", doc))


def test_live_workspace_rejects_synthetic_graph_inputs(live_ws):
    out = run_import(live_ws, "topology", fixture_bytes(AP, "topology.json"), recompute=False)
    assert out.status == "failed" and "synthetic" in _errs(out)


# --------------------------------------------------------------------------- migration


def test_migration_downgrade_and_upgrade(tmp_path):
    from alembic import command

    w = db.resolve_workspace(tmp_path / "mig")
    db.init_workspace(w, synthetic=True)
    cfg = db._alembic_config(w)
    command.downgrade(cfg, "0001_initial")
    from sqlalchemy import inspect

    with db.get_engine(w).connect() as c:
        assert "analysis_runs" not in inspect(c).get_table_names()
    command.upgrade(cfg, "head")
    assert db.schema_problems(w) == []
    db.dispose_engine(w)


# --------------------------------------------------------------------------- API and UI


@pytest.fixture
def client(ap):
    from tiw.api.app import create_app

    return TestClient(create_app(ap), base_url=HOST)


def _auth(ws):
    return {"Authorization": f"Bearer {ws.token_path.read_text().strip()}"}


def test_api_requires_token_and_returns_envelopes(client, ap):
    assert client.get("/api/v1/graph").status_code == 401
    r = client.get("/api/v1/graph", headers=_auth(ap))
    assert r.status_code == 200 and r.json()["result"]["counts"]["paths"] == 7
    r = client.post("/api/v1/triage/optimize", json={"budget": -1}, headers=_auth(ap))
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_input"
    r = client.post("/api/v1/triage/optimize", json={"budget": 2}, headers=_auth(ap))
    assert r.status_code == 200 and r.json()["result"]["selected"]["actions"] == ["A-patch-api"] and r.json()["created"] is False
    r = client.get("/api/v1/graph/paths/PATH-001", headers=_auth(ap))
    assert r.status_code == 200 and r.json()["hops"]
    assert client.get("/api/v1/graph/paths/PATH-FFFFFFFFFF", headers=_auth(ap)).status_code == 404
    runs = client.get("/api/v1/analysis-runs", headers=_auth(ap)).json()["items"]
    norm = client.get(f"/api/v1/analysis-runs/{runs[0]['id']}?format=normalized", headers=_auth(ap))
    assert norm.status_code == 200 and "evidence_hash" in norm.json()
    r = client.post("/api/v1/graph/hypotheses", json={"candidates": [{"schema_version": "1.0", "hypothesis_id": "x", "source_asset_id": "ghost",
                                                                     "target_asset_id": "ap-api-01", "required_conditions": []}]}, headers=_auth(ap))
    assert r.json()["external"]["rejected"]
    r = client.post("/api/v1/triage/robustness", json={"budget": 2, "record": False}, headers=_auth(ap))
    assert r.status_code == 200 and r.json()["run"] is None


def test_api_graph_not_ready(ws):
    from tiw.api.app import create_app

    c = TestClient(create_app(ws), base_url=HOST)
    r = c.get("/api/v1/graph", headers=_auth(ws))
    assert r.status_code == 409 and r.json()["error"]["code"] == "graph_not_ready"


def test_ui_pages_render_escape_and_do_not_write(client, ap):
    with db.session_scope(ap) as s:
        n = s.execute(select(func.count(M.AnalysisRun.id))).scalar_one()
        a = s.execute(select(func.count(M.AuditEvent.id))).scalar_one()
    pages = ["/attack-paths", "/attack-paths?edge=e-vpn-api", "/attack-paths?target=OBJ-hr&status=conditional",
             "/attack-paths/PATH-0393D77E03", "/remediation-lab?budget=3&compare=kev_first", "/robustness",
             "/robustness?withdraw=claim:g-sftp-api&unknown_edge=e-web-api", "/analysis-runs", "/"]
    for p in pages:
        r = client.get(p)
        assert r.status_code == 200, p
        assert "<script>alert(1)</script>" not in r.text
        assert "Content-Security-Policy" in r.headers
    r = client.get("/robustness?withdraw=claim:g-sftp-api")
    assert "Recommendation flips." in r.text
    assert client.get("/attack-paths/<script>").status_code == 404
    assert client.get("/robustness?withdraw=%3Cscript%3E").status_code == 200
    with db.session_scope(ap) as s:
        assert s.execute(select(func.count(M.AnalysisRun.id))).scalar_one() == n
        assert s.execute(select(func.count(M.AuditEvent.id))).scalar_one() == a


def test_hostile_labels_are_escaped(ap, client):
    doc = _fixture("topology.json")
    doc["nodes"][0]["label"] = '<img src=x onerror=alert(1)>'
    assert _imp(ap, "topology", doc).status == "succeeded"
    r = client.get("/attack-paths")
    assert "<img src=x" not in r.text and "&lt;img src=x" in r.text


def test_ui_posts_need_csrf_and_record_and_reset_work(client, ap):
    r = client.post("/remediation-lab/record", data={"budget": "3"})
    assert r.status_code == 403
    r = client.post("/demo/attack-path/reset", data={"step": "1"})
    assert r.status_code == 403
    page = client.get("/remediation-lab")
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    r = client.post("/remediation-lab/record", data={"budget": "3", "csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/analysis-runs/")
    r = client.post("/demo/attack-path/advance", data={"csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303
    assert "A-patch-vpn" in client.get("/remediation-lab").text
    r = client.post("/demo/attack-path/reset", data={"csrf_token": tok, "step": "1"}, follow_redirects=False)
    assert r.status_code == 303
    assert _opt(ap)["selected"]["actions"] == ["A-patch-api"]
    r = client.post("/remediation-lab/record", data={"budget": "2", "csrf_token": tok}, headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_ui_reset_refuses_live_workspace(live_ws):
    from tiw.api.app import create_app

    c = TestClient(create_app(live_ws), base_url=HOST)
    tok = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/settings").text).group(1)
    r = c.post("/demo/attack-path/reset", data={"csrf_token": tok})
    assert r.status_code == 409
    assert c.get("/attack-paths").status_code == 200  # not-ready page, no crash


def test_cli_end_to_end(tmp_path):
    from typer.testing import CliRunner

    from tiw.cli.main import app

    d = str(tmp_path / "cli")
    run = CliRunner().invoke
    assert run(app, ["demo", "seed", "--scenario", "attack-path", "--data-dir", d]).exit_code == 0
    r = run(app, ["graph", "build", "--data-dir", d])
    assert r.exit_code == 0 and "paths=7" in r.output
    r = run(app, ["graph", "explain", "--path-id", "PATH-001", "--data-dir", d])
    assert r.exit_code == 0 and "hop" in r.output
    r = run(app, ["triage", "optimize", "--budget", "2", "--data-dir", d])
    assert r.exit_code == 0 and "selected: A-patch-api" in r.output
    r = run(app, ["triage", "robustness", "--budget", "2", "--data-dir", d])
    assert r.exit_code == 0 and "not a probability" in r.output
    r = run(app, ["export", "--analysis-run", "latest-optimize", "--format", "json", "--normalized", "--data-dir", d])
    assert r.exit_code == 0
    r = run(app, ["export", "--data-dir", d])
    assert r.exit_code == 2
    cand = tmp_path / "cand.json"
    cand.write_text(json.dumps([{"schema_version": "1.0", "hypothesis_id": "m1", "source_asset_id": "ap-web-01", "target_asset_id": "ap-hr-db",
                                 "required_conditions": ["network_reachability"], "supporting_evidence_ids": ["claim:invented"]}]))
    r = run(app, ["graph", "hypotheses", "--from-file", str(cand), "--data-dir", d])
    assert r.exit_code == 0 and "fabricated" in r.output
    r = run(app, ["demo", "reset", "--yes", "--data-dir", d])
    assert r.exit_code == 0

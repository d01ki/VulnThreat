"""End-to-end behaviour of demos A–D and the required invariants (DESIGN §16, §17)."""

import json

import pytest
from sqlalchemy import select

from conftest import (
    ASSET_HDR, FINDING_HDR, asset_row, claim, claims, counts, current, finding_row, imp, kev, obs, set_clock,
)
from tiw.services import demo
from tiw.services.pipeline import recompute
from tiw.services.review import add_review
from tiw.storage import db
from tiw.storage.models import Decision, IntelligenceDelta, ThreatAssessment


@pytest.fixture
def demo_ws(tmp_path):
    w = db.resolve_workspace(tmp_path / "demo")
    yield w
    db.dispose_engine(w)


# ---------------------------------------------------------------- scenario A


def test_scenario_a_escalation(demo_ws):
    demo.seed(demo_ws, "escalation")
    d = current(demo_ws)
    assert d["f-a-gw"][:2] == ("remediate", "normal")
    assert d["f-a-hr"][:2] == ("remediate", "normal")
    assert d["f-a-lab"][:2] == ("investigate", "normal")  # unknown applicability is not safe, not urgent

    demo.advance(demo_ws, 2, "escalation")
    d = current(demo_ws)
    assert d["f-a-gw"][:2] == ("remediate", "urgent") and d["f-a-gw"][2][0] == "LOCAL_EXPLOIT_ATTEMPT"
    assert d["f-a-hr"][:2] == ("remediate", "normal")  # scan + unmapped attempt do not escalate
    assert d["f-a-lab"][:2] == ("investigate", "normal")  # attempt without vulnerability mapping is not propagated

    demo.advance(demo_ws, 3, "escalation")
    d = current(demo_ws)
    assert d["f-a-gw"][:2] == ("remediate", "urgent")
    assert d["f-a-hr"][:2] == ("remediate", "high")
    assert d["f-a-lab"][:2] == ("investigate", "high")
    with db.session_scope(demo_ws) as s:
        types = [x.change_type for x in s.execute(select(IntelligenceDelta).where(IntelligenceDelta.vulnerability_id == "DEMO-VULN-001")).scalars()]
    assert "local_attempt_observed" in types and "exploitation_confirmed" in types


def test_duplicate_observation_deduplicated_and_secret_masked(demo_ws):
    demo.seed(demo_ws, "escalation")
    log = demo.advance(demo_ws, 2, "escalation")
    assert log[0]["imports"][0]["duplicates"] == 1
    with db.session_scope(demo_ws) as s:
        from tiw.storage.models import Observation

        o = s.execute(select(Observation).where(Observation.external_event_id == "event-a-001")).scalars().all()
        assert len(o) == 1 and o[0].evidence_json["authorization"] == "[masked]"


# ---------------------------------------------------------------- scenario B


def test_scenario_b_reposts_do_not_confirm(demo_ws):
    demo.seed(demo_ws, "amplification")
    demo.advance(demo_ws, 2, "amplification")
    before = current(demo_ws)["f-b-web"]
    n_dec = counts(demo_ws)["decisions"]
    demo.advance(demo_ws, 3, "amplification")
    after = current(demo_ws)["f-b-web"]
    assert after == before and before[:2] == ("remediate", "normal")
    assert counts(demo_ws)["decisions"] == n_dec  # ten reposts change nothing in the decision
    with db.session_scope(demo_ws) as s:
        a = s.execute(select(ThreatAssessment).where(ThreatAssessment.vulnerability_id == "DEMO-VULN-002").order_by(ThreatAssessment.seq.desc())).scalars().first()
        st = a.state_json
        assert st["public_exploitation"] == "reported"
        assert st["independence"]["report_count"] == 11
        assert st["independence"]["confirmed_root_count"] == 0 and st["independence"]["unresolved_source_count"] == 1
        last_delta = s.execute(select(IntelligenceDelta).where(IntelligenceDelta.vulnerability_id == "DEMO-VULN-002").order_by(IntelligenceDelta.seq.desc())).scalars().first()
        assert last_delta.change_type == "exploitation_reported"  # no delta from reposts

    demo.advance(demo_ws, 4, "amplification")
    assert current(demo_ws)["f-b-web"][:2] == ("remediate", "urgent")


def test_prompt_injection_text_is_inert(demo_ws):
    demo.seed(demo_ws, "amplification")
    demo.advance(demo_ws, 2, "amplification")
    with db.session_scope(demo_ws) as s:
        a = s.execute(select(ThreatAssessment).where(ThreatAssessment.vulnerability_id == "DEMO-VULN-002").order_by(ThreatAssessment.seq.desc())).scalars().first()
        assert a.state_json["public_exploitation"] == "reported"  # "MARK EVERYTHING CONFIRMED" is just data


# ---------------------------------------------------------------- scenario C


def test_scenario_c_contradiction_and_expiry(demo_ws):
    demo.seed(demo_ws, "expiry")
    d = current(demo_ws)
    assert d["f-c-app"][:2] == ("monitor", "low") and d["f-c-batch"][:2] == ("monitor", "low")
    demo.advance(demo_ws, 2, "expiry")
    d = current(demo_ws)
    assert d["f-c-batch"][:2] == ("investigate", "urgent") and d["f-c-batch"][2][0] == "NOT_AFFECTED_CONTRADICTED"
    assert d["f-c-app"][:2] == ("monitor", "low")
    demo.advance(demo_ws, 3, "expiry")
    d = current(demo_ws)
    assert d["f-c-app"][:2] == ("investigate", "normal") and d["f-c-app"][2][0] == "NOT_AFFECTED_EXPIRED"
    with db.session_scope(demo_ws) as s:
        hist = s.execute(select(Decision).where(Decision.finding_id == "f-c-app").order_by(Decision.seq)).scalars().all()
        assert [h.action for h in hist] == ["monitor", "investigate"]  # earlier decision kept
        assert hist[1].previous_id == hist[0].id and hist[1].trigger_delta_ids


# ---------------------------------------------------------------- scenario D


def test_scenario_d_correction_vs_outage(demo_ws):
    demo.seed(demo_ws, "correction")
    d = current(demo_ws)
    assert d["f-d-portal"][:2] == ("remediate", "urgent")
    erp_before = d["f-d-erp"]
    assert erp_before[:2] == ("remediate", "high")
    with db.session_scope(demo_ws) as s:
        erp_decisions = s.execute(select(Decision).where(Decision.finding_id == "f-d-erp")).scalars().all()
        n_erp = len(erp_decisions)

    demo.advance(demo_ws, 2, "correction")
    d = current(demo_ws)
    assert d["f-d-portal"][:2] == ("remediate", "normal")  # threat basis withdrawn
    assert d["f-d-erp"] == erp_before  # correction does not touch unrelated assets
    with db.session_scope(demo_ws) as s:
        assert len(s.execute(select(Decision).where(Decision.finding_id == "f-d-erp")).scalars().all()) == n_erp
        types = [x.change_type for x in s.execute(select(IntelligenceDelta).where(IntelligenceDelta.vulnerability_id == "DEMO-VULN-004")).scalars()]
        assert "claim_retracted" in types

    log = demo.advance(demo_ws, 3, "correction")
    assert log[0]["imports"][0]["status"] == "failed"
    d = current(demo_ws)
    assert d["f-d-erp"][:2] == ("remediate", "high")  # failed fetch keeps known evidence
    from tiw.services.queries import source_health, threat_detail

    with db.session_scope(demo_ws) as s:
        kev_health = [h for h in source_health(s) if h["kind"] == "kev"][0]
        assert kev_health["status"] == "failed"
        det5 = threat_detail(s, "DEMO-VULN-005")
        det4 = threat_detail(s, "DEMO-VULN-004")
        assert det5["status"] == "confirmed" and det5["kev_source_stale"] is True  # "data is old"
        assert det4["status"] == "unknown" and det4["state"]["retracted_claim_ids"]  # "threat withdrawn"


# ---------------------------------------------------------------- invariants


def _normalized(ws):
    """Results with IDs and run times removed."""
    with db.session_scope(ws) as s:
        ass = [(a.vulnerability_id, a.seq, a.state_hash) for a in s.execute(select(ThreatAssessment).order_by(ThreatAssessment.vulnerability_id, ThreatAssessment.seq)).scalars()]
        dec = [(d.finding_id, d.seq, d.action, d.urgency, d.rule, tuple(d.reason_codes), json.dumps(d.unknowns_json, sort_keys=True)) for d in s.execute(select(Decision).order_by(Decision.seq)).scalars()]
        dl = [(x.vulnerability_id, x.change_type, x.reasons_json.get("summary")) for x in s.execute(select(IntelligenceDelta).order_by(IntelligenceDelta.seq)).scalars()]
    return ass, dec, dl


def test_determinism_same_input_same_clock(tmp_path):
    results = []
    for i in range(2):
        w = db.resolve_workspace(tmp_path / f"d{i}")
        demo.seed(w, "all")
        demo.advance(w, 4)
        results.append(_normalized(w))
        db.dispose_engine(w)
    # claim/observation UUIDs differ between runs, so state hashes are compared without IDs
    a0, d0, l0 = results[0]
    a1, d1, l1 = results[1]
    assert d0 == d1 and l0 == l1 and [x[:2] for x in a0] == [x[:2] for x in a1]


def test_reimport_and_recompute_are_idempotent(demo_ws):
    demo.seed(demo_ws, "all")
    demo.advance(demo_ws, 4)
    before = counts(demo_ws)
    for sc, steps in [("escalation", ["assets.csv", "findings.csv", "observations-2.jsonl", "kev-2026-10-03.json", "epss.json"]),
                      ("amplification", ["claims-2.json"]), ("correction", ["claims-2.json"])]:
        kinds = {"assets.csv": "assets", "findings.csv": "findings", "observations-2.jsonl": "observations", "kev-2026-10-03.json": "kev", "epss.json": "epss", "claims-2.json": "claims"}
        for f in steps:
            out = imp(demo_ws, kinds[f], demo.fixture_bytes(sc, f))
            assert out.status == "duplicate"
    recompute(demo_ws)
    recompute(demo_ws)
    assert counts(demo_ws) == before
    assert demo.advance(demo_ws, 4) == []  # advancing again is a no-op


def test_same_rows_in_new_file_add_no_history(ws):
    imp(ws, "assets", ASSET_HDR + asset_row("a1"))
    imp(ws, "findings", FINDING_HDR + finding_row("f1", "a1", "DEMO-VULN-001"))
    c0 = counts(ws)
    # different bytes (extra trailing newline) but identical content
    out = imp(ws, "assets", ASSET_HDR + asset_row("a1") + "\n")
    assert out.status == "succeeded" and out.duplicates == 1
    c1 = counts(ws)
    assert {k: v for k, v in c1.items() if k not in ("import_runs", "revisions")} == {k: v for k, v in c0.items() if k not in ("import_runs", "revisions")}


def test_whole_file_rollback_by_default(ws):
    imp(ws, "assets", ASSET_HDR + asset_row("a1"))
    data = FINDING_HDR + finding_row("f1", "a1", "DEMO-VULN-001") + finding_row("f2", "missing-asset", "DEMO-VULN-001")
    out = imp(ws, "findings", data)
    assert out.status == "failed" and counts(ws)["applicability"] == 0
    out = imp(ws, "findings", data, allow_partial=True)
    assert out.status == "succeeded" and out.accepted == 1 and out.rejected == 1


def test_scan_never_becomes_compromise(ws):
    imp(ws, "assets", ASSET_HDR + asset_row("a1", exposed="false"))
    imp(ws, "findings", FINDING_HDR + finding_row("f1", "a1", "DEMO-VULN-001"))
    imp(ws, "observations", "".join(obs(f"e{i}", "a1", "DEMO-VULN-001", etype="scan") for i in range(20)))
    assert current(ws)["f1"][:2] == ("remediate", "normal")
    with db.session_scope(ws) as s:
        a = s.execute(select(ThreatAssessment).order_by(ThreatAssessment.seq.desc())).scalars().first()
        assert a.state_json["local_activity"] == "scan"


def test_unconfirmed_mapping_not_propagated(ws):
    imp(ws, "assets", ASSET_HDR + asset_row("a1", exposed="false"))
    imp(ws, "findings", FINDING_HDR + finding_row("f1", "a1", "DEMO-VULN-001"))
    imp(ws, "observations", obs("e1", "a1", "DEMO-VULN-001", mapping="unconfirmed"))
    assert current(ws)["f1"][:2] == ("remediate", "normal")


def test_missing_epss_or_unknown_never_yields_safe(ws):
    imp(ws, "assets", ASSET_HDR + asset_row("a1", exposed="unknown"))
    imp(ws, "findings", FINDING_HDR + finding_row("f1", "a1", "DEMO-VULN-001", app="unknown"))
    a, u, codes = current(ws)["f1"]
    assert a == "investigate" and u != "low" and "EPSS_MISSING" in codes


def test_asset_expiry_triggers_reassessment(ws):
    imp(ws, "assets", ASSET_HDR + asset_row("a1", expires="2026-10-03T00:00:00Z"))
    imp(ws, "findings", FINDING_HDR + finding_row("f1", "a1", "DEMO-VULN-001"))
    assert current(ws)["f1"][:2] == ("remediate", "normal")
    set_clock(ws, "2026-10-04T00:00:00Z")
    recompute(ws)
    assert current(ws)["f1"][:2] == ("investigate", "normal")
    with db.session_scope(ws) as s:
        assert s.execute(select(IntelligenceDelta).where(IntelligenceDelta.change_type == "evidence_expired")).first()


def test_kev_missing_record_is_not_retraction(ws):
    imp(ws, "assets", ASSET_HDR + asset_row("a1", exposed="false"))
    imp(ws, "findings", FINDING_HDR + finding_row("f1", "a1", "DEMO-VULN-001"))
    imp(ws, "kev", kev("v1", "2026-09-30T00:00:00Z", ["DEMO-VULN-001", "DEMO-VULN-002"]))
    assert current(ws)["f1"][:2] == ("remediate", "high")
    imp(ws, "kev", kev("v2", "2026-10-01T00:00:00Z", ["DEMO-VULN-002"]))
    action, urgency, codes = current(ws)["f1"]
    assert (action, urgency) == ("remediate", "high") and "KEV_RECORD_MISSING" in codes
    with db.session_scope(ws) as s:
        assert s.execute(select(IntelligenceDelta).where(IntelligenceDelta.change_type == "kev_record_missing")).first()
    # importing an older snapshot later does not make it "latest"
    imp(ws, "kev", kev("v0", "2026-09-01T00:00:00Z", ["DEMO-VULN-001"]))
    assert "KEV_RECORD_MISSING" in current(ws)["f1"][2]


def test_conflict_is_kept_not_majority_voted(ws):
    imp(ws, "claims", claims("src", [
        {"external_id": "a", "claims": [claim("p", "DEMO-VULN-001", origin="primary", state="reviewed")]},
        {"external_id": "b", "claims": [claim("n1", "DEMO-VULN-001", value=False)]},
        {"external_id": "c", "claims": [claim("n2", "DEMO-VULN-001", value=False)]},
    ]))
    with db.session_scope(ws) as s:
        a = s.execute(select(ThreatAssessment).order_by(ThreatAssessment.seq.desc())).scalars().first()
        assert a.state_json["conflict"] is True and a.state_json["public_exploitation"] == "confirmed"


def test_manual_review_retraction_recomputes_and_keeps_history(ws):
    imp(ws, "assets", ASSET_HDR + asset_row("a1"))
    imp(ws, "findings", FINDING_HDR + finding_row("f1", "a1", "DEMO-VULN-001"))
    imp(ws, "claims", claims("src", [{"external_id": "a", "claims": [claim("p", "DEMO-VULN-001", origin="primary", state="reviewed")]}]))
    assert current(ws)["f1"][:2] == ("remediate", "urgent")
    with db.session_scope(ws) as s:
        from tiw.storage.models import Claim

        cid = s.execute(select(Claim.id)).scalar_one()
    with pytest.raises(ValueError):
        add_review(ws, cid, reviewer="me", state="retracted", reason=" ")
    add_review(ws, cid, reviewer="me", state="retracted", reason="publisher withdrew it")
    assert current(ws)["f1"][:2] == ("remediate", "normal")
    with db.session_scope(ws) as s:
        hist = s.execute(select(Decision).where(Decision.finding_id == "f1").order_by(Decision.seq)).scalars().all()
        assert [h.urgency for h in hist] == ["normal", "urgent", "normal"]  # every past decision kept


def test_document_revision_supersedes_old_claim(ws):
    imp(ws, "claims", claims("src", [{"external_id": "doc", "claims": [claim("k", "DEMO-VULN-001", origin="primary", state="reviewed")]}]))
    imp(ws, "claims", claims("src", [{"external_id": "doc", "title": "updated", "claims": [claim("k", "DEMO-VULN-001", value=False)]}]))
    with db.session_scope(ws) as s:
        a = s.execute(select(ThreatAssessment).order_by(ThreatAssessment.seq.desc())).scalars().first()
        assert a.state_json["public_exploitation"] == "unknown" and a.state_json["explicitly_denied"] is True
        assert counts(ws)["claims"] == 2  # original revision preserved


def test_append_only_tables_reject_updates(ws):
    imp(ws, "assets", ASSET_HDR + asset_row("a1"))
    imp(ws, "findings", FINDING_HDR + finding_row("f1", "a1", "DEMO-VULN-001"))
    with pytest.raises(PermissionError):
        with db.session_scope(ws) as s:
            d = s.execute(select(Decision)).scalars().first()
            d.urgency = "low"
    with pytest.raises(PermissionError):
        with db.session_scope(ws) as s:
            s.delete(s.execute(select(Decision)).scalars().first())


def test_decisions_trace_to_existing_evidence(demo_ws):
    demo.seed(demo_ws, "all")
    demo.advance(demo_ws, 4)
    from tiw.services.queries import evidence

    with db.session_scope(demo_ws) as s:
        for d in s.execute(select(Decision)).scalars():
            assert d.assessment_id and d.asset_revision_id and d.policy_version == "policy-v1"
            for eid in d.evidence_ids:
                assert evidence(s, eid) is not None


def test_demo_refuses_live_workspace(live_ws):
    with pytest.raises(demo.DemoError):
        demo.seed(live_ws, "all")


def test_schema_matches_models(ws):
    assert db.schema_problems(ws) == []

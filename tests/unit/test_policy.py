"""policy-v1 rule boundaries (DESIGN §10)."""

from datetime import datetime, timedelta, timezone

import pytest

from tiw.domain.decisions import TriageInput, evaluate, sort_key

NOW = datetime(2026, 10, 5, tzinfo=timezone.utc)
FUTURE = NOW + timedelta(days=30)
PAST = NOW - timedelta(days=1)


def state(public="unknown", local=None, epss=None, conflict=False, kinds=None, kev_latest=None, unresolved=0):
    return {
        "public_exploitation": public,
        "public_basis_kinds": kinds if kinds is not None else (["kev"] if public == "confirmed" else []),
        "public_basis_claim_ids": [], "reported_claim_ids": [],
        "local_by_asset": {"a1": local} if local else {},
        "conflict": conflict, "recency": "fresh", "epss": epss,
        "kev": {"listed_ever": kev_latest is not None, "in_latest_snapshot": kev_latest},
        "independence": {"report_count": 0, "confirmed_root_count": 0, "unresolved_source_count": unresolved},
    }


def run(st, app="affected", app_exp=FUTURE, exposure="true", exp_exp=FUTURE, crit="normal"):
    return evaluate(TriageInput("f1", "a1", "DEMO-VULN-001", crit, exposure, exp_exp, NOW - timedelta(days=3), app, app_exp, "r", "why", st, NOW))


@pytest.mark.parametrize(
    "kwargs,expected",
    [
        ({"st": state(local="compromise_confirmed"), "app": "not_affected"}, ("incident_response", "urgent", 1)),
        ({"st": state(local="exploit_attempt"), "app": "not_affected"}, ("investigate", "urgent", 2)),
        ({"st": state(public="confirmed"), "app": "not_affected"}, ("monitor", "low", 3)),
        ({"st": state(), "app": "unknown"}, ("investigate", "normal", 4)),
        ({"st": state(public="confirmed"), "app": "unknown"}, ("investigate", "high", 4)),
        ({"st": state(local="exploit_attempt"), "app": "unknown"}, ("investigate", "high", 4)),
        ({"st": state(), "app": "not_affected", "app_exp": PAST}, ("investigate", "normal", 4)),
        ({"st": state(local="exploit_attempt"), "app": "not_affected", "app_exp": PAST}, ("investigate", "high", 4)),
        ({"st": state(local="exploit_attempt"), "exposure": "false"}, ("remediate", "urgent", 5)),
        ({"st": state(public="confirmed"), "exposure": "true"}, ("remediate", "urgent", 6)),
        ({"st": state(public="confirmed"), "exposure": "false", "crit": "critical"}, ("remediate", "urgent", 6)),
        ({"st": state(public="confirmed"), "exposure": "false", "crit": "high"}, ("remediate", "high", 7)),
        ({"st": state(public="confirmed"), "exposure": "true", "exp_exp": PAST}, ("remediate", "high", 7)),
        ({"st": state(), "exposure": "unknown", "crit": "critical"}, ("investigate", "high", 8)),
        ({"st": state(), "exposure": "true", "exp_exp": PAST}, ("investigate", "normal", 8)),
        ({"st": state(), "exposure": "false"}, ("remediate", "normal", 9)),
    ],
)
def test_rule_table(kwargs, expected):
    r = run(**kwargs)
    assert (r.action, r.urgency, r.rule) == expected


def test_scan_only_never_escalates():
    r = run(state(local="scan"), exposure="false")
    assert (r.action, r.urgency, r.rule) == ("remediate", "normal", 9)
    assert "LOCAL_SCAN_ONLY" in r.reason_codes


def test_reported_does_not_raise_urgency():
    base = run(state(), exposure="true")
    rep = run(state(public="reported", unresolved=1), exposure="true")
    assert (rep.action, rep.urgency) == (base.action, base.urgency)
    assert "PUBLIC_EXPLOITATION_REPORTED" in rep.reason_codes and "ROOT_UNRESOLVED" in rep.reason_codes


def test_epss_never_changes_action_or_urgency():
    high = run(state(epss={"probability": 0.99, "percentile": 0.99, "score_date": "2026-10-05", "stale": False}))
    low = run(state(epss={"probability": 0.0001, "percentile": 0.01, "score_date": "2026-10-05", "stale": False}))
    missing = run(state(epss=None))
    assert {(r.action, r.urgency) for r in (high, low, missing)} == {("remediate", "normal")}
    assert "EPSS_MISSING" in missing.reason_codes


@pytest.mark.parametrize("app,app_exp", [("unknown", FUTURE), ("not_affected", PAST)])
def test_unknown_or_expired_never_becomes_monitor(app, app_exp):
    r = run(state(epss=None), app=app, app_exp=app_exp, exposure="unknown")
    assert r.action != "monitor" and r.urgency != "low"


def test_kev_missing_is_context_not_downgrade():
    r = run(state(public="confirmed", kev_latest=False), exposure="true")
    assert (r.action, r.urgency) == ("remediate", "urgent")
    assert "KEV_RECORD_MISSING" in r.reason_codes


def test_confirmed_by_primary_uses_distinct_code():
    r = run(state(public="confirmed", kinds=["reviewed_primary"]), exposure="true")
    assert r.reason_codes[0] == "CONFIRMED_AND_EXPOSED"


def test_unknowns_listed():
    r = run(state(), app="unknown", exposure="unknown")
    fields = {u["field"] for u in r.unknowns}
    assert {"applicability", "internet_exposure", "epss", "local_activity"} <= fields


def test_sort_order_within_urgency():
    fresh = {"probability": 0.5, "stale": False}
    stale = {"probability": 0.9, "stale": True}
    rows = [("normal", None, "f3"), ("critical", None, "f9"), ("normal", stale, "f1"), ("normal", fresh, "f2")]
    ordered = sorted(rows, key=lambda r: sort_key(r[0], r[1], "high", r[2]))
    assert [r[2] for r in ordered] == ["f9", "f2", "f1", "f3"]

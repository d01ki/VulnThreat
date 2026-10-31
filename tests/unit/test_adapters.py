"""Import validation (DESIGN §7, §8)."""

import json
from datetime import datetime, timezone

import pytest

from tiw.adapters.claims import parse_claims
from tiw.adapters.common import InputMalformed, InputTooLarge, ParseContext, check_size
from tiw.adapters.feeds import parse_epss, parse_kev
from tiw.adapters.inventory import parse_assets, parse_findings
from tiw.adapters.observations import parse_observations

NOW = datetime(2026, 10, 1, 9, tzinfo=timezone.utc)
SYN = ParseContext(NOW, True)
LIVE = ParseContext(NOW, False)


def test_findings_not_affected_requires_rationale_and_expiry():
    data = (
        "finding_id,asset_id,vulnerability_id,applicability,observed_at,rationale,evidence_ref,reviewer,expires_at\n"
        "f1,a1,DEMO-VULN-001,not_affected,2026-10-01T00:00:00Z,,,,\n"
        "f2,a1,DEMO-VULN-001,not_affected,2026-10-01T00:00:00Z,why,ref,me,2026-11-01T00:00:00Z\n"
    ).encode()
    r = parse_findings(data, SYN)
    assert [x["finding_id"] for x in r.records] == ["f2"]
    assert r.errors[0].line == 2 and "not adopted" in r.errors[0].reason


def test_assets_validation_reports_line_and_field():
    data = (
        "asset_id,name,criticality,internet_exposed,observed_at,expires_at\n"
        "a1,n,extreme,true,2026-10-01T00:00:00Z,\n"
        "a2,n,high,maybe,2026-10-01T00:00:00Z,\n"
        "a3,n,high,true,2026-10-01T00:00:00,\n"
    ).encode()
    r = parse_assets(data, SYN)
    assert [(e.line, e.field) for e in r.errors] == [(2, "criticality"), (3, "internet_exposed"), (4, "observed_at")]


def test_missing_required_column_rejects_file():
    with pytest.raises(InputMalformed):
        parse_assets(b"asset_id,name\na,b\n", SYN)


def test_live_workspace_rejects_synthetic_and_demo_ids_need_synthetic():
    kev = {"dateReleased": "2026-10-01", "synthetic": True, "vulnerabilities": [{"cveID": "DEMO-VULN-001", "dateAdded": "2026-10-01"}]}
    assert parse_kev(json.dumps(kev).encode(), LIVE).errors
    kev2 = {"dateReleased": "2026-10-01", "vulnerabilities": [{"cveID": "DEMO-VULN-001", "dateAdded": "2026-10-01"}]}
    r = parse_kev(json.dumps(kev2).encode(), LIVE)
    assert r.errors and "CVE" in r.errors[0].reason


def test_synthetic_rejects_cve_like_ids():
    kev = {"dateReleased": "2026-10-01", "synthetic": True, "vulnerabilities": [{"cveID": "CVE-2026-12345", "dateAdded": "2026-10-01"}]}
    assert parse_kev(json.dumps(kev).encode(), SYN).errors


def test_live_cve_format_validated():
    kev = {"dateReleased": "2026-10-01", "vulnerabilities": [{"cveID": "CVE-2026-1", "dateAdded": "2026-10-01"}, {"cveID": "CVE-2026-0001", "dateAdded": "2026-10-01"}]}
    r = parse_kev(json.dumps(kev).encode(), LIVE)
    assert len(r.records) == 1 and len(r.errors) == 1


def test_truncated_kev_is_malformed():
    with pytest.raises(InputMalformed):
        parse_kev(b'{"vulnerabilities": [', SYN)


def test_epss_bounds():
    doc = {"data": [{"cve": "DEMO-VULN-001", "epss": "1.5", "percentile": "0.2", "date": "2026-10-01"}], "synthetic": True}
    assert parse_epss(json.dumps(doc).encode(), SYN).errors


def _obs(**kw):
    base = {"schema_version": "1.0", "sensor_id": "s", "observed_at": "2026-10-01T08:00:00Z", "event_type": "scan", "synthetic": True}
    base.update(kw)
    return (json.dumps(base) + "\n").encode()


def test_compromise_requires_reviewer_and_rationale():
    r = parse_observations(_obs(event_type="compromise_confirmed"), SYN)
    assert not r.records and "reviewer" in r.errors[0].reason
    r = parse_observations(_obs(event_type="compromise_confirmed", reviewer="ir", rationale="forensics"), SYN)
    assert r.records


def test_future_observation_quarantined_and_skew_allowed():
    r = parse_observations(_obs(observed_at="2026-10-01T09:04:00Z") + _obs(observed_at="2026-10-01T09:06:00Z", external_event_id="x"), SYN)
    assert [x["quarantine"] is None for x in r.records] == [True, False]


def test_date_only_keeps_day_precision():
    r = parse_observations(_obs(observed_at="2026-09-30"), SYN)
    assert r.records[0]["precision"] == "day"


def test_naive_timestamp_rejected():
    r = parse_observations(_obs(observed_at="2026-09-30T10:00:00"), SYN)
    assert r.errors and "timezone" in r.errors[0].reason


def test_evidence_minimised():
    r = parse_observations(_obs(evidence={"Authorization": "Bearer abc", "body": "GET /", "rule_id": "x"}), SYN)
    ev = r.records[0]["evidence"]
    assert ev["Authorization"] == "[masked]" and ev["body"].startswith("[dropped") and ev["rule_id"] == "x"


def test_error_messages_do_not_echo_secret_values():
    bad = _obs(event_type="nope", evidence={"password": "hunter2"})
    r = parse_observations(bad, SYN)
    assert "hunter2" not in json.dumps([e.as_dict() for e in r.errors])


def test_claims_model_origin_cannot_be_reviewed_and_reviewed_needs_reviewer():
    doc = {"schema_version": "1.0", "synthetic": True, "source": {"name": "x"}, "documents": [{"external_id": "d", "claims": [
        {"claim_key": "a", "subject_id": "DEMO-VULN-001", "predicate": "exploited_in_wild", "value": True, "origin": "model", "review_state": "reviewed", "reviewer": "x", "review_reason": "y"},
        {"claim_key": "b", "subject_id": "DEMO-VULN-001", "predicate": "exploited_in_wild", "value": True, "origin": "primary", "review_state": "reviewed"},
    ]}]}
    r = parse_claims(json.dumps(doc).encode(), SYN)
    assert len(r.errors) == 2 and not r.records[0]["claims"]


def test_size_and_archive_limits():
    with pytest.raises(InputTooLarge):
        check_size(b"x" * (10 * 1024 * 1024 + 1))
    with pytest.raises(InputMalformed):
        check_size(b"PK\x03\x04rest")

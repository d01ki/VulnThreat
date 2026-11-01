"""Production mode: allowlisted feed fetching, relevance scope, onboarding (no real network used)."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from conftest import ASSET_HDR, FINDING_HDR, asset_row, current, imp
from tiw.api.app import create_app
from tiw.services import fetch as F
from tiw.services import queries
from tiw.storage import db

PUBLIC = lambda host: ["93.184.216.34"]  # noqa: E731 - resolver stub returning a public address


def kev_body(cves):
    return json.dumps({"title": "CISA Catalog", "catalogVersion": "2026.10.30", "dateReleased": "2026-10-30T17:00:00.000Z",
                       "count": len(cves), "vulnerabilities": [{"cveID": c, "dateAdded": "2026-10-01", "shortDescription": "x"} for c in cves]}).encode()


def fetcher(handler, resolver=PUBLIC):
    return F.Fetcher(httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False), resolver=resolver, sleep=lambda _: None)


def live_setup(ws):
    imp(ws, "assets", ASSET_HDR + asset_row("web-01", exposed="true"))
    imp(ws, "findings", FINDING_HDR + "f1,web-01,CVE-2021-44228,affected,2026-10-01T00:00:00Z,,,,\n")


def test_fetch_kev_imports_and_raises_decision(live_ws):
    live_setup(live_ws)
    assert current(live_ws)["f1"][:2] == ("remediate", "normal")
    seen = []

    def handler(req):
        seen.append(str(req.url))
        return httpx.Response(200, content=kev_body(["CVE-2021-44228", "CVE-2023-4863"]))

    out = F.fetch_kev(live_ws, fetcher(handler))
    assert out.status == "succeeded" and out.accepted == 2
    assert seen == [F.KEV_URL]
    assert current(live_ws)["f1"][:2] == ("remediate", "urgent")
    assert F.fetch_kev(live_ws, fetcher(handler)).status == "duplicate"


def test_fetch_epss_only_for_tracked_cves(live_ws):
    live_setup(live_ws)
    queried = []

    def handler(req):
        queried.append(req.url.params["cve"])
        return httpx.Response(200, json={"status": "OK", "data": [{"cve": "CVE-2021-44228", "epss": "0.9", "percentile": "0.99", "date": "2026-10-01"}]})

    out = F.fetch_epss(live_ws, fetcher(handler))
    assert out.status == "succeeded" and queried == ["CVE-2021-44228"]


def test_failed_fetch_is_recorded_and_keeps_evidence(live_ws):
    live_setup(live_ws)
    F.fetch_kev(live_ws, fetcher(lambda r: httpx.Response(200, content=kev_body(["CVE-2021-44228"]))))
    before = current(live_ws)["f1"]
    out = F.fetch_kev(live_ws, fetcher(lambda r: httpx.Response(503)))
    assert out.status == "failed" and "503" in out.errors[0]["reason"]
    assert current(live_ws)["f1"] == before
    with db.session_scope(live_ws) as s:
        kev = [h for h in queries.source_health(s) if h["kind"] == "kev"][0]
        assert kev["status"] == "failed"


def test_redirect_to_other_host_refused(live_ws):
    out = F.fetch_kev(live_ws, fetcher(lambda r: httpx.Response(302, headers={"location": "https://evil.example/kev.json"})))
    assert out.status == "failed" and "allowlist" in out.errors[0]["reason"]


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "192.168.1.1"])
def test_private_resolution_refused(live_ws, addr):
    out = F.fetch_kev(live_ws, fetcher(lambda r: httpx.Response(200, content=b"{}"), resolver=lambda h: [addr]))
    assert out.status == "failed" and "non-public" in out.errors[0]["reason"]


def test_url_checks():
    with pytest.raises(F.FetchError):
        F.check_url("http://www.cisa.gov/x", PUBLIC)
    with pytest.raises(F.FetchError):
        F.check_url("https://www.cisa.gov:8443/x", PUBLIC)
    with pytest.raises(F.FetchError):
        F.check_url("https://cisa.gov.evil.example/x", PUBLIC)
    F.check_url(F.KEV_URL, PUBLIC)


def test_oversized_response_refused(live_ws, monkeypatch):
    monkeypatch.setattr(F, "MAX_FILE_BYTES", 100)
    out = F.fetch_kev(live_ws, fetcher(lambda r: httpx.Response(200, content=b"x" * 500)))
    assert out.status == "failed" and "exceeds" in out.errors[0]["reason"]


def test_fetch_refused_in_synthetic_workspace(ws):
    with pytest.raises(F.FetchError):
        F.fetch_kev(ws, fetcher(lambda r: httpx.Response(200)))


def test_epss_needs_tracked_cves(live_ws):
    with pytest.raises(F.FetchError):
        F.fetch_epss(live_ws, fetcher(lambda r: httpx.Response(200)))


def test_scope_hides_unrelated_kev_entries(live_ws):
    live_setup(live_ws)
    F.fetch_kev(live_ws, fetcher(lambda r: httpx.Response(200, content=kev_body(["CVE-2021-44228", "CVE-2023-4863", "CVE-2024-0001"]))))
    with db.session_scope(live_ws) as s:
        mine = queries.threats(s, scope="mine")["items"]
        everything = queries.threats(s, scope="all")["items"]
        assert [t["id"] for t in mine] == ["CVE-2021-44228"]
        assert len(everything) == 3
        h = queries.home(s, "7d", "mine")
        assert h["kpis"][0]["value"] == 1 and h["evidence_total"] == 1
        assert queries.home(s, "7d", "all")["kpis"][0]["value"] == 3


def test_onboarding_and_templates(live_ws):
    c = TestClient(create_app(live_ws, extra_hosts=("testserver",)))
    r = c.get("/")
    assert "Get started" in r.text and "0 of 5 done" in r.text and "Synthetic workspace" not in r.text
    assert c.get("/guide").status_code == 200
    start = c.get("/start")
    assert start.status_code == 200 and "Which fix breaks the most attack paths?" in start.text
    assert 'aria-label="Workflow"' in start.text and 'href="/remediation-lab"' in start.text
    for kind in ("assets", "findings", "observations"):
        body = c.get(f"/import/template/{kind}").content
        out = imp(live_ws, kind, body, dry_run=True)
        assert out.status in ("validated", "failed")
    assert imp(live_ws, "assets", c.get("/import/template/assets").content, dry_run=True).status == "validated"
    assert c.get("/import/template/../../tiw.db").status_code == 404
    live_setup(live_ws)
    r = c.get("/")
    assert "2 of 5 done" in r.text
    assert "Fetch KEV" in c.get("/sources").text


def test_ui_fetch_requires_csrf(live_ws):
    c = TestClient(create_app(live_ws, extra_hosts=("testserver",)))
    assert c.post("/sources/fetch/kev").status_code == 403


def test_no_intel_jargon_in_ui(live_ws):
    live_setup(live_ws)
    c = TestClient(create_app(live_ws, extra_hosts=("testserver",)))
    for p in ["/", "/start", "/threats?scope=all", "/guide", "/sources", "/assets"]:
        assert "intel" not in c.get(p).text.lower().replace("intelligence-", "")


def test_loopback_any_port_allowed_but_foreign_host_denied(live_ws):
    c = TestClient(create_app(live_ws))
    assert c.get("/", headers={"host": "127.0.0.1:9000"}).status_code == 200
    assert c.get("/", headers={"host": "localhost:12345"}).status_code == 200
    assert c.get("/", headers={"host": "attacker.example:8787"}).status_code == 403
    assert c.get("/", headers={"host": "127.0.0.1.attacker.example"}).status_code == 403

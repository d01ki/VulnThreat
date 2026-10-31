"""UI/API boundaries: escaping, CSP, CSRF, Host/Origin, token, path handling, error envelope (DESIGN §14, §15)."""

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from conftest import counts
from tiw.api.app import create_app
from tiw.services import demo
from tiw.storage import db
from tiw.storage.models import Decision


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    w = db.resolve_workspace(tmp_path_factory.mktemp("web") / "demo")
    demo.seed(w, "all")
    demo.advance(w, 4)
    client = TestClient(create_app(w, extra_hosts=("testserver",)))
    token = w.token_path.read_text().strip()
    yield w, client, token
    db.dispose_engine(w)


def csrf(client, path="/import"):
    r = client.get(path)
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    return m.group(1)


PAGES = ["/", "/?period=24h", "/?period=30d", "/?period=all", "/threats", "/threats?status=reported", "/threats?q=001&changed=1",
         "/threats/DEMO-VULN-001", "/threats/DEMO-VULN-002?tab=observations", "/threats/DEMO-VULN-003?tab=assets",
         "/threats/DEMO-VULN-004?tab=decisions", "/observations", "/observations?event_type=scan", "/assets", "/assets?urgency=urgent",
         "/investigations", "/investigations?show=all", "/sources", "/import", "/settings"]


@pytest.mark.parametrize("path", PAGES)
def test_pages_render(env, path):
    _, c, _ = env
    r = c.get(path)
    assert r.status_code == 200
    assert "Synthetic workspace" in r.text
    assert "style=\"" not in r.text  # CSP forbids inline styles
    assert "<script>" not in r.text.replace('<script src="/static/app.js" defer></script>', "")


def test_every_decision_diff_renders(env):
    w, c, _ = env
    with db.session_scope(w) as s:
        ids = [d.id for d in s.execute(select(Decision)).scalars()]
    for i in ids:
        assert c.get(f"/decisions/{i}").status_code == 200


def test_untrusted_html_is_escaped(env):
    _, c, _ = env
    r = c.get("/threats/DEMO-VULN-001")
    assert "&lt;script&gt;alert(&#39;not executed&#39;)&lt;/script&gt;" in r.text
    r = c.get("/threats/DEMO-VULN-002")
    assert "<img src=x" not in r.text


def test_security_headers(env):
    _, c, _ = env
    r = c.get("/")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert "access-control-allow-origin" not in r.headers


def test_bad_host_rejected(env):
    _, c, _ = env
    assert c.get("/", headers={"host": "evil.example"}).status_code == 403


def test_cross_origin_post_rejected(env):
    _, c, _ = env
    tok = csrf(c)
    r = c.post("/settings", data={"csrf_token": tok, "timezone_name": "UTC"}, headers={"origin": "http://evil.example"})
    assert r.status_code == 403


def test_csrf_required_for_ui_changes(env):
    w, c, _ = env
    r = c.post("/settings", data={"timezone_name": "UTC"})
    assert r.status_code == 403
    tok = csrf(c, "/settings")
    r = c.post("/settings", data={"csrf_token": tok, "timezone_name": "Asia/Tokyo"}, follow_redirects=False)
    assert r.status_code == 303


def test_import_flow_validate_then_commit(env):
    w, c, _ = env
    tok = csrf(c)
    body = b"asset_id,name,criticality,internet_exposed,observed_at,expires_at,synthetic\nasset-new,n,normal,false,2026-10-01T00:00:00Z,,true\n"
    before = counts(w)
    r = c.post("/import/validate", data={"csrf_token": tok, "kind": "assets"}, files={"file": ("../../evil.csv", body, "text/csv")})
    assert r.status_code == 200 and "Validation passed" in r.text
    assert counts(w)["asset_revisions"] == before["asset_revisions"]  # nothing written yet
    sha = re.search(r'name="sha" value="([0-9a-f]{64})"', r.text).group(1)
    r = c.post("/import/commit", data={"csrf_token": tok, "kind": "assets", "sha": sha})
    assert r.status_code == 200 and "Imported." in r.text
    assert not (w.data_dir.parent / "evil.csv").exists()


def test_import_validation_errors_shown(env):
    _, c, _ = env
    tok = csrf(c)
    body = b"asset_id,name,criticality,internet_exposed,observed_at,expires_at\na,n,bogus,true,2026-10-01T00:00:00Z,\n"
    r = c.post("/import/validate", data={"csrf_token": tok, "kind": "assets"}, files={"file": ("x.csv", body)})
    assert r.status_code == 422 and "criticality" in r.text and "Nothing was written" in r.text


def test_commit_rejects_path_traversal(env):
    _, c, _ = env
    tok = csrf(c)
    r = c.post("/import/commit", data={"csrf_token": tok, "kind": "assets", "sha": "../../tiw.db"})
    assert r.status_code == 422


def test_static_path_traversal(env):
    _, c, _ = env
    assert c.get("/static/..%2f..%2fstorage%2fdb.py").status_code == 404


def test_api_requires_token_and_uses_error_envelope(env):
    _, c, token = env
    r = c.get("/api/v1/threats")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthorized"
    r = c.get("/api/v1/threats/NOPE", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 404 and set(r.json()["error"]) == {"code", "message", "details"}
    r = c.post("/api/v1/claims/x/reviews", json={"state": "reviewed"}, headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_input"


def test_api_import_errors_and_size(env):
    _, c, token = env
    h = {"Authorization": f"Bearer {token}"}
    r = c.post("/api/v1/imports/kev", files={"file": ("k.json", b"{bad")}, headers=h)
    assert r.status_code == 422
    r = c.post("/api/v1/imports/kev", files={"file": ("k.json", b" " * (10 * 1024 * 1024 + 1))}, headers=h)
    assert r.status_code == 413
    r = c.post("/api/v1/imports/nope", files={"file": ("k.json", b"{}")}, headers=h)
    assert r.status_code == 404


def test_api_threat_pagination_and_diff(env):
    w, c, token = env
    h = {"Authorization": f"Bearer {token}"}
    r = c.get("/api/v1/threats?limit=2", headers=h).json()
    assert len(r["items"]) == 2 and r["next_cursor"]
    r2 = c.get(f"/api/v1/threats?limit=2&cursor={r['next_cursor']}", headers=h).json()
    assert r2["items"][0]["id"] > r["items"][-1]["id"]
    with db.session_scope(w) as s:
        d = s.execute(select(Decision).where(Decision.previous_id.is_not(None))).scalars().first()
    diff = c.get(f"/api/v1/decisions/{d.id}/diff", headers=h).json()
    assert diff["why"] and diff["previous"]["id"] == d.previous_id


def test_api_export_and_gets_do_not_modify(env):
    w, c, token = env
    h = {"Authorization": f"Bearer {token}"}
    before = counts(w)
    for p in ["/api/v1/threats", "/api/v1/threats/DEMO-VULN-001", "/api/v1/threats/DEMO-VULN-001/timeline", "/api/v1/investigations", "/api/v1/health/sources"]:
        assert c.get(p, headers=h).status_code == 200
    for p in PAGES:
        c.get(p)
    assert counts(w) == before
    r = c.post("/api/v1/exports", json={"vulnerability_id": "DEMO-VULN-001", "format": "markdown"}, headers=h)
    assert r.status_code == 201
    md = r.json()["content"]
    assert "SYNTHETIC DATA" in md and "<script>" not in md


def test_api_review_requires_reason(env):
    w, c, token = env
    h = {"Authorization": f"Bearer {token}"}
    det = c.get("/api/v1/threats/DEMO-VULN-002", headers=h).json()
    cid = next(e["id"] for e in det["evidence"] if e["origin"] == "secondary")
    r = c.post(f"/api/v1/claims/{cid}/reviews", json={"reviewer": "me", "state": "rejected", "reason": ""}, headers=h)
    assert r.status_code == 422

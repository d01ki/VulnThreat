from __future__ import annotations

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("build_static_demo", Path(__file__).resolve().parents[2] / "scripts" / "build_static_demo.py")
bsd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bsd)


def test_norm_key_drops_empty_and_sorts():
    assert bsd.norm_key("/robustness", "withdraw=&objective=weighted-paths&budget=2") == "/robustness?budget=2&objective=weighted-paths"
    assert bsd.norm_key("/x", "notice=saved") == "/x"


def test_rewrite_links_forms_and_unknown_targets():
    mapping = {"/attack-paths": "attack-paths.html", "/threats/V?tab=assets": "threats__V--abc.html"}
    body = (
        '<main class="main" id="content">'
        '<a href="/attack-paths#paths">a</a><a href="/import">b</a><a href="?tab=assets">c</a>'
        '<use href="/static/icons.svg#i-x"></use>'
        '<form method="get" action="/remediation-lab"></form>'
        '<form method="post" action="/demo/attack-path/advance"></form>'
        '<form method="post" action="/import/drafts"></form>'
        '<script src="../static/app.js" defer></script>'
    )
    out = bsd.rewrite(body, mapping, 1, "/threats/V")
    assert 'href="attack-paths.html#paths"' in out
    assert 'href="unavailable.html"' in out
    assert 'href="threats__V--abc.html"' in out
    assert 'href="../static/icons.svg#i-x"' in out
    assert 'data-static-form="/remediation-lab"' in out and 'action="#"' in out
    assert 'data-static-goto="../step2/remediation-lab.html"' in out
    assert 'novalidate data-static-goto="unavailable.html"' in out
    assert "Static snapshot (step 1 of 2)" in out and "static-demo.js" in out

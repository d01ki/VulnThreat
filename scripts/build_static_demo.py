"""Build a static, read-only snapshot of the synthetic attack-path demo (for GitHub Pages).

Usage:  uv run python scripts/build_static_demo.py --out site [--check]

How it works
- Seeds the synthetic ``attack-path`` demo in a temporary workspace, renders pages with the real
  app (FastAPI TestClient, no network), then advances to step 2 and renders again.
- Pages are discovered by following links (bounded) plus explicit enumeration of the GET form
  variants (Remediation Lab budgets/objectives/baselines, single-factor what-ifs).
- All links are rewritten to relative files. GET forms are resolved in the browser through a
  manifest; POST forms are disabled except the demo "Reset" / "Step 2" buttons, which switch
  between the step-1 and step-2 snapshots. Nothing in the snapshot can change any data.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import shutil
import tempfile
from collections import deque
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

ROOT = Path(__file__).resolve().parents[1]
STATIC_SRC = ROOT / "src" / "tiw" / "static"
HOST = "http://127.0.0.1:8787"
REPO_URL = "https://github.com/d01ki/VulnThreat"
ATTR_RE = re.compile(r'(\s(?:href|src))="([^"]*)"')
FORM_RE = re.compile(r'<form\b([^>]*)>', re.I)
SKIP_PREFIXES = ("/api/", "/static/", "/demo/")
CAP_PER_PATH = {"/attack-paths": 260, "/threats": 40, "/observations": 20, "/assets": 30}
DEFAULT_CAP = 60
MAX_PAGES = 1200


def norm_key(path: str, query: str) -> str:
    """Canonical page key: decoded params, empty values dropped, sorted. Mirrored in static-demo.js."""
    params = sorted((k, v) for k, v in parse_qsl(query, keep_blank_values=True) if v != "" and k not in ("notice",))
    return path + ("?" + "&".join(f"{k}={v}" for k, v in params) if params else "")


def file_for(key: str) -> str:
    path, _, query = key.partition("?")
    slug = path.strip("/").replace("/", "__") or "home"
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", slug)[:80]
    if query:
        slug += "--" + hashlib.sha1(query.encode()).hexdigest()[:10]
    return slug


def form_variants(client) -> list[str]:  # noqa: ANN001
    """Explicit GET-form submissions to pre-render."""
    out = []
    lab = client.get("/remediation-lab").text
    baselines = sorted(set(re.findall(r'<option value="([a-z_]+)"[^>]*>\1</option>', lab)) & {
        "cvss_desc", "epss_desc", "kev_first", "criticality_exposure", "graph_only"})
    for b in range(0, 6):
        for obj in ("weighted-paths", "reachable-targets"):
            for cmp in baselines:
                out.append(f"/remediation-lab?budget={b}&objective={obj}&compare={cmp}")
    rob = client.get("/robustness").text
    for name in ("withdraw", "unknown_edge", "unknown_app"):
        block = re.search(rf'<select name="{name}">(.*?)</select>', rob, re.S)
        for v in re.findall(r'<option value="([^"]+)"', block.group(1) if block else ""):
            out.append(f"/robustness?budget=2&objective=weighted-paths&{name}={html.unescape(v)}")
    out.append("/robustness?budget=2&objective=weighted-paths")
    return out


def crawl(client, seeds: list[str]) -> dict[str, tuple[str, bytes]]:  # noqa: ANN001
    """Return key -> (content type, body) for every reachable GET page (bounded)."""
    pages: dict[str, tuple[str, bytes]] = {}
    per_path: dict[str, int] = {}
    q = deque(seeds)
    seen: set[str] = set()
    while q and len(pages) < MAX_PAGES:
        raw = q.popleft()
        parts = urlsplit(raw)
        key = norm_key(parts.path, parts.query)
        if key in seen or parts.path.startswith(SKIP_PREFIXES):
            continue
        seen.add(key)
        cap = CAP_PER_PATH.get(parts.path, DEFAULT_CAP)
        if per_path.get(parts.path, 0) >= cap:
            continue
        r = client.get(key)
        if r.status_code != 200:
            continue
        per_path[parts.path] = per_path.get(parts.path, 0) + 1
        ctype = r.headers.get("content-type", "text/html").split(";")[0]
        pages[key] = (ctype, r.content)
        if ctype == "text/html":
            for _, val in ATTR_RE.findall(r.text):
                v = html.unescape(val)
                if v.startswith("?"):
                    v = parts.path + v
                if v.startswith("/") and not v.startswith("//"):
                    q.append(v.split("#", 1)[0])
    return pages


def ext_for(ctype: str) -> str:
    return {"text/html": ".html", "application/json": ".json", "text/markdown": ".md", "text/csv": ".csv"}.get(ctype, ".txt")


BANNER = (
    '<div class="callout warn static-banner" role="note"><span><strong>Static snapshot (step {step} of 2)</strong> of the synthetic '
    'attack-path demo. Every page and option shown was pre-rendered from the real tool; nothing here can change data. '
    'Imports, editing and live analysis need the local tool: <a href="{repo}">{repo}</a>'
    '{switch}</span></div>'
)


def rewrite(body: str, mapping: dict[str, str], step: int, page_path: str = "/") -> str:
    def attr(m: re.Match[str]) -> str:
        name, val = m.group(1), html.unescape(m.group(2))
        if val.startswith("?"):
            val = page_path + val
        if not val.startswith("/") or val.startswith("//"):
            return m.group(0)
        path, _, frag = val.partition("#")
        if path.startswith("/static/"):
            new = ".." + path
        else:
            p = urlsplit(path)
            key = norm_key(p.path, p.query)
            new = mapping.get(key, "unavailable.html")
        return f'{name}="{html.escape(new + ("#" + frag if frag else ""), quote=True)}"'

    def form(m: re.Match[str]) -> str:
        attrs = m.group(1)
        action = html.unescape((re.search(r'action="([^"]*)"', attrs) or [None, ""])[1])
        method = (re.search(r'method="([^"]*)"', attrs, re.I) or [None, "get"])[1].lower()
        attrs = re.sub(r'\saction="[^"]*"', ' action="#"', attrs)
        if method == "get":
            return f'<form{attrs} data-static-form="{html.escape(action, quote=True)}">'
        if action == "/demo/attack-path/reset":
            goto = "../step1/attack-paths.html"
        elif action == "/demo/attack-path/advance":
            goto = "../step2/remediation-lab.html"
        else:
            goto = "unavailable.html"
        return f'<form{attrs} novalidate data-static-goto="{goto}">'

    body = FORM_RE.sub(form, body)
    body = ATTR_RE.sub(attr, body)
    other = 2 if step == 1 else 1
    switch = f' · <a href="../step{other}/attack-paths.html">Go to step {other}</a>'
    body = body.replace('<main class="main" id="content">',
                        '<main class="main" id="content">' + BANNER.format(step=step, repo=REPO_URL, switch=switch), 1)
    body = body.replace('<script src="../static/app.js" defer></script>',
                        '<script src="manifest.js" defer></script><script src="../static/app.js" defer></script>'
                        '<script src="../static/static-demo.js" defer></script>', 1)
    return body


STATIC_JS = r"""// Static-snapshot behaviour for the GitHub Pages demo (no server).
(function () {
  "use strict";
  var M = window.TIW_STATIC || {};
  function key(path, params) {
    var pairs = [];
    params.forEach(function (v, k) { if (v !== "" && k !== "notice") pairs.push([k, v]); });
    pairs.sort(function (a, b) { return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0); });
    return path + (pairs.length ? "?" + pairs.map(function (p) { return p[0] + "=" + p[1]; }).join("&") : "");
  }
  function notice(form, text) {
    var n = form.querySelector(".static-note");
    if (!n) { n = document.createElement("p"); n.className = "static-note small"; n.setAttribute("role", "status"); form.appendChild(n); }
    n.textContent = text;
  }
  document.querySelectorAll("form[data-static-form]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var k = key(form.getAttribute("data-static-form"), new URLSearchParams(new FormData(form)));
      if (M[k]) { window.location.href = M[k]; return; }
      notice(form, "This combination was not pre-rendered in the static snapshot. Run the tool locally to try any value.");
    });
  });
  document.querySelectorAll("form[data-static-goto]").forEach(function (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      window.location.href = form.getAttribute("data-static-goto");
    });
  });
})();
"""

UNAVAILABLE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not available in the static demo</title><link rel="stylesheet" href="../static/app.css"></head>
<body><main class="main" style="max-width:720px;margin:40px auto"><h1>Not available in the static snapshot</h1>
<p class="lede">This action needs the running tool (imports, editing, recording runs, or an option that was not pre-rendered).</p>
<p data-x="mt4">Run it locally in one minute: <code>uv sync</code>, <code>uv run tiw demo seed --scenario attack-path</code>,
<code>uv run tiw serve --data-dir .tiw-demo</code> — see <a href="REPO">REPO</a>.</p>
<p data-x="mt4"><a href="attack-paths.html">Back to Attack Paths</a></p></main></body></html>
""".replace("REPO", REPO_URL)

INDEX = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="0; url=step1/start.html"><title>VulnThreat demo</title></head>
<body><p><a href="step1/start.html">Open the static VulnThreat demo</a> · <a href="REPO">Source code</a></p></body></html>
""".replace("REPO", REPO_URL)


def build(out: Path) -> dict[str, int]:
    from fastapi.testclient import TestClient

    from tiw.api.app import create_app
    from tiw.services import demo
    from tiw.storage import db

    if out.exists():
        shutil.rmtree(out)
    (out / "static").mkdir(parents=True)
    for f in STATIC_SRC.iterdir():
        if f.is_file():
            shutil.copy2(f, out / "static" / f.name)
    (out / "static" / "static-demo.js").write_text(STATIC_JS, encoding="utf-8", newline="\n")
    (out / "static" / "app.css").write_text((STATIC_SRC / "app.css").read_text(encoding="utf-8")
                                            + "\n.static-banner{margin-bottom:var(--space-5)}.static-note{color:var(--warning);margin-top:8px}\n",
                                            encoding="utf-8", newline="\n")
    (out / "index.html").write_text(INDEX, encoding="utf-8", newline="\n")
    (out / ".nojekyll").write_text("", encoding="utf-8")
    stats = {}
    with tempfile.TemporaryDirectory(prefix="tiw-static-") as tmp:
        ws = db.resolve_workspace(Path(tmp) / "demo")
        demo.seed(ws, "attack-path")
        client = TestClient(create_app(ws), base_url=HOST)
        for step in (1, 2):
            if step == 2:
                demo.advance(ws, 2, "attack-path")
            seeds = ["/start", "/attack-paths", "/topology", "/remediation-lab", "/robustness", "/analysis-runs", "/", "/threats",
                     "/assets", "/investigations", "/observations", "/sources", "/import", "/guide", "/settings"]
            seeds += form_variants(client)
            pages = crawl(client, seeds)
            mapping = {k: file_for(k) + ext_for(ct) for k, (ct, _) in pages.items()}
            d = out / f"step{step}"
            d.mkdir()
            for k, (ct, body) in pages.items():
                target = d / mapping[k]
                if ct == "text/html":
                    target.write_text(rewrite(body.decode("utf-8"), mapping, step, k.partition("?")[0]), encoding="utf-8", newline="\n")
                else:
                    target.write_bytes(body)
            (d / "manifest.js").write_text("window.TIW_STATIC = " + json.dumps(mapping, sort_keys=True) + ";\n", encoding="utf-8", newline="\n")
            (d / "unavailable.html").write_text(UNAVAILABLE, encoding="utf-8", newline="\n")
            stats[f"step{step}"] = len(pages)
        db.dispose_engine(ws)
    return stats


def check(out: Path) -> list[str]:
    """Every relative href/src in every HTML file must resolve to an existing file."""
    broken = []
    for f in out.rglob("*.html"):
        for _, val in ATTR_RE.findall(f.read_text(encoding="utf-8")):
            v = html.unescape(val)
            if v.startswith(("http://", "https://", "#", "mailto:")) or not v:
                continue
            target = (f.parent / v.split("#", 1)[0]).resolve()
            if not target.exists():
                broken.append(f"{f.relative_to(out)} -> {v}")
    return broken


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="site")
    ap.add_argument("--check", action="store_true", help="verify that every internal link resolves")
    a = ap.parse_args()
    out = Path(a.out).resolve()
    stats = build(out)
    print(f"built {out}: " + ", ".join(f"{k}={v} pages" for k, v in stats.items()))
    if a.check:
        broken = check(out)
        print(f"link check: {len(broken)} broken")
        for b in broken[:20]:
            print("  " + b)
        if broken:
            raise SystemExit(1)


if __name__ == "__main__":
    main()

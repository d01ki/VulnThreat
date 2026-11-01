"""JSON / Markdown export of recorded analysis runs (graph, optimize, robustness).

Every export carries the evidence snapshot hash, algorithm version, objective and tie-breaking,
assumptions, used/excluded paths, scenario set, selected portfolio and per-action reasons.
``normalized`` output contains only the deterministic result (no run ids or wall-clock times),
so repeating the demo yields byte-identical normalized JSON.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from tiw.services.export import md_escape
from tiw.services.triage import run_with_diff
from tiw.storage import db

ANALYSIS_EXPORT_VERSION = "analysis-export-1"


def analysis_document(ws: db.Workspace, run_id: str) -> dict[str, Any]:
    with db.session_scope(ws) as s:
        doc = run_with_diff(s, run_id)
    if doc is None:
        raise LookupError(f"unknown analysis run {run_id}")
    return {"export_version": ANALYSIS_EXPORT_VERSION, **doc}


def normalized_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False)


def _paths_table(L: list[str], rows: list[dict[str, Any]]) -> None:
    if not rows:
        L.append("None.")
        return
    L.append("| Path | Objective | Status | Counted | Route |")
    L.append("|---|---|---|---|---|")
    for p in rows:
        L.append(f"| {md_escape(p['id'])} | {md_escape(p['objective_id'])} | {md_escape(p['status'])} | {'yes' if p['counted'] else 'no'} | {md_escape(' > '.join(p['nodes']))} |")


def to_markdown(doc: dict[str, Any]) -> str:
    run, r = doc["run"], doc["result"]
    L: list[str] = [f"# Analysis run {md_escape(run['id'])} ({md_escape(run['kind'])})", ""]
    if r.get("synthetic"):
        L += ["> **SYNTHETIC DATA**: generated from demo fixtures; demonstrates behaviour only, not real-world effectiveness.", ""]
    L.append(f"- Recorded: {md_escape(run['created_at'])} by {md_escape(run['actor'])} ({doc['export_version']})")
    L.append(f"- Evidence snapshot hash: `{md_escape(r.get('evidence_hash', ''))}`")
    L.append(f"- Result hash: `{md_escape(run['result_hash'])}`")
    L.append(f"- Algorithm / policy version: {md_escape(r.get('algorithm_version', ''))}")
    L.append(f"- Evaluation clock: {md_escape(r.get('clock', ''))}")
    for k, v in sorted((r.get("inputs") or {}).items()):
        L.append(f"- Input {md_escape(k)}: seq {v.get('seq')} `{md_escape(v.get('content_hash', ''))[:16]}`")
    if r.get("objective"):
        L += ["", "## Objective", "", f"- **{md_escape(r['objective']['name'])}**: {md_escape(r['objective']['semantics'])}",
              f"- Tie-breaking: {md_escape(r['objective']['tie_breaking'])}"]
    if r.get("params"):
        L.append(f"- Parameters: {md_escape(json.dumps(r['params'], sort_keys=True))}")
    if r.get("kind") == "optimize":
        sel = r["selected"]
        L += ["", "## Selected portfolio", "",
              f"- Actions: **{md_escape(' + '.join(sel['actions']) or 'no action')}** (effort {sel['effort']} {md_escape(r.get('cost_unit', ''))})",
              f"- Objective value: {sel['objective_value']} (before any action: {r['before']['objective_value']})",
              f"- Method: {md_escape(r['method'])} ({'exact optimum' if r['exact'] else 'approximate, optimality gap unknown'}; {r['evaluated_portfolios']} portfolios evaluated, {r['feasible_portfolios']} feasible)",
              f"- Re-simulation consistent: {r['resimulation']['consistent']}", "", "### Reasons", ""]
        for x in r["reasons"]:
            L.append(f"- {md_escape(x['text'])}")
        if r["ties"]:
            L += ["", "### Ties", ""] + [f"- {md_escape(' + '.join(t['actions']))} (value {t['objective_value']}, effort {t['effort']})" for t in r["ties"]]
        L += ["", "## Equal-budget baselines", "", "| Baseline | Actions | Objective | Notes |", "|---|---|---|---|"]
        for b in r["baselines"]:
            L.append(f"| {md_escape(b['name'])} | {md_escape(' + '.join(b['actions']) or 'none')} | {b['objective_value']} | {md_escape('; '.join(b['notes']) or '')} |")
        L += ["", "## Paths used by the objective", ""]
        _paths_table(L, [p for p in r["paths"] if p["counted"]])
        L += ["", "## Paths excluded from the objective", ""]
        _paths_table(L, r["excluded_paths"])
        L += ["", "## Surviving paths after the portfolio", ""]
        _paths_table(L, r["surviving_paths"])
    elif r.get("kind") == "robustness":
        L += ["", "## Scenario set", "", f"- {md_escape(r['disclaimer'])}", ""]
        for p in r["summary"]["portfolios"]:
            L.append(f"- {md_escape(p['text'])}")
        L += ["", "| Scenario | Kind | Selected | Objective | Same as recorded |", "|---|---|---|---|---|"]
        for x in r["scenarios"]:
            L.append(f"| {md_escape(x['scenario']['id'])} | {md_escape(x['scenario']['kind'])} | {md_escape(' + '.join(x['selected']) or 'none')} | {x['objective_value']} | {'yes' if x['same_portfolio'] else '**no**'} |")
        L += ["", "### Flip explanations", ""]
        for x in r["scenarios"]:
            if not x["same_portfolio"]:
                L.append(f"- **{md_escape(x['scenario']['id'])}**")
                for reason in x["flip_reasons"]:
                    L.append(f"  - {md_escape(reason)}")
        if r["uncovered"]:
            L += ["", "### Not covered", ""] + [f"- {md_escape(u)}" for u in r["uncovered"]]
    else:
        L += ["", "## Paths", ""]
        _paths_table(L, r.get("paths", []))
    if doc.get("diff"):
        L += ["", "## Change since the previous run", ""] + [f"- {md_escape(w)}" for w in doc["diff"].get("why", [])]
    L += ["", "## Assumptions and limitations", ""] + [f"- {md_escape(a)}" for a in r.get("assumptions", [])]
    L.append("")
    return "\n".join(L)


def export_analysis_run(ws: db.Workspace, run_id: str, fmt: str, *, normalized: bool = False) -> tuple[str, str]:
    if fmt not in ("json", "markdown"):
        raise ValueError("format must be json or markdown")
    doc = analysis_document(ws, run_id)
    if fmt == "json":
        content = normalized_json(doc["result"]) if normalized else json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False)
    else:
        content = to_markdown(doc)
    digest = hashlib.sha256(content.encode()).hexdigest()[:12]
    safe = re.sub(r"[^A-Za-z0-9-]", "_", run_id)[:40]
    ws.exports_dir.mkdir(parents=True, exist_ok=True)
    path = ws.exports_dir / f"analysis-{safe}-{digest}.{'json' if fmt == 'json' else 'md'}"
    path.write_text(content, encoding="utf-8")
    with db.session_scope(ws) as s:
        from tiw.services.ingest import audit

        audit(s, "export", "export", "analysis_run", run_id, {"format": fmt, "file": path.name})
    return str(path), content

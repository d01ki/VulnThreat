"""`tiw graph ...` and `tiw triage ...`: evidence-grounded attack paths and counterfactual triage."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Optional

import typer

from tiw.storage import db

graph_app = typer.Typer(help="Evidence-grounded attack graph (model paths, not observed attacks).", no_args_is_help=True)
triage_app = typer.Typer(help="Counterfactual patch triage and decision robustness.", no_args_is_help=True)
draft_app = typer.Typer(help="Generate editable draft inputs from imported assets and findings.", no_args_is_help=True)
DataDir = typer.Option(None, "--data-dir", help="Workspace directory (default: $TIW_DATA_DIR or ./.tiw)")


def _ws(data_dir: Optional[Path]) -> db.Workspace:
    ws = db.resolve_workspace(data_dir)
    try:
        db.ensure_schema_present(ws)
    except FileNotFoundError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    return ws


def _echo_json(obj: object) -> None:
    typer.echo(json.dumps(obj, indent=2, default=str, ensure_ascii=False, sort_keys=True))


def _analysis(fn: Callable[..., Any], **kw: Any) -> Any:
    from tiw.services.graph import GraphNotReady
    from tiw.services.triage import AnalysisError

    try:
        return fn(**kw)
    except (GraphNotReady, AnalysisError) as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None


def resolve_run(ws: db.Workspace, ref: str) -> str:
    """Accept a run id or latest-graph / latest-optimize / latest-robustness."""
    from tiw.services import triage

    if ref.startswith("latest-"):
        kind = ref[len("latest-"):]
        with db.session_scope(ws) as s:
            run = next((r for r in triage.latest_runs(s, 500) if r.kind == kind), None)
        if run is None:
            raise LookupError(f"no recorded {kind} run")
        return run.id
    return ref


@graph_app.command("build")
def graph_build(
    data_dir: Optional[Path] = DataDir,
    as_json: bool = typer.Option(False, "--json", help="Print the normalized result as JSON"),
    record: bool = typer.Option(True, "--record/--no-record", help="Append an analysis run (idempotent)"),
) -> None:
    """Build the attack graph and enumerate bounded model paths to security objectives."""
    from tiw.services import triage

    ws = _ws(data_dir)
    with db.session_scope(ws) as s:
        payload = _analysis(triage.analyze_graph, s=s)
    r = payload["result"]
    run = created = None
    if record:
        run, created, _ = triage.record(ws, "graph", "graph", payload, actor="cli")
    if as_json:
        _echo_json(r)
        return
    c = r["counts"]
    typer.echo(f"nodes={c['nodes']} edges={c['edges']} findings={c['findings']} objectives={c['objectives']} "
               f"paths={c['paths']} counted={c['counted_paths']} by_status={c['by_status']}")
    trunc = f" ({'; '.join(r['truncation_reasons'])})" if r["truncated"] else ""
    typer.echo(f"evidence hash {r['evidence_hash'][:16]}  truncated={r['truncated']}{trunc}")
    for p in r["paths"]:
        flag = "counted " if p["counted"] else "excluded"
        typer.echo(f"  {p['id']}  {p['objective_id']:<12} {p['status']:<22} {flag}  {' > '.join(p['nodes'])}")
    if run is not None:
        typer.echo(f"analysis run {run.id} ({'recorded' if created else 'unchanged; existing run reused'})")
    typer.echo("Model paths only: not observed attacks and not proof of reachability or compromise.")


@graph_app.command("explain")
def graph_explain(
    path_id: str = typer.Option(..., "--path-id", help="PATH-XXXXXXXXXX, or an ordinal such as PATH-001"),
    data_dir: Optional[Path] = DataDir,
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """Show every hop, fact, evidence item and unknown for one path."""
    from tiw.services import triage

    ws = _ws(data_dir)
    with db.session_scope(ws) as s:
        x = _analysis(triage.explain_path, s=s, path_id=path_id)
    if x is None:
        typer.secho(f"unknown path {path_id}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    if as_json:
        _echo_json(x)
        return
    p = x["path"]
    typer.echo(f"{p['id']} -> {p['objective_id']} ({p['objective_label']}): {p['status']}  [{'counted' if p['counted'] else 'excluded'}]")
    typer.echo(f"  {p['status_text']}")
    for h in x["hops"]:
        typer.echo(f"  hop {h['source']} -> {h['target']} via {h['via']} (edge {h['edge_id']}, gains {h['capability']})")
        for f in h["facts"]:
            reasons = " ".join(r for r in f["reasons"] if not r.startswith("EVIDENCE_INACTIVE"))
            typer.echo(f"     [{f['status']:<11}] {f['fact_id']}: {f['label']}  {reasons}")
            for e in f["evidence"]:
                state = "active" if e["active"] else f"inactive ({e['inactive_reason']})"
                typer.echo(f"         - {e['polarity']:<8} {e['id']} {state}: {e['label']}")
    typer.echo(f"  broken by: {', '.join(x['broken_by']) or 'no catalogued action'}")


@graph_app.command("hypotheses")
def graph_hypotheses(
    from_file: Optional[Path] = typer.Option(
        None, "--from-file", exists=True, dir_okay=False,
        help="Untrusted candidate JSON array (e.g. from an external model). Gated and verified; never executed.",
    ),
    data_dir: Optional[Path] = DataDir,
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    """List deterministic rule-based hypotheses and verify optional external candidates."""
    from tiw.services import triage

    ws = _ws(data_dir)
    raw = None
    if from_file is not None:
        if from_file.stat().st_size > 1_000_000:
            typer.secho("candidate file is larger than 1 MB", fg=typer.colors.RED, err=True)
            raise typer.Exit(2)
        try:
            raw = json.loads(from_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            typer.secho(f"error: candidate file is not valid JSON: {exc}", fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from None
    with db.session_scope(ws) as s:
        out = _analysis(triage.hypotheses, s=s, external=raw)
    if as_json:
        _echo_json(out)
        return
    for h in out["rule_based"]:
        hy, v = h["hypothesis"], h["verification"]
        typer.echo(f"  {hy['hypothesis_id']} [{v['status']:<21}] {hy['source_asset_id']} -> {hy['target_asset_id']} {hy['candidate_vulnerability_id'] or '(trust)'}")
    if out["external"] is not None:
        ext = out["external"]
        typer.echo(f"external candidates: accepted={len(ext['accepted'])} rejected={len(ext['rejected'])}")
        for h in ext["accepted"]:
            typer.echo(f"  {h['hypothesis']['hypothesis_id']} [{h['verification']['status']}] (candidate only; never changes the graph)")
        for rj in ext["rejected"]:
            typer.echo(f"  rejected #{rj['index']}: {rj['reason']}")


@triage_app.command("optimize")
def triage_optimize(
    budget: int = typer.Option(..., "--budget", min=0, help="Maximum total effort (integer)"),
    objective: str = typer.Option("weighted-paths", "--objective", help="weighted-paths | reachable-targets"),
    downtime_cap: Optional[str] = typer.Option(None, "--downtime-cap", help="none | low | high"),
    inclusion: str = typer.Option("as_recorded", "--inclusion", help="as_recorded | pessimistic | optimistic"),
    record: bool = typer.Option(True, "--record/--no-record"),
    as_json: bool = typer.Option(False, "--json"),
    data_dir: Optional[Path] = DataDir,
) -> None:
    """Select the best feasible remediation portfolio under a budget; compare equal-budget baselines."""
    from tiw.services import triage

    ws = _ws(data_dir)
    with db.session_scope(ws) as s:
        payload = _analysis(triage.optimize_analysis, s=s, budget=budget, objective=objective, downtime_cap=downtime_cap, inclusion=inclusion)
    r = payload["result"]
    run = created = diff = None
    if record:
        run, created, diff = triage.record(ws, "optimize", triage.run_key("optimize", r["params"]), payload, actor="cli")
    if as_json:
        _echo_json(r)
        return
    sel = r["selected"]
    typer.echo(f"selected: {' + '.join(sel['actions']) or 'no action'}  effort {sel['effort']}/{budget}  "
               f"{objective}={sel['objective_value']} (before {r['before']['objective_value']})  [{r['method']}]")
    for x in r["reasons"]:
        typer.echo(f"  - {x['text']}")
    typer.echo("equal-budget baselines:")
    for b in r["baselines"]:
        typer.echo(f"  {b['name']:<22} {' + '.join(b['actions']) or 'none':<40} {objective}={b['objective_value']}")
    surv = ", ".join(p["id"] for p in r["surviving_paths"]) or "none"
    excl = ", ".join(f"{p['id']}:{p['status']}" for p in r["excluded_paths"]) or "none"
    typer.echo(f"surviving paths: {surv}; excluded from the objective: {excl}")
    if run is not None:
        typer.echo(f"analysis run {run.id} ({'recorded' if created else 'unchanged'})")
        for w in (diff or {}).get("why", []):
            typer.echo(f"  changed: {w}")


@triage_app.command("robustness")
def triage_robustness(
    budget: int = typer.Option(..., "--budget", min=0),
    objective: str = typer.Option("weighted-paths", "--objective"),
    downtime_cap: Optional[str] = typer.Option(None, "--downtime-cap"),
    scenario_set: str = typer.Option("default", "--scenario-set", help="default"),
    stale_days: int = typer.Option(90, "--stale-days", min=1, max=3650),
    record: bool = typer.Option(True, "--record/--no-record"),
    as_json: bool = typer.Option(False, "--json"),
    data_dir: Optional[Path] = DataDir,
) -> None:
    """Re-run the optimiser under counterfactual evidence scenarios and explain recommendation flips."""
    from tiw.services import triage

    ws = _ws(data_dir)
    with db.session_scope(ws) as s:
        payload = _analysis(triage.robustness_analysis, s=s, budget=budget, objective=objective, downtime_cap=downtime_cap,
                            scenario_set=scenario_set, stale_days=stale_days)
    r = payload["result"]
    run = created = None
    if record:
        run, created, _ = triage.record(ws, "robustness", triage.run_key("robustness", r["params"]), payload, actor="cli")
    if as_json:
        _echo_json(r)
        return
    for p in r["summary"]["portfolios"]:
        typer.echo(p["text"])
    for x in r["scenarios"]:
        if not x["same_portfolio"]:
            typer.echo(f"  FLIP {x['scenario']['id']}: {' + '.join(x['selected']) or 'no action'}")
            for reason in x["flip_reasons"]:
                typer.echo(f"     {reason}")
    for u in r["uncovered"]:
        typer.echo(f"  not covered: {u}")
    typer.echo(r["disclaimer"])
    if run is not None:
        typer.echo(f"analysis run {run.id} ({'recorded' if created else 'unchanged'})")


@triage_app.command("runs")
def triage_runs(data_dir: Optional[Path] = DataDir, limit: int = typer.Option(20, "--limit", min=1, max=500)) -> None:
    """List recorded analysis runs (append-only)."""
    from tiw.services import triage

    ws = _ws(data_dir)
    with db.session_scope(ws) as s:
        for r in triage.latest_runs(s, limit):
            typer.echo(f"{r.id}  #{r.seq:<3} {r.kind:<10} {r.run_key:<44} {db.utc_iso(r.created_at)}  evidence {r.evidence_hash[:12]}")


def _draft(kind: str, out: Optional[Path], do_import: bool, data_dir: Optional[Path]) -> None:
    from tiw.services import drafts

    ws = _ws(data_dir)
    kinds = drafts.DRAFT_KINDS if kind == "all" else (kind,)
    try:
        if do_import:
            for r in drafts.draft_and_import(ws, kinds, actor="cli"):
                typer.echo(f"{r['kind']}: {r['status']} accepted={r['accepted']} duplicates={r['duplicates']}")
                for e in r["errors"][:10]:
                    typer.echo(f"  {e['field']}: {e['reason']}")
                if r["status"] == "failed":
                    raise typer.Exit(1)
            typer.echo("Drafts are unreviewed: service ports are 'any' (an unknown fact on every hop) and efforts are placeholders. "
                       "Export them with --out, edit, and re-import to refine.")
            return
        for k in kinds:
            content = drafts.draft_bytes(ws, k)
            if out is None:
                typer.echo(content.decode())
            else:
                target = out if len(kinds) == 1 else out.with_name(f"{out.stem}-{k}{out.suffix or '.json'}")
                target.write_bytes(content)
                typer.echo(f"Wrote {target}")
    except drafts.DraftError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None


@draft_app.command("exploit-conditions")
def draft_conditions(
    out: Optional[Path] = typer.Option(None, "--out", dir_okay=False, help="Write the draft here instead of stdout"),
    do_import: bool = typer.Option(False, "--import", help="Import the draft directly"),
    data_dir: Optional[Path] = DataDir,
) -> None:
    """One entry per vulnerability with findings (ports 'any', unreviewed). Existing entries are kept."""
    _draft("exploit_conditions", out, do_import, data_dir)


@draft_app.command("remediations")
def draft_remediations(
    out: Optional[Path] = typer.Option(None, "--out", dir_okay=False),
    do_import: bool = typer.Option(False, "--import"),
    data_dir: Optional[Path] = DataDir,
) -> None:
    """One patch action per finding (effort 1 placeholder, unverified). Existing actions are kept."""
    _draft("remediations", out, do_import, data_dir)


@draft_app.command("all")
def draft_all(
    out: Optional[Path] = typer.Option(None, "--out", dir_okay=False, help="Base file name; '-<kind>' is appended"),
    do_import: bool = typer.Option(False, "--import"),
    data_dir: Optional[Path] = DataDir,
) -> None:
    """Exploit conditions and remediations drafts together."""
    _draft("all", out, do_import, data_dir)

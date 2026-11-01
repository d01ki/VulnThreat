"""`tiw` command line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from tiw.adapters.common import InputMalformed, InputTooLarge
from tiw.cli import v2
from tiw.services import demo as demo_svc
from tiw.storage import db

app = typer.Typer(help="threat-intel-workbench: evidence-driven threat intelligence for patch decisions.", no_args_is_help=True)
demo_app = typer.Typer(help="Offline synthetic demo scenarios (A-D and attack-path).", no_args_is_help=True)
app.add_typer(demo_app, name="demo")
app.add_typer(v2.graph_app, name="graph")
app.add_typer(v2.triage_app, name="triage")
app.add_typer(v2.draft_app, name="draft")

DataDir = typer.Option(None, "--data-dir", help="Workspace directory (default: $TIW_DATA_DIR or ./.tiw)")
DemoDir = typer.Option(".tiw-demo", "--data-dir", help="Demo workspace directory (kept separate from real data)")


def _ws(data_dir: Optional[Path]) -> db.Workspace:
    return db.resolve_workspace(data_dir)


def _require(ws: db.Workspace) -> None:
    try:
        db.ensure_schema_present(ws)
    except FileNotFoundError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None


def _echo_json(obj: object) -> None:
    typer.echo(json.dumps(obj, indent=2, default=str, ensure_ascii=False))


@app.command()
def init(
    data_dir: Optional[Path] = DataDir,
    synthetic: bool = typer.Option(False, "--synthetic", help="Mark the workspace as synthetic (demo/testing)"),
) -> None:
    """Create or migrate a workspace. Never deletes existing data."""
    ws = _ws(data_dir)
    created = db.init_workspace(ws, synthetic=synthetic)
    problems = db.schema_problems(ws)
    with db.session_scope(ws) as s:
        mode = db.get_meta(s, "data_mode")
    typer.echo(f"{'Created' if created else 'Migrated'} workspace {ws.data_dir} (mode: {mode})")
    if problems:
        typer.secho("Schema check failed:\n" + "\n".join(problems), fg=typer.colors.RED, err=True)
        raise typer.Exit(1)
    typer.echo("Schema check: OK")


@app.command("import")
def import_cmd(
    kind: str = typer.Argument(..., help="kev | epss | assets | findings | observations | claims | topology | exploit-conditions | remediations"),
    path: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    data_dir: Optional[Path] = DataDir,
    allow_partial: bool = typer.Option(False, "--allow-partial", help="Accept valid rows even if some rows fail"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Validate only; write nothing"),
    as_json: bool = typer.Option(False, "--json", help="Print the full result as JSON"),
) -> None:
    """Import one file (whole-file rollback on any invalid row by default)."""
    from tiw.services.ingest import run_import

    ws = _ws(data_dir)
    _require(ws)
    try:
        out = run_import(ws, kind, path.read_bytes(), actor="cli", allow_partial=allow_partial, dry_run=dry_run)
    except (InputTooLarge, InputMalformed, ValueError) as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    if as_json:
        _echo_json(out.as_dict())
    else:
        typer.echo(
            f"{out.status}: accepted={out.accepted} duplicates={out.duplicates} rejected={out.rejected} quarantined={out.quarantined}"
        )
        for e in out.errors[:50]:
            typer.echo(f"  line {e['line']} field {e['field']}: {e['reason']}")
        if out.recompute:
            r = out.recompute
            typer.echo(f"recompute: assessments={r['assessments']} deltas={r['deltas']} decisions={r['decisions']}")
    if out.status == "failed":
        raise typer.Exit(1)


@app.command()
def fetch(
    feed: str = typer.Argument(..., help="kev | epss"),
    data_dir: Optional[Path] = DataDir,
) -> None:
    """Download CISA KEV or FIRST EPSS from the official URLs and import it (explicit, allowlisted)."""
    from tiw.services.fetch import FetchError, fetch_epss, fetch_kev

    ws = _ws(data_dir)
    _require(ws)
    if feed not in ("kev", "epss"):
        typer.secho("feed must be kev or epss", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    try:
        out = fetch_kev(ws) if feed == "kev" else fetch_epss(ws)
    except FetchError as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    typer.echo(f"{feed}: {out.status} accepted={out.accepted} duplicates={out.duplicates} rejected={out.rejected}")
    for e in out.errors[:10]:
        typer.echo(f"  {e['field'] or ''}: {e['reason']}")
    if out.recompute:
        r = out.recompute
        typer.echo(f"recompute: assessments={r['assessments']} changes={r['deltas']} decisions={r['decisions']}")
    if out.status == "failed":
        raise typer.Exit(1)


@app.command()
def assess(
    changed: bool = typer.Option(True, "--changed/--all", help="Recompute changed inputs (P0 re-evaluates every vulnerability; idempotent)"),
    vulnerability: Optional[list[str]] = typer.Option(None, "--id", help="Only these vulnerability IDs"),
    data_dir: Optional[Path] = DataDir,
) -> None:
    """Re-evaluate assessments and decisions (e.g. after time passes and evidence expires)."""
    from tiw.services.pipeline import recompute

    ws = _ws(data_dir)
    _require(ws)
    r = recompute(ws, vulnerability_ids=vulnerability or None, actor="cli", trigger="assess")
    typer.echo(f"vulnerabilities={r['vulnerabilities']} new assessments={r['assessments']} deltas={r['deltas']} decisions={r['decisions']}")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Bind address (P0 supports localhost only)"),
    port: int = typer.Option(8787),
    data_dir: Optional[Path] = DataDir,
) -> None:
    """Run the local web UI and REST API."""
    import uvicorn

    from tiw.api.app import create_app

    if host not in ("127.0.0.1", "localhost", "::1"):
        typer.secho("Refusing to bind a non-loopback address: LAN exposure is outside P0 support.", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    ws = _ws(data_dir)
    _require(ws)
    typer.echo(f"Serving {ws.data_dir} on http://{host}:{port}  (API token: {ws.token_path})")
    uvicorn.run(create_app(ws, port=port), host=host, port=port, log_level="info")


@app.command()
def export(
    threat: Optional[str] = typer.Option(None, "--threat", help="Vulnerability ID, e.g. DEMO-VULN-001"),
    analysis_run: Optional[str] = typer.Option(None, "--analysis-run", help="Run ID from `tiw triage runs`, or latest-optimize / latest-robustness / latest-graph"),
    fmt: str = typer.Option("markdown", "--format", help="json | markdown"),
    normalized: bool = typer.Option(False, "--normalized", help="JSON only: deterministic result without run ids or timestamps"),
    stdout: bool = typer.Option(False, "--stdout", help="Also print the export"),
    data_dir: Optional[Path] = DataDir,
) -> None:
    """Write a local JSON/Markdown report for one threat or one recorded analysis run."""
    from tiw.services.analysis_export import export_analysis_run
    from tiw.services.export import export_threat

    ws = _ws(data_dir)
    _require(ws)
    if bool(threat) == bool(analysis_run):
        typer.secho("pass exactly one of --threat or --analysis-run", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    try:
        if analysis_run:
            path, content = export_analysis_run(ws, v2.resolve_run(ws, analysis_run), fmt, normalized=normalized)
        else:
            path, content = export_threat(ws, threat or "", fmt)
    except (LookupError, ValueError) as exc:
        typer.secho(f"error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    typer.echo(f"Wrote {path}")
    if stdout:
        sys.stdout.write(content + "\n")


@app.command("set")
def set_setting(
    key: str = typer.Argument(..., help="timezone | brand_name"),
    value: str = typer.Argument(...),
    data_dir: Optional[Path] = DataDir,
) -> None:
    """Change a display setting."""
    from zoneinfo import ZoneInfo

    ws = _ws(data_dir)
    _require(ws)
    if key == "timezone":
        try:
            ZoneInfo(value)
        except Exception:  # noqa: BLE001
            typer.secho("unknown IANA timezone", fg=typer.colors.RED, err=True)
            raise typer.Exit(2) from None
    elif key != "brand_name":
        typer.secho("only timezone and brand_name can be set", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    with db.session_scope(ws) as s:
        db.set_meta(s, key, value[:80])
    typer.echo(f"{key} = {value}")


def _print_demo_log(log: list[dict]) -> None:
    if not log:
        typer.echo("Nothing to apply (steps already applied).")
    for e in log:
        typer.echo(f"[{e['letter']}] step {e['step']} @ {e['clock']}: {e['title']}")
        for i in e["imports"]:
            extra = f" — {i['errors'][0]['reason']}" if i["errors"] else ""
            typer.echo(f"     {i['kind']:<12} {i['file']:<24} {i['status']} (accepted {i['accepted']}, duplicates {i['duplicates']}){extra}")
        r = e["recompute"]
        typer.echo(f"     → new assessments {r['assessments']}, deltas {r['deltas']}, decisions {r['decisions']}")
        for a in r.get("analysis_runs", []):
            typer.echo(f"     → analysis run {a['kind']:<10} {a['run_id']} ({'recorded' if a['created'] else 'unchanged'})")


@demo_app.command("seed")
def demo_seed(
    scenario: str = typer.Option("all", "--scenario", help="escalation (A) | amplification (B) | expiry (C) | correction (D) | all (A-D) | attack-path"),
    data_dir: Path = DemoDir,
) -> None:
    """Create a synthetic demo workspace and apply step 1."""
    ws = db.resolve_workspace(data_dir)
    try:
        _print_demo_log(demo_svc.seed(ws, scenario))
    except demo_svc.DemoError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None
    typer.echo(f"Demo workspace: {ws.data_dir}. Next: tiw demo advance --step 2 --data-dir {data_dir}")


@demo_app.command("advance")
def demo_advance(
    step: int = typer.Option(..., "--step", min=1, help="Apply all steps up to this number"),
    scenario: Optional[str] = typer.Option(None, "--scenario", help="Limit to one scenario (default: all seeded)"),
    data_dir: Path = DemoDir,
) -> None:
    """Advance the seeded scenarios to a step (idempotent)."""
    ws = db.resolve_workspace(data_dir)
    try:
        _print_demo_log(demo_svc.advance(ws, step, scenario))
    except demo_svc.DemoError as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from None


@demo_app.command("status")
def demo_status(data_dir: Path = DemoDir) -> None:
    """Show which demo steps are applied."""
    ws = db.resolve_workspace(data_dir)
    for r in demo_svc.status(ws):
        typer.echo(f"[{r['letter']}] {r['scenario']:<14} step {r['applied_step']}/{r['steps']}  {r['title']}" + (f"  next: {r['next']}" if r["next"] else ""))


@demo_app.command("reset")
def demo_reset(
    data_dir: Path = DemoDir,
    yes: bool = typer.Option(False, "--yes", help="Confirm deletion of the synthetic demo workspace"),
) -> None:
    """Delete a synthetic demo workspace (refuses to touch live workspaces)."""
    import shutil

    ws = db.resolve_workspace(data_dir)
    if not ws.exists():
        typer.echo("No demo workspace to reset.")
        return
    with db.session_scope(ws) as s:
        synthetic = db.is_synthetic_workspace(s)
    if not synthetic:
        typer.secho("Refusing: this is not a synthetic workspace.", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)
    if not yes:
        typer.secho("Pass --yes to delete the demo workspace.", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(1)
    db.dispose_engine(ws)
    shutil.rmtree(ws.data_dir)
    typer.echo(f"Deleted {ws.data_dir}")


if __name__ == "__main__":
    app()

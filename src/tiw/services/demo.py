"""Offline demo scenarios A–D (DESIGN §16). All data is synthetic and the clock is fixed per step."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any

from tiw.services.ingest import run_import
from tiw.services.pipeline import recompute
from tiw.storage import db


@dataclass(frozen=True)
class Step:
    number: int
    clock: str
    title: str
    imports: tuple[tuple[str, str], ...]  # (kind, file name)
    analyze: bool = False  # record v2 analysis runs after this step (attack-path scenario)


@dataclass(frozen=True)
class Scenario:
    key: str
    letter: str
    title: str
    steps: tuple[Step, ...]


SCENARIOS: dict[str, Scenario] = {
    "escalation": Scenario(
        "escalation",
        "A",
        "Intelligence changes the remediation decision",
        (
            Step(1, "2026-10-01T09:00:00Z", "Three assets for DEMO-VULN-001 (exposed / internal / applicability unknown)",
                 (("assets", "assets.csv"), ("findings", "findings.csv"), ("epss", "epss.json"), ("observations", "observations-1.jsonl"))),
            Step(2, "2026-10-02T12:00:00Z", "A confirmed local exploit attempt against the gateway",
                 (("observations", "observations-2.jsonl"),)),
            Step(3, "2026-10-03T12:00:00Z", "KEV-format snapshot lists DEMO-VULN-001",
                 (("kev", "kev-2026-10-03.json"),)),
        ),
    ),
    "amplification": Scenario(
        "amplification",
        "B",
        "More articles, no more evidence",
        (
            Step(1, "2026-10-01T09:00:00Z", "One exposed asset affected by DEMO-VULN-002",
                 (("assets", "assets.csv"), ("findings", "findings.csv"))),
            Step(2, "2026-10-02T12:00:00Z", "One unverified article reports exploitation",
                 (("claims", "claims-1.json"),)),
            Step(3, "2026-10-03T12:00:00Z", "Ten articles explicitly cite that article",
                 (("claims", "claims-2.json"),)),
            Step(4, "2026-10-04T12:00:00Z", "An independent, reviewed vendor confirmation",
                 (("claims", "claims-3.json"),)),
        ),
    ),
    "expiry": Scenario(
        "expiry",
        "C",
        "The basis for deferral breaks",
        (
            Step(1, "2026-10-01T09:00:00Z", "Two reviewed not_affected findings for DEMO-VULN-003",
                 (("assets", "assets.csv"), ("findings", "findings.csv"))),
            Step(2, "2026-10-02T12:00:00Z", "A confirmed exploit attempt hits a not_affected asset",
                 (("observations", "observations.jsonl"),)),
            Step(3, "2026-10-07T09:00:00Z", "Time passes: the other not_affected review expires", ()),
        ),
    ),
    "correction": Scenario(
        "correction",
        "D",
        "Correction is not the same as an outage",
        (
            Step(1, "2026-10-01T09:00:00Z", "A single reviewed exploitation report (DEMO-VULN-004) and a KEV listing (DEMO-VULN-005)",
                 (("assets", "assets.csv"), ("findings", "findings.csv"), ("claims", "claims-1.json"), ("kev", "kev-2026-09-30.json"))),
            Step(2, "2026-10-02T12:00:00Z", "The publisher retracts the only report",
                 (("claims", "claims-2.json"),)),
            Step(3, "2026-10-11T09:00:00Z", "The KEV feed retrieval fails (truncated file); existing evidence is kept",
                 (("kev", "kev-broken.json"),)),
        ),
    ),
    "attack-path": Scenario(
        "attack-path",
        "AP",
        "Evidence-grounded attack paths and counterfactual patch triage (no WAF/IDS logs)",
        (
            Step(1, "2026-10-20T09:00:00Z", "Assets, findings, saved KEV/EPSS, reviewed graph claims, topology, preconditions and remediation catalog",
                 (("assets", "assets.csv"), ("findings", "findings.csv"), ("epss", "epss.json"), ("kev", "kev-2026-10-19.json"),
                  ("claims", "claims-1.json"), ("topology", "topology.json"), ("exploit_conditions", "exploit_conditions.json"),
                  ("remediations", "remediations.json")), analyze=True),
            Step(2, "2026-10-21T09:00:00Z", "The partner-integration runbook claim (SFTP → API) is retracted",
                 (("claims", "claims-2.json"),), analyze=True),
        ),
    ),
}
LEGACY = ("escalation", "amplification", "expiry", "correction")
ALIASES = {"a": "escalation", "b": "amplification", "c": "expiry", "d": "correction", "ap": "attack-path", "attack_path": "attack-path", "v2": "attack-path"}
DEMO_BUDGET = 2


class DemoError(Exception):
    pass


def resolve(names: str) -> list[str]:
    if names == "all":
        return list(LEGACY)
    out = []
    for n in names.split(","):
        n = ALIASES.get(n.strip().lower(), n.strip().lower())
        if n not in SCENARIOS:
            raise DemoError(f"unknown scenario {n!r}; choose from {', '.join(SCENARIOS)} or all")
        out.append(n)
    return out


def fixture_bytes(scenario: str, name: str) -> bytes:
    return resources.files("tiw.demo_data").joinpath(scenario, name).read_bytes()


def _guard(ws: db.Workspace) -> None:
    if ws.exists():
        with db.session_scope(ws) as s:
            if not db.is_synthetic_workspace(s):
                raise DemoError(
                    f"{ws.data_dir} is a live workspace; demo data is never written into it. Use a separate --data-dir."
                )


def applied(ws: db.Workspace) -> dict[str, int]:
    with db.session_scope(ws) as s:
        return dict(db.get_meta_json(s, "demo_applied", {}))  # type: ignore[arg-type]


def _set_clock(ws: db.Workspace, clock: str) -> None:
    with db.session_scope(ws) as s:
        current = db.get_meta(s, "clock_fixed")
        if current is None or db.parse_utc(clock) > db.parse_utc(current):
            db.set_meta(s, "clock_fixed", clock)


def _apply(ws: db.Workspace, scenario: str, upto: int) -> list[dict[str, Any]]:
    sc = SCENARIOS[scenario]
    done = applied(ws).get(scenario, 0)
    log: list[dict[str, Any]] = []
    for step in sc.steps:
        if step.number <= done or step.number > upto:
            continue
        _set_clock(ws, step.clock)
        results = []
        for kind, name in step.imports:
            out = run_import(ws, kind, fixture_bytes(scenario, name), actor="demo", recompute=False)
            results.append({"file": name, **{k: out.as_dict()[k] for k in ("kind", "status", "accepted", "duplicates", "rejected", "errors")}})
        summary = recompute(ws, actor="demo", trigger=f"demo:{scenario}:{step.number}")
        if step.analyze:
            summary = {**summary, "analysis_runs": record_demo_analyses(ws)}
        with db.session_scope(ws) as s:
            state = dict(db.get_meta_json(s, "demo_applied", {}))  # type: ignore[arg-type]
            state[scenario] = step.number
            db.set_meta(s, "demo_applied", json.dumps(state))
        log.append({"scenario": scenario, "letter": sc.letter, "step": step.number, "title": step.title, "clock": step.clock, "imports": results, "recompute": summary})
    return log


def record_demo_analyses(ws: db.Workspace) -> list[dict[str, Any]]:
    """Record the graph, budget-2 optimisation and robustness runs (append-only, idempotent)."""
    from tiw.services import triage

    out = []
    with db.session_scope(ws) as s:
        payloads = [
            ("graph", "graph", triage.analyze_graph(s)),
            ("optimize", None, triage.optimize_analysis(s, budget=DEMO_BUDGET)),
            ("robustness", None, triage.robustness_analysis(s, budget=DEMO_BUDGET)),
        ]
    for kind, key, payload in payloads:
        rk = key or triage.run_key(kind, payload["result"]["params"])
        run, created, _diff = triage.record(ws, kind, rk, payload, actor="demo")
        out.append({"kind": kind, "run_id": run.id, "created": created})
    return out


def _family_check(ws: db.Workspace, names: list[str]) -> None:
    if not ws.exists():
        return
    with db.session_scope(ws) as s:
        seeded = set(db.get_meta_json(s, "demo_scenarios", []))  # type: ignore[arg-type]
    new_ap, new_legacy = "attack-path" in names, any(n in LEGACY for n in names)
    has_ap, has_legacy = "attack-path" in seeded, bool(seeded & set(LEGACY))
    if (new_ap and has_legacy) or (new_legacy and has_ap) or (new_ap and new_legacy):
        raise DemoError(
            "the attack-path scenario uses its own synthetic KEV snapshot and cannot share a workspace with scenarios A-D; "
            "run `tiw demo reset --yes` first or pass a different --data-dir"
        )


def seed(ws: db.Workspace, scenarios: str = "all") -> list[dict[str, Any]]:
    """Create (or reuse) a synthetic workspace and apply step 1. Never deletes anything."""
    _guard(ws)
    names = resolve(scenarios)
    _family_check(ws, names)
    db.init_workspace(ws, synthetic=True)
    with db.session_scope(ws) as s:
        seeded = set(db.get_meta_json(s, "demo_scenarios", []))  # type: ignore[arg-type]
        db.set_meta(s, "demo_scenarios", json.dumps(sorted(seeded | set(names))))
    log: list[dict[str, Any]] = []
    for n in names:
        log += _apply(ws, n, 1)
    return log


def advance(ws: db.Workspace, step: int, scenarios: str | None = None) -> list[dict[str, Any]]:
    _guard(ws)
    if not ws.exists():
        raise DemoError("demo workspace not seeded; run `tiw demo seed` first")
    with db.session_scope(ws) as s:
        seeded = list(db.get_meta_json(s, "demo_scenarios", []))  # type: ignore[arg-type]
    names = resolve(scenarios) if scenarios else seeded
    done = applied(ws)
    # Apply pending steps of all scenarios in global clock order so the fixed clock never jumps back.
    pending = sorted(
        (db.parse_utc(st.clock), SCENARIOS[n].letter, n, st.number)
        for n in names
        for st in SCENARIOS[n].steps
        if done.get(n, 0) < st.number <= step
    )
    log: list[dict[str, Any]] = []
    for _clock, _letter, n, number in pending:
        log += _apply(ws, n, number)
    return log


def reset_workspace(ws: db.Workspace) -> None:
    """Delete a synthetic demo workspace's data (never a live one). Keeps the API token file."""
    import shutil

    if not ws.exists():
        return
    with db.session_scope(ws) as s:
        if not db.is_synthetic_workspace(s):
            raise DemoError("refusing: this is not a synthetic workspace")
    token = ws.token_path.read_text(encoding="utf-8") if ws.token_path.exists() else None
    db.dispose_engine(ws)
    for name in ("tiw.db", "tiw.db-wal", "tiw.db-shm"):
        (ws.data_dir / name).unlink(missing_ok=True)
    for d in (ws.objects_dir, ws.exports_dir, ws.staging_dir):
        shutil.rmtree(d, ignore_errors=True)
    if token is not None:
        ws.token_path.write_text(token, encoding="utf-8")


def reseed(ws: db.Workspace, scenario: str = "attack-path", step: int = 1) -> list[dict[str, Any]]:
    """One-click demo reset: delete synthetic data, seed again and advance to ``step``."""
    reset_workspace(ws)
    log = seed(ws, scenario)
    if step > 1:
        log += advance(ws, step, scenario)
    return log


def seeded(ws: db.Workspace) -> list[str]:
    if not ws.exists():
        return []
    with db.session_scope(ws) as s:
        return list(db.get_meta_json(s, "demo_scenarios", []))  # type: ignore[arg-type]


def status(ws: db.Workspace) -> list[dict[str, Any]]:
    done = applied(ws) if ws.exists() else {}
    return [
        {"scenario": k, "letter": sc.letter, "title": sc.title, "applied_step": done.get(k, 0), "steps": len(sc.steps),
         "next": next((st.title for st in sc.steps if st.number == done.get(k, 0) + 1), None)}
        for k, sc in SCENARIOS.items()
    ]

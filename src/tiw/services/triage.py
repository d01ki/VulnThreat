"""v2 analyses: attack paths, counterfactual portfolio optimisation, baselines, robustness, recorded runs.

All results are deterministic for the same inputs and clock. ``result`` dictionaries are the
normalized output (stable ordering, no wall-clock data); timing lives under ``diagnostics``
and is excluded from hashes and normalized exports.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from tiw.domain import agents
from tiw.domain.attack_graph import (
    GRAPH_ALGORITHM_VERSION,
    INCLUSION,
    PATH_STATUS_TEXT,
    Enumeration,
    FactOverride,
    GraphModel,
    Limits,
    canonical_hash,
    enumerate_paths,
)
from tiw.domain.remediation import (
    BASELINE_TEXT,
    BASELINES,
    OBJECTIVES,
    OPTIMIZER_VERSION,
    Constraints,
    Evaluation,
    Evaluator,
    PortfolioError,
    explain_choice,
    optimize,
    ranked_baseline,
    removal_for,
    single_action_effects,
)
from tiw.domain.robustness import (
    ROBUSTNESS_VERSION,
    SCENARIO_TEXT,
    Scenario,
    ScenarioOutcome,
    default_scenarios,
    explain_flip,
    run_scenario,
    stability_summary,
)
from tiw.services import graph as graph_svc
from tiw.services.ingest import audit, next_seq
from tiw.storage import db
from tiw.storage.models import AnalysisRun

ALGORITHM_VERSION = f"{GRAPH_ALGORITHM_VERSION}+{OPTIMIZER_VERSION}+{ROBUSTNESS_VERSION}"
TIE_BREAKING = "objective, then the other objective, then total effort, then max downtime, then number of actions, then sorted action ids"
OBJECTIVE_TEXT = {
    "weighted-paths": "Sum of configured objective weights over counted model paths that survive the portfolio (lower is better). A proxy sensitive to graph granularity and enumeration limits.",
    "reachable-targets": "Number of security objectives that still have at least one counted model path (lower is better).",
}
INCLUSION_TEXT = {
    "as_recorded": "Counts supported, conditional and contradicted paths (unknown is not safe; disputes are not resolved by voting). Insufficient-evidence paths are excluded and listed.",
    "pessimistic": "Sensitivity bound: also counts insufficient-evidence paths.",
    "optimistic": "Sensitivity bound: counts only supported paths.",
}


class AnalysisError(ValueError):
    pass


# --------------------------------------------------------------------------- helpers


def _path_row(p: Any, enum: Enumeration, counted: set[str], model: GraphModel) -> dict[str, Any]:
    obj = next(o for o in model.objectives if o.id == p.objective_id)
    unknowns = [f for f, st in p.fact_status if st in ("unknown", "unsupported", "disputed")]
    return {
        **p.as_dict(),
        "objective_label": obj.label,
        "weight": obj.weight,
        "counted": p.id in counted,
        "status_text": PATH_STATUS_TEXT[p.status],
        "unknown_facts": unknowns,
        "labels": [model.nodes[n].label for n in p.nodes],
    }


def _assumptions(w: graph_svc.Workspace2, enum: Enumeration, inclusion: str) -> list[str]:
    lim = w.model.limits
    out = [
        "Paths are model paths over recorded topology, findings and structured preconditions. They are not observed attacks and do not prove reachability or compromise.",
        "A 'supported' path means every model precondition has active reviewed evidence; it is not hands-on verification.",
        "The optimiser objective uses only graph structure and configured objective weights. CVSS, EPSS and KEV are used only by the comparison baselines.",
        "EPSS is a 30-day exploitation estimate per CVE, not a per-hop probability; it is never multiplied along a path.",
        f"Objective weights are configured per security objective: {', '.join(f'{o.id}={o.weight}' for o in sorted(w.model.objectives, key=lambda o: o.id))}.",
        f"Inclusion policy {inclusion}: {INCLUSION_TEXT[inclusion]}",
        "Remediation effects are modelled as removal of edges, ports or findings; they cannot create new paths.",
        f"Enumeration limits: max {lim.max_hops} hops, {lim.max_paths} paths, {lim.max_expansions} expansions"
        + (f"; TRUNCATED ({'; '.join(enum.truncation_reasons)}), so counts are lower bounds." if enum.truncated else "; not truncated for this graph."),
    ]
    unverified = sorted(a.id for a in w.actions if a.verification_status != "verified")
    if unverified:
        out.append(f"Effects of unverified actions are assumed, not tested: {', '.join(unverified)}.")
    if w.synthetic:
        out.append("All data in this workspace is synthetic. Results demonstrate behaviour only, not real-world effectiveness.")
    return out


def _evidence_rows(enum: Enumeration, fact_ids: list[str]) -> list[dict[str, Any]]:
    out = []
    for fid in fact_ids:
        f = enum.facts[fid]
        st, reasons = enum.fact_status[fid]
        out.append({
            "fact_id": fid,
            "kind": f.kind,
            "label": f.label,
            "declared": f.declared,
            "status": st,
            "reasons": reasons,
            "evidence": [e.as_dict() for e in f.evidence],
        })
    return out


def layout(model: GraphModel, enum: Enumeration) -> dict[str, Any]:
    """Layered left-to-right layout by shortest hop distance from any entry point."""
    depth: dict[str, int] = {}
    frontier = sorted(n for n, v in model.nodes.items() if v.kind == "entry_point")
    for n in frontier:
        depth[n] = 0
    adj: dict[str, list[str]] = {}
    for e in model.edges:
        adj.setdefault(e.source, []).append(e.target)
    while frontier:
        nxt = []
        for n in frontier:
            for m in sorted(adj.get(n, [])):
                if m not in depth:
                    depth[m] = depth[n] + 1
                    nxt.append(m)
        frontier = sorted(set(nxt))
    maxd = max(depth.values(), default=0)
    for n in sorted(model.nodes):
        depth.setdefault(n, maxd + 1)
    layers: dict[int, list[str]] = {}
    for n, d in sorted(depth.items(), key=lambda kv: (kv[1], kv[0])):
        layers.setdefault(d, []).append(n)
    col_w, row_h, node_w, node_h, pad = 190, 86, 150, 46, 20
    height = max(len(v) for v in layers.values()) * row_h + pad
    width = (max(layers) + 1) * col_w + pad
    pos = {}
    for d, ns in layers.items():
        off = (height - len(ns) * row_h) / 2
        for i, n in enumerate(ns):
            pos[n] = {"x": pad + d * col_w, "y": round(off + i * row_h + 10, 1)}
    objective_assets = {o.asset_id for o in model.objectives}
    counted = {p.id for p in enum.counted("as_recorded")}
    edge_paths: dict[str, list[str]] = {}
    for p in enum.paths:
        for h in p.hops:
            edge_paths.setdefault(h.edge_id, []).append(p.id)
    nodes = []
    for n in sorted(model.nodes):
        v = model.nodes[n]
        nodes.append({"id": n, "label": v.label[:22], "kind": v.kind, "crown_jewel": n in objective_assets,
                      "criticality": v.criticality, **pos[n], "w": node_w, "h": node_h})
    edges = []
    for e in sorted(model.edges, key=lambda e: e.id):
        a, b = pos[e.source], pos[e.target]
        st = enum.fact_status[e.reachability.id][0]
        x1, y1 = a["x"] + node_w, a["y"] + node_h / 2
        x2, y2 = b["x"], b["y"] + node_h / 2
        if b["x"] <= a["x"]:  # backward / same-layer edge: route below
            x1, y1, x2, y2 = a["x"] + node_w / 2, a["y"] + node_h, b["x"] + node_w / 2, b["y"] + node_h
            dpath = f"M{x1},{y1} C{x1},{y1 + 40} {x2},{y2 + 40} {x2},{y2}"
        else:
            mx = (x1 + x2) / 2
            dpath = f"M{x1},{y1} C{mx},{y1} {mx},{y2} {x2},{y2}"
        on_paths = sorted(set(edge_paths.get(e.id, [])))
        edges.append({"id": e.id, "source": e.source, "target": e.target, "status": st, "kind": e.kind,
                      "d": dpath, "ports": list(e.ports), "paths": on_paths,
                      "on_counted": any(p in counted for p in on_paths), "lx": round((x1 + x2) / 2, 1), "ly": round((y1 + y2) / 2 - 6, 1)})
    return {"width": width, "height": height, "nodes": nodes, "edges": edges}


# --------------------------------------------------------------------------- graph


def analyze_graph(s: Session, *, at: datetime | None = None, limits: Limits | None = None) -> dict[str, Any]:
    w = graph_svc.load(s, limits=limits, at=at)
    enum = enumerate_paths(w.model, at=w.now)
    counted = {p.id for p in enum.counted("as_recorded")}
    hyps = agents.rule_based(w.model)
    verified = [{"hypothesis": h.as_dict(), "verification": agents.verify(h, w.model, enum)} for h in hyps]
    by_status: dict[str, int] = {}
    for p in enum.paths:
        by_status[p.status] = by_status.get(p.status, 0) + 1
    result = {
        "evidence_hash": w.evidence_hash,
        "algorithm_version": GRAPH_ALGORITHM_VERSION,
        "clock": db.utc_iso(w.now),
        "inputs": w.inputs,
        "counts": {"nodes": len(w.model.nodes), "edges": len(w.model.edges), "findings": len(w.model.exploits),
                   "objectives": len(w.model.objectives), "paths": len(enum.paths), "counted_paths": len(counted),
                   "blocked_hops": len(enum.blocked), "by_status": dict(sorted(by_status.items()))},
        "truncated": enum.truncated,
        "truncation_reasons": enum.truncation_reasons,
        "objectives": [{"id": o.id, "asset_id": o.asset_id, "label": o.label, "weight": o.weight} for o in sorted(w.model.objectives, key=lambda o: o.id)],
        "paths": [_path_row(p, enum, counted, w.model) for p in enum.paths],
        "blocked": enum.blocked,
        "facts": _evidence_rows(enum, sorted(enum.facts)),
        "hypotheses": verified,
        "hypothesis_generator": {"name": agents.GENERATOR_VERSION, "provider": "disabled (deterministic rules only)",
                                 "external": None},
        "assets": w.assets,
        "vulnerabilities": w.vulns,
        "assumptions": _assumptions(w, enum, "as_recorded"),
        "synthetic": w.synthetic,
    }
    return {"result": result, "layout": layout(w.model, enum), "diagnostics": {"expansions": enum.expansions}}


def hypotheses(s: Session, *, external: Any = None, at: datetime | None = None) -> dict[str, Any]:
    """Deterministic hypotheses plus optional untrusted external candidates (gated, verified, never applied)."""
    w = graph_svc.load(s, at=at)
    enum = enumerate_paths(w.model, at=w.now)
    rule = [{"hypothesis": h.as_dict(), "verification": agents.verify(h, w.model, enum)} for h in agents.rule_based(w.model)]
    ext = None
    if external is not None:
        known = {e.id for f in enum.facts.values() for e in f.evidence}
        g = agents.gate(external, w.model, known, origin="model")
        ext = {"accepted": [{"hypothesis": h.as_dict(), "verification": agents.verify(h, w.model, enum)} for h in g.accepted],
               "rejected": g.rejected,
               "note": "External candidates are untrusted. They are never persisted as facts and never change paths or priorities."}
    return {"generator": agents.GENERATOR_VERSION, "schema_version": agents.HYPOTHESIS_SCHEMA_VERSION,
            "rule_based": rule, "external": ext, "evidence_hash": w.evidence_hash}


def explain_path(s: Session, path_id: str, *, at: datetime | None = None) -> dict[str, Any] | None:
    w = graph_svc.load(s, at=at)
    enum = enumerate_paths(w.model, at=w.now)
    p = next((p for p in enum.paths if p.id == path_id.upper()), None)
    if p is None:
        idx = path_id.upper().removeprefix("PATH-")
        if idx.isdigit() and 0 < int(idx) <= len(enum.paths):
            p = enum.paths[int(idx) - 1]
    if p is None:
        return None
    counted = {x.id for x in enum.counted("as_recorded")}
    hops = []
    for h in p.hops:
        hops.append({**h.as_dict(), "source_label": w.model.nodes[h.source].label, "target_label": w.model.nodes[h.target].label,
                     "facts": _evidence_rows(enum, list(h.fact_ids))})
    breakers = Evaluator(w.model, enum, w.actions, "pessimistic").breakers.get(p.id, frozenset())
    return {"path": _path_row(p, enum, counted, w.model), "hops": hops, "broken_by": sorted(breakers),
            "evidence_hash": w.evidence_hash, "clock": db.utc_iso(w.now), "synthetic": w.synthetic,
            "assumptions": _assumptions(w, enum, "as_recorded")[:3]}


# --------------------------------------------------------------------------- optimisation


def _eval_dict(e: Evaluation, objective: str, w: graph_svc.Workspace2) -> dict[str, Any]:
    by_id = {a.id: a for a in w.actions}
    return {**e.as_dict(objective), "action_details": [by_id[a].as_dict() for a in e.action_ids]}


def _graph_only_choice(w: graph_svc.Workspace2, c: Constraints) -> tuple[Evaluation, list[str]]:
    """Optimise while ignoring provenance: declared topology/findings only, claims ignored."""
    overrides = [FactOverride(fid, "refuted" if f.declared == "not_satisfied" else "satisfied", "graph_only_ignores_provenance")
                 for fid, f in graph_svc._all_facts(w.model).items()]
    enum2 = enumerate_paths(w.model, at=w.now, overrides=overrides)
    res = optimize(w.model, enum2, w.actions, replace(c, inclusion="pessimistic"))
    return res.best, ["ignores evidence state: every declared edge and condition is taken at face value"]


def optimize_analysis(
    s: Session,
    *,
    budget: int,
    objective: str = "weighted-paths",
    downtime_cap: str | None = None,
    inclusion: str = "as_recorded",
    at: datetime | None = None,
    overrides: list[FactOverride] | None = None,
    withdraw: list[str] | None = None,
) -> dict[str, Any]:
    if objective not in OBJECTIVES:
        raise AnalysisError(f"objective must be one of {', '.join(OBJECTIVES)}")
    if inclusion not in INCLUSION:
        raise AnalysisError(f"inclusion must be one of {', '.join(INCLUSION)}")
    w = graph_svc.load(s, at=at)
    if not w.actions:
        raise AnalysisError("no remediation catalog imported: run `tiw import remediations remediations.json`")
    model = w.model
    from tiw.domain.robustness import withdraw_evidence

    for eid in withdraw or []:
        model = withdraw_evidence(model, eid)
    w = replace(w, model=model)
    c = Constraints(budget=budget, downtime_cap=downtime_cap, objective=objective, inclusion=inclusion)
    try:
        c.check()
    except PortfolioError as exc:
        raise AnalysisError(str(exc)) from None
    enum = enumerate_paths(model, at=w.now, overrides=overrides or [])
    res = optimize(model, enum, w.actions, c)
    ev = Evaluator(model, enum, w.actions, inclusion)
    counted = {p.id for p in ev.paths}
    # Baselines: same budget, same permitted actions, same constraints, judged by the same evaluator.
    baselines = []
    for name in BASELINES:
        if name == "graph_only":
            choice, notes = _graph_only_choice(w, c)
            e = ev.evaluate(choice.action_ids)
            order: list[str] = []
        else:
            e, order, notes = ranked_baseline(name, ev, w.signals, c)
        baselines.append({"name": name, "description": BASELINE_TEXT[name], **_eval_dict(e, objective, w), "ranking": order,
                          "notes": notes, "same_as_optimised": e.action_ids == res.best.action_ids,
                          "why_optimised_differs": [] if e.action_ids == res.best.action_ids else explain_choice(ev, res.best, e, objective)})
    # Re-simulate the selected portfolio on the counterfactual graph.
    rm = removal_for([ev.by_id[i] for i in res.best.action_ids], model)
    after = enumerate_paths(model, at=w.now, overrides=overrides or [], removed_edges=rm.edges, removed_findings=rm.findings, removed_ports=rm.ports)
    after_counted = {p.id for p in after.counted(inclusion)}
    resim = {"consistent": after_counted == set(res.best.surviving), "counterfactual_paths": sorted(after_counted),
             "note": "Selected portfolio re-simulated on the modified graph." + ("" if after_counted == set(res.best.surviving) else " Differences indicate enumeration truncation; treat counts as lower bounds.")}
    excluded = [_path_row(p, enum, counted, model) for p in enum.paths if p.id not in counted]
    by_path = {p.id: _path_row(p, enum, counted, model) for p in enum.paths}
    result = {
        "kind": "optimize",
        "evidence_hash": w.evidence_hash,
        "algorithm_version": ALGORITHM_VERSION,
        "clock": db.utc_iso(w.now),
        "inputs": w.inputs,
        "params": {"budget": budget, "objective": objective, "downtime_cap": downtime_cap, "inclusion": inclusion,
                   "overrides": [o.__dict__ for o in overrides or []], "withdrawn_evidence": sorted(withdraw or [])},
        "objective": {"name": objective, "semantics": OBJECTIVE_TEXT[objective], "tie_breaking": TIE_BREAKING},
        "cost_unit": w.cost_unit,
        "method": res.method,
        "exact": res.method == "exact",
        "evaluated_portfolios": res.evaluated,
        "feasible_portfolios": res.feasible,
        "before": _eval_dict(res.baseline_value, objective, w),
        "selected": _eval_dict(res.best, objective, w),
        "ties": [_eval_dict(e, objective, w) for e in res.ties],
        "alternatives": [_eval_dict(e, objective, w) for e in res.alternatives],
        "infeasible_examples": res.infeasible_examples,
        "baselines": baselines,
        "single_action_effects": single_action_effects(ev),
        "paths": [by_path[p.id] for p in enum.paths],
        "excluded_paths": excluded,
        "surviving_paths": [by_path[p] for p in res.best.surviving],
        "disrupted_paths": [by_path[p] for p in res.best.disrupted],
        "resimulation": resim,
        "truncated": enum.truncated,
        "truncation_reasons": enum.truncation_reasons,
        "reasons": _reasons(ev, res.best, baselines, objective, w),
        "facts": _evidence_rows(enum, sorted({f for p in enum.paths for f, _ in p.fact_status})),
        "assumptions": _assumptions(w, enum, inclusion),
        "synthetic": w.synthetic,
    }
    return {"result": result, "diagnostics": {"runtime_ms": res.runtime_ms}}


def _reasons(ev: Evaluator, best: Evaluation, baselines: list[dict[str, Any]], objective: str, w: graph_svc.Workspace2) -> list[dict[str, Any]]:
    """One reason entry per selected action: what it breaks and what it shares with others."""
    out = []
    sel = set(best.action_ids)
    for aid in best.action_ids:
        a = ev.by_id[aid]
        alone = [p.id for p in ev.paths if aid in ev.breakers[p.id]]
        unique = [p for p in alone if not (ev.breakers[p] & (sel - {aid}))]
        txt = f"{aid} ({a.label}, effort {a.cost}) breaks {len(alone)} counted path(s)"
        if len(alone) >= 2:
            txt += " — a shared choke point"
        if a.requires:
            txt += f"; depends on {', '.join(a.requires)}"
        if not alone and any(aid in ev.by_id[o].requires for o in sel):
            txt += "; included only because another selected action depends on it"
        out.append({"action": aid, "text": txt, "breaks": alone, "uniquely_breaks": unique, "verification_status": a.verification_status})
    cv = next((b for b in baselines if b["name"] == "cvss_desc"), None)
    if cv and not cv["same_as_optimised"]:
        out.append({"action": None, "text": "Compared with highest-CVSS-first under the same budget: " + "; ".join(cv["why_optimised_differs"]),
                    "breaks": [], "uniquely_breaks": [], "verification_status": None})
    return out


# --------------------------------------------------------------------------- robustness


def robustness_analysis(
    s: Session,
    *,
    budget: int,
    objective: str = "weighted-paths",
    downtime_cap: str | None = None,
    scenario_set: str = "default",
    stale_days: int = 90,
    extra: list[Scenario] | None = None,
    at: datetime | None = None,
) -> dict[str, Any]:
    if scenario_set not in ("default", "custom"):
        raise AnalysisError("scenario_set must be default or custom")
    w = graph_svc.load(s, at=at)
    if not w.actions:
        raise AnalysisError("no remediation catalog imported")
    c = Constraints(budget=budget, downtime_cap=downtime_cap, objective=objective)
    try:
        c.check()
    except PortfolioError as exc:
        raise AnalysisError(str(exc)) from None
    base_enum = enumerate_paths(w.model, at=w.now)
    if scenario_set == "default":
        scenarios, uncovered = default_scenarios(w.model, base_enum, w.now, w.now + timedelta(days=stale_days))
    else:
        scenarios, uncovered = [Scenario("S-as-recorded", "as_recorded", "As recorded")], []
    scenarios += extra or []
    outcomes: list[ScenarioOutcome] = []
    base_res = None
    base_enum_used = None
    for sc in scenarios:
        enum, res, ev = run_scenario(w.model, w.actions, c, sc, w.now)
        if sc.kind == "as_recorded" and base_res is None:
            base_res, base_enum_used = res, enum
        outcomes.append(ScenarioOutcome(sc, enum, res, ev, same_portfolio=False))
    assert base_res is not None and base_enum_used is not None
    rows = []
    for o in outcomes:
        o.same_portfolio = o.result.best.action_ids == base_res.best.action_ids
        o.flips = [] if o.scenario.kind == "as_recorded" else explain_flip(base_enum_used, o.enum, "as_recorded", o.scenario.inclusion)
        reasons = _flip_reasons(o, base_res, objective, w)
        rows.append({
            "scenario": o.scenario.as_dict(),
            "selected": list(o.result.best.action_ids),
            "objective_value": o.result.best.objective(objective),
            "before_value": o.result.baseline_value.objective(objective),
            "effort": o.result.best.cost,
            "same_portfolio": o.same_portfolio,
            "counted_paths": len(o.evaluator.paths),
            "path_changes": o.flips,
            "flip_reasons": reasons,
            "method": o.result.method,
        })
    summary = stability_summary(outcomes)
    result = {
        "kind": "robustness",
        "evidence_hash": w.evidence_hash,
        "algorithm_version": ALGORITHM_VERSION,
        "clock": db.utc_iso(w.now),
        "inputs": w.inputs,
        "params": {"budget": budget, "objective": objective, "downtime_cap": downtime_cap, "scenario_set": scenario_set, "stale_days": stale_days},
        "objective": {"name": objective, "semantics": OBJECTIVE_TEXT[objective], "tie_breaking": TIE_BREAKING},
        "as_recorded": list(base_res.best.action_ids),
        "scenarios": rows,
        "summary": summary,
        "uncovered": uncovered,
        "scenario_kinds": SCENARIO_TEXT,
        "disclaimer": "Scenario counts are counts of constructed cases. They are not probabilities or confidence scores.",
        "assumptions": _assumptions(w, base_enum, "as_recorded"),
        "synthetic": w.synthetic,
    }
    return {"result": result, "diagnostics": {}}


def _flip_reasons(o: ScenarioOutcome, base: Any, objective: str, w: graph_svc.Workspace2) -> list[str]:
    if o.scenario.kind == "as_recorded":
        return []
    out: list[str] = []
    for ch in o.flips:
        facts = "; ".join(
            f"{f['fact_id']} {f['before']}→{f['after']}"
            + (f" (evidence: {', '.join(f['evidence_ids'])})" if f["evidence_ids"] else "")
            for f in ch["facts"]
        )
        counted = ""
        if ch["counted_before"] != ch["counted_after"]:
            counted = " — now counted" if ch["counted_after"] else " — no longer counted"
        why = facts or ("inclusion policy " + o.scenario.inclusion if ch["inclusion_change"] else "")
        out.append(f"{ch['path_id']}: {ch['before']}→{ch['after']}{counted}" + (f" because {why}" if why else ""))
    if not o.same_portfolio:
        out.insert(0, f"Recommendation changes from {' + '.join(base.best.action_ids) or 'no action'} to "
                      f"{' + '.join(o.result.best.action_ids) or 'no action'} ({objective} {base.best.objective(objective)} → {o.result.best.objective(objective)})")
    elif o.flips:
        out.insert(0, "Recommendation unchanged although path statuses changed")
    return out


# --------------------------------------------------------------------------- recorded runs


def record(ws: db.Workspace, kind: str, run_key: str, payload: dict[str, Any], actor: str) -> tuple[AnalysisRun, bool, dict[str, Any] | None]:
    """Append an analysis run. Identical result for the same run key is not duplicated."""
    result = payload["result"]
    rhash = canonical_hash(result)
    with db.session_scope(ws) as s:
        prev = s.execute(select(AnalysisRun).where(AnalysisRun.run_key == run_key).order_by(AnalysisRun.seq.desc()).limit(1)).scalar_one_or_none()
        if prev is not None and prev.result_hash == rhash:
            return prev, False, None
        run = AnalysisRun(
            kind=kind, run_key=run_key, created_at=db.now(s), evidence_hash=result.get("evidence_hash", ""),
            algorithm_version=result.get("algorithm_version", ALGORITHM_VERSION), params_json=result.get("params", {}),
            result_json=result, result_hash=rhash, previous_id=prev.id if prev else None, actor=actor,
            seq=next_seq(s, AnalysisRun),
        )
        s.add(run)
        s.flush()
        audit(s, actor, "analysis_run", "analysis_run", run.id, {"kind": kind, "run_key": run_key, "result_hash": rhash})
        diff = run_diff(prev.result_json, result) if prev else None
        return run, True, diff


def run_key(kind: str, params: dict[str, Any]) -> str:
    if kind == "graph":
        return "graph"
    parts = [kind, params.get("objective", "weighted-paths"), f"b{params.get('budget')}", f"d{params.get('downtime_cap') or 'any'}"]
    if kind == "optimize":
        parts.append(params.get("inclusion", "as_recorded"))
    else:
        parts.append(params.get("scenario_set", "default"))
    return ":".join(str(p) for p in parts)


def run_diff(prev: dict[str, Any], cur: dict[str, Any]) -> dict[str, Any]:
    """Before/after decision diff between two recorded runs of the same analysis."""
    out: dict[str, Any] = {"evidence_changed": prev.get("evidence_hash") != cur.get("evidence_hash"), "inputs_changed": [], "why": []}
    for k in sorted(set(prev.get("inputs", {})) | set(cur.get("inputs", {}))):
        a, b = prev.get("inputs", {}).get(k, {}).get("content_hash"), cur.get("inputs", {}).get(k, {}).get("content_hash")
        if a != b:
            out["inputs_changed"].append(k)
    if cur.get("kind") == "optimize":
        pa, ca = prev["selected"]["actions"], cur["selected"]["actions"]
        out["actions_added"] = sorted(set(ca) - set(pa))
        out["actions_removed"] = sorted(set(pa) - set(ca))
        out["portfolio_changed"] = pa != ca
        out["objective_before"] = prev["selected"]["objective_value"]
        out["objective_after"] = cur["selected"]["objective_value"]
        pp = {p["id"]: p for p in prev.get("paths", [])}
        cp = {p["id"]: p for p in cur.get("paths", [])}
        changes = []
        for pid in sorted(set(pp) | set(cp)):
            a, b = pp.get(pid), cp.get(pid)
            sa = (a["status"], a["counted"]) if a else ("absent", False)
            sb = (b["status"], b["counted"]) if b else ("absent", False)
            if sa == sb:
                continue
            fa, fb = (a or {}).get("facts", {}), (b or {}).get("facts", {})
            facts = [{"fact_id": f, "before": fa.get(f, "absent"), "after": fb.get(f, "absent")} for f in sorted(set(fa) | set(fb)) if fa.get(f) != fb.get(f)]
            changes.append({"path_id": pid, "before": sa[0], "after": sb[0], "counted_before": sa[1], "counted_after": sb[1], "facts": facts})
        out["path_changes"] = changes
        if out["portfolio_changed"]:
            out["why"].append(f"Portfolio changed from {' + '.join(pa) or 'no action'} to {' + '.join(ca) or 'no action'}.")
        for ch in changes:
            fx = ", ".join(f"{f['fact_id']} {f['before']}→{f['after']}" for f in ch["facts"])
            cnt = " (now counted)" if ch["counted_after"] and not ch["counted_before"] else " (no longer counted)" if ch["counted_before"] and not ch["counted_after"] else ""
            out["why"].append(f"{ch['path_id']} {ch['before']}→{ch['after']}{cnt}" + (f": {fx}" if fx else ""))
        out["fact_reasons"] = _fact_reason_changes(prev, cur, {f["fact_id"] for ch in changes for f in ch["facts"]})
    elif cur.get("kind") == "robustness":
        out["as_recorded_before"] = prev.get("as_recorded")
        out["as_recorded_after"] = cur.get("as_recorded")
        out["portfolio_changed"] = prev.get("as_recorded") != cur.get("as_recorded")
    if not out["why"] and out.get("portfolio_changed") is False:
        out["why"].append("Recommendation unchanged.")
    return out


def _fact_reason_changes(prev: dict[str, Any], cur: dict[str, Any], fact_ids: set[str]) -> list[dict[str, Any]]:
    """Explain fact status changes from the evidence recorded inside the runs (claims retracted etc.)."""
    del prev
    out = []
    facts = {f["fact_id"]: f for f in cur.get("facts", [])}
    for fid in sorted(fact_ids):
        f = facts.get(fid)
        if f:
            out.append({"fact_id": fid, "status": f["status"], "reasons": f["reasons"],
                        "evidence": [{k: e[k] for k in ("id", "claim_key", "kind", "polarity", "active", "inactive_reason", "label")} for e in f["evidence"]]})
    return out


def latest_runs(s: Session, limit: int = 50) -> list[AnalysisRun]:
    return list(s.execute(select(AnalysisRun).order_by(AnalysisRun.seq.desc()).limit(limit)).scalars())


def latest_run_for(s: Session, key: str) -> AnalysisRun | None:
    return s.execute(select(AnalysisRun).where(AnalysisRun.run_key == key).order_by(AnalysisRun.seq.desc()).limit(1)).scalar_one_or_none()


def run_with_diff(s: Session, run_id: str) -> dict[str, Any] | None:
    run = s.get(AnalysisRun, run_id)
    if run is None:
        return None
    prev = s.get(AnalysisRun, run.previous_id) if run.previous_id else None
    return {"run": run_meta(run), "result": run.result_json, "previous": run_meta(prev) if prev else None,
            "diff": run_diff(prev.result_json, run.result_json) if prev else None}


def run_meta(r: AnalysisRun) -> dict[str, Any]:
    return {"id": r.id, "seq": r.seq, "kind": r.kind, "run_key": r.run_key, "created_at": db.utc_iso(r.created_at),
            "evidence_hash": r.evidence_hash, "algorithm_version": r.algorithm_version, "result_hash": r.result_hash,
            "previous_id": r.previous_id, "actor": r.actor, "params": r.params_json}

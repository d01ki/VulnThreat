"""Counterfactual remediation: action effects, portfolio feasibility, exact/approximate optimizer, baselines.

Objective semantics (documented, not a risk score)
--------------------------------------------------
``weighted-paths``   sum over *counted* surviving model paths of the configured weight of the
                     path's security objective. Path counts are a proxy that depends on graph
                     granularity and on the enumeration limits.
``reachable-targets`` number of security objectives that still have at least one counted path.

Lower is better. Ties are broken deterministically by: objective, then (other objective),
then total effort, then downtime rank, then number of actions, then sorted action ids.

Action effects only *remove* graph elements (edges, ports, findings), so the surviving path set
of a portfolio is exactly the set of enumerated paths none of whose hops is removed -- the
combined effect of the set, not a sum of individual effects. Because enumeration can be
truncated, the selected portfolio is re-simulated on the counterfactual graph and any
difference is reported.
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from tiw.domain.attack_graph import Enumeration, GraphModel, Path, matching_ports

OPTIMIZER_VERSION = "portfolio-1"
ACTION_TYPES = ("patch_finding", "disable_service", "restrict_edge", "isolate_asset", "enabler")
DOWNTIME = ("none", "low", "high")
DOWNTIME_RANK = {"none": 0, "low": 1, "high": 2}
OBJECTIVES = ("weighted-paths", "reachable-targets")
EXACT_MAX_ACTIONS = 16
BASELINES = ("cvss_desc", "epss_desc", "kev_first", "criticality_exposure", "graph_only")
BASELINE_TEXT = {
    "cvss_desc": "Highest CVSS base score first (actions without CVSS last)",
    "epss_desc": "Highest EPSS first (actions without EPSS last)",
    "kev_first": "KEV-listed first, then CVSS",
    "criticality_exposure": "Asset criticality, then internet exposure",
    "graph_only": "Graph optimisation without provenance or robustness (every recorded edge treated as allowed, claims ignored)",
}


class PortfolioError(ValueError):
    pass


@dataclass(frozen=True)
class Action:
    id: str
    type: str
    label: str
    cost: int
    downtime: str = "none"
    finding_id: str | None = None
    edge_id: str | None = None
    asset_id: str | None = None
    ports: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    conflict_group: str | None = None
    verification_status: str = "unverified"  # verified / unverified
    preconditions: tuple[str, ...] = ()
    notes: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "cost": self.cost,
            "downtime": self.downtime,
            "finding_id": self.finding_id,
            "edge_id": self.edge_id,
            "asset_id": self.asset_id,
            "ports": list(self.ports),
            "requires": list(self.requires),
            "conflict_group": self.conflict_group,
            "verification_status": self.verification_status,
            "preconditions": list(self.preconditions),
        }


@dataclass(frozen=True)
class Removal:
    edges: frozenset[str] = frozenset()
    findings: frozenset[str] = frozenset()
    ports: frozenset[tuple[str, str]] = frozenset()


def removal_for(actions: Iterable[Action], model: GraphModel) -> Removal:
    edges: set[str] = set()
    findings: set[str] = set()
    ports: set[tuple[str, str]] = set()
    for a in actions:
        if a.type == "patch_finding" and a.finding_id:
            findings.add(a.finding_id)
        elif a.type == "restrict_edge" and a.edge_id:
            edges.add(a.edge_id)
        elif a.type == "disable_service" and a.asset_id:
            for p in a.ports:
                ports.add((a.asset_id, p))
        elif a.type == "isolate_asset" and a.asset_id:
            edges.update(e.id for e in model.edges if a.asset_id in (e.source, e.target))
    return Removal(frozenset(edges), frozenset(findings), frozenset(ports))


def breaks(action: Action, path: Path, model: GraphModel) -> bool:
    r = removal_for([action], model)
    for h in path.hops:
        if h.edge_id in r.edges:
            return True
        if h.via.startswith("finding:") and h.via[8:] in r.findings:
            return True
        if r.ports and h.via.startswith("finding:"):
            x = next((x for x in model.exploits if x.finding_id == h.via[8:]), None)
            edge = next((e for e in model.edges if e.id == h.edge_id), None)
            if x and edge:
                open_ports = {p for p in edge.ports if (edge.target, p) not in r.ports}
                if not matching_ports(x.service_ports, open_ports):
                    return True
    return False


def validate_actions(actions: list[Action], model: GraphModel) -> None:
    ids = [a.id for a in actions]
    if len(ids) != len(set(ids)):
        raise PortfolioError("duplicate action id")
    known = set(ids)
    findings = {x.finding_id for x in model.exploits}
    edges = {e.id for e in model.edges}
    for a in actions:
        if a.type not in ACTION_TYPES:
            raise PortfolioError(f"action {a.id}: unknown type {a.type}")
        if not isinstance(a.cost, int) or isinstance(a.cost, bool) or a.cost < 0:
            raise PortfolioError(f"action {a.id}: cost must be a non-negative integer")
        if a.downtime not in DOWNTIME:
            raise PortfolioError(f"action {a.id}: downtime must be one of {', '.join(DOWNTIME)}")
        if a.type == "patch_finding" and a.finding_id not in findings:
            raise PortfolioError(f"action {a.id}: unknown finding {a.finding_id}")
        if a.type == "restrict_edge" and a.edge_id not in edges:
            raise PortfolioError(f"action {a.id}: unknown edge {a.edge_id}")
        if a.type in ("disable_service", "isolate_asset") and a.asset_id not in model.nodes:
            raise PortfolioError(f"action {a.id}: unknown asset {a.asset_id}")
        for r in a.requires:
            if r not in known:
                raise PortfolioError(f"action {a.id}: requires unknown action {r}")
            if r == a.id:
                raise PortfolioError(f"action {a.id}: requires itself")
    # dependency cycles
    by_id = {a.id: a for a in actions}
    for a in actions:
        seen, todo = set(), list(a.requires)
        while todo:
            x = todo.pop()
            if x == a.id:
                raise PortfolioError(f"action {a.id}: dependency cycle")
            if x not in seen:
                seen.add(x)
                todo.extend(by_id[x].requires)


@dataclass(frozen=True)
class Constraints:
    budget: int
    downtime_cap: str | None = None  # none / low / high (max allowed per action)
    objective: str = "weighted-paths"
    inclusion: str = "as_recorded"

    def check(self) -> None:
        if not isinstance(self.budget, int) or isinstance(self.budget, bool) or self.budget < 0:
            raise PortfolioError("budget must be a non-negative integer")
        if self.downtime_cap is not None and self.downtime_cap not in DOWNTIME:
            raise PortfolioError(f"downtime_cap must be one of {', '.join(DOWNTIME)}")
        if self.objective not in OBJECTIVES:
            raise PortfolioError(f"objective must be one of {', '.join(OBJECTIVES)}")


def infeasibility(portfolio: Iterable[Action], c: Constraints) -> list[str]:
    acts = list(portfolio)
    ids = {a.id for a in acts}
    out: list[str] = []
    cost = sum(a.cost for a in acts)
    if cost > c.budget:
        out.append(f"effort {cost} exceeds budget {c.budget}")
    for a in acts:
        missing = [r for r in a.requires if r not in ids]
        if missing:
            out.append(f"{a.id} requires {', '.join(missing)}")
        if c.downtime_cap is not None and DOWNTIME_RANK[a.downtime] > DOWNTIME_RANK[c.downtime_cap]:
            out.append(f"{a.id} downtime {a.downtime} exceeds cap {c.downtime_cap}")
    groups: dict[str, list[str]] = {}
    for a in acts:
        if a.conflict_group:
            groups.setdefault(a.conflict_group, []).append(a.id)
    for g, members in sorted(groups.items()):
        if len(members) > 1:
            out.append(f"conflict group {g}: {', '.join(sorted(members))} cannot be combined")
    return out


@dataclass
class Evaluation:
    action_ids: tuple[str, ...]
    cost: int
    downtime_rank: int
    weighted_paths: int
    reachable_targets: int
    surviving: list[str]
    disrupted: list[str]

    def objective(self, name: str) -> int:
        return self.weighted_paths if name == "weighted-paths" else self.reachable_targets

    def key(self, name: str) -> tuple[Any, ...]:
        other = self.reachable_targets if name == "weighted-paths" else self.weighted_paths
        return (self.objective(name), other, self.cost, self.downtime_rank, len(self.action_ids), self.action_ids)

    def as_dict(self, objective: str) -> dict[str, Any]:
        return {
            "actions": list(self.action_ids),
            "effort": self.cost,
            "objective": objective,
            "objective_value": self.objective(objective),
            "weighted_paths": self.weighted_paths,
            "reachable_targets": self.reachable_targets,
            "surviving_paths": self.surviving,
            "disrupted_paths": self.disrupted,
        }


class Evaluator:
    """Precomputes, for each counted path, which actions break it; evaluates sets exactly."""

    def __init__(self, model: GraphModel, enum: Enumeration, actions: list[Action], inclusion: str):
        self.model = model
        self.enum = enum
        self.actions = sorted(actions, key=lambda a: a.id)
        self.by_id = {a.id: a for a in self.actions}
        self.paths = enum.counted(inclusion)
        self.weight = {o.id: o.weight for o in model.objectives}
        self.breakers: dict[str, frozenset[str]] = {
            p.id: frozenset(a.id for a in self.actions if breaks(a, p, model)) for p in self.paths
        }

    def evaluate(self, ids: Iterable[str]) -> Evaluation:
        sel = tuple(sorted(set(ids)))
        sset = set(sel)
        surviving = [p for p in self.paths if not (self.breakers[p.id] & sset)]
        disrupted = [p.id for p in self.paths if self.breakers[p.id] & sset]
        acts = [self.by_id[i] for i in sel]
        return Evaluation(
            action_ids=sel,
            cost=sum(a.cost for a in acts),
            downtime_rank=max((DOWNTIME_RANK[a.downtime] for a in acts), default=0),
            weighted_paths=sum(self.weight.get(p.objective_id, 0) for p in surviving),
            reachable_targets=len({p.objective_id for p in surviving}),
            surviving=[p.id for p in surviving],
            disrupted=disrupted,
        )


@dataclass
class OptimizeResult:
    method: str  # exact / approximate-greedy
    constraints: Constraints
    best: Evaluation
    baseline_value: Evaluation  # no action
    alternatives: list[Evaluation]
    ties: list[Evaluation]
    evaluated: int
    feasible: int
    runtime_ms: float
    infeasible_examples: list[dict[str, Any]] = field(default_factory=list)
    resimulation: dict[str, Any] = field(default_factory=dict)


def _closure(ids: Iterable[str], by_id: dict[str, Action]) -> set[str]:
    out, todo = set(), list(ids)
    while todo:
        x = todo.pop()
        if x not in out:
            out.add(x)
            todo.extend(by_id[x].requires)
    return out


def optimize(
    model: GraphModel,
    enum: Enumeration,
    actions: list[Action],
    c: Constraints,
    *,
    max_alternatives: int = 5,
    time_budget_s: float = 5.0,
    force_method: str | None = None,
) -> OptimizeResult:
    c.check()
    validate_actions(actions, model)
    t0 = time.perf_counter()
    ev = Evaluator(model, enum, actions, c.inclusion)
    none = ev.evaluate(())
    # Actions over the downtime cap can never be part of a feasible portfolio.
    eligible = [a for a in ev.actions if c.downtime_cap is None or DOWNTIME_RANK[a.downtime] <= DOWNTIME_RANK[c.downtime_cap]]
    method = force_method or ("exact" if len(eligible) <= EXACT_MAX_ACTIONS else "approximate-greedy")
    feasible: list[Evaluation] = []
    evaluated = 0
    infeasible_examples: list[dict[str, Any]] = []
    if method == "exact":
        ids = [a.id for a in eligible]
        for r in range(len(ids) + 1):
            for combo in itertools.combinations(ids, r):
                evaluated += 1
                acts = [ev.by_id[i] for i in combo]
                probs = infeasibility(acts, c)
                if probs:
                    if len(infeasible_examples) < 5 and sum(a.cost for a in acts) <= c.budget:
                        infeasible_examples.append({"actions": list(combo), "reasons": probs})
                    continue
                feasible.append(ev.evaluate(combo))
    else:
        chosen: set[str] = set()
        deadline = t0 + time_budget_s
        while time.perf_counter() < deadline:
            current = ev.evaluate(chosen)
            best_gain: tuple[Any, ...] | None = None
            best_set: set[str] | None = None
            for a in eligible:
                if a.id in chosen:
                    continue
                cand = chosen | _closure([a.id], ev.by_id)
                acts = [ev.by_id[i] for i in cand]
                evaluated += 1
                if infeasibility(acts, c):
                    continue
                e = ev.evaluate(cand)
                gain = current.objective(c.objective) - e.objective(c.objective)
                added = max(1, e.cost - current.cost)
                k = (-gain / added, e.key(c.objective))
                if gain > 0 and (best_gain is None or k < best_gain):
                    best_gain, best_set = k, cand
            if best_set is None:
                break
            chosen = best_set
        feasible = [ev.evaluate(chosen), none]
    feasible.sort(key=lambda e: e.key(c.objective))
    best = feasible[0] if feasible else none
    ties = [e for e in feasible[1:] if e.objective(c.objective) == best.objective(c.objective) and e.cost == best.cost]
    alts: list[Evaluation] = []
    seen = {best.action_ids}
    for e in feasible[1:]:
        if e.action_ids in seen or not e.action_ids:
            continue
        seen.add(e.action_ids)
        alts.append(e)
        if len(alts) >= max_alternatives:
            break
    return OptimizeResult(
        method=method,
        constraints=c,
        best=best,
        baseline_value=none,
        alternatives=alts,
        ties=ties,
        evaluated=evaluated,
        feasible=len(feasible),
        runtime_ms=round((time.perf_counter() - t0) * 1000, 2),
        infeasible_examples=infeasible_examples,
    )


# --------------------------------------------------------------------------- baselines


@dataclass(frozen=True)
class ActionSignals:
    """Per-action signals used only by the heuristic baselines (never by the optimiser)."""

    cvss: float | None
    epss: float | None
    kev: bool | None
    criticality_rank: int | None  # 0 = critical
    exposed: bool | None


def ranked_baseline(
    name: str,
    ev: Evaluator,
    signals: dict[str, ActionSignals],
    c: Constraints,
) -> tuple[Evaluation, list[str], list[str]]:
    """Greedy pick in ranking order under the same budget/constraints. Returns (eval, order, notes)."""

    def key(a: Action) -> tuple[Any, ...]:
        s = signals.get(a.id) or ActionSignals(None, None, None, None, None)
        if name == "cvss_desc":
            return (s.cvss is None, -(s.cvss or 0.0), a.cost, a.id)
        if name == "epss_desc":
            return (s.epss is None, -(s.epss or 0.0), a.cost, a.id)
        if name == "kev_first":
            return (not bool(s.kev), s.cvss is None, -(s.cvss or 0.0), a.cost, a.id)
        if name == "criticality_exposure":
            return (s.criticality_rank if s.criticality_rank is not None else 9, not bool(s.exposed), a.cost, a.id)
        raise PortfolioError(f"unknown baseline {name}")

    notes: list[str] = []
    order = sorted(ev.actions, key=key)
    missing = [a.id for a in order if _signal_missing(name, signals.get(a.id))]
    if missing:
        notes.append(f"{len(missing)} action(s) lack the ranking signal and were ranked last: {', '.join(missing)}")
    chosen: list[str] = []
    for a in order:
        cand = chosen + [a.id]
        if infeasibility([ev.by_id[i] for i in cand], c):
            # try adding missing dependencies first
            deps = [r for r in sorted(_closure([a.id], ev.by_id)) if r not in chosen and r != a.id]
            cand2 = chosen + deps + [a.id]
            if deps and not infeasibility([ev.by_id[i] for i in cand2], c):
                chosen = cand2
            continue
        chosen = cand
    return ev.evaluate(chosen), [a.id for a in order], notes


def _signal_missing(name: str, s: ActionSignals | None) -> bool:
    if s is None:
        return True
    return {
        "cvss_desc": s.cvss is None,
        "epss_desc": s.epss is None,
        "kev_first": s.kev is None,
        "criticality_exposure": s.criticality_rank is None,
    }.get(name, False)


def explain_choice(ev: Evaluator, chosen: Evaluation, other: Evaluation, objective: str) -> list[str]:
    """Plain-language reasons why ``chosen`` beats ``other`` (both under the same constraints)."""
    out: list[str] = []
    only_chosen = sorted(set(chosen.disrupted) - set(other.disrupted))
    only_other = sorted(set(other.disrupted) - set(chosen.disrupted))
    if only_chosen:
        out.append(f"Breaks {len(only_chosen)} path(s) the alternative leaves open: {', '.join(only_chosen)}")
    if only_other:
        out.append(f"Leaves {len(only_other)} path(s) open that the alternative breaks: {', '.join(only_other)}")
    for aid in chosen.action_ids:
        n = sum(1 for p in ev.paths if aid in ev.breakers[p.id])
        if n >= 2:
            out.append(f"{aid} is a shared choke point: on its own it breaks {n} counted paths")
    d = other.objective(objective) - chosen.objective(objective)
    out.append(
        f"{objective}: {chosen.objective(objective)} vs {other.objective(objective)} "
        f"({'better by ' + str(d) if d > 0 else 'equal' if d == 0 else 'worse by ' + str(-d)}); effort {chosen.cost} vs {other.cost}"
    )
    return out


def single_action_effects(ev: Evaluator) -> list[dict[str, Any]]:
    out = []
    for a in ev.actions:
        broken = [p.id for p in ev.paths if a.id in ev.breakers[p.id]]
        out.append({"action": a.id, "cost": a.cost, "breaks": broken, "count": len(broken)})
    return out


Ranker = Callable[[Action], tuple[Any, ...]]

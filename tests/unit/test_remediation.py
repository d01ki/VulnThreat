from __future__ import annotations

import itertools
import random

import pytest

from tiw.domain.attack_graph import GraphModel, Limits, Node, Objective, enumerate_paths
from tiw.domain.remediation import (
    ActionSignals,
    Constraints,
    Evaluator,
    PortfolioError,
    infeasibility,
    optimize,
    ranked_baseline,
    validate_actions,
)
from v2_helpers import NOW, act, chain_model, edge, vuln


def _setup():
    m = chain_model()
    enum = enumerate_paths(m, at=NOW)
    actions = [
        act("A-a", 1, finding_id="f-a"),
        act("A-b", 1, finding_id="f-b"),
        act("A-c", 2, finding_id="f-c"),
        act("A-edge", 1, type="restrict_edge", edge_id="e-ac"),
    ]
    return m, enum, actions


def test_combined_effect_and_choke_point():
    m, enum, actions = _setup()
    res = optimize(m, enum, actions, Constraints(budget=2))
    assert res.method == "exact"
    assert res.best.weighted_paths == 0
    # two portfolios reach 0 with effort 2; tie-break prefers fewer actions
    assert res.best.action_ids == ("A-c",)
    assert any(t.action_ids == ("A-a", "A-b") for t in res.ties)
    ev = Evaluator(m, enum, actions, "as_recorded")
    # overlapping effects are not additive: A-a and A-edge both break the same path
    assert ev.evaluate(["A-a", "A-edge"]).weighted_paths == ev.evaluate(["A-a"]).weighted_paths


def test_zero_and_insufficient_budget():
    m, enum, actions = _setup()
    r0 = optimize(m, enum, actions, Constraints(budget=0))
    assert r0.best.action_ids == () and r0.best.weighted_paths == 6
    r1 = optimize(m, enum, actions, Constraints(budget=1))
    assert r1.best.weighted_paths == 3


def test_dependencies_conflicts_and_downtime():
    m, enum, _ = _setup()
    actions = [
        act("A-proxy", 1, type="enabler"),
        act("A-c", 1, finding_id="f-c", requires=("A-proxy",)),
        act("A-a", 1, finding_id="f-a", conflict_group="g"),
        act("A-b", 1, finding_id="f-b", conflict_group="g", downtime="high"),
    ]
    assert infeasibility([actions[1]], Constraints(budget=5)) == ["A-c requires A-proxy"]
    assert "conflict group g" in infeasibility([actions[2], actions[3]], Constraints(budget=5))[0]
    res = optimize(m, enum, actions, Constraints(budget=2))
    assert res.best.action_ids == ("A-c", "A-proxy")
    res = optimize(m, enum, actions, Constraints(budget=1))
    assert res.best.weighted_paths == 3  # A-c alone is infeasible; A-a/A-b each break one path
    res = optimize(m, enum, actions, Constraints(budget=1, downtime_cap="low"))
    assert res.best.action_ids == ("A-a",)


@pytest.mark.parametrize(
    "bad,msg",
    [
        (act("x", -1, finding_id="f-a"), "non-negative"),
        (act("x", 1, finding_id="nope"), "unknown finding"),
        (act("x", 1, requires=("ghost",), finding_id="f-a"), "unknown action"),
    ],
)
def test_action_validation(bad, msg):
    m, _, _ = _setup()
    with pytest.raises(PortfolioError, match=msg):
        validate_actions([bad], m)


def test_dependency_cycle_rejected():
    m, _, _ = _setup()
    with pytest.raises(PortfolioError, match="cycle"):
        validate_actions([act("x", 1, type="enabler", requires=("y",)), act("y", 1, type="enabler", requires=("x",))], m)


def test_exact_matches_brute_force_on_random_small_graphs():
    rng = random.Random(7)
    for _ in range(15):
        n = 6
        nodes = {f"n{i}": Node(f"n{i}", "asset", f"n{i}") for i in range(n)}
        nodes["inet"] = Node("inet", "entry_point", "i")
        edges = [edge(f"ei{i}", "inet", f"n{i}") for i in range(2)]
        edges += [edge(f"e{i}-{j}", f"n{i}", f"n{j}") for i in range(n) for j in range(n) if i != j and rng.random() < 0.35]
        exploits = [vuln(f"f{i}", f"n{i}") for i in range(n)]
        m = GraphModel(nodes, edges, exploits, [Objective("O1", "n5", "O1", 3), Objective("O2", "n4", "O2", 1)], Limits())
        enum = enumerate_paths(m, at=NOW)
        actions = [act(f"A{i}", rng.randint(1, 3), finding_id=f"f{i}") for i in range(n)]
        actions += [act(f"R{k}", rng.randint(1, 2), type="restrict_edge", edge_id=e.id) for k, e in enumerate(edges[:4])]
        budget = rng.randint(0, 5)
        res = optimize(m, enum, actions, Constraints(budget=budget))
        ev = Evaluator(m, enum, actions, "as_recorded")
        best = min(
            (ev.evaluate(c).weighted_paths for r in range(len(actions) + 1) for c in itertools.combinations([a.id for a in actions], r)
             if sum(ev.by_id[i].cost for i in c) <= budget),
        )
        assert res.best.weighted_paths == best
        greedy = optimize(m, enum, actions, Constraints(budget=budget), force_method="approximate-greedy")
        assert greedy.best.weighted_paths >= best and greedy.best.cost <= budget


def test_monotone_in_budget_for_removal_only_effects():
    m, enum, actions = _setup()
    vals = [optimize(m, enum, actions, Constraints(budget=b)).best.weighted_paths for b in range(5)]
    assert vals == sorted(vals, reverse=True)


def test_baselines_use_same_budget_and_report_missing_signals():
    m, enum, actions = _setup()
    ev = Evaluator(m, enum, actions, "as_recorded")
    signals = {"A-a": ActionSignals(9.8, 0.5, False, 1, True), "A-b": ActionSignals(9.1, 0.1, True, 1, True),
               "A-c": ActionSignals(6.0, None, False, 0, False)}
    e, order, notes = ranked_baseline("cvss_desc", ev, signals, Constraints(budget=2))
    assert e.action_ids == ("A-a", "A-b") and e.cost <= 2
    assert order[0] == "A-a" and any("A-edge" in n for n in notes)
    e2, _, _ = ranked_baseline("kev_first", ev, signals, Constraints(budget=1))
    assert e2.action_ids == ("A-b",)


def test_objective_reachable_targets():
    m, enum, actions = _setup()
    res = optimize(m, enum, actions, Constraints(budget=1, objective="reachable-targets"))
    assert res.best.reachable_targets == 1
    with pytest.raises(PortfolioError):
        Constraints(budget=-1).check()

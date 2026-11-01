from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from tiw.domain.attack_graph import (
    Fact,
    FactOverride,
    GraphInputError,
    GraphModel,
    Limits,
    Node,
    Objective,
    enumerate_paths,
)
from v2_helpers import NOW, chain_model, edge, ev, fact, vuln


def _routes(enum):
    return sorted(tuple(p.nodes) for p in enum.paths)


def test_two_paths_through_choke_point_and_direction():
    m = chain_model()
    enum = enumerate_paths(m, at=NOW)
    assert _routes(enum) == [("inet", "a", "c"), ("inet", "b", "c")]
    assert all(p.status == "supported" for p in enum.paths)
    # reversing an edge removes the path that relied on its direction
    m.edges[2] = edge("e-ac", "c", "a")
    assert _routes(enumerate_paths(m, at=NOW)) == [("inet", "b", "c")]


def test_cycles_terminate_and_paths_are_simple():
    m = chain_model()
    m.edges += [edge("e-ab", "a", "b"), edge("e-ba", "b", "a")]
    enum = enumerate_paths(m, at=NOW)
    assert not enum.truncated
    for p in enum.paths:
        assert len(p.nodes) == len(set(p.nodes))
    assert ("inet", "a", "b", "c") in _routes(enum)


@pytest.mark.parametrize(
    "facts,expected",
    [
        ((ev("x"),), "satisfied"),
        ((ev("x", "refutes"),), "refuted"),
        ((ev("x"), ev("y", "refutes")), "disputed"),
        ((ev("x", active=False),), "unsupported"),
        ((), "unknown"),
    ],
)
def test_fact_resolution(facts, expected):
    declared = "unknown" if not facts else "satisfied"
    assert Fact("f", "reachability", "f", declared, facts).resolve(NOW)[0] == expected


def test_unknown_is_never_false_or_safe():
    # an expired support or a withdrawn refutation becomes unknown, never refuted
    f1 = Fact("f", "reachability", "f", "satisfied", (ev("x", expires=NOW - timedelta(days=1)),))
    assert f1.resolve(NOW)[0] == "unknown"
    f2 = Fact("f", "reachability", "f", "not_satisfied", (ev("x", "refutes", active=False),))
    assert f2.resolve(NOW)[0] == "unknown"


def test_path_statuses_and_refuted_edges_block():
    m = chain_model()
    m.edges[2] = edge("e-ac", "a", "c", f=fact("edge:e-ac", "unknown"))
    m.edges[3] = edge("e-bc", "b", "c", f=fact("edge:e-bc", "satisfied", ev("s"), ev("r", "refutes")))
    enum = enumerate_paths(m, at=NOW)
    st = {tuple(p.nodes): p.status for p in enum.paths}
    assert st == {("inet", "a", "c"): "conditional", ("inet", "b", "c"): "contradicted"}
    m.edges[3] = edge("e-bc", "b", "c", f=fact("edge:e-bc", "not_satisfied", ev("r", "refutes")))
    enum = enumerate_paths(m, at=NOW)
    assert _routes(enum) == [("inet", "a", "c")]
    assert enum.blocked and enum.blocked[0]["edge_id"] == "e-bc"


def test_retracted_only_support_gives_insufficient_evidence_and_is_excluded_as_recorded():
    m = chain_model()
    m.edges[2] = edge("e-ac", "a", "c", f=fact("edge:e-ac", "satisfied", ev("claim:k", active=False)))
    enum = enumerate_paths(m, at=NOW)
    st = {tuple(p.nodes): p.status for p in enum.paths}
    assert st[("inet", "a", "c")] == "insufficient_evidence"
    assert {tuple(p.nodes) for p in enum.counted("as_recorded")} == {("inet", "b", "c")}
    assert len(enum.counted("pessimistic")) == 2


def test_overrides_do_not_mutate_model():
    m = chain_model()
    before = [e.reachability for e in m.edges]
    enum = enumerate_paths(m, at=NOW, overrides=[FactOverride("edge:e-ac", "unknown", "t")])
    assert {p.status for p in enum.paths} == {"supported", "conditional"}
    assert [e.reachability for e in m.edges] == before


def test_port_and_capability_preconditions():
    m = chain_model()
    m.exploits[2] = vuln("f-c", "c", port="tcp/5432", grants="data_access")
    assert enumerate_paths(m, at=NOW).paths == []  # service port not reachable on any edge


def test_truncation_reported():
    m = chain_model(Limits(max_hops=1))
    enum = enumerate_paths(m, at=NOW)
    assert enum.truncated and any("hop limit" in r for r in enum.truncation_reasons)
    m2 = replace(chain_model(), limits=Limits(max_paths=1))
    enum2 = enumerate_paths(m2, at=NOW)
    assert len(enum2.paths) == 1 and enum2.truncated


def test_path_explosion_is_bounded():
    n = 40
    nodes = {f"n{i}": Node(f"n{i}", "asset", f"n{i}") for i in range(n)}
    nodes["inet"] = Node("inet", "entry_point", "i")
    edges = [edge(f"e-i{i}", "inet", f"n{i}") for i in range(n)]
    edges += [edge(f"e{i}-{j}", f"n{i}", f"n{j}") for i in range(n) for j in range(n) if i != j]
    exploits = [vuln(f"f{i}", f"n{i}") for i in range(n)]
    m = GraphModel(nodes, edges, exploits, [Objective("O", "n0", "O", 1)], Limits(max_paths=50, max_expansions=5000))
    enum = enumerate_paths(m, at=NOW)
    assert enum.truncated and len(enum.paths) <= 50 and enum.expansions <= 5001


def test_validation_rejects_bad_graphs():
    m = chain_model()
    m.edges.append(edge("e-ia", "inet", "b"))
    with pytest.raises(GraphInputError, match="duplicate"):
        enumerate_paths(m)
    m = chain_model()
    m.edges.append(edge("e-self", "a", "a"))
    with pytest.raises(GraphInputError, match="self-loop"):
        enumerate_paths(m)
    m = chain_model()
    m.edges.append(edge("e-x", "a", "ghost"))
    with pytest.raises(GraphInputError, match="unknown node"):
        enumerate_paths(m)
    m = chain_model(Limits(max_nodes=2))
    with pytest.raises(GraphInputError, match="limit"):
        enumerate_paths(m)


def test_deterministic_ids_and_order():
    a = enumerate_paths(chain_model(), at=NOW)
    m = chain_model()
    m.edges.reverse()
    b = enumerate_paths(m, at=NOW)
    assert [p.id for p in a.paths] == [p.id for p in b.paths]
    assert [p.as_dict() for p in a.paths] == [p.as_dict() for p in b.paths]

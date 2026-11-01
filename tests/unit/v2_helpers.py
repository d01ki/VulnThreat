"""Builders for small, hand-checkable attack-graph models (pure domain, no DB)."""

from __future__ import annotations

from datetime import datetime, timezone

from tiw.domain.attack_graph import Edge, EvidenceItem, Exploit, Fact, GraphModel, Limits, Node, Objective
from tiw.domain.remediation import Action

NOW = datetime(2026, 10, 20, 9, tzinfo=timezone.utc)


def ev(eid: str, polarity: str = "supports", active: bool = True, expires: datetime | None = None) -> EvidenceItem:
    return EvidenceItem(eid, "claim", polarity, active, None if active else "retracted", expires_at=expires)


def fact(fid: str, declared: str = "satisfied", *evidence: EvidenceItem) -> Fact:
    if not evidence and declared == "satisfied":
        evidence = (ev(f"rec:{fid}"),)
    return Fact(fid, "reachability", fid, declared, tuple(evidence))


def edge(eid: str, s: str, t: str, port: str = "tcp/443", f: Fact | None = None, kind: str = "network", **kw) -> Edge:
    return Edge(eid, s, t, kind, (port,) if kind == "network" else (), f or fact(f"edge:{eid}"), **kw)


def vuln(fid: str, asset: str, port: str = "tcp/443", grants: str = "code_execution", app: Fact | None = None, conds=()) -> Exploit:
    return Exploit(fid, asset, f"DEMO-VULN-{sum(map(ord, fid)) % 900 + 100}", (port,), "network_access", grants,
                   app or Fact(f"applicability:{fid}", "applicability", fid, "satisfied", (ev(f"app:{fid}"),)), tuple(conds))


def chain_model(limits: Limits | None = None) -> GraphModel:
    """inet -> a -> c ; inet -> b -> c ; c is the crown jewel. Choke point: the finding on c."""
    nodes = {n: Node(n, "asset", n) for n in ("a", "b", "c")}
    nodes["inet"] = Node("inet", "entry_point", "Internet")
    edges = [edge("e-ia", "inet", "a"), edge("e-ib", "inet", "b"), edge("e-ac", "a", "c"), edge("e-bc", "b", "c")]
    exploits = [vuln("f-a", "a"), vuln("f-b", "b"), vuln("f-c", "c", grants="data_access")]
    return GraphModel(nodes, edges, exploits, [Objective("OBJ-c", "c", "C", 3)], limits or Limits())


def act(aid: str, cost: int = 1, **kw) -> Action:
    kw.setdefault("type", "patch_finding")
    return Action(aid, label=aid, cost=cost, **kw)

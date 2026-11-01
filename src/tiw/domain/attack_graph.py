"""Deterministic attack-graph model: typed facts, fact resolution, bounded path enumeration.

Pure and deterministic: no IO, no clock, no randomness. Inputs are plain dataclasses built by
``tiw.services.graph``. An edge is a *potential* reachability or capability transition, never
a confirmed exploitation. A "supported" path only means every model precondition is satisfied
by active, reviewed, unexpired evidence; it is not empirical confirmation of compromise.

Fact statuses (one per required condition)
-----------------------------------------
- ``satisfied``   active reviewed evidence supports it and nothing active refutes it
- ``unknown``     declared unknown, or its only support expired (stale) -- never "false"
- ``unsupported`` asserted, but no active reviewed evidence remains (unreviewed, retracted,
                  rejected or superseded)
- ``disputed``    active evidence both supports and refutes it (no majority voting)
- ``refuted``     active evidence refutes it and nothing active supports it

Path statuses (worst fact wins; a refuted fact removes the hop entirely)
-----------------------------------------------------------------------
``contradicted`` > ``insufficient_evidence`` > ``conditional`` > ``supported``
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Iterable

GRAPH_ALGORITHM_VERSION = "attack-graph-1"

FACT_STATUSES = ("satisfied", "unknown", "unsupported", "disputed", "refuted")
PATH_STATUSES = ("supported", "conditional", "insufficient_evidence", "contradicted")
PATH_STATUS_RANK = {"supported": 0, "conditional": 1, "insufficient_evidence": 2, "contradicted": 3}
PATH_STATUS_TEXT = {
    "supported": "Every model precondition is satisfied by active reviewed evidence (model check, not proof of compromise).",
    "conditional": "No refuting evidence, but at least one precondition is unknown or stale.",
    "insufficient_evidence": "At least one precondition is asserted without active reviewed evidence (e.g. its only support was retracted).",
    "contradicted": "Active evidence both supports and refutes at least one precondition; a reviewer must resolve it.",
}
NODE_KINDS = ("entry_point", "asset", "security_objective")
EDGE_KINDS = ("network", "trust")
REACHABILITY = ("allowed", "blocked", "unknown")
CONDITION_KINDS = ("affected_component", "authentication", "configuration", "attacker_capability", "network_service")
CAPABILITIES = ("network_access", "user_context", "code_execution", "admin_context", "credential_access", "data_access")
CONDITION_DECLARED = ("satisfied", "not_satisfied", "unknown")

# Inclusion policies: which path statuses count in the objective.
INCLUSION = {
    # Conservative default: unknown is not safe, disputes are not resolved by voting.
    "as_recorded": ("supported", "conditional", "contradicted"),
    # Sensitivity bounds (not world states).
    "pessimistic": ("supported", "conditional", "contradicted", "insufficient_evidence"),
    "optimistic": ("supported",),
}


class GraphInputError(ValueError):
    """Structural problem in graph inputs (dangling reference, duplicate, self-loop...)."""


# --------------------------------------------------------------------------- evidence


@dataclass(frozen=True)
class EvidenceItem:
    """One piece of evidence about a fact: a claim from the ledger or the topology record itself."""

    id: str  # claim id or "topology:<edge id>" / "conditions:<vuln>:<cond>"
    kind: str  # claim / topology / exploit_conditions / applicability
    polarity: str  # supports / refutes
    active: bool
    inactive_reason: str | None = None
    label: str = ""
    review_state: str = "reviewed"
    source: str = ""
    observed_at: datetime | None = None
    expires_at: datetime | None = None
    claim_key: str | None = None
    quote: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "polarity": self.polarity,
            "active": self.active,
            "inactive_reason": self.inactive_reason,
            "label": self.label,
            "review_state": self.review_state,
            "source": self.source,
            "observed_at": _iso(self.observed_at),
            "expires_at": _iso(self.expires_at),
            "claim_key": self.claim_key,
            "quote": self.quote,
        }


@dataclass(frozen=True)
class Fact:
    """A required condition with its evidence. Resolution is deterministic (see module doc)."""

    id: str  # e.g. "edge:e-web-api", "applicability:f-1", "cond:DEMO-VULN-102:auth"
    kind: str  # reachability / applicability / condition / capability
    label: str
    declared: str  # satisfied / not_satisfied / unknown
    evidence: tuple[EvidenceItem, ...] = ()

    def resolve(self, at: datetime | None = None) -> tuple[str, list[str]]:
        """Return (status, reason codes)."""
        reasons: list[str] = []
        sup, ref = [], []
        stale_support = False
        for e in self.evidence:
            if not e.active:
                reasons.append(f"EVIDENCE_INACTIVE:{e.id}:{e.inactive_reason or 'inactive'}")
                continue
            if at is not None and e.expires_at is not None and e.expires_at <= at:
                reasons.append(f"EVIDENCE_EXPIRED:{e.id}")
                if e.polarity == "supports":
                    stale_support = True
                continue
            (sup if e.polarity == "supports" else ref).append(e)
        if sup and ref:
            return "disputed", reasons + ["CONFLICTING_EVIDENCE"]
        if ref:
            return "refuted", reasons + ["REFUTED"]
        if sup:
            return "satisfied", reasons
        if self.declared == "unknown":
            return "unknown", reasons + ["DECLARED_UNKNOWN"]
        if stale_support:
            return "unknown", reasons + ["SUPPORT_EXPIRED"]
        if self.declared == "not_satisfied":
            # declared false but every refuting record is inactive: treat as unknown, never as safe.
            return "unknown", reasons + ["REFUTATION_WITHDRAWN"]
        return "unsupported", reasons + ["NO_ACTIVE_SUPPORT"]


@dataclass(frozen=True)
class FactOverride:
    """Scenario override: force a fact status without touching canonical inputs."""

    fact_id: str
    status: str  # one of FACT_STATUSES
    reason: str


# --------------------------------------------------------------------------- graph inputs


@dataclass(frozen=True)
class Node:
    id: str
    kind: str  # entry_point / asset
    label: str
    criticality: str | None = None
    internet_exposed: str | None = None
    zone: str | None = None
    grants: str = "network_access"  # capability an attacker holds at an entry point


@dataclass(frozen=True)
class Objective:
    """Crown jewel / security objective. Weight is configured, never inferred from CVSS/EPSS."""

    id: str
    asset_id: str
    label: str
    weight: int
    required_capabilities: tuple[str, ...] = ("code_execution", "admin_context", "credential_access", "data_access")


@dataclass(frozen=True)
class Edge:
    id: str
    source: str
    target: str
    kind: str  # network / trust
    ports: tuple[str, ...]  # e.g. "tcp/443"; empty for trust edges
    reachability: Fact
    requires_capability: str | None = None  # trust edges: capability needed at the source
    grants_capability: str | None = None  # trust edges: capability gained at the target
    label: str = ""


@dataclass(frozen=True)
class Exploit:
    """A finding (vulnerability on an asset) with its structured, non-executable preconditions."""

    finding_id: str
    asset_id: str
    vulnerability_id: str
    service_ports: tuple[str, ...]
    requires_capability: str  # at the source of the hop
    grants_capability: str  # on the target asset
    applicability: Fact
    conditions: tuple[Fact, ...] = ()
    cvss: dict[str, Any] | None = None
    title: str = ""


@dataclass(frozen=True)
class Limits:
    max_hops: int = 6
    max_paths: int = 500
    max_nodes: int = 2_000
    max_edges: int = 10_000
    max_expansions: int = 200_000


@dataclass
class GraphModel:
    nodes: dict[str, Node]
    edges: list[Edge]
    exploits: list[Exploit]
    objectives: list[Objective]
    limits: Limits = field(default_factory=Limits)

    def validate(self) -> None:
        if len(self.nodes) > self.limits.max_nodes:
            raise GraphInputError(f"graph has {len(self.nodes)} nodes; limit is {self.limits.max_nodes}")
        if len(self.edges) > self.limits.max_edges:
            raise GraphInputError(f"graph has {len(self.edges)} edges; limit is {self.limits.max_edges}")
        seen: set[str] = set()
        for e in self.edges:
            if e.id in seen:
                raise GraphInputError(f"duplicate edge id {e.id}")
            seen.add(e.id)
            if e.source not in self.nodes or e.target not in self.nodes:
                raise GraphInputError(f"edge {e.id} references an unknown node")
            if e.source == e.target:
                raise GraphInputError(f"edge {e.id} is a self-loop")
            if self.nodes[e.target].kind == "entry_point":
                raise GraphInputError(f"edge {e.id} points into entry point {e.target}")
        for x in self.exploits:
            if x.asset_id not in self.nodes:
                raise GraphInputError(f"finding {x.finding_id} references unknown asset {x.asset_id}")
        for o in self.objectives:
            if o.asset_id not in self.nodes:
                raise GraphInputError(f"objective {o.id} references unknown asset {o.asset_id}")
            if o.weight < 0:
                raise GraphInputError(f"objective {o.id} has a negative weight")


# --------------------------------------------------------------------------- paths


@dataclass(frozen=True)
class Hop:
    edge_id: str
    source: str
    target: str
    via: str  # "finding:<id>" or "trust:<edge id>"
    capability: str  # capability held on target after the hop
    fact_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source": self.source,
            "target": self.target,
            "via": self.via,
            "capability": self.capability,
            "fact_ids": list(self.fact_ids),
        }


@dataclass(frozen=True)
class Path:
    id: str
    objective_id: str
    target: str
    entry: str
    hops: tuple[Hop, ...]
    status: str
    fact_status: tuple[tuple[str, str], ...]  # (fact id, status), sorted

    @property
    def nodes(self) -> list[str]:
        return [self.entry] + [h.target for h in self.hops]

    @property
    def finding_ids(self) -> list[str]:
        return [h.via.split(":", 1)[1] for h in self.hops if h.via.startswith("finding:")]

    @property
    def edge_ids(self) -> list[str]:
        return [h.edge_id for h in self.hops]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "objective_id": self.objective_id,
            "target": self.target,
            "entry": self.entry,
            "nodes": self.nodes,
            "hops": [h.as_dict() for h in self.hops],
            "status": self.status,
            "facts": {k: v for k, v in self.fact_status},
        }


def path_id(entry: str, objective_id: str, hops: Iterable[Hop]) -> str:
    key = json.dumps([entry, objective_id, [(h.edge_id, h.via) for h in hops]], separators=(",", ":"))
    return "PATH-" + hashlib.sha256(key.encode()).hexdigest()[:10].upper()


@dataclass
class Enumeration:
    paths: list[Path]
    blocked: list[dict[str, Any]]  # candidate hops removed because a fact was refuted
    truncated: bool
    truncation_reasons: list[str]
    expansions: int
    fact_status: dict[str, tuple[str, list[str]]]
    facts: dict[str, Fact]

    def counted(self, inclusion: str = "as_recorded") -> list[Path]:
        allowed = INCLUSION[inclusion]
        return [p for p in self.paths if p.status in allowed]


def _status_of_path(statuses: list[str]) -> str:
    if "disputed" in statuses:
        return "contradicted"
    if "unsupported" in statuses:
        return "insufficient_evidence"
    if "unknown" in statuses:
        return "conditional"
    return "supported"


def _cap_ok(have: str, need: str | None) -> bool:
    if need is None or need == "network_access":
        return True
    if have == need:
        return True
    # admin context implies code execution and user context; code execution implies user context.
    order = {"network_access": 0, "user_context": 1, "code_execution": 2, "admin_context": 3}
    if have in order and need in order:
        return order[have] >= order[need]
    return False


def all_facts(model: GraphModel) -> dict[str, Fact]:
    out: dict[str, Fact] = {}
    for e in model.edges:
        out[e.reachability.id] = e.reachability
    for x in model.exploits:
        out[x.applicability.id] = x.applicability
        for c in x.conditions:
            out[c.id] = c
    return out


def resolve_facts(
    model: GraphModel, at: datetime | None, overrides: Iterable[FactOverride] = ()
) -> tuple[dict[str, Fact], dict[str, tuple[str, list[str]]]]:
    facts = all_facts(model)
    status = {fid: f.resolve(at) for fid, f in sorted(facts.items())}
    for o in overrides:
        if o.fact_id in status:
            status[o.fact_id] = (o.status, status[o.fact_id][1] + [f"SCENARIO_OVERRIDE:{o.reason}"])
    return facts, status


def enumerate_paths(
    model: GraphModel,
    *,
    at: datetime | None = None,
    overrides: Iterable[FactOverride] = (),
    removed_edges: frozenset[str] = frozenset(),
    removed_findings: frozenset[str] = frozenset(),
    removed_ports: frozenset[tuple[str, str]] = frozenset(),  # (asset id, port)
) -> Enumeration:
    """Bounded DFS over (node, capability) states, simple paths only (no node revisited).

    Removal arguments let the remediation simulator evaluate a counterfactual graph without
    mutating the canonical model.
    """
    model.validate()
    facts, fstatus = resolve_facts(model, at, overrides)
    lim = model.limits
    out_edges: dict[str, list[Edge]] = {}
    for e in sorted(model.edges, key=lambda e: e.id):
        if e.id in removed_edges:
            continue
        out_edges.setdefault(e.source, []).append(e)
    exploits_on: dict[str, list[Exploit]] = {}
    for x in sorted(model.exploits, key=lambda x: (x.asset_id, x.finding_id)):
        if x.finding_id in removed_findings:
            continue
        exploits_on.setdefault(x.asset_id, []).append(x)
    objectives_on: dict[str, list[Objective]] = {}
    for o in sorted(model.objectives, key=lambda o: o.id):
        objectives_on.setdefault(o.asset_id, []).append(o)

    blocked: dict[tuple[str, str], dict[str, Any]] = {}
    paths: dict[str, Path] = {}
    truncated = False
    reasons: list[str] = []
    expansions = 0

    def hop_options(src: str, cap: str) -> list[Hop]:
        opts: list[Hop] = []
        for e in out_edges.get(src, []):
            reach_status = fstatus[e.reachability.id][0]
            if reach_status == "refuted":
                blocked[(e.id, "edge")] = {"edge_id": e.id, "via": None, "fact_id": e.reachability.id, "reason": "reachability refuted"}
                continue
            if e.kind == "trust":
                if not _cap_ok(cap, e.requires_capability):
                    continue
                opts.append(Hop(e.id, e.source, e.target, f"trust:{e.id}", e.grants_capability or "user_context", (e.reachability.id,)))
                continue
            open_ports = tuple(p for p in e.ports if (e.target, p) not in removed_ports)
            for x in exploits_on.get(e.target, []):
                if not set(x.service_ports) & set(open_ports):
                    continue
                if not _cap_ok(cap, x.requires_capability):
                    continue
                fids = (e.reachability.id, x.applicability.id, *[c.id for c in x.conditions])
                refuted = [f for f in fids if fstatus[f][0] == "refuted"]
                if refuted:
                    blocked[(e.id, x.finding_id)] = {"edge_id": e.id, "via": f"finding:{x.finding_id}", "fact_id": refuted[0], "reason": "precondition refuted"}
                    continue
                opts.append(Hop(e.id, e.source, e.target, f"finding:{x.finding_id}", x.grants_capability, fids))
        return opts

    entries = sorted(n for n, node in model.nodes.items() if node.kind == "entry_point")
    for entry in entries:
        stack: list[tuple[str, str, tuple[Hop, ...], frozenset[str]]] = [
            (entry, model.nodes[entry].grants or "network_access", (), frozenset({entry}))
        ]
        while stack:
            node, cap, hops, visited = stack.pop()
            expansions += 1
            if expansions > lim.max_expansions:
                truncated = True
                reasons.append(f"expansion limit {lim.max_expansions} reached")
                break
            if hops:
                for o in objectives_on.get(node, []):
                    if any(_cap_ok(cap, rc) for rc in o.required_capabilities):
                        pid = path_id(entry, o.id, hops)
                        if pid not in paths:
                            if len(paths) >= lim.max_paths:
                                truncated = True
                                reasons.append(f"path limit {lim.max_paths} reached")
                                break
                            fids = sorted({f for h in hops for f in h.fact_ids})
                            sts = [fstatus[f][0] for f in fids]
                            paths[pid] = Path(pid, o.id, node, entry, hops, _status_of_path(sts), tuple((f, fstatus[f][0]) for f in fids))
                if truncated:
                    break
            if len(hops) >= lim.max_hops:
                if any(h.target not in visited for h in hop_options(node, cap)):
                    if f"hop limit {lim.max_hops} reached" not in reasons:
                        reasons.append(f"hop limit {lim.max_hops} reached")
                    truncated = True
                continue
            # push in reverse so exploration order is lexicographic and deterministic
            for h in reversed(hop_options(node, cap)):
                if h.target in visited:
                    continue
                stack.append((h.target, h.capability, hops + (h,), visited | {h.target}))
        if truncated and any(r.startswith(("expansion", "path")) for r in reasons):
            break
    ordered = sorted(paths.values(), key=lambda p: (p.objective_id, len(p.hops), p.nodes, p.id))
    return Enumeration(
        paths=ordered,
        blocked=[blocked[k] for k in sorted(blocked, key=lambda k: (k[0], k[1] or ""))],
        truncated=truncated,
        truncation_reasons=sorted(set(reasons)),
        expansions=expansions,
        fact_status=fstatus,
        facts=facts,
    )


def with_limits(model: GraphModel, limits: Limits) -> GraphModel:
    return replace(model, limits=limits)


def _iso(v: Any) -> Any:
    return v.isoformat().replace("+00:00", "Z") if isinstance(v, datetime) else v


def canonical_hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":"), default=_iso).encode()).hexdigest()

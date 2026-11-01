"""Hypothesis contract, deterministic generator, schema/provenance gate and verification.

A hypothesis is an *untrusted candidate* attacker transition. It never changes graph facts,
findings or action priority. The graph builder only uses transitions that already exist in
the reviewed topology + findings; a hypothesis can be verified against those facts or be
reported as unsupported. Therefore the optimiser produces identical results with AI disabled.

The deterministic rule-based generator is the default and needs no network or API key.
An optional external provider (e.g. an LLM) must implement ``HypothesisProvider``; its raw
output is passed through ``gate`` before anything else sees it. No tool, shell or network
call is ever made from model output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from tiw.domain.attack_graph import Enumeration, GraphModel, matching_ports

HYPOTHESIS_SCHEMA_VERSION = "1.0"
GENERATOR_VERSION = "rule-hypotheses-1"
MAX_HYPOTHESES = 500
MAX_TEXT = 500
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
PLACEHOLDER_TECHNIQUES = {"T0000"}
CONDITION_NAMES = ("network_reachability", "affected_component", "authentication", "configuration", "attacker_capability", "trust_relation")
ALLOWED_KEYS = {
    "schema_version", "hypothesis_id", "source_asset_id", "target_asset_id", "technique_id",
    "candidate_vulnerability_id", "required_conditions", "supporting_evidence_ids", "assumptions", "rationale",
}
VERIFICATION = ("supported", "conditional", "contradicted", "insufficient_evidence", "unsupported", "rejected")


@dataclass
class Hypothesis:
    hypothesis_id: str
    source_asset_id: str
    target_asset_id: str
    candidate_vulnerability_id: str | None
    required_conditions: list[str]
    supporting_evidence_ids: list[str]
    assumptions: list[str]
    rationale: str
    technique_id: str | None = None
    origin: str = "rule"  # rule / model
    schema_version: str = HYPOTHESIS_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "hypothesis_id": self.hypothesis_id,
            "source_asset_id": self.source_asset_id,
            "target_asset_id": self.target_asset_id,
            "technique_id": self.technique_id,
            "candidate_vulnerability_id": self.candidate_vulnerability_id,
            "required_conditions": self.required_conditions,
            "supporting_evidence_ids": self.supporting_evidence_ids,
            "assumptions": self.assumptions,
            "rationale": self.rationale,
            "origin": self.origin,
        }


@dataclass
class GateResult:
    accepted: list[Hypothesis] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)


class HypothesisProvider(Protocol):
    """Provider-neutral contract. Receives a sanitized summary, returns raw JSON-like objects."""

    name: str

    def propose(self, summary: dict[str, Any], *, max_items: int) -> list[Any]: ...


class DisabledProvider:
    name = "disabled"

    def propose(self, summary: dict[str, Any], *, max_items: int) -> list[Any]:
        return []


class ProviderUnavailable(RuntimeError):
    pass


def graph_summary(model: GraphModel) -> dict[str, Any]:
    """Minimal, sanitized view for an external provider: identifiers and structure only, no free text."""
    return {
        "schema_version": HYPOTHESIS_SCHEMA_VERSION,
        "nodes": [{"id": n.id, "kind": n.kind} for n in sorted(model.nodes.values(), key=lambda n: n.id)],
        "edges": [{"source": e.source, "target": e.target, "kind": e.kind, "ports": list(e.ports)} for e in sorted(model.edges, key=lambda e: e.id)],
        "findings": [{"asset_id": x.asset_id, "vulnerability_id": x.vulnerability_id} for x in sorted(model.exploits, key=lambda x: x.finding_id)],
        "objectives": [o.asset_id for o in sorted(model.objectives, key=lambda o: o.id)],
    }


def rule_based(model: GraphModel) -> list[Hypothesis]:
    """One candidate per (edge, applicable finding on the target) and per trust edge. Deterministic."""
    out: list[Hypothesis] = []
    n = 0
    for e in sorted(model.edges, key=lambda e: e.id):
        if e.kind == "trust":
            n += 1
            out.append(Hypothesis(
                f"H-{n:03d}", e.source, e.target, None, ["trust_relation", "attacker_capability"],
                sorted({ev.id for ev in e.reachability.evidence}), [f"requires {e.requires_capability or 'any'} on {e.source}"],
                "Rule: recorded trust relation could be abused (candidate, not confirmed)",
            ))
            continue
        for x in sorted(model.exploits, key=lambda x: x.finding_id):
            if x.asset_id != e.target or not matching_ports(x.service_ports, e.ports):
                continue
            n += 1
            ev_ids = sorted({ev.id for ev in e.reachability.evidence} | {ev.id for ev in x.applicability.evidence}
                            | {ev.id for c in x.conditions for ev in c.evidence})
            conds = ["network_reachability", "affected_component"] + sorted({c.kind for c in x.conditions if c.kind in CONDITION_NAMES})
            assumptions = [f"{c.id} declared {c.declared}" for c in x.conditions if c.declared != "satisfied"]
            out.append(Hypothesis(
                f"H-{n:03d}", e.source, e.target, x.vulnerability_id, conds, ev_ids, assumptions,
                f"Rule: {e.source} reaches {e.target} on {', '.join(matching_ports(x.service_ports, e.ports))} where {x.vulnerability_id} is recorded (candidate, not confirmed exploitation)",
            ))
            if n >= MAX_HYPOTHESES:
                return out
    return out


def gate(raw: list[Any], model: GraphModel, known_evidence_ids: set[str], *, origin: str = "model") -> GateResult:
    """Strict schema + provenance gate. Unknown keys, unknown objects or fabricated evidence reject."""
    res = GateResult()
    vulns = {x.vulnerability_id for x in model.exploits}
    seen: set[str] = set()
    if not isinstance(raw, list):
        res.rejected.append({"index": None, "reason": "provider output must be a JSON array"})
        return res
    for i, h in enumerate(raw[:MAX_HYPOTHESES]):
        def rej(reason: str) -> None:
            res.rejected.append({"index": i, "hypothesis_id": (str(h.get("hypothesis_id"))[:40] if isinstance(h, dict) else None), "reason": reason})

        if not isinstance(h, dict):
            rej("hypothesis must be an object")
            continue
        extra = set(h) - ALLOWED_KEYS
        if extra:
            rej(f"unexpected keys: {', '.join(sorted(extra))[:200]}")
            continue
        if h.get("schema_version") != HYPOTHESIS_SCHEMA_VERSION:
            rej("schema_version must be '1.0'")
            continue
        hid = h.get("hypothesis_id")
        if not isinstance(hid, str) or not ID_RE.match(hid) or hid in seen:
            rej("hypothesis_id missing, malformed or duplicated")
            continue
        src, dst = h.get("source_asset_id"), h.get("target_asset_id")
        if not (isinstance(src, str) and src in model.nodes and isinstance(dst, str) and dst in model.nodes):
            rej("source_asset_id/target_asset_id must reference known nodes")
            continue
        vid = h.get("candidate_vulnerability_id")
        if vid is not None and (not isinstance(vid, str) or vid not in vulns):
            rej("candidate_vulnerability_id does not reference a recorded finding")
            continue
        tech = h.get("technique_id")
        if tech is not None and (not isinstance(tech, str) or not TECHNIQUE_RE.match(tech)):
            rej("technique_id malformed")
            continue
        conds = h.get("required_conditions")
        if not isinstance(conds, list) or not all(isinstance(c, str) and c in CONDITION_NAMES for c in conds):
            rej(f"required_conditions must be a list drawn from {', '.join(CONDITION_NAMES)}")
            continue
        evid = h.get("supporting_evidence_ids", [])
        if not isinstance(evid, list) or not all(isinstance(e, str) for e in evid):
            rej("supporting_evidence_ids must be a list of strings")
            continue
        fabricated = [e for e in evid if e not in known_evidence_ids]
        if fabricated:
            rej(f"unknown (fabricated) evidence ids: {', '.join(e[:40] for e in fabricated[:5])}")
            continue
        assumptions = h.get("assumptions", [])
        if not isinstance(assumptions, list) or not all(isinstance(a, str) for a in assumptions):
            rej("assumptions must be a list of strings")
            continue
        rationale = h.get("rationale", "")
        if not isinstance(rationale, str):
            rej("rationale must be a string")
            continue
        seen.add(hid)
        res.accepted.append(Hypothesis(
            hid, src, dst, vid, list(conds), list(evid), [a[:MAX_TEXT] for a in assumptions[:20]], rationale[:MAX_TEXT],
            technique_id=tech, origin=origin,
        ))
    if len(raw) > MAX_HYPOTHESES:
        res.rejected.append({"index": MAX_HYPOTHESES, "reason": f"{len(raw) - MAX_HYPOTHESES} items over the limit were ignored"})
    return res


def verify(h: Hypothesis, model: GraphModel, enum: Enumeration) -> dict[str, Any]:
    """Check a candidate against recorded facts. Never adds facts; unmatched candidates are unsupported."""
    matches = []
    for e in sorted(model.edges, key=lambda e: e.id):
        if e.source != h.source_asset_id or e.target != h.target_asset_id:
            continue
        if h.candidate_vulnerability_id is None:
            if e.kind == "trust":
                matches.append((e, None))
            continue
        for x in model.exploits:
            if x.asset_id == e.target and x.vulnerability_id == h.candidate_vulnerability_id and matching_ports(x.service_ports, e.ports):
                matches.append((e, x))
    notes = []
    if h.technique_id in PLACEHOLDER_TECHNIQUES:
        notes.append("technique_id is a placeholder and is never used for attribution")
    elif h.technique_id:
        notes.append("technique_id not validated against a pinned ATT&CK snapshot (none shipped); display only")
    if not matches:
        return {"hypothesis_id": h.hypothesis_id, "status": "unsupported", "facts": {}, "edge_id": None, "finding_id": None,
                "notes": notes + ["no recorded edge/finding matches this transition; it is not added to the graph"]}
    best: dict[str, Any] | None = None
    for e, x in matches:
        fids = [e.reachability.id] + ([x.applicability.id, *[c.id for c in x.conditions]] if x else [])
        sts = {f: enum.fact_status[f][0] for f in fids}
        vals = list(sts.values())
        if "refuted" in vals:
            st = "rejected"
        elif "disputed" in vals:
            st = "contradicted"
        elif "unsupported" in vals:
            st = "insufficient_evidence"
        elif "unknown" in vals:
            st = "conditional"
        else:
            st = "supported"
        cand = {"hypothesis_id": h.hypothesis_id, "status": st, "facts": sts, "edge_id": e.id, "finding_id": x.finding_id if x else None,
                "notes": notes + (["a required fact is refuted by active evidence"] if st == "rejected" else [])}
        rank = VERIFICATION.index(st)
        if best is None or rank < VERIFICATION.index(best["status"]):
            best = cand
    assert best is not None
    return best

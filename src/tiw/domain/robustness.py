"""Decision robustness: counterfactual evidence scenarios and recommendation flip explanations.

Scenarios never modify canonical inputs; each builds a transformed copy of the frozen model.
Scenario counts ("selected in 4/6 scenarios") are counts of *constructed* cases, not
probabilities, and must never be presented as real-world confidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

from tiw.domain.attack_graph import (
    INCLUSION,
    Enumeration,
    Fact,
    FactOverride,
    GraphModel,
    enumerate_paths,
)
from tiw.domain.remediation import Action, Constraints, Evaluator, OptimizeResult, optimize

ROBUSTNESS_VERSION = "robustness-1"
SCENARIO_KINDS = (
    "as_recorded",
    "withdraw_claim",
    "reachability_unknown",
    "applicability_unknown",
    "stale_evidence",
    "pessimistic",
    "optimistic",
)
SCENARIO_TEXT = {
    "as_recorded": "Accepted evidence and recorded topology, as-is.",
    "withdraw_claim": "Remove only this claim's influence (other evidence, supersedes and retractions unchanged).",
    "reachability_unknown": "Treat this edge's reachability as unknown (not blocked).",
    "applicability_unknown": "Treat this finding's applicability as unknown (original review kept for attribution).",
    "stale_evidence": "Evaluate at a later clock; expired evidence stops supporting facts.",
    "pessimistic": "Sensitivity bound: also count paths whose support is missing (insufficient_evidence).",
    "optimistic": "Sensitivity bound: count only fully supported paths (unknown and disputed facts assumed false).",
}
DEFAULT_CAP = 12


@dataclass(frozen=True)
class Scenario:
    id: str
    kind: str
    label: str
    target: str | None = None  # claim id / edge id / finding id
    at: datetime | None = None
    inclusion: str = "as_recorded"

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "target": self.target,
            "at": self.at.isoformat().replace("+00:00", "Z") if self.at else None,
            "inclusion": self.inclusion,
            "description": SCENARIO_TEXT[self.kind],
        }


def withdraw_evidence(model: GraphModel, evidence_id: str, reason: str = "scenario: withdrawn") -> GraphModel:
    """Copy of ``model`` with one evidence item marked inactive wherever it is cited."""

    def fix(f: Fact) -> Fact:
        if not any(e.id == evidence_id for e in f.evidence):
            return f
        ev = tuple(replace(e, active=False, inactive_reason=reason) if e.id == evidence_id else e for e in f.evidence)
        return replace(f, evidence=ev)

    edges = [replace(e, reachability=fix(e.reachability)) for e in model.edges]
    exploits = [replace(x, applicability=fix(x.applicability), conditions=tuple(fix(c) for c in x.conditions)) for x in model.exploits]
    return replace(model, edges=edges, exploits=exploits)


def apply(model: GraphModel, sc: Scenario, now: datetime) -> tuple[GraphModel, datetime, list[FactOverride]]:
    at = sc.at or now
    if sc.kind == "withdraw_claim" and sc.target:
        return withdraw_evidence(model, sc.target), at, []
    if sc.kind == "reachability_unknown" and sc.target:
        return model, at, [FactOverride(f"edge:{sc.target}", "unknown", f"reachability_unknown:{sc.target}")]
    if sc.kind == "applicability_unknown" and sc.target:
        return model, at, [FactOverride(f"applicability:{sc.target}", "unknown", f"applicability_unknown:{sc.target}")]
    return model, at, []


def default_scenarios(model: GraphModel, enum: Enumeration, now: datetime, stale_at: datetime | None, cap: int = DEFAULT_CAP) -> tuple[list[Scenario], list[str]]:
    """Single-factor scenarios derived from the evidence actually cited by counted paths."""
    counted = enum.counted("as_recorded")
    used_facts = sorted({f for p in counted for f, _ in p.fact_status})
    claim_ids: list[tuple[str, str]] = []
    for fid in used_facts:
        for e in enum.facts[fid].evidence:
            if e.kind == "claim" and e.active and (e.id, e.claim_key or e.id) not in claim_ids:
                claim_ids.append((e.id, e.claim_key or e.id))
    edges = sorted({fid[5:] for fid in used_facts if fid.startswith("edge:") and enum.fact_status[fid][0] == "satisfied"})
    findings = sorted({fid[14:] for fid in used_facts if fid.startswith("applicability:") and enum.fact_status[fid][0] == "satisfied"})
    out = [Scenario("S-as-recorded", "as_recorded", "As recorded")]
    uncovered: list[str] = []
    for cid, key in sorted(claim_ids, key=lambda t: t[1])[:cap]:
        out.append(Scenario(f"S-withdraw-{key}", "withdraw_claim", f"Withdraw claim {key}", cid))
    if len(claim_ids) > cap:
        uncovered.append(f"{len(claim_ids) - cap} withdraw_claim scenarios over the cap of {cap}")
    for e in edges[:cap]:
        out.append(Scenario(f"S-unknown-edge-{e}", "reachability_unknown", f"Edge {e} reachability unknown", e))
    if len(edges) > cap:
        uncovered.append(f"{len(edges) - cap} reachability_unknown scenarios over the cap of {cap}")
    for f in findings[:cap]:
        out.append(Scenario(f"S-unknown-app-{f}", "applicability_unknown", f"Finding {f} applicability unknown", f))
    if len(findings) > cap:
        uncovered.append(f"{len(findings) - cap} applicability_unknown scenarios over the cap of {cap}")
    if stale_at is not None:
        out.append(Scenario("S-stale", "stale_evidence", f"Evaluate at {stale_at.date().isoformat()}", None, stale_at))
    out.append(Scenario("S-pessimistic", "pessimistic", "Pessimistic bound", inclusion="pessimistic"))
    out.append(Scenario("S-optimistic", "optimistic", "Optimistic bound", inclusion="optimistic"))
    n_factors = len(claim_ids) + len(edges) + len(findings)
    if n_factors > 1:
        uncovered.append(
            f"only single-factor scenarios are enumerated; {2 ** min(n_factors, 60) - n_factors - 1} multi-factor combinations are not covered"
        )
    return out, uncovered


@dataclass
class ScenarioOutcome:
    scenario: Scenario
    enum: Enumeration
    result: OptimizeResult
    evaluator: Evaluator
    same_portfolio: bool
    flips: list[dict[str, Any]] = field(default_factory=list)


def run_scenario(
    model: GraphModel, actions: list[Action], c: Constraints, sc: Scenario, now: datetime
) -> tuple[Enumeration, OptimizeResult, Evaluator]:
    m2, at, overrides = apply(model, sc, now)
    enum = enumerate_paths(m2, at=at, overrides=overrides)
    c2 = replace(c, inclusion=sc.inclusion)
    res = optimize(m2, enum, actions, c2)
    return enum, res, Evaluator(m2, enum, actions, sc.inclusion)


def explain_flip(base: Enumeration, other: Enumeration, base_inclusion: str, other_inclusion: str) -> list[dict[str, Any]]:
    """Every counted-path change, linked to the facts (and evidence ids) whose status changed."""
    out: list[dict[str, Any]] = []
    b = {p.id: p for p in base.paths}
    o = {p.id: p for p in other.paths}
    bc = {p.id for p in base.counted(base_inclusion)}
    oc = {p.id for p in other.counted(other_inclusion)}
    for pid in sorted(bc | oc | set(b) | set(o)):
        before = b[pid].status if pid in b else "absent"
        after = o[pid].status if pid in o else "absent"
        counted_change = (pid in bc) != (pid in oc)
        if before == after and not counted_change:
            continue
        p = b.get(pid) or o[pid]
        changed_facts = []
        for fid, _ in p.fact_status:
            s1 = base.fact_status.get(fid, ("absent", []))[0]
            s2 = other.fact_status.get(fid, ("absent", []))[0]
            if s1 != s2:
                changed_facts.append({
                    "fact_id": fid,
                    "before": s1,
                    "after": s2,
                    "reasons": [r for r in other.fact_status.get(fid, ("", []))[1] if r not in base.fact_status.get(fid, ("", []))[1]],
                    "evidence_ids": [e.id for e in other.facts[fid].evidence] if fid in other.facts else [],
                })
        out.append({
            "path_id": pid,
            "before": before,
            "after": after,
            "counted_before": pid in bc,
            "counted_after": pid in oc,
            "facts": changed_facts,
            "inclusion_change": base_inclusion != other_inclusion,
        })
    return out


def stability_summary(outcomes: list[ScenarioOutcome]) -> dict[str, Any]:
    counts: dict[tuple[str, ...], int] = {}
    for o in outcomes:
        counts[o.result.best.action_ids] = counts.get(o.result.best.action_ids, 0) + 1
    total = len(outcomes)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return {
        "scenarios": total,
        "portfolios": [{"actions": list(k), "selected_in": v, "of": total, "text": f"{' + '.join(k) or 'no action'} selected in {v}/{total} enumerated scenarios (not a probability)"} for k, v in ranked],
        "stable": len(counts) == 1,
        "flipped_scenarios": [o.scenario.id for o in outcomes if not o.same_portfolio],
    }


__all__ = [
    "INCLUSION",
    "Scenario",
    "ScenarioOutcome",
    "apply",
    "default_scenarios",
    "explain_flip",
    "run_scenario",
    "stability_summary",
    "withdraw_evidence",
]

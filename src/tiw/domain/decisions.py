"""policy-v1: deterministic asset-level triage (DESIGN §10).

This is an independent product policy. It is not SSVC and does not claim SSVC compatibility.
EPSS/CVSS are never added to other signals; EPSS only orders results inside one urgency.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from tiw.domain.vocab import CRITICALITY_RANK, URGENCY_RANK

POLICY_VERSION = "policy-v1"


@dataclass(frozen=True)
class TriageInput:
    finding_id: str
    asset_id: str
    vulnerability_id: str
    criticality: str
    exposure_value: str  # true/false/unknown as recorded
    exposure_expires_at: datetime | None
    exposure_observed_at: datetime | None
    applicability: str  # affected/not_affected/unknown
    applicability_expires_at: datetime | None
    applicability_reviewer: str | None
    applicability_rationale: str | None
    state: dict[str, Any]
    now: datetime


@dataclass
class TriageResult:
    action: str
    urgency: str
    rule: int
    reason_codes: list[str]
    unknowns: list[dict[str, str]]
    inputs: dict[str, Any]
    evidence_claim_ids: list[str] = field(default_factory=list)

    def outcome_hash(self) -> str:
        payload = {
            "action": self.action,
            "urgency": self.urgency,
            "rule": self.rule,
            "reason_codes": self.reason_codes,
            "unknowns": self.unknowns,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


def effective_exposure(value: str, expires_at: datetime | None, now: datetime) -> str:
    if value == "unknown":
        return "unknown"
    if expires_at is not None and expires_at <= now:
        return "expired"
    return value


def effective_applicability(status: str, expires_at: datetime | None, now: datetime) -> str:
    if status == "not_affected" and (expires_at is None or expires_at <= now):
        return "not_affected_expired"
    return status


def evaluate(inp: TriageInput) -> TriageResult:
    st = inp.state
    public = st["public_exploitation"]
    local = st["local_by_asset"].get(inp.asset_id, "none_observed")
    exposure = effective_exposure(inp.exposure_value, inp.exposure_expires_at, inp.now)
    app = effective_applicability(inp.applicability, inp.applicability_expires_at, inp.now)
    critical = inp.criticality == "critical"
    attempt = local in ("exploit_attempt", "compromise_confirmed")
    kev_basis = "kev" in st.get("public_basis_kinds", [])

    unknowns: list[dict[str, str]] = []
    if app == "unknown":
        unknowns.append({"field": "applicability", "detail": "Affected version/configuration not confirmed", "check": "Confirm installed version and configuration with the asset owner"})
    if app == "not_affected_expired":
        unknowns.append({"field": "applicability", "detail": "Reviewed not_affected has expired", "check": "Re-confirm the not_affected rationale with current evidence"})
    if app == "not_affected" and inp.applicability_expires_at:
        unknowns.append({"field": "applicability_expiry", "detail": f"not_affected valid until {inp.applicability_expires_at.isoformat()}", "check": "Re-review before expiry"})
    if exposure == "unknown":
        unknowns.append({"field": "internet_exposure", "detail": "Internet exposure not recorded", "check": "Obtain current network/configuration evidence"})
    if exposure == "expired":
        unknowns.append({"field": "internet_exposure", "detail": "Exposure evidence expired", "check": "Obtain current network/configuration evidence"})
    if st.get("epss") is None:
        unknowns.append({"field": "epss", "detail": "No EPSS score imported", "check": "Import a current EPSS response"})
    elif st["epss"]["stale"]:
        unknowns.append({"field": "epss", "detail": f"EPSS score from {st['epss']['score_date']} is stale", "check": "Import a current EPSS response"})
    if local == "none_observed":
        unknowns.append({"field": "local_activity", "detail": "No confirmed activity in imported observations; this is not evidence of safety", "check": "Check sensor coverage for this asset"})

    # ---- policy-v1, first match wins ----------------------------------------------
    if local == "compromise_confirmed":
        rule, action, urgency, codes = 1, "incident_response", "urgent", ["LOCAL_COMPROMISE_CONFIRMED"]
    elif app == "not_affected" and attempt:
        rule, action, urgency, codes = 2, "investigate", "urgent", ["NOT_AFFECTED_CONTRADICTED"]
    elif app == "not_affected":
        rule, action, urgency, codes = 3, "monitor", "low", ["NOT_AFFECTED_REVIEWED"]
    elif app in ("unknown", "not_affected_expired"):
        high = public == "confirmed" or attempt
        rule, action, urgency = 4, "investigate", "high" if high else "normal"
        codes = ["APPLICABILITY_UNKNOWN" if app == "unknown" else "NOT_AFFECTED_EXPIRED"]
        if attempt:
            codes.append("LOCAL_EXPLOIT_ATTEMPT")
        if public == "confirmed":
            codes.append("PUBLIC_EXPLOITATION_CONFIRMED")
    elif attempt:
        rule, action, urgency, codes = 5, "remediate", "urgent", ["LOCAL_EXPLOIT_ATTEMPT"]
    elif public == "confirmed" and (exposure == "true" or critical):
        rule, action, urgency = 6, "remediate", "urgent"
        if exposure == "true":
            codes = ["KEV_AND_EXPOSED" if kev_basis else "CONFIRMED_AND_EXPOSED"]
        else:
            codes = ["CONFIRMED_AND_CRITICAL"]
    elif public == "confirmed":
        rule, action, urgency, codes = 7, "remediate", "high", ["PUBLIC_EXPLOITATION_CONFIRMED"]
    elif exposure in ("unknown", "expired"):
        rule, action, urgency = 8, "investigate", "high" if critical else "normal"
        codes = ["EXPOSURE_UNKNOWN" if exposure == "unknown" else "EVIDENCE_EXPIRED"]
    else:
        rule, action, urgency, codes = 9, "remediate", "normal", ["AFFECTED"]

    # ---- context codes: never change action/urgency ------------------------------
    if public == "reported":
        codes.append("PUBLIC_EXPLOITATION_REPORTED")
    if st.get("conflict"):
        codes.append("EVIDENCE_CONFLICT")
    if local == "scan":
        codes.append("LOCAL_SCAN_ONLY")
    if st.get("epss") is None:
        codes.append("EPSS_MISSING")
    elif st["epss"]["stale"]:
        codes.append("EPSS_STALE")
    if (st.get("kev") or {}).get("in_latest_snapshot") is False and st["kev"].get("listed_ever"):
        codes.append("KEV_RECORD_MISSING")
    if st.get("independence", {}).get("unresolved_source_count"):
        codes.append("ROOT_UNRESOLVED")
    if exposure == "expired" and "EVIDENCE_EXPIRED" not in codes and rule != 8:
        codes.append("EVIDENCE_EXPIRED")

    inputs = {
        "criticality": inp.criticality,
        "exposure": {
            "recorded": inp.exposure_value,
            "effective": exposure,
            "observed_at": inp.exposure_observed_at.isoformat() if inp.exposure_observed_at else None,
            "expires_at": inp.exposure_expires_at.isoformat() if inp.exposure_expires_at else None,
        },
        "applicability": {
            "recorded": inp.applicability,
            "effective": app,
            "reviewer": inp.applicability_reviewer,
            "rationale": inp.applicability_rationale,
            "expires_at": inp.applicability_expires_at.isoformat() if inp.applicability_expires_at else None,
        },
        "public_exploitation": public,
        "public_basis_kinds": st.get("public_basis_kinds", []),
        "local_activity_on_asset": local,
        "conflict": st.get("conflict", False),
        "recency": st.get("recency"),
        "epss": st.get("epss"),
        "independence": {
            k: st.get("independence", {}).get(k)
            for k in ("report_count", "confirmed_root_count", "unresolved_source_count")
        },
        "kev_in_latest_snapshot": (st.get("kev") or {}).get("in_latest_snapshot"),
    }
    evidence = sorted(set(st.get("public_basis_claim_ids", [])) | set(st.get("reported_claim_ids", [])))
    return TriageResult(action, urgency, rule, codes, unknowns, inputs, evidence)


def sort_key(criticality: str, epss: dict[str, Any] | None, urgency: str, finding_id: str) -> tuple[Any, ...]:
    """urgency → criticality desc → fresh EPSS desc (missing/stale last) → finding_id asc."""
    fresh = epss is not None and not epss.get("stale")
    return (
        URGENCY_RANK[urgency],
        CRITICALITY_RANK.get(criticality, 9),
        0 if fresh else 1,
        -(epss["probability"] if fresh and epss else 0.0),
        finding_id,
    )

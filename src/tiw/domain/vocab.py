"""Controlled vocabularies and identifier rules shared by adapters, engine and UI."""

from __future__ import annotations

import re

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
DEMO_RE = re.compile(r"^DEMO-VULN-\d{3,}$")

CRITICALITY = ("critical", "high", "normal")
CRITICALITY_RANK = {"critical": 0, "high": 1, "normal": 2}
EXPOSURE = ("true", "false", "unknown")
APPLICABILITY = ("affected", "not_affected", "unknown")
EVENT_TYPES = ("scan", "exploit_attempt", "compromise_confirmed")
LOCAL_ACTIVITY_ORDER = ("none_observed", "scan", "exploit_attempt", "compromise_confirmed")
CONFIRMED_MAPPING = ("reviewer_confirmed", "explicit")
MAPPING_STATUS = ("reviewer_confirmed", "explicit", "unconfirmed")
ORIGINS = ("primary", "secondary", "vendor", "kev", "epss", "model")
INITIAL_REVIEW_STATES = ("unreviewed", "reviewed", "candidate")
REVIEW_STATES = ("unreviewed", "reviewed", "rejected", "retracted", "candidate")
RELATION_KINDS = ("cites", "duplicates", "supports", "contradicts", "supersedes")
RELATION_VERIFICATION = ("explicit", "reviewer_confirmed", "candidate")
PREDICATES = ("exploited_in_wild", "poc_published", "affected_versions", "fixed_versions", "mitigation")
# v2 graph-evidence predicates: subject is a graph fact ("edge:<id>" or "cond:<vuln>:<id>"), value is bool.
GRAPH_PREDICATES = ("reachability", "precondition")
GRAPH_SUBJECT_RE = re.compile(r"^(edge:[A-Za-z0-9_.:-]{1,58}|cond:[A-Za-z0-9_.:-]{1,58})$")

ACTIONS = ("incident_response", "remediate", "investigate", "monitor")
URGENCIES = ("urgent", "high", "normal", "low")
URGENCY_RANK = {"urgent": 0, "high": 1, "normal": 2, "low": 3}

DELTA_TYPES = (
    # DESIGN §9.4
    "exploitation_confirmed",
    "local_attempt_observed",
    "local_compromise_confirmed",
    "claim_retracted",
    "evidence_conflict",
    "asset_exposure_changed",
    "evidence_expired",
    "applicability_changed",
    # additions recorded in IMPLEMENTATION_STATUS.md
    "exploitation_reported",
    "kev_record_missing",
)

DELTA_LABELS = {
    "exploitation_confirmed": "Exploitation confirmed",
    "exploitation_reported": "Exploitation reported (unconfirmed)",
    "local_attempt_observed": "Local attempt observed",
    "local_compromise_confirmed": "Local compromise confirmed",
    "claim_retracted": "Claim retracted",
    "evidence_conflict": "Conflicting evidence",
    "asset_exposure_changed": "Asset exposure changed",
    "evidence_expired": "Evidence expired",
    "applicability_changed": "Applicability changed",
    "kev_record_missing": "KEV record missing from latest snapshot",
}

REASON_TEXT = {
    "LOCAL_COMPROMISE_CONFIRMED": "Reviewed compromise confirmed on this asset; patching alone does not resolve it.",
    "NOT_AFFECTED_CONTRADICTED": "Reviewed not_affected conflicts with a confirmed local exploit attempt on this asset.",
    "NOT_AFFECTED_REVIEWED": "A valid reviewed not_affected assessment exists and nothing contradicts it.",
    "APPLICABILITY_UNKNOWN": "Applicability is unknown; unknown is not treated as safe.",
    "NOT_AFFECTED_EXPIRED": "The reviewed not_affected assessment has expired and must be re-confirmed.",
    "LOCAL_EXPLOIT_ATTEMPT": "A confirmed exploit attempt against this asset was observed locally.",
    "KEV_AND_EXPOSED": "Exploitation is confirmed publicly and the asset is internet-exposed.",
    "CONFIRMED_AND_CRITICAL": "Exploitation is confirmed publicly and the asset is critical.",
    "PUBLIC_EXPLOITATION_CONFIRMED": "Exploitation is confirmed publicly.",
    "EXPOSURE_UNKNOWN": "Internet exposure of the asset is unknown.",
    "EVIDENCE_EXPIRED": "Asset exposure evidence has expired.",
    "AFFECTED": "The asset is affected; plan a normal remediation.",
    "PUBLIC_EXPLOITATION_REPORTED": "Exploitation is reported but not confirmed (context only).",
    "EVIDENCE_CONFLICT": "Positive and negative exploitation claims coexist (context only).",
    "LOCAL_SCAN_ONLY": "Only scanning was observed; scanning is not exploitation (context only).",
    "EPSS_STALE": "EPSS score is older than 72 h (context only).",
    "EPSS_MISSING": "No EPSS score available (context only).",
    "KEV_RECORD_MISSING": "The vulnerability is missing from the latest KEV snapshot; not treated as a retraction.",
    "ROOT_UNRESOLVED": "Some reports have an unknown origin and are not counted as independent.",
}


def is_valid_vuln_id(value: str, *, synthetic: bool) -> bool:
    """Live records must be CVE IDs. Synthetic records must use DEMO-VULN-### (never CVE-like)."""
    if synthetic:
        return bool(DEMO_RE.match(value))
    return bool(CVE_RE.match(value))


def parse_bool_tri(value: str) -> str | None:
    v = (value or "").strip().lower()
    return v if v in EXPOSURE else None

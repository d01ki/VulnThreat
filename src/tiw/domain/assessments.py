"""Deterministic per-vulnerability threat assessment (DESIGN §9.1) and delta derivation (§9.4).

The assessment keeps separate axes and never merges them into a single score.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from tiw.domain.claims import ClaimView, RelationView, independence, mark_inactive
from tiw.domain.vocab import CONFIRMED_MAPPING, LOCAL_ACTIVITY_ORDER

ENGINE_VERSION = "assess-1"
EPSS_MAX_AGE = timedelta(hours=72)
RECENT_WINDOW = timedelta(days=30)


@dataclass(frozen=True)
class ObservationView:
    id: str
    asset_id: str | None
    event_type: str
    mapping_status: str
    observed_at: datetime
    sensor_id: str
    reviewer: str | None


@dataclass(frozen=True)
class KevContext:
    """KEV snapshot facts for one vulnerability."""

    listed_ever: bool
    in_latest_snapshot: bool | None  # None when there is no KEV snapshot at all
    latest_snapshot_released: str | None
    date_added: str | None


def canonical_hash(state: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _level(a: str, b: str) -> str:
    return a if LOCAL_ACTIVITY_ORDER.index(a) >= LOCAL_ACTIVITY_ORDER.index(b) else b


def assess(
    vulnerability_id: str,
    claims: list[ClaimView],
    relations: list[RelationView],
    observations: list[ObservationView],
    kev: KevContext,
    now: datetime,
) -> tuple[dict[str, Any], list[str]]:
    """Return (state_json, evidence_ids). Pure function of its inputs and ``now``."""
    mark_inactive(claims, relations)
    indep = independence(claims, relations)
    derived_inactive = set(indep.derived_from_inactive)

    expl = [c for c in claims if c.predicate == "exploited_in_wild"]
    active_pos = [c for c in expl if c.positive and c.inactive_reason is None and c.id not in derived_inactive]
    active_neg = [c for c in expl if c.negative and c.inactive_reason is None]
    retracted = sorted(c.id for c in claims if c.effective_state == "retracted")

    confirming = [
        c
        for c in active_pos
        if c.origin == "kev" or (c.effective_state == "reviewed" and c.origin in ("primary", "vendor"))
    ]
    if confirming:
        public = "confirmed"
    elif active_pos:
        public = "reported"
    else:
        public = "unknown"
    basis_kinds = sorted({"kev" if c.origin == "kev" else "reviewed_primary" for c in confirming})

    if active_pos:
        latest = max(c.evidence_time for c in active_pos)
        recency = "fresh" if now - latest <= RECENT_WINDOW else "stale"
        latest_iso = latest.isoformat()
    else:
        recency, latest_iso = "unknown", None

    # Local activity: only reviewer-confirmed / explicit CVE mappings propagate (DESIGN §7.6).
    local = "none_observed"
    by_asset: dict[str, str] = {}
    counts = {"scan": 0, "exploit_attempt": 0, "compromise_confirmed": 0}
    unmapped = 0
    used_obs: list[str] = []
    last_local = None
    for o in observations:
        if o.mapping_status not in CONFIRMED_MAPPING:
            unmapped += 1
            continue
        used_obs.append(o.id)
        counts[o.event_type] += 1
        local = _level(local, o.event_type)
        if o.asset_id:
            by_asset[o.asset_id] = _level(by_asset.get(o.asset_id, "none_observed"), o.event_type)
        last_local = max(last_local, o.observed_at) if last_local else o.observed_at

    epss_claims = [c for c in claims if c.predicate == "epss_score" and c.inactive_reason is None]
    epss = None
    epss_id = None
    if epss_claims:
        best = max(epss_claims, key=lambda c: (c.value.get("score_date", ""), c.fetched_at))
        epss_id = best.id
        score_date = datetime.fromisoformat(best.value["score_date"] + "T00:00:00+00:00")
        epss = {
            "probability": best.value["probability"],
            "percentile": best.value["percentile"],
            "score_date": best.value["score_date"],
            "stale": now - score_date > EPSS_MAX_AGE,
        }

    poc = any(
        c.predicate == "poc_published" and c.value.get("value") is True and c.inactive_reason is None for c in claims
    )

    state: dict[str, Any] = {
        "vulnerability_id": vulnerability_id,
        "public_exploitation": public,
        "public_basis_claim_ids": sorted(c.id for c in confirming),
        "public_basis_kinds": basis_kinds,
        "reported_claim_ids": sorted(c.id for c in active_pos),
        "denying_claim_ids": sorted(c.id for c in active_neg),
        "explicitly_denied": bool(active_neg) and not active_pos,
        "conflict": bool(active_pos) and bool(active_neg),
        "recency": recency,
        "latest_public_evidence_at": latest_iso,
        "local_activity": local,
        "local_by_asset": dict(sorted(by_asset.items())),
        "local_counts": counts,
        "last_local_observation_at": last_local.isoformat() if last_local else None,
        "unmapped_observation_count": unmapped,
        "independence": indep.as_dict(),
        "epss": epss,
        "kev": {
            "listed_ever": kev.listed_ever,
            "in_latest_snapshot": kev.in_latest_snapshot,
            "latest_snapshot_released": kev.latest_snapshot_released,
            "date_added": kev.date_added,
        },
        "retracted_claim_ids": retracted,
        "poc_published": poc,
    }
    evidence = sorted(
        set(state["reported_claim_ids"])
        | set(state["denying_claim_ids"])
        | set(retracted)
        | set(used_obs)
        | ({epss_id} if epss_id else set())
    )
    return state, evidence


EMPTY_STATE: dict[str, Any] = {
    "public_exploitation": "unknown",
    "conflict": False,
    "recency": "unknown",
    "local_activity": "none_observed",
    "local_by_asset": {},
    "epss": None,
    "kev": {"listed_ever": False, "in_latest_snapshot": None},
    "retracted_claim_ids": [],
}


def derive_deltas(old: dict[str, Any] | None, new: dict[str, Any]) -> list[dict[str, Any]]:
    """Return meaningful changes only. Refetches and reposts produce nothing here."""
    o = old or EMPTY_STATE
    out: list[dict[str, Any]] = []
    op, np_ = o["public_exploitation"], new["public_exploitation"]
    rank = {"unknown": 0, "reported": 1, "confirmed": 2}
    new_retractions = sorted(set(new["retracted_claim_ids"]) - set(o.get("retracted_claim_ids", [])))

    if np_ == "confirmed" and op != "confirmed":
        out.append(
            {
                "change_type": "exploitation_confirmed",
                "summary": f"Public exploitation {op} → confirmed ({', '.join(new['public_basis_kinds'])})",
                "before": {"public_exploitation": op},
                "after": {"public_exploitation": np_},
                "evidence_ids": new["public_basis_claim_ids"],
            }
        )
    elif np_ == "reported" and op == "unknown":
        out.append(
            {
                "change_type": "exploitation_reported",
                "summary": "Exploitation reported by unconfirmed sources; not treated as confirmed",
                "before": {"public_exploitation": op},
                "after": {"public_exploitation": np_},
                "evidence_ids": new["reported_claim_ids"],
            }
        )
    if new_retractions or rank[np_] < rank[op]:
        out.append(
            {
                "change_type": "claim_retracted",
                "summary": (
                    f"{len(new_retractions)} claim(s) retracted; public exploitation {op} → {np_}"
                    if new_retractions
                    else f"Supporting claim superseded or rejected; public exploitation {op} → {np_}"
                ),
                "before": {"public_exploitation": op},
                "after": {"public_exploitation": np_},
                "evidence_ids": new_retractions,
            }
        )
    for asset, level in new["local_by_asset"].items():
        before = o["local_by_asset"].get(asset, "none_observed")
        if level == "compromise_confirmed" and before != "compromise_confirmed":
            out.append(
                {
                    "change_type": "local_compromise_confirmed",
                    "summary": f"Reviewed compromise confirmed on {asset}",
                    "before": {"local_activity": before},
                    "after": {"local_activity": level},
                    "asset_id": asset,
                    "evidence_ids": [],
                }
            )
        elif level == "exploit_attempt" and before in ("none_observed", "scan"):
            out.append(
                {
                    "change_type": "local_attempt_observed",
                    "summary": f"Confirmed exploit attempt observed against {asset}",
                    "before": {"local_activity": before},
                    "after": {"local_activity": level},
                    "asset_id": asset,
                    "evidence_ids": [],
                }
            )
    if new["conflict"] and not o["conflict"]:
        out.append(
            {
                "change_type": "evidence_conflict",
                "summary": "Positive and negative exploitation claims now coexist",
                "before": {"conflict": False},
                "after": {"conflict": True},
                "evidence_ids": new["reported_claim_ids"] + new["denying_claim_ids"],
            }
        )
    oe, ne = o.get("epss"), new.get("epss")
    if ne and ne["stale"] and not (oe and oe["stale"]) and oe is not None:
        out.append(
            {
                "change_type": "evidence_expired",
                "summary": f"EPSS score from {ne['score_date']} is older than 72 h; refresh needed",
                "before": {"epss_stale": False},
                "after": {"epss_stale": True},
                "evidence_kind": "epss",
                "evidence_ids": [],
            }
        )
    if o["recency"] == "fresh" and new["recency"] == "stale":
        out.append(
            {
                "change_type": "evidence_expired",
                "summary": "Latest public exploitation evidence is older than 30 days (historical fact retained)",
                "before": {"recency": "fresh"},
                "after": {"recency": "stale"},
                "evidence_kind": "public_recency",
                "evidence_ids": [],
            }
        )
    ok, nk = o.get("kev") or {}, new.get("kev") or {}
    if ok.get("in_latest_snapshot") is True and nk.get("in_latest_snapshot") is False:
        out.append(
            {
                "change_type": "kev_record_missing",
                "summary": "Missing from the latest KEV snapshot; prior listing retained, verify before changing",
                "before": {"kev_in_latest": True},
                "after": {"kev_in_latest": False},
                "evidence_ids": [],
            }
        )
    return out

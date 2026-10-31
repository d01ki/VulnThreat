"""Append-only claim reviews and reviewer-confirmed relations (POST /claims/{id}/reviews)."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select

from tiw.domain.vocab import RELATION_KINDS
from tiw.services.ingest import audit, next_seq
from tiw.services.pipeline import recompute_in_session
from tiw.storage import db
from tiw.storage.models import Claim, ClaimRelation, ClaimReview

REVIEWABLE_STATES = ("reviewed", "rejected", "retracted", "unreviewed")


class ReviewError(ValueError):
    pass


def add_review(
    ws: db.Workspace,
    claim_id: str,
    *,
    reviewer: str,
    state: str,
    reason: str,
    relation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if state not in REVIEWABLE_STATES:
        raise ReviewError(f"state must be one of {', '.join(REVIEWABLE_STATES)}")
    if not reason or not reason.strip():
        raise ReviewError("reason is required")
    if not reviewer or not reviewer.strip():
        raise ReviewError("reviewer is required")
    with db.session_scope(ws) as s:
        claim = s.get(Claim, claim_id)
        if claim is None:
            raise LookupError("claim not found")
        if claim.origin in ("kev", "epss") and state == "reviewed":
            raise ReviewError("feed records are already authoritative snapshots")
        review = ClaimReview(
            claim_id=claim.id,
            reviewer=reviewer.strip()[:120],
            state=state,
            reason=reason.strip()[:2000],
            recorded_at=db.now(s),
            seq=next_seq(s, ClaimReview),
        )
        s.add(review)
        s.flush()
        rel_id = None
        if relation:
            to = s.get(Claim, str(relation.get("to_claim_id")))
            kind = relation.get("kind")
            if to is None or kind not in RELATION_KINDS or to.id == claim.id:
                raise ReviewError("relation requires an existing to_claim_id and a valid kind")
            existing = s.execute(
                select(ClaimRelation).where(
                    ClaimRelation.from_claim_id == claim.id,
                    ClaimRelation.to_claim_id == to.id,
                    ClaimRelation.kind == kind,
                )
            ).scalar_one_or_none()
            if existing is None:
                r = ClaimRelation(
                    from_claim_id=claim.id, to_claim_id=to.id, kind=kind, verification="reviewer_confirmed", created_at=db.now(s)
                )
                s.add(r)
                s.flush()
                rel_id = r.id
        audit(s, reviewer, "claim_review", "claim", claim.id, {"state": state, "relation_id": rel_id})
        summary = recompute_in_session(s, None, actor=reviewer, trigger=f"review:{review.id}")
        return {"review_id": review.id, "claim_id": claim.id, "state": state, "relation_id": rel_id, "recompute": summary}

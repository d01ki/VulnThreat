"""Human-reviewed advisory claim JSON adapter (DESIGN §4 P0, §9).

Document text is stored as data only. Nothing inside it is interpreted as an instruction.
"""

from __future__ import annotations

import json
from typing import Any

from tiw.adapters.common import (
    MAX_RECORDS,
    InputMalformed,
    InputTooLarge,
    ParseContext,
    ParseResult,
    check_synthetic,
    decode_text,
    parse_time_field,
    truthy,
)
from tiw.domain.vocab import (
    INITIAL_REVIEW_STATES,
    GRAPH_PREDICATES,
    GRAPH_SUBJECT_RE,
    ORIGINS,
    PREDICATES,
    RELATION_KINDS,
    RELATION_VERIFICATION,
    is_valid_vuln_id,
)

CLAIMS_ADAPTER_VERSION = "claims-1"
MAX_TEXT = 20_000


def parse_claims(data: bytes, ctx: ParseContext) -> ParseResult:
    result = ParseResult()
    try:
        doc = json.loads(decode_text(data))
    except json.JSONDecodeError as exc:
        raise InputMalformed(f"claims file is not valid JSON (line {exc.lineno})") from exc
    if not isinstance(doc, dict) or doc.get("schema_version") != "1.0":
        raise InputMalformed("claims file must be an object with schema_version '1.0'")
    src = doc.get("source")
    if not isinstance(src, dict) or not src.get("name"):
        raise InputMalformed("claims file requires source.name")
    docs = doc.get("documents")
    if not isinstance(docs, list) or not docs:
        raise InputMalformed("claims file requires a non-empty 'documents' array")
    synthetic = truthy(doc.get("synthetic"))
    if not check_synthetic(synthetic, ctx, result, None):
        return result
    synthetic = synthetic or ctx.synthetic_workspace
    result.meta = {
        "synthetic": synthetic,
        "source": {
            "name": str(src["name"])[:200],
            "kind": str(src.get("kind") or "advisory")[:32],
            "canonical_url": (str(src["canonical_url"])[:500] if src.get("canonical_url") else None),
            "license_note": (str(src["license_note"])[:500] if src.get("license_note") else None),
        },
    }
    total = 0
    keys_in_file: set[str] = set()
    for di, d in enumerate(docs):
        loc = f"documents[{di}]"
        if not isinstance(d, dict) or not d.get("external_id"):
            result.error(di + 1, loc, "document requires external_id")
            continue
        try:
            published_at = parse_time_field(d.get("published_at"), allow_date_only=True)[0] if d.get("published_at") else None
        except ValueError as exc:
            result.error(di + 1, f"{loc}.published_at", str(exc))
            continue
        claims_out: list[dict[str, Any]] = []
        for ci, c in enumerate(d.get("claims") or []):
            cloc = f"{loc}.claims[{ci}]"
            total += 1
            if total > MAX_RECORDS:
                raise InputTooLarge(f"more than {MAX_RECORDS} records")
            if not isinstance(c, dict):
                result.error(di + 1, cloc, "claim must be an object")
                continue
            key = str(c.get("claim_key") or "")
            if not key or len(key) > 200:
                result.error(di + 1, f"{cloc}.claim_key", "claim_key is required (max 200 chars)")
                continue
            if key in keys_in_file:
                result.error(di + 1, f"{cloc}.claim_key", f"duplicate claim_key {key[:60]}")
                continue
            subject = str(c.get("subject_id") or "")
            predicate = c.get("predicate")
            if predicate not in PREDICATES and predicate not in GRAPH_PREDICATES:
                result.error(di + 1, f"{cloc}.predicate", f"must be one of {', '.join(PREDICATES + GRAPH_PREDICATES)}")
                continue
            if predicate in GRAPH_PREDICATES:
                if not GRAPH_SUBJECT_RE.match(subject):
                    result.error(di + 1, f"{cloc}.subject_id", "graph claims need subject edge:<edge id> or cond:<vulnerability>:<condition id>")
                    continue
                if not isinstance(c.get("value"), bool):
                    result.error(di + 1, f"{cloc}.value", f"{predicate} value must be true or false")
                    continue
            elif not is_valid_vuln_id(subject, synthetic=synthetic):
                result.error(di + 1, f"{cloc}.subject_id", f"invalid identifier {subject[:40]!r}")
                continue
            origin = c.get("origin")
            if origin not in ORIGINS or origin in ("kev", "epss"):
                result.error(di + 1, f"{cloc}.origin", "must be primary, secondary, vendor or model")
                continue
            state = c.get("review_state", "unreviewed")
            if state not in INITIAL_REVIEW_STATES:
                result.error(di + 1, f"{cloc}.review_state", f"must be one of {', '.join(INITIAL_REVIEW_STATES)}")
                continue
            if origin == "model" and state != "candidate":
                result.error(di + 1, f"{cloc}.review_state", "model-origin claims can only be candidates")
                continue
            if state == "reviewed" and not (c.get("reviewer") and c.get("review_reason")):
                result.error(di + 1, f"{cloc}.reviewer", "reviewed claims require reviewer and review_reason")
                continue
            if predicate == "exploited_in_wild" and not isinstance(c.get("value"), bool):
                result.error(di + 1, f"{cloc}.value", "exploited_in_wild value must be true or false")
                continue
            relations = []
            bad_rel = False
            for ri, r in enumerate(c.get("relations") or []):
                if (
                    not isinstance(r, dict)
                    or r.get("kind") not in RELATION_KINDS
                    or r.get("verification", "explicit") not in RELATION_VERIFICATION
                    or not r.get("to")
                ):
                    result.error(di + 1, f"{cloc}.relations[{ri}]", "relation requires kind, to and a valid verification")
                    bad_rel = True
                    break
                if r["to"] == key:
                    result.error(di + 1, f"{cloc}.relations[{ri}]", "a claim cannot relate to itself")
                    bad_rel = True
                    break
                relations.append(
                    {"kind": r["kind"], "to": str(r["to"]), "verification": r.get("verification", "explicit")}
                )
            if bad_rel:
                continue
            keys_in_file.add(key)
            claims_out.append(
                {
                    "claim_key": key,
                    "subject_id": subject,
                    "predicate": predicate,
                    "value": {"value": c.get("value")},
                    "quote": (str(c["quote"])[:2000] if c.get("quote") else None),
                    "locator": (str(c["locator"])[:200] if c.get("locator") else None),
                    "origin": origin,
                    "review_state": state,
                    "reviewer": c.get("reviewer"),
                    "review_reason": c.get("review_reason"),
                    "relations": relations,
                }
            )
        retractions = []
        for ri, r in enumerate(d.get("retractions") or []):
            if not isinstance(r, dict) or not r.get("claim_key") or not r.get("reason"):
                result.error(di + 1, f"{loc}.retractions[{ri}]", "retraction requires claim_key and reason")
                continue
            retractions.append(
                {"claim_key": str(r["claim_key"]), "reason": str(r["reason"])[:1000], "reviewer": r.get("reviewer")}
            )
        result.records.append(
            {
                "external_id": str(d["external_id"])[:300],
                "title": (str(d["title"])[:500] if d.get("title") else None),
                "published_at": published_at,
                "text": (str(d["text"])[:MAX_TEXT] if d.get("text") else ""),
                "claims": claims_out,
                "retractions": retractions,
            }
        )
    return result

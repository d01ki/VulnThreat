"""Saved-response adapters for CISA KEV and FIRST EPSS (P0: files only, no network)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from tiw.adapters.common import (
    MAX_RECORDS,
    InputMalformed,
    InputTooLarge,
    ParseContext,
    ParseResult,
    check_synthetic,
    decode_text,
    truthy,
)
from tiw.domain.vocab import is_valid_vuln_id

KEV_ADAPTER_VERSION = "kev-1"
EPSS_ADAPTER_VERSION = "epss-1"


def _date(value: Any) -> datetime:
    return datetime.strptime(str(value), "%Y-%m-%d").replace(tzinfo=timezone.utc)


def parse_kev(data: bytes, ctx: ParseContext) -> ParseResult:
    """Parse a KEV catalog snapshot (the official JSON layout)."""
    result = ParseResult()
    try:
        doc = json.loads(decode_text(data))
    except json.JSONDecodeError as exc:
        raise InputMalformed(f"KEV snapshot is not valid JSON (line {exc.lineno})") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities"), list):
        raise InputMalformed("KEV snapshot must be an object with a 'vulnerabilities' array")
    synthetic = truthy(doc.get("synthetic"))
    if not check_synthetic(synthetic, ctx, result, None):
        return result
    try:
        released = _date(str(doc.get("dateReleased", ""))[:10])
    except ValueError:
        raise InputMalformed("KEV snapshot 'dateReleased' must start with YYYY-MM-DD") from None
    vulns = doc["vulnerabilities"]
    if len(vulns) > MAX_RECORDS:
        raise InputTooLarge(f"more than {MAX_RECORDS} records")
    result.meta = {
        "catalog_version": str(doc.get("catalogVersion") or released.date().isoformat()),
        "released": released,
        "synthetic": synthetic or ctx.synthetic_workspace,
        "title": str(doc.get("title") or "KEV catalog"),
    }
    seen: set[str] = set()
    for i, v in enumerate(vulns):
        loc = f"vulnerabilities[{i}]"
        if not isinstance(v, dict):
            result.error(i + 1, loc, "entry must be an object")
            continue
        vid = str(v.get("cveID") or "")
        if not is_valid_vuln_id(vid, synthetic=result.meta["synthetic"]):
            expected = "DEMO-VULN-### (synthetic)" if result.meta["synthetic"] else "CVE-YYYY-NNNN"
            result.error(i + 1, f"{loc}.cveID", f"invalid identifier {vid[:40]!r}; expected {expected}")
            continue
        if vid in seen:
            result.error(i + 1, f"{loc}.cveID", f"duplicate entry for {vid}")
            continue
        try:
            added = _date(v.get("dateAdded"))
        except (ValueError, TypeError):
            result.error(i + 1, f"{loc}.dateAdded", "dateAdded must be YYYY-MM-DD")
            continue
        seen.add(vid)
        result.records.append(
            {
                "vulnerability_id": vid,
                "date_added": added,
                "vendor_project": str(v.get("vendorProject") or ""),
                "product": str(v.get("product") or ""),
                "name": str(v.get("vulnerabilityName") or ""),
                "short_description": str(v.get("shortDescription") or ""),
                "required_action": str(v.get("requiredAction") or ""),
                # Kept for reference only; never adopted as a legal deadline (DESIGN §10).
                "due_date_reference": str(v.get("dueDate") or ""),
                "ransomware_use": str(v.get("knownRansomwareCampaignUse") or "Unknown"),
                "locator": f"{loc} (cveID={vid})",
            }
        )
    return result


def parse_epss(data: bytes, ctx: ParseContext) -> ParseResult:
    """Parse a saved FIRST EPSS API response ({"status": "OK", "data": [...]})."""
    result = ParseResult()
    try:
        doc = json.loads(decode_text(data))
    except json.JSONDecodeError as exc:
        raise InputMalformed(f"EPSS response is not valid JSON (line {exc.lineno})") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("data"), list):
        raise InputMalformed("EPSS response must be an object with a 'data' array")
    synthetic = truthy(doc.get("synthetic"))
    if not check_synthetic(synthetic, ctx, result, None):
        return result
    rows = doc["data"]
    if len(rows) > MAX_RECORDS:
        raise InputTooLarge(f"more than {MAX_RECORDS} records")
    synthetic = synthetic or ctx.synthetic_workspace
    result.meta = {"synthetic": synthetic, "title": "EPSS scores"}
    dates: list[datetime] = []
    for i, r in enumerate(rows):
        loc = f"data[{i}]"
        if not isinstance(r, dict):
            result.error(i + 1, loc, "entry must be an object")
            continue
        vid = str(r.get("cve") or "")
        if not is_valid_vuln_id(vid, synthetic=synthetic):
            result.error(i + 1, f"{loc}.cve", f"invalid identifier {vid[:40]!r}")
            continue
        try:
            prob = float(r.get("epss"))
            pct = float(r.get("percentile"))
            score_date = _date(r.get("date"))
        except (TypeError, ValueError):
            result.error(i + 1, loc, "epss, percentile must be numbers and date YYYY-MM-DD")
            continue
        if not (0.0 <= prob <= 1.0 and 0.0 <= pct <= 1.0):
            result.error(i + 1, loc, "epss and percentile must be within 0..1")
            continue
        dates.append(score_date)
        result.records.append(
            {"vulnerability_id": vid, "probability": prob, "percentile": pct, "score_date": score_date, "locator": loc}
        )
    result.meta["score_date"] = max(dates) if dates else None
    return result

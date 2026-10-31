"""Local observation JSONL adapter (DESIGN §8). Also accepts sensor_window records."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from tiw.adapters.common import (
    CLOCK_SKEW,
    MAX_RECORDS,
    InputTooLarge,
    ParseContext,
    ParseResult,
    check_synthetic,
    decode_text,
    parse_time_field,
    truthy,
)
from tiw.domain.vocab import EVENT_TYPES, MAPPING_STATUS, is_valid_vuln_id

OBSERVATIONS_ADAPTER_VERSION = "observations-1"
SENSITIVE_KEYS = ("password", "passwd", "secret", "token", "cookie", "authorization", "api_key", "apikey")
DROPPED_KEYS = ("body", "payload", "raw", "raw_request", "raw_response")
MAX_EVIDENCE_BYTES = 4096


def sanitize_evidence(evidence: Any) -> dict[str, Any]:
    """Minimise stored evidence: mask secrets, drop raw traffic bodies, cap size."""
    if not isinstance(evidence, dict):
        return {}
    clean: dict[str, Any] = {}
    for k, v in evidence.items():
        key = str(k)[:80]
        low = key.lower()
        if any(d == low for d in DROPPED_KEYS):
            clean[key] = "[dropped: raw content not stored]"
        elif any(s in low for s in SENSITIVE_KEYS):
            clean[key] = "[masked]"
        elif isinstance(v, (str, int, float, bool)) or v is None:
            clean[key] = v if not isinstance(v, str) else v[:500]
        else:
            clean[key] = json.dumps(v, sort_keys=True)[:500]
    if len(json.dumps(clean)) > MAX_EVIDENCE_BYTES:
        clean = {"truncated": True, "keys": sorted(clean)[:50]}
    return clean


def parse_observations(data: bytes, ctx: ParseContext) -> ParseResult:
    result = ParseResult()
    lines = decode_text(data).splitlines()
    if len(lines) > MAX_RECORDS:
        raise InputTooLarge(f"more than {MAX_RECORDS} records")
    windows: list[dict[str, Any]] = []
    for lineno, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            result.error(lineno, None, "line is not valid JSON")
            continue
        if not isinstance(rec, dict):
            result.error(lineno, None, "line must be a JSON object")
            continue
        if rec.get("schema_version") != "1.0":
            result.error(lineno, "schema_version", "unsupported schema_version; expected '1.0'")
            continue
        synthetic = truthy(rec.get("synthetic"))
        if not check_synthetic(synthetic, ctx, result, lineno):
            continue
        synthetic = synthetic or ctx.synthetic_workspace
        sensor = str(rec.get("sensor_id") or "")
        if not sensor or len(sensor) > 120:
            result.error(lineno, "sensor_id", "sensor_id is required (max 120 chars)")
            continue

        if rec.get("record_type") == "sensor_window":
            try:
                start, _ = parse_time_field(rec.get("start"))
                end, _ = parse_time_field(rec.get("end"))
            except ValueError as exc:
                result.error(lineno, "start/end", str(exc))
                continue
            if end <= start:
                result.error(lineno, "end", "end must be after start")
                continue
            status = rec.get("status")
            if status not in ("ok", "outage"):
                result.error(lineno, "status", "sensor window status must be ok or outage")
                continue
            cov = rec.get("coverage") if isinstance(rec.get("coverage"), dict) else {}
            windows.append(
                {"line": lineno, "sensor_id": sensor, "start": start, "end": end, "status": status, "coverage": cov}
            )
            continue

        event_type = rec.get("event_type")
        if event_type not in EVENT_TYPES:
            result.error(lineno, "event_type", f"must be one of {', '.join(EVENT_TYPES)}")
            continue
        try:
            observed_at, precision = parse_time_field(rec.get("observed_at"), allow_date_only=True)
        except ValueError as exc:
            result.error(lineno, "observed_at", str(exc))
            continue
        mapping = rec.get("mapping_status", "unconfirmed")
        if mapping not in MAPPING_STATUS:
            result.error(lineno, "mapping_status", f"must be one of {', '.join(MAPPING_STATUS)}")
            continue
        vid = rec.get("vulnerability_id") or rec.get("cve_id")
        if vid is not None:
            vid = str(vid)
            if not is_valid_vuln_id(vid, synthetic=synthetic):
                result.error(lineno, "vulnerability_id", f"invalid identifier {vid[:40]!r}")
                continue
        reviewer = rec.get("reviewer")
        rationale = rec.get("rationale")
        if event_type == "compromise_confirmed" and not (reviewer and rationale):
            # A detection-rule alert alone can never establish a compromise (DESIGN §8).
            result.error(lineno, "reviewer/rationale", "compromise_confirmed requires reviewer and rationale")
            continue
        asset_id = rec.get("asset_id")
        ext = rec.get("external_event_id")
        evidence = sanitize_evidence(rec.get("evidence"))
        normalized = {
            "sensor_id": sensor,
            "observed_at": observed_at.isoformat(),
            "asset_id": asset_id,
            "vulnerability_id": vid,
            "event_type": event_type,
            "evidence": evidence,
        }
        dedup = (
            f"ext:{ext}"
            if ext
            else "hash:" + hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
        )
        quarantine = None
        if observed_at > ctx.now + CLOCK_SKEW:
            quarantine = "observed_at is more than 5 minutes in the future"
        result.records.append(
            {
                "line": lineno,
                "sensor_id": sensor,
                "external_event_id": str(ext) if ext else None,
                "dedup_key": dedup,
                "observed_at": observed_at,
                "precision": precision,
                "asset_id": str(asset_id) if asset_id else None,
                "vulnerability_id": vid,
                "event_type": event_type,
                "mapping_status": mapping,
                "reviewer": reviewer,
                "rationale": rationale,
                "evidence": evidence,
                "synthetic": synthetic,
                "quarantine": quarantine,
            }
        )
    result.meta = {"windows": windows, "synthetic": ctx.synthetic_workspace or any(r["synthetic"] for r in result.records)}
    return result

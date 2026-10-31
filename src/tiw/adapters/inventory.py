"""Asset CSV and finding (asset ↔ vulnerability) CSV adapters (DESIGN §8)."""

from __future__ import annotations

from tiw.adapters.common import (
    ParseContext,
    ParseResult,
    check_synthetic,
    decode_text,
    parse_time_field,
    read_csv,
    truthy,
)
from tiw.domain.vocab import APPLICABILITY, CRITICALITY, is_valid_vuln_id, parse_bool_tri

ASSETS_ADAPTER_VERSION = "assets-1"
FINDINGS_ADAPTER_VERSION = "findings-1"

ASSET_COLUMNS = ["asset_id", "name", "criticality", "internet_exposed", "observed_at", "expires_at"]
FINDING_COLUMNS = ["finding_id", "asset_id", "vulnerability_id", "applicability", "observed_at"]
NOT_AFFECTED_COLUMNS = ["rationale", "evidence_ref", "reviewer", "expires_at"]
_ID_MAX = 120


def _id_ok(value: str) -> bool:
    return 0 < len(value) <= _ID_MAX and all(c.isalnum() or c in "-_.:" for c in value)


def parse_assets(data: bytes, ctx: ParseContext) -> ParseResult:
    result = ParseResult()
    rows = read_csv(decode_text(data), ASSET_COLUMNS, result)
    seen: set[str] = set()
    for line, row in rows:
        synthetic = truthy(row.get("synthetic"))
        if not check_synthetic(synthetic, ctx, result, line):
            continue
        aid = row["asset_id"]
        if not _id_ok(aid):
            result.error(line, "asset_id", "asset_id must be 1-120 chars of letters, digits, - _ . :")
            continue
        if aid in seen:
            result.error(line, "asset_id", f"duplicate asset_id {aid} in file")
            continue
        if not row["name"]:
            result.error(line, "name", "name is required")
            continue
        crit = row["criticality"].lower()
        if crit not in CRITICALITY:
            result.error(line, "criticality", f"must be one of {', '.join(CRITICALITY)}")
            continue
        exposed = parse_bool_tri(row["internet_exposed"])
        if exposed is None:
            result.error(line, "internet_exposed", "must be true, false or unknown")
            continue
        try:
            observed_at, _ = parse_time_field(row["observed_at"])
        except ValueError as exc:
            result.error(line, "observed_at", str(exc))
            continue
        expires_at = None
        if row["expires_at"]:
            try:
                expires_at, _ = parse_time_field(row["expires_at"])
            except ValueError as exc:
                result.error(line, "expires_at", str(exc))
                continue
            if expires_at <= observed_at:
                result.error(line, "expires_at", "expires_at must be after observed_at")
                continue
        seen.add(aid)
        context = {
            k: v
            for k, v in row.items()
            if k not in ASSET_COLUMNS and k not in ("owner", "synthetic") and v
        }
        result.records.append(
            {
                "line": line,
                "asset_id": aid,
                "name": row["name"][:200],
                "owner": row.get("owner") or None,
                "criticality": crit,
                "internet_exposed": exposed,
                "observed_at": observed_at,
                "expires_at": expires_at,
                "context": context,
                "synthetic": synthetic or ctx.synthetic_workspace,
            }
        )
    return result


def parse_findings(data: bytes, ctx: ParseContext) -> ParseResult:
    result = ParseResult()
    rows = read_csv(decode_text(data), FINDING_COLUMNS, result)
    seen: set[str] = set()
    for line, row in rows:
        synthetic = truthy(row.get("synthetic"))
        if not check_synthetic(synthetic, ctx, result, line):
            continue
        fid = row["finding_id"]
        if not _id_ok(fid):
            result.error(line, "finding_id", "finding_id must be 1-120 chars of letters, digits, - _ . :")
            continue
        if fid in seen:
            result.error(line, "finding_id", f"duplicate finding_id {fid} in file")
            continue
        vid = row["vulnerability_id"]
        if not is_valid_vuln_id(vid, synthetic=synthetic or ctx.synthetic_workspace):
            result.error(line, "vulnerability_id", f"invalid identifier {vid[:40]!r}")
            continue
        status = row["applicability"].lower()
        if status not in APPLICABILITY:
            result.error(line, "applicability", f"must be one of {', '.join(APPLICABILITY)}")
            continue
        try:
            observed_at, _ = parse_time_field(row["observed_at"])
        except ValueError as exc:
            result.error(line, "observed_at", str(exc))
            continue
        expires_at = None
        if status == "not_affected":
            missing = [c for c in NOT_AFFECTED_COLUMNS if not row.get(c)]
            if missing:
                result.error(
                    line,
                    ",".join(missing),
                    "not_affected requires rationale, evidence_ref, reviewer and expires_at; row not adopted",
                )
                continue
        if row.get("expires_at"):
            try:
                expires_at, _ = parse_time_field(row["expires_at"])
            except ValueError as exc:
                result.error(line, "expires_at", str(exc))
                continue
        seen.add(fid)
        result.records.append(
            {
                "line": line,
                "finding_id": fid,
                "asset_id": row["asset_id"],
                "vulnerability_id": vid,
                "applicability": status,
                "observed_at": observed_at,
                "expires_at": expires_at,
                "rationale": row.get("rationale") or None,
                "evidence_ref": row.get("evidence_ref") or None,
                "reviewer": row.get("reviewer") or None,
                "scanner_ref": row.get("scanner_ref") or None,
                "synthetic": synthetic or ctx.synthetic_workspace,
            }
        )
    return result

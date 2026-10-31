"""Shared adapter types. Adapters only parse and validate; they never touch the DB."""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from tiw.storage.db import parse_utc

MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 50_000
CLOCK_SKEW = timedelta(minutes=5)


class InputTooLarge(Exception):
    """Raised when an input exceeds the P0 limits (maps to HTTP 413)."""


class InputMalformed(Exception):
    """Raised when the whole file cannot be parsed (maps to HTTP 422)."""


@dataclass
class RowError:
    line: int | None
    field: str | None
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"line": self.line, "field": self.field, "reason": self.reason}


@dataclass
class ParseContext:
    now: datetime
    synthetic_workspace: bool


@dataclass
class ParseResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[RowError] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def error(self, line: int | None, fld: str | None, reason: str) -> None:
        self.errors.append(RowError(line, fld, reason))


def check_size(data: bytes) -> None:
    if len(data) > MAX_FILE_BYTES:
        raise InputTooLarge(f"input is {len(data)} bytes; the P0 limit is {MAX_FILE_BYTES} bytes")
    if data[:2] == b"PK" or data[:2] == b"\x1f\x8b" or data[:2] == b"MZ" or data[:4] == b"\x7fELF":
        raise InputMalformed("archives and executables are not accepted")


def decode_text(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputMalformed("input must be UTF-8 text") from exc


def parse_time_field(value: Any, *, allow_date_only: bool = False) -> tuple[datetime, str]:
    """Return (utc datetime, precision). Date-only values keep day precision."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp is required")
    v = value.strip()
    if allow_date_only and len(v) == 10 and v[4] == "-" and v[7] == "-":
        d = datetime.strptime(v, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return d, "day"
    return parse_utc(v), "second"


def read_csv(text: str, required: list[str], result: ParseResult) -> list[tuple[int, dict[str, str]]]:
    reader = csv.DictReader(io.StringIO(text))
    header = [h.strip() for h in (reader.fieldnames or [])]
    missing = [c for c in required if c not in header]
    if missing:
        raise InputMalformed(f"missing required columns: {', '.join(missing)}")
    rows: list[tuple[int, dict[str, str]]] = []
    for idx, row in enumerate(reader, start=2):  # header is line 1
        if len(rows) >= MAX_RECORDS:
            raise InputTooLarge(f"more than {MAX_RECORDS} records")
        if None in row:
            result.error(idx, None, "row has more values than header columns")
            continue
        rows.append((idx, {k.strip(): (v or "").strip() for k, v in row.items() if k is not None}))
    return rows


def truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("true", "1", "yes")


def check_synthetic(rec_synthetic: bool, ctx: ParseContext, result: ParseResult, line: int | None) -> bool:
    """Live workspaces reject synthetic records so demo data is never mixed with real data."""
    if rec_synthetic and not ctx.synthetic_workspace:
        result.error(line, "synthetic", "synthetic record rejected in a live workspace")
        return False
    return True

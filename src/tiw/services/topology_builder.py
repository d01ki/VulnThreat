"""Simplified topology input: an edge CSV or the "Network Paths" form instead of hand-written JSON.

Everything is converted into a normal ``topology.json`` document and imported through the
same validation (``parse_topology`` + the import writer), so no second set of rules exists.

Conventions
-----------
- ``source`` = ``internet`` or ``entry:<name>`` declares an entry point. Any other name must be an
  imported asset (a typo is an error, never a silent new entry point).
- Crown jewels (security objectives), in priority order:
  1. assets whose ``assets.csv`` row has a ``crown_jewel_weight`` column (integer > 0);
  2. otherwise the objectives of the current topology (still-present assets);
  3. otherwise every asset with criticality ``critical``, each with weight 1 (equal weights:
     relative importance is never guessed). The choice is recorded in the description.
- A row without ``reviewer`` is stored as unreviewed. An unreviewed ``allowed`` edge without a
  reviewed claim is *unsupported*, so paths through it are excluded as insufficient evidence.
"""

from __future__ import annotations

import csv
import hashlib
import io
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from tiw.adapters.common import InputMalformed, InputTooLarge, ParseResult, decode_text
from tiw.adapters.graph_inputs import MAX_EDGES, PORT_RE
from tiw.services.graph import latest_input
from tiw.services.pipeline import latest_asset_revision
from tiw.storage import db
from tiw.storage.models import Asset

EDGE_CSV_COLUMNS = ["source", "target", "ports", "reachability", "evidence_ref", "reviewer", "kind", "valid_from", "valid_until",
                    "claim_keys", "requires_capability", "grants_capability", "label", "source_zone", "destination_zone", "control", "id"]
REQUIRED = ["source", "target"]
ENTRY_RE = re.compile(r"^(internet|entry:[A-Za-z0-9_.-]{1,50})$")
SAFE_ID = re.compile(r"[^A-Za-z0-9_.:-]")


class TopologyBuildError(ValueError):
    def __init__(self, errors: list[dict[str, Any]]):
        super().__init__("; ".join(f"line {e['line']}: {e['field']}: {e['reason']}" for e in errors[:5]))
        self.errors = errors


def normalize_ports(raw: str) -> list[str]:
    out = []
    for p in re.split(r"[\s;,|]+", (raw or "").strip()):
        if not p:
            continue
        p = p.lower()
        if p.isdigit():
            p = f"tcp/{p}"
        out.append(p)
    return sorted(set(out))


def entry_id(name: str) -> str:
    return "internet" if name == "internet" else name.split(":", 1)[1]


def edge_id(source: str, target: str, ports: list[str], used: set[str]) -> str:
    base = SAFE_ID.sub("-", f"e-{entry_id(source) if ENTRY_RE.match(source) else source}-{target}")
    if len(base) > 50:
        base = base[:41] + "-" + hashlib.sha256(base.encode()).hexdigest()[:8]
    eid, n = base, 2
    while eid in used:
        eid = f"{base[:54]}-{n}"
        n += 1
    used.add(eid)
    return eid


def parse_edge_csv(data: bytes) -> list[tuple[int, dict[str, str]]]:
    if len(data) > 10 * 1024 * 1024:
        raise InputTooLarge("edge CSV larger than 10 MB")
    reader = csv.DictReader(io.StringIO(decode_text(data)))
    header = [h.strip() for h in (reader.fieldnames or [])]
    missing = [c for c in REQUIRED if c not in header]
    if missing:
        raise InputMalformed(f"missing required columns: {', '.join(missing)} (expected {','.join(EDGE_CSV_COLUMNS[:5])},...)")
    unknown = [h for h in header if h and h not in EDGE_CSV_COLUMNS]
    if unknown:
        raise InputMalformed(f"unknown columns: {', '.join(unknown)[:200]}")
    rows = []
    for i, r in enumerate(reader, start=2):
        if i - 1 > MAX_EDGES:
            raise InputTooLarge(f"more than {MAX_EDGES} edges")
        if None in r:
            raise InputMalformed(f"line {i}: more values than header columns")
        rows.append((i, {k.strip(): (v or "").strip() for k, v in r.items() if k}))
    return rows


def _objectives(s: Session, asset_ids: set[str]) -> tuple[list[dict[str, Any]], str, list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    weighted = []
    for a in s.execute(select(Asset).where(Asset.active.is_(True)).order_by(Asset.id)).scalars():
        rev = latest_asset_revision(s, a.id)
        raw = (rev.context_json or {}).get("crown_jewel_weight") if rev else None
        if raw in (None, ""):
            continue
        try:
            w = int(str(raw))
            if not 0 < w <= 1000:
                raise ValueError
        except ValueError:
            errors.append({"line": None, "field": f"assets.csv crown_jewel_weight ({a.id})", "reason": "must be an integer 1-1000"})
            continue
        weighted.append({"id": f"OBJ-{a.id}"[:58], "asset_id": a.id, "label": f"{a.name} (crown jewel)", "weight": w})
    if weighted:
        return weighted, "crown jewels from assets.csv crown_jewel_weight", errors
    cur = latest_input(s, "topology")
    if cur is not None:
        kept = [o for o in cur.content_json["objectives"] if s.get(Asset, o["asset_id"]) is not None]
        if kept:
            return kept, "crown jewels kept from the current topology", errors
    crit = [{"id": f"OBJ-{a.id}"[:58], "asset_id": a.id, "label": f"{a.name} (crown jewel)", "weight": 1}
            for a in s.execute(select(Asset).where(Asset.active.is_(True), Asset.criticality == "critical").order_by(Asset.id)).scalars()]
    return crit, "crown jewels defaulted to criticality=critical assets with equal weight 1", errors


def build_document(s: Session, rows: list[tuple[int, dict[str, str]]], *, objectives: list[dict[str, Any]] | None = None,
                   source_name: str = "topology CSV") -> dict[str, Any]:
    """Turn edge rows into a topology document. Raises TopologyBuildError with line-numbered errors."""
    errors: list[dict[str, Any]] = []
    assets = {a.id: a for a in s.execute(select(Asset).where(Asset.active.is_(True))).scalars()}
    entries: dict[str, dict[str, Any]] = {}
    nodes: set[str] = set()
    edges = []
    used: set[str] = set()
    for line, r in rows:
        src, dst = r.get("source", ""), r.get("target", "")
        if ENTRY_RE.match(src):
            eid = entry_id(src)
            entries.setdefault(eid, {"id": eid, "label": "Internet" if eid == "internet" else eid, "grants": "network_access"})
        elif src in assets:
            nodes.add(src)
        else:
            errors.append({"line": line, "field": "source", "reason": f"{src[:60]!r} is neither an imported asset nor 'internet' / 'entry:<name>'"})
            continue
        if dst not in assets:
            errors.append({"line": line, "field": "target", "reason": f"{dst[:60]!r} is not an imported asset"})
            continue
        nodes.add(dst)
        kind = (r.get("kind") or "network").lower()
        ports = normalize_ports(r.get("ports", ""))
        bad = [p for p in ports if not PORT_RE.match(p)]
        if bad:
            errors.append({"line": line, "field": "ports", "reason": f"invalid port(s) {', '.join(bad)[:60]}; use 443 or tcp/443 (several: '443 8443')"})
            continue
        reach = (r.get("reachability") or "allowed").lower()
        reviewer = r.get("reviewer") or None
        e: dict[str, Any] = {
            "id": r.get("id") or edge_id(src, dst, ports, used),
            "source": entry_id(src) if ENTRY_RE.match(src) else src,
            "target": dst, "kind": kind, "ports": ports, "reachability": reach,
            "review_state": "reviewed" if reviewer else "unreviewed",
        }
        used.add(e["id"])
        for k in ("evidence_ref", "valid_from", "valid_until", "label", "requires_capability", "grants_capability",
                  "source_zone", "destination_zone", "control"):
            if r.get(k):
                e[k] = r[k]
        if reviewer:
            e["reviewer"] = reviewer
        if r.get("claim_keys"):
            e["claim_keys"] = [k for k in re.split(r"[\s;,|]+", r["claim_keys"]) if k]
        e["_line"] = line
        edges.append(e)
    if objectives is None:
        objectives, how, oerr = _objectives(s, set(assets))
        errors += oerr
    else:
        how = "crown jewels chosen on the Network Paths screen"
    if not objectives:
        errors.append({"line": None, "field": "objectives", "reason": "no crown jewel: add a crown_jewel_weight column to assets.csv, mark an asset critical, or choose one on the Network Paths screen"})
    nodes |= {o["asset_id"] for o in objectives}
    if not entries:
        entries["internet"] = {"id": "internet", "label": "Internet", "grants": "network_access"}
    if errors:
        raise TopologyBuildError(errors)
    zones = {}
    for aid in nodes:
        rev = latest_asset_revision(s, aid)
        z = (rev.context_json or {}).get("zone") if rev else None
        if z:
            zones[aid] = str(z)[:60]
    return {
        "schema_version": "1.0",
        "synthetic": db.is_synthetic_workspace(s),
        "description": f"Built from {source_name}; {how}.",
        "source": {"name": source_name},
        "entry_points": sorted(entries.values(), key=lambda x: x["id"]),
        "nodes": [{"asset_id": a, **({"zone": zones[a]} if a in zones else {})} for a in sorted(nodes)],
        "objectives": sorted(objectives, key=lambda o: o["id"]),
        "edges": edges,
    }


def strip_lines(doc: dict[str, Any]) -> tuple[dict[str, Any], dict[int, int]]:
    """Remove the private ``_line`` markers; return edge index -> CSV line for error mapping."""
    mapping = {}
    for i, e in enumerate(doc["edges"]):
        if "_line" in e:
            mapping[i + 1] = e.pop("_line")
    return doc, mapping


def current_document(s: Session) -> dict[str, Any] | None:
    cur = latest_input(s, "topology")
    if cur is None:
        return None
    doc = cur.content_json
    clean = lambda d: {k: v for k, v in d.items() if v not in (None, [], "")}  # noqa: E731
    return {
        "schema_version": "1.0",
        "synthetic": db.is_synthetic_workspace(s),
        "description": doc.get("description") or "topology",
        "source": {"name": "Network Paths screen"},
        **({"observed_at": doc["observed_at"]} if doc.get("observed_at") else {}),
        "entry_points": [clean(e) for e in doc["entry_points"]],
        "nodes": [clean(n) for n in doc["nodes"]],
        "objectives": [clean(o) for o in doc["objectives"]],
        "edges": [clean(e) for e in doc["edges"]],
    }


def to_csv(doc: dict[str, Any]) -> str:
    """Current topology as an edge CSV (round-trips through the CSV import)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(EDGE_CSV_COLUMNS)
    entry_ids = {e["id"] for e in doc["entry_points"]}
    for e in doc["edges"]:
        src = e["source"]
        if src in entry_ids:
            src = "internet" if src == "internet" else f"entry:{src}"
        w.writerow([src, e["target"], " ".join(e.get("ports") or []), e.get("reachability", ""), e.get("evidence_ref") or "",
                    e.get("reviewer") or "", e.get("kind", "network"), e.get("valid_from") or "", e.get("valid_until") or "",
                    " ".join(e.get("claim_keys") or []), e.get("requires_capability") or "", e.get("grants_capability") or "",
                    e.get("label") or "", e.get("source_zone") or "", e.get("destination_zone") or "", e.get("control") or "", e["id"]])
    return buf.getvalue()


def map_errors(pr_errors: list[Any], mapping: dict[int, int]) -> list[dict[str, Any]]:
    out = []
    for e in pr_errors:
        d = e.as_dict() if hasattr(e, "as_dict") else dict(e)
        if d.get("field", "") and str(d["field"]).startswith("edges[") and d.get("line") in mapping:
            d["line"] = mapping[d["line"]]
        out.append(d)
    return out



def run_csv_import(ws: db.Workspace, data: bytes, *, actor: str = "cli", allow_partial: bool = False,
                   dry_run: bool = False, recompute: bool = True) -> Any:
    """Import an edge CSV: build a topology document, then run the normal topology import."""
    import json

    from tiw.services.ingest import ImportOutcome, RowError, _failed, run_import

    sha = hashlib.sha256(data).hexdigest()
    try:
        rows = parse_edge_csv(data)
    except InputMalformed as exc:
        return _failed(ws, "topology_csv", "topology-csv-1", sha, [RowError(None, None, str(exc))], actor, dry_run)
    with db.session_scope(ws) as s:
        try:
            doc = build_document(s, rows, source_name="topology CSV")
        except TopologyBuildError as exc:
            errs = [RowError(e["line"], e["field"], e["reason"]) for e in exc.errors]
            return _failed(ws, "topology_csv", "topology-csv-1", sha, errs, actor, dry_run)
    doc, mapping = strip_lines(doc)
    out: ImportOutcome = run_import(ws, "topology", json.dumps(doc).encode(), actor=actor, allow_partial=allow_partial,
                                    dry_run=dry_run, recompute=recompute)
    out.errors = map_errors(out.errors, mapping)
    out.kind = "topology_csv"
    return out


def apply_change(ws: db.Workspace, *, add: dict[str, str] | None = None, delete: str | None = None,
                 objectives: list[dict[str, Any]] | None = None, actor: str = "ui") -> Any:
    """Edit the topology from the Network Paths screen; every change is a new append-only version."""
    import json

    from tiw.services.ingest import RowError, _failed, run_import

    with db.session_scope(ws) as s:
        cur = current_document(s)
        rows = parse_edge_csv(to_csv(cur).encode()) if cur else []
        if delete is not None:
            if not any(r["id"] == delete for _, r in rows):
                raise LookupError(f"unknown edge {delete}")
            rows = [(ln, r) for ln, r in rows if r["id"] != delete]
        if add is not None:
            rows.append((len(rows) + 2, {k: str(v).strip() for k, v in add.items() if k in EDGE_CSV_COLUMNS}))
        keep = objectives if objectives is not None else (cur["objectives"] if cur else None)
        try:
            doc = build_document(s, rows, objectives=keep, source_name="Network Paths screen")
        except TopologyBuildError as exc:
            return _failed(ws, "topology", "topology-1", "form", [RowError(None, e["field"], e["reason"]) for e in exc.errors], actor, True)
    if cur and cur.get("observed_at"):
        doc["observed_at"] = cur["observed_at"]
    doc, _ = strip_lines(doc)
    return run_import(ws, "topology", json.dumps(doc).encode(), actor=actor)

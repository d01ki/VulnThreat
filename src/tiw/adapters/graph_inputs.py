"""v2 model-input adapters: topology.json, exploit_conditions.json, remediation_catalog.json.

Adapters parse and validate structure only (no DB). Cross-references against the workspace
(assets, findings, claim keys, edges) are checked by the import writer, which rolls the whole
file back on any error. Unknown keys are rejected so executable payloads, commands or scripts
can never ride along in these files.
"""

from __future__ import annotations

import json
import math
import re
from typing import Any

from tiw.adapters.common import (
    InputMalformed,
    InputTooLarge,
    ParseContext,
    ParseResult,
    check_synthetic,
    decode_text,
    parse_time_field,
    truthy,
)
from tiw.domain.attack_graph import CAPABILITIES, CONDITION_DECLARED, CONDITION_KINDS, EDGE_KINDS, REACHABILITY
from tiw.domain.remediation import ACTION_TYPES, DOWNTIME
from tiw.domain.vocab import is_valid_vuln_id

TOPOLOGY_ADAPTER_VERSION = "topology-1"
CONDITIONS_ADAPTER_VERSION = "exploit-conditions-1"
REMEDIATIONS_ADAPTER_VERSION = "remediations-1"

MAX_NODES = 2_000
MAX_EDGES = 10_000
MAX_ACTIONS = 2_000
MAX_TEXT = 1_000
ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,58}$")
PORT_RE = re.compile(r"^(tcp|udp)/\d{1,5}$")
REVIEW = ("reviewed", "unreviewed")
VERIFICATION = ("verified", "unverified")


def _load(data: bytes, what: str) -> dict[str, Any]:
    try:
        doc = json.loads(decode_text(data), parse_constant=_reject_constant)
    except json.JSONDecodeError as exc:
        raise InputMalformed(f"{what} file is not valid JSON (line {exc.lineno})") from exc
    if not isinstance(doc, dict) or doc.get("schema_version") != "1.0":
        raise InputMalformed(f"{what} file must be an object with schema_version '1.0'")
    return doc


def _reject_constant(name: str) -> Any:
    raise InputMalformed(f"non-finite number {name} is not allowed")


def _text(v: Any) -> str | None:
    return str(v)[:MAX_TEXT] if v not in (None, "") else None


def _extra(obj: dict[str, Any], allowed: set[str]) -> list[str]:
    return sorted(set(obj) - allowed)


def _source(doc: dict[str, Any]) -> dict[str, Any]:
    src = doc.get("source")
    if not isinstance(src, dict) or not src.get("name"):
        raise InputMalformed("file requires source.name")
    return {"name": str(src["name"])[:200], "evidence_ref": _text(src.get("evidence_ref")), "license_note": _text(src.get("license_note"))}


def _time(v: Any) -> Any:
    return parse_time_field(v)[0] if v else None


# --------------------------------------------------------------------------- topology

EDGE_KEYS = {
    "id", "source", "target", "kind", "ports", "protocols", "reachability", "review_state", "reviewer", "evidence_ref",
    "valid_from", "valid_until", "claim_keys", "source_zone", "destination_zone", "control", "requires_capability",
    "grants_capability", "label",
}


def parse_topology(data: bytes, ctx: ParseContext) -> ParseResult:
    result = ParseResult()
    doc = _load(data, "topology")
    bad = _extra(doc, {"schema_version", "synthetic", "source", "observed_at", "entry_points", "nodes", "objectives", "edges", "description"})
    if bad:
        raise InputMalformed(f"unexpected top-level keys: {', '.join(bad)[:200]}")
    synthetic = truthy(doc.get("synthetic"))
    if not check_synthetic(synthetic, ctx, result, None):
        return result
    src = _source(doc)
    try:
        observed_at = _time(doc.get("observed_at"))
    except ValueError as exc:
        result.error(None, "observed_at", str(exc))
        return result
    entries_raw, nodes_raw, obj_raw, edges_raw = (doc.get(k) or [] for k in ("entry_points", "nodes", "objectives", "edges"))
    for name, v in (("entry_points", entries_raw), ("nodes", nodes_raw), ("objectives", obj_raw), ("edges", edges_raw)):
        if not isinstance(v, list):
            raise InputMalformed(f"{name} must be an array")
    if len(entries_raw) + len(nodes_raw) > MAX_NODES:
        raise InputTooLarge(f"more than {MAX_NODES} nodes")
    if len(edges_raw) > MAX_EDGES:
        raise InputTooLarge(f"more than {MAX_EDGES} edges")
    if not entries_raw:
        result.error(None, "entry_points", "at least one entry point is required")
    ids: set[str] = set()
    entries, nodes, objectives, edges = [], [], [], []
    for i, e in enumerate(entries_raw):
        loc = f"entry_points[{i}]"
        if not isinstance(e, dict) or _extra(e, {"id", "label", "grants"}) or not isinstance(e.get("id"), str) or not ID_RE.match(e["id"]):
            result.error(i + 1, loc, "entry point needs id (letters, digits, - _ . :) and only id/label/grants")
            continue
        if e["id"] in ids:
            result.error(i + 1, f"{loc}.id", f"duplicate node id {e['id']}")
            continue
        grants = e.get("grants", "network_access")
        if grants not in CAPABILITIES:
            result.error(i + 1, f"{loc}.grants", f"must be one of {', '.join(CAPABILITIES)}")
            continue
        ids.add(e["id"])
        entries.append({"id": e["id"], "label": _text(e.get("label")) or e["id"], "grants": grants})
    for i, n in enumerate(nodes_raw):
        loc = f"nodes[{i}]"
        if not isinstance(n, dict) or _extra(n, {"asset_id", "zone", "label"}) or not isinstance(n.get("asset_id"), str) or not ID_RE.match(n["asset_id"]):
            result.error(i + 1, loc, "node needs asset_id (an imported asset) and only asset_id/zone/label")
            continue
        if n["asset_id"] in ids:
            result.error(i + 1, f"{loc}.asset_id", f"duplicate node id {n['asset_id']}")
            continue
        ids.add(n["asset_id"])
        nodes.append({"asset_id": n["asset_id"], "zone": _text(n.get("zone")), "label": _text(n.get("label"))})
    obj_ids: set[str] = set()
    for i, o in enumerate(obj_raw):
        loc = f"objectives[{i}]"
        if not isinstance(o, dict) or _extra(o, {"id", "asset_id", "label", "weight", "required_capabilities"}):
            result.error(i + 1, loc, "objective allows id, asset_id, label, weight, required_capabilities")
            continue
        if not isinstance(o.get("id"), str) or not ID_RE.match(o["id"]) or o["id"] in obj_ids:
            result.error(i + 1, f"{loc}.id", "objective id missing, malformed or duplicated")
            continue
        if o.get("asset_id") not in ids or o.get("asset_id") in {x["id"] for x in entries}:
            result.error(i + 1, f"{loc}.asset_id", "objective must reference a node asset")
            continue
        w = o.get("weight")
        if not isinstance(w, int) or isinstance(w, bool) or w < 0 or w > 1000:
            result.error(i + 1, f"{loc}.weight", "weight must be an integer 0-1000 (configured, not derived from CVSS/EPSS)")
            continue
        caps = o.get("required_capabilities") or ["code_execution", "admin_context", "credential_access", "data_access"]
        if not isinstance(caps, list) or not all(c in CAPABILITIES for c in caps):
            result.error(i + 1, f"{loc}.required_capabilities", f"must be drawn from {', '.join(CAPABILITIES)}")
            continue
        obj_ids.add(o["id"])
        objectives.append({"id": o["id"], "asset_id": o["asset_id"], "label": _text(o.get("label")) or o["id"], "weight": w, "required_capabilities": sorted(caps)})
    if not objectives:
        result.error(None, "objectives", "at least one security objective (crown jewel) is required")
    edge_ids: set[str] = set()
    triples: set[tuple[str, str, str, tuple[str, ...]]] = set()
    entry_ids = {x["id"] for x in entries}
    for i, e in enumerate(edges_raw):
        loc = f"edges[{i}]"
        if not isinstance(e, dict):
            result.error(i + 1, loc, "edge must be an object")
            continue
        bad = _extra(e, EDGE_KEYS)
        if bad:
            result.error(i + 1, loc, f"unexpected keys: {', '.join(bad)[:120]}")
            continue
        eid = e.get("id")
        if not isinstance(eid, str) or not ID_RE.match(eid):
            result.error(i + 1, f"{loc}.id", "edge id is required (letters, digits, - _ . :, max 58)")
            continue
        if eid in edge_ids:
            result.error(i + 1, f"{loc}.id", f"duplicate edge id {eid}")
            continue
        s, t = e.get("source"), e.get("target")
        if s not in ids or t not in ids:
            result.error(i + 1, loc, "source and target must be declared entry points or nodes")
            continue
        if s == t:
            result.error(i + 1, loc, "self-loops are not allowed")
            continue
        if t in entry_ids:
            result.error(i + 1, f"{loc}.target", "edges cannot point into an entry point")
            continue
        kind = e.get("kind", "network")
        if kind not in EDGE_KINDS:
            result.error(i + 1, f"{loc}.kind", f"must be one of {', '.join(EDGE_KINDS)}")
            continue
        ports = e.get("ports") or []
        if not isinstance(ports, list) or not all(isinstance(p, str) and PORT_RE.match(p) and 0 < int(p.split("/")[1]) < 65536 for p in ports):
            result.error(i + 1, f"{loc}.ports", "ports must be a list like ['tcp/443']")
            continue
        if kind == "network" and not ports:
            result.error(i + 1, f"{loc}.ports", "network edges need at least one allowed port")
            continue
        reach = e.get("reachability")
        if reach not in REACHABILITY:
            result.error(i + 1, f"{loc}.reachability", f"must be one of {', '.join(REACHABILITY)}")
            continue
        state = e.get("review_state", "unreviewed")
        if state not in REVIEW:
            result.error(i + 1, f"{loc}.review_state", "must be reviewed or unreviewed")
            continue
        if state == "reviewed" and not e.get("reviewer"):
            result.error(i + 1, f"{loc}.reviewer", "reviewed edges require a reviewer")
            continue
        if not e.get("evidence_ref") and not e.get("claim_keys"):
            result.error(i + 1, f"{loc}.evidence_ref", "every edge must be anchored by evidence_ref or claim_keys (missing citation)")
            continue
        keys = e.get("claim_keys") or []
        if not isinstance(keys, list) or not all(isinstance(k, str) and 0 < len(k) <= 200 for k in keys):
            result.error(i + 1, f"{loc}.claim_keys", "claim_keys must be a list of claim keys")
            continue
        try:
            vf, vu = _time(e.get("valid_from")), _time(e.get("valid_until"))
        except ValueError as exc:
            result.error(i + 1, f"{loc}.valid_from/valid_until", str(exc))
            continue
        if vf and vu and vu <= vf:
            result.error(i + 1, f"{loc}.valid_until", "valid_until must be after valid_from")
            continue
        req, grants = e.get("requires_capability"), e.get("grants_capability")
        if kind == "trust":
            if req not in CAPABILITIES or grants not in CAPABILITIES:
                result.error(i + 1, loc, "trust edges need requires_capability and grants_capability")
                continue
        elif req is not None or grants is not None:
            result.error(i + 1, loc, "requires/grants_capability are only valid on trust edges")
            continue
        triple = (s, t, kind, tuple(sorted(ports)))
        if triple in triples:
            result.error(i + 1, loc, f"duplicate edge {s} -> {t} ({kind}, same ports)")
            continue
        edge_ids.add(eid)
        triples.add(triple)
        edges.append({
            "id": eid, "source": s, "target": t, "kind": kind, "ports": sorted(ports), "reachability": reach,
            "review_state": state, "reviewer": _text(e.get("reviewer")), "evidence_ref": _text(e.get("evidence_ref")),
            "valid_from": vf, "valid_until": vu, "claim_keys": sorted(set(keys)),
            "source_zone": _text(e.get("source_zone")), "destination_zone": _text(e.get("destination_zone")),
            "control": _text(e.get("control")), "requires_capability": req, "grants_capability": grants,
            "label": _text(e.get("label")),
        })
    result.meta = {"synthetic": synthetic or ctx.synthetic_workspace, "source": src}
    result.records.append({"observed_at": observed_at, "entry_points": entries, "nodes": nodes, "objectives": objectives, "edges": edges,
                           "description": _text(doc.get("description"))})
    return result


# --------------------------------------------------------------------------- exploit conditions

VULN_KEYS = {
    "vulnerability_id", "title", "service_ports", "requires_capability", "grants_capability", "cvss", "citation",
    "review_state", "reviewer", "conditions", "notes",
}
COND_KEYS = {"id", "kind", "description", "status", "evidence_ref", "claim_keys", "review_state", "reviewer", "expires_at"}


def parse_exploit_conditions(data: bytes, ctx: ParseContext) -> ParseResult:
    result = ParseResult()
    doc = _load(data, "exploit conditions")
    bad = _extra(doc, {"schema_version", "synthetic", "source", "vulnerabilities", "description"})
    if bad:
        raise InputMalformed(f"unexpected top-level keys: {', '.join(bad)[:200]}")
    synthetic = truthy(doc.get("synthetic"))
    if not check_synthetic(synthetic, ctx, result, None):
        return result
    synthetic = synthetic or ctx.synthetic_workspace
    src = _source(doc)
    vulns = doc.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise InputMalformed("vulnerabilities must be a non-empty array")
    if len(vulns) > MAX_NODES:
        raise InputTooLarge(f"more than {MAX_NODES} vulnerabilities")
    seen: set[str] = set()
    out = []
    for i, v in enumerate(vulns):
        loc = f"vulnerabilities[{i}]"
        if not isinstance(v, dict):
            result.error(i + 1, loc, "entry must be an object")
            continue
        bad = _extra(v, VULN_KEYS)
        if bad:
            result.error(i + 1, loc, f"unexpected keys (no payloads or commands allowed): {', '.join(bad)[:120]}")
            continue
        vid = v.get("vulnerability_id")
        if not isinstance(vid, str) or not is_valid_vuln_id(vid, synthetic=synthetic):
            result.error(i + 1, f"{loc}.vulnerability_id", f"invalid identifier {str(vid)[:40]!r}")
            continue
        if vid in seen:
            result.error(i + 1, f"{loc}.vulnerability_id", f"duplicate entry for {vid}")
            continue
        ports = v.get("service_ports")
        if not isinstance(ports, list) or not ports or not all(isinstance(p, str) and PORT_RE.match(p) for p in ports):
            result.error(i + 1, f"{loc}.service_ports", "service_ports must be a non-empty list like ['tcp/443']")
            continue
        req, grants = v.get("requires_capability", "network_access"), v.get("grants_capability")
        if req not in CAPABILITIES or grants not in CAPABILITIES:
            result.error(i + 1, loc, f"requires_capability/grants_capability must be one of {', '.join(CAPABILITIES)}")
            continue
        if not v.get("citation"):
            result.error(i + 1, f"{loc}.citation", "a source citation is required")
            continue
        state = v.get("review_state", "unreviewed")
        if state not in REVIEW or (state == "reviewed" and not v.get("reviewer")):
            result.error(i + 1, f"{loc}.review_state", "review_state must be reviewed (with reviewer) or unreviewed")
            continue
        cvss = v.get("cvss")
        if cvss is not None:
            if not isinstance(cvss, dict) or _extra(cvss, {"version", "vector", "base_score", "source"}):
                result.error(i + 1, f"{loc}.cvss", "cvss allows version, vector, base_score, source")
                continue
            score = cvss.get("base_score")
            if not isinstance(score, (int, float)) or isinstance(score, bool) or math.isnan(score) or not 0 <= score <= 10:
                result.error(i + 1, f"{loc}.cvss.base_score", "base_score must be a number 0.0-10.0")
                continue
            if not cvss.get("version") or not cvss.get("source"):
                result.error(i + 1, f"{loc}.cvss", "cvss needs version and source (provenance is preserved)")
                continue
            cvss = {"version": str(cvss["version"])[:8], "vector": _text(cvss.get("vector")), "base_score": float(score), "source": str(cvss["source"])[:200]}
        conds = []
        cids: set[str] = set()
        cond_err = False
        for ci, c in enumerate(v.get("conditions") or []):
            cloc = f"{loc}.conditions[{ci}]"
            if not isinstance(c, dict) or _extra(c, COND_KEYS):
                result.error(i + 1, cloc, f"condition allows only {', '.join(sorted(COND_KEYS))}")
                cond_err = True
                break
            if not isinstance(c.get("id"), str) or not ID_RE.match(c["id"]) or c["id"] in cids:
                result.error(i + 1, f"{cloc}.id", "condition id missing, malformed or duplicated")
                cond_err = True
                break
            if c.get("kind") not in CONDITION_KINDS:
                result.error(i + 1, f"{cloc}.kind", f"must be one of {', '.join(CONDITION_KINDS)}")
                cond_err = True
                break
            if c.get("status") not in CONDITION_DECLARED:
                result.error(i + 1, f"{cloc}.status", f"must be one of {', '.join(CONDITION_DECLARED)}")
                cond_err = True
                break
            cstate = c.get("review_state", state)
            if cstate not in REVIEW:
                result.error(i + 1, f"{cloc}.review_state", "must be reviewed or unreviewed")
                cond_err = True
                break
            if c["status"] != "unknown" and not c.get("evidence_ref") and not c.get("claim_keys"):
                result.error(i + 1, f"{cloc}.evidence_ref", "a satisfied/not_satisfied condition needs evidence_ref or claim_keys")
                cond_err = True
                break
            keys = c.get("claim_keys") or []
            if not isinstance(keys, list) or not all(isinstance(k, str) for k in keys):
                result.error(i + 1, f"{cloc}.claim_keys", "claim_keys must be a list of strings")
                cond_err = True
                break
            try:
                exp = _time(c.get("expires_at"))
            except ValueError as exc:
                result.error(i + 1, f"{cloc}.expires_at", str(exc))
                cond_err = True
                break
            cids.add(c["id"])
            conds.append({"id": c["id"], "kind": c["kind"], "description": _text(c.get("description")), "status": c["status"],
                          "evidence_ref": _text(c.get("evidence_ref")), "claim_keys": sorted(set(keys)), "review_state": cstate,
                          "reviewer": _text(c.get("reviewer") or v.get("reviewer")), "expires_at": exp})
        if cond_err:
            continue
        seen.add(vid)
        out.append({"vulnerability_id": vid, "title": _text(v.get("title")), "service_ports": sorted(set(ports)),
                    "requires_capability": req, "grants_capability": grants, "cvss": cvss, "citation": _text(v["citation"]),
                    "review_state": state, "reviewer": _text(v.get("reviewer")), "conditions": conds, "notes": _text(v.get("notes"))})
    result.meta = {"synthetic": synthetic, "source": src}
    result.records.append({"vulnerabilities": out, "description": _text(doc.get("description"))})
    return result


# --------------------------------------------------------------------------- remediation catalog

ACTION_KEYS = {
    "id", "type", "label", "cost", "downtime", "finding_id", "edge_id", "asset_id", "ports", "requires",
    "conflict_group", "verification_status", "preconditions", "notes",
}


def parse_remediations(data: bytes, ctx: ParseContext) -> ParseResult:
    result = ParseResult()
    doc = _load(data, "remediation catalog")
    bad = _extra(doc, {"schema_version", "synthetic", "source", "actions", "description", "cost_unit"})
    if bad:
        raise InputMalformed(f"unexpected top-level keys: {', '.join(bad)[:200]}")
    synthetic = truthy(doc.get("synthetic"))
    if not check_synthetic(synthetic, ctx, result, None):
        return result
    src = _source(doc)
    actions = doc.get("actions")
    if not isinstance(actions, list) or not actions:
        raise InputMalformed("actions must be a non-empty array")
    if len(actions) > MAX_ACTIONS:
        raise InputTooLarge(f"more than {MAX_ACTIONS} actions")
    seen: set[str] = set()
    out = []
    for i, a in enumerate(actions):
        loc = f"actions[{i}]"
        if not isinstance(a, dict):
            result.error(i + 1, loc, "action must be an object")
            continue
        bad = _extra(a, ACTION_KEYS)
        if bad:
            result.error(i + 1, loc, f"unexpected keys: {', '.join(bad)[:120]}")
            continue
        aid = a.get("id")
        if not isinstance(aid, str) or not ID_RE.match(aid):
            result.error(i + 1, f"{loc}.id", "action id is required (letters, digits, - _ . :)")
            continue
        if aid in seen:
            result.error(i + 1, f"{loc}.id", f"duplicate action id {aid}")
            continue
        t = a.get("type")
        if t not in ACTION_TYPES:
            result.error(i + 1, f"{loc}.type", f"must be one of {', '.join(ACTION_TYPES)}")
            continue
        cost = a.get("cost")
        if not isinstance(cost, int) or isinstance(cost, bool) or cost < 0 or cost > 10_000:
            result.error(i + 1, f"{loc}.cost", "cost must be a non-negative integer (effort units)")
            continue
        dt = a.get("downtime", "none")
        if dt not in DOWNTIME:
            result.error(i + 1, f"{loc}.downtime", f"must be one of {', '.join(DOWNTIME)}")
            continue
        need = {"patch_finding": "finding_id", "restrict_edge": "edge_id", "disable_service": "asset_id", "isolate_asset": "asset_id"}.get(t)
        if need and not isinstance(a.get(need), str):
            result.error(i + 1, f"{loc}.{need}", f"{t} requires {need}")
            continue
        ports = a.get("ports") or []
        if t == "disable_service" and (not isinstance(ports, list) or not ports or not all(isinstance(p, str) and PORT_RE.match(p) for p in ports)):
            result.error(i + 1, f"{loc}.ports", "disable_service requires ports like ['tcp/8443']")
            continue
        req = a.get("requires") or []
        if not isinstance(req, list) or not all(isinstance(r, str) for r in req) or aid in req:
            result.error(i + 1, f"{loc}.requires", "requires must be a list of other action ids")
            continue
        vs = a.get("verification_status", "unverified")
        if vs not in VERIFICATION:
            result.error(i + 1, f"{loc}.verification_status", "must be verified or unverified")
            continue
        pre = a.get("preconditions") or []
        if not isinstance(pre, list) or not all(isinstance(p, str) for p in pre):
            result.error(i + 1, f"{loc}.preconditions", "preconditions must be a list of strings")
            continue
        if not a.get("label"):
            result.error(i + 1, f"{loc}.label", "label is required")
            continue
        seen.add(aid)
        out.append({"id": aid, "type": t, "label": _text(a["label"]), "cost": cost, "downtime": dt,
                    "finding_id": a.get("finding_id"), "edge_id": a.get("edge_id"), "asset_id": a.get("asset_id"),
                    "ports": sorted(set(ports)), "requires": sorted(set(req)), "conflict_group": _text(a.get("conflict_group")),
                    "verification_status": vs, "preconditions": [p[:200] for p in pre[:20]], "notes": _text(a.get("notes"))})
    known = {a["id"] for a in out}
    for a in out:
        missing = [r for r in a["requires"] if r not in known]
        if missing:
            result.error(None, f"actions[{a['id']}].requires", f"unknown action ids: {', '.join(missing)[:120]}")
    # dependency cycles
    by_id = {a["id"]: a for a in out}
    for a in out:
        seen_c, todo = set(), list(a["requires"])
        while todo:
            x = todo.pop()
            if x == a["id"]:
                result.error(None, f"actions[{a['id']}].requires", "dependency cycle")
                break
            if x in by_id and x not in seen_c:
                seen_c.add(x)
                todo.extend(by_id[x]["requires"])
    result.meta = {"synthetic": synthetic or ctx.synthetic_workspace, "source": src}
    result.records.append({"actions": out, "description": _text(doc.get("description")), "cost_unit": _text(doc.get("cost_unit")) or "effort units"})
    return result

"""Build the attack-graph model from the workspace (assets, findings, applicability, claims, v2 inputs).

Reads only; never writes. The resulting model and an evidence-snapshot hash make every
analysis reproducible from archived inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from tiw.domain.attack_graph import (
    ANY_PORT,
    GRAPH_ALGORITHM_VERSION,
    Edge,
    EvidenceItem,
    Exploit,
    Fact,
    GraphModel,
    Limits,
    Node,
    Objective,
    canonical_hash,
    matching_ports,
)
from tiw.domain.claims import ClaimView, mark_inactive
from tiw.domain.remediation import Action, ActionSignals
from tiw.domain.vocab import CRITICALITY_RANK, GRAPH_PREDICATES
from tiw.services.pipeline import effective_review_states, kev_snapshots, latest_applicability, latest_asset_revision
from tiw.storage import db
from tiw.storage.models import Asset, Claim, ClaimRelation, Finding, GraphInput, Source, SourceRevision


class GraphNotReady(LookupError):
    """Raised when topology / exploit conditions have not been imported yet."""


@dataclass
class Workspace2:
    """Everything an analysis needs, with provenance for the export."""

    model: GraphModel
    actions: list[Action]
    signals: dict[str, ActionSignals]
    inputs: dict[str, dict[str, Any]]  # kind -> {id, seq, content_hash, source_revision_id}
    evidence_hash: str
    now: datetime
    claims: dict[str, ClaimView]
    assets: dict[str, dict[str, Any]]
    vulns: dict[str, dict[str, Any]]
    cost_unit: str
    synthetic: bool


def latest_input(s: Session, kind: str) -> GraphInput | None:
    return s.execute(select(GraphInput).where(GraphInput.kind == kind).order_by(GraphInput.seq.desc()).limit(1)).scalar_one_or_none()


def _graph_claims(s: Session) -> dict[str, ClaimView]:
    """Latest revision of every graph-evidence claim, keyed by claim_key, with effective state."""
    rows = s.execute(
        select(Claim, SourceRevision, Source)
        .join(SourceRevision, Claim.revision_id == SourceRevision.id)
        .join(Source, SourceRevision.source_id == Source.id)
        .where(Claim.predicate.in_(GRAPH_PREDICATES))
        .order_by(SourceRevision.seq)
    ).all()
    states = effective_review_states(s, [c.id for c, _, _ in rows])
    views: dict[str, ClaimView] = {}
    for c, rev, src in rows:
        views[c.claim_key] = ClaimView(
            id=c.id, key=c.claim_key, subject_id=c.subject_id, predicate=c.predicate, value=c.value_json,
            origin=c.origin, initial_state=c.review_state, effective_state=states.get(c.id, c.review_state),
            revision_id=rev.id, revision_is_latest=True, source_name=src.name, source_kind=src.kind,
            published_at=rev.published_at, fetched_at=rev.fetched_at, quote=c.quote, locator=c.locator,
        )
    ids = [v.id for v in views.values()]
    rels = []
    if ids:
        from tiw.domain.claims import RelationView

        rels = [RelationView(r.from_claim_id, r.to_claim_id, r.kind, r.verification)
                for r in s.execute(select(ClaimRelation).where(ClaimRelation.to_claim_id.in_(ids))).scalars()]
    mark_inactive(list(views.values()), rels)
    for v in views.values():
        if v.inactive_reason is None and v.effective_state != "reviewed":
            v.inactive_reason = "unreviewed (no effect until reviewed)"
    return views


def _claim_evidence(keys: list[str], claims: dict[str, ClaimView]) -> list[EvidenceItem]:
    out = []
    for k in keys:
        c = claims.get(k)
        if c is None:
            continue
        out.append(EvidenceItem(
            id=f"claim:{c.key}", kind="claim", polarity="supports" if c.value.get("value") is True else "refutes",
            active=c.inactive_reason is None, inactive_reason=c.inactive_reason,
            label=f"{c.source_name} · {c.predicate}={c.value.get('value')}", review_state=c.effective_state,
            source=c.source_name, observed_at=c.published_at or c.fetched_at, claim_key=c.key, quote=c.quote,
        ))
    return out


def _dt(v: Any) -> datetime | None:
    return db.parse_utc(v) if isinstance(v, str) and v else None


def load(s: Session, *, limits: Limits | None = None, at: datetime | None = None) -> Workspace2:
    topo = latest_input(s, "topology")
    conds = latest_input(s, "exploit_conditions")
    rem = latest_input(s, "remediations")
    if topo is None:
        raise GraphNotReady("no topology imported: run `tiw import topology topology.json`")
    if conds is None:
        raise GraphNotReady("no exploit conditions imported: run `tiw import exploit-conditions exploit_conditions.json`")
    now = at or db.now(s)
    claims = _graph_claims(s)
    t = topo.content_json
    c = conds.content_json

    assets: dict[str, dict[str, Any]] = {}
    nodes: dict[str, Node] = {}
    for e in t["entry_points"]:
        nodes[e["id"]] = Node(e["id"], "entry_point", e["label"], grants=e["grants"])
    for n in t["nodes"]:
        a = s.get(Asset, n["asset_id"])
        rev = latest_asset_revision(s, n["asset_id"])
        exposed = rev.internet_exposed if rev else "unknown"
        if rev and rev.expires_at and rev.expires_at <= now:
            exposed = "unknown"
        assets[n["asset_id"]] = {"id": n["asset_id"], "name": a.name if a else n["asset_id"], "criticality": a.criticality if a else None,
                                 "internet_exposed": exposed, "zone": n["zone"]}
        nodes[n["asset_id"]] = Node(n["asset_id"], "asset", n.get("label") or (a.name if a else n["asset_id"]),
                                    criticality=a.criticality if a else None, internet_exposed=exposed, zone=n["zone"])
    objectives = [Objective(o["id"], o["asset_id"], o["label"], o["weight"], tuple(o["required_capabilities"])) for o in t["objectives"]]

    edges: list[Edge] = []
    for e in t["edges"]:
        ev: list[EvidenceItem] = []
        if e["reachability"] in ("allowed", "blocked"):
            reviewed = e["review_state"] == "reviewed"
            ev.append(EvidenceItem(
                id=f"topology:{e['id']}", kind="topology", polarity="supports" if e["reachability"] == "allowed" else "refutes",
                active=reviewed, inactive_reason=None if reviewed else "unreviewed topology record",
                label=f"{topo_source(s, topo)} · {e.get('evidence_ref') or 'no citation'}", review_state=e["review_state"],
                source=topo_source(s, topo), observed_at=_dt(e.get("valid_from")) or _dt(t.get("observed_at")),
                expires_at=_dt(e.get("valid_until")),
            ))
        ev += _claim_evidence(e["claim_keys"], claims)
        declared = {"allowed": "satisfied", "blocked": "not_satisfied", "unknown": "unknown"}[e["reachability"]]
        fact = Fact(f"edge:{e['id']}", "reachability", f"{e['source']} → {e['target']} ({', '.join(e['ports']) or e['kind']})", declared, tuple(ev))
        edges.append(Edge(e["id"], e["source"], e["target"], e["kind"], tuple(e["ports"]), fact,
                          e.get("requires_capability"), e.get("grants_capability"), e.get("label") or ""))

    vuln_meta = {v["vulnerability_id"]: v for v in c["vulnerabilities"]}
    vulns: dict[str, dict[str, Any]] = {}
    kev_latest, kev_listed = kev_snapshots(s)
    exploits: list[Exploit] = []
    graph_assets = set(assets)
    for f in s.execute(select(Finding).order_by(Finding.id)).scalars():
        if f.asset_id not in graph_assets or f.vulnerability_id not in vuln_meta:
            continue
        v = vuln_meta[f.vulnerability_id]
        ar = latest_applicability(s, f.id)
        app_ev: list[EvidenceItem] = []
        declared = "unknown"
        if ar is not None and ar.status in ("affected", "not_affected"):
            declared = "satisfied" if ar.status == "affected" else "not_satisfied"
            app_ev.append(EvidenceItem(
                id=f"applicability:{f.id}#{ar.seq}", kind="applicability", polarity="supports" if ar.status == "affected" else "refutes",
                active=True, label=f"applicability review: {ar.status}" + (f" by {ar.reviewer}" if ar.reviewer else ""),
                review_state="reviewed" if ar.reviewer or ar.status == "affected" else "recorded", source="findings import",
                observed_at=ar.observed_at, expires_at=ar.expires_at,
            ))
        app = Fact(f"applicability:{f.id}", "applicability", f"{f.vulnerability_id} applies to {f.asset_id}", declared, tuple(app_ev))
        cfacts: list[Fact] = []
        for cd in v["conditions"]:
            cev: list[EvidenceItem] = []
            if cd["status"] in ("satisfied", "not_satisfied"):
                reviewed = cd["review_state"] == "reviewed"
                cev.append(EvidenceItem(
                    id=f"conditions:{f.vulnerability_id}:{cd['id']}", kind="exploit_conditions",
                    polarity="supports" if cd["status"] == "satisfied" else "refutes",
                    active=reviewed, inactive_reason=None if reviewed else "unreviewed condition record",
                    label=f"{cd.get('evidence_ref') or v['citation']}", review_state=cd["review_state"],
                    source=v["citation"] or "", expires_at=_dt(cd.get("expires_at")),
                ))
            cev += _claim_evidence(cd["claim_keys"], claims)
            cfacts.append(Fact(f"cond:{f.vulnerability_id}:{cd['id']}", cd["kind"], cd.get("description") or cd["id"], cd["status"], tuple(cev)))
        if ANY_PORT in v["service_ports"]:
            cfacts.append(Fact(f"cond:{f.vulnerability_id}:service-port", "network_service",
                               "service port not recorded (draft): any open port on the edge is assumed", "unknown", ()))
        exploits.append(Exploit(f.id, f.asset_id, f.vulnerability_id, tuple(v["service_ports"]), v["requires_capability"], v["grants_capability"],
                                app, tuple(cfacts), v.get("cvss"), v.get("title") or ""))
        epss = _epss(s, f.vulnerability_id)
        vulns[f.vulnerability_id] = {
            "id": f.vulnerability_id, "title": v.get("title"), "cvss": v.get("cvss"), "epss": epss,
            "kev_listed": (f.vulnerability_id in kev_listed.get(kev_latest.id, set())) if kev_latest else None,
            "kev_snapshot": (kev_latest.published_at or kev_latest.fetched_at).date().isoformat() if kev_latest else None,
            "citation": v.get("citation"),
        }

    model = GraphModel(nodes, edges, exploits, objectives, limits or Limits())
    actions: list[Action] = []
    cost_unit = "effort units"
    if rem is not None:
        cost_unit = rem.content_json.get("cost_unit") or cost_unit
        edge_ids = {e.id for e in edges}
        finding_ids = {x.finding_id for x in exploits}
        for a in rem.content_json["actions"]:
            # actions whose scope left the current graph are skipped (reported via inputs)
            if a["type"] == "patch_finding" and a["finding_id"] not in finding_ids:
                continue
            if a["type"] == "restrict_edge" and a["edge_id"] not in edge_ids:
                continue
            if a["type"] in ("disable_service", "isolate_asset") and a["asset_id"] not in nodes:
                continue
            actions.append(Action(a["id"], a["type"], a["label"], a["cost"], a["downtime"], a.get("finding_id"), a.get("edge_id"),
                                  a.get("asset_id"), tuple(a.get("ports") or ()), tuple(a.get("requires") or ()), a.get("conflict_group"),
                                  a.get("verification_status", "unverified"), tuple(a.get("preconditions") or ())))
        known = {a.id for a in actions}
        actions = [a for a in actions if all(r in known for r in a.requires)]
    signals = {a.id: _signals(a, model, vulns, assets) for a in actions}
    inputs = {k: {"seq": g.seq, "content_hash": g.content_hash}
              for k, g in (("topology", topo), ("exploit_conditions", conds), ("remediations", rem)) if g is not None}
    snapshot = {
        "algorithm": GRAPH_ALGORITHM_VERSION,
        "inputs": {k: v["content_hash"] for k, v in inputs.items()},
        "facts": {fid: [f.declared, [e.as_dict() for e in f.evidence]] for fid, f in sorted(_all_facts(model).items())},
        "assets": assets,
        "vulns": vulns,
        "clock": db.utc_iso(now),
    }
    return Workspace2(model, actions, signals, inputs, canonical_hash(snapshot), now, claims, assets, vulns, cost_unit,
                      db.is_synthetic_workspace(s))


def _all_facts(model: GraphModel) -> dict[str, Fact]:
    from tiw.domain.attack_graph import all_facts

    return all_facts(model)


_topo_cache: dict[str, str] = {}


def topo_source(s: Session, g: GraphInput) -> str:
    if g.source_revision_id not in _topo_cache:
        rev = s.get(SourceRevision, g.source_revision_id)
        src = s.get(Source, rev.source_id) if rev else None
        _topo_cache[g.source_revision_id] = src.name if src else "topology"
    return _topo_cache[g.source_revision_id]


def _epss(s: Session, vid: str) -> float | None:
    row = s.execute(
        select(Claim).join(SourceRevision, Claim.revision_id == SourceRevision.id)
        .where(Claim.subject_id == vid, Claim.predicate == "epss_score")
        .order_by(SourceRevision.seq.desc()).limit(1)
    ).scalar_one_or_none()
    if row is None:
        return None
    try:
        return float(row.value_json.get("probability"))
    except (TypeError, ValueError):
        return None


def _signals(a: Action, model: GraphModel, vulns: dict[str, dict[str, Any]], assets: dict[str, dict[str, Any]]) -> ActionSignals:
    """Signals the heuristic baselines rank by. Patching uses the finding's vulnerability."""
    vids: list[str] = []
    asset_ids: list[str] = []
    if a.type == "patch_finding":
        x = next((x for x in model.exploits if x.finding_id == a.finding_id), None)
        if x:
            vids, asset_ids = [x.vulnerability_id], [x.asset_id]
    elif a.type in ("disable_service", "isolate_asset") and a.asset_id:
        asset_ids = [a.asset_id]
        vids = sorted({x.vulnerability_id for x in model.exploits if x.asset_id == a.asset_id
                       and (a.type == "isolate_asset" or matching_ports(x.service_ports, a.ports))})
    elif a.type == "restrict_edge" and a.edge_id:
        e = next((e for e in model.edges if e.id == a.edge_id), None)
        if e:
            asset_ids = [e.target]
    cvss = [vulns[v]["cvss"]["base_score"] for v in vids if v in vulns and vulns[v].get("cvss")]
    epss = [vulns[v]["epss"] for v in vids if v in vulns and vulns[v].get("epss") is not None]
    kev_vals = [vulns[v]["kev_listed"] for v in vids if v in vulns and vulns[v].get("kev_listed") is not None]
    crit = [CRITICALITY_RANK[assets[x]["criticality"]] for x in asset_ids if x in assets and assets[x].get("criticality") in CRITICALITY_RANK]
    exp = [assets[x]["internet_exposed"] == "true" for x in asset_ids if x in assets]
    return ActionSignals(
        cvss=max(cvss) if cvss else None,
        epss=max(epss) if epss else None,
        kev=any(kev_vals) if kev_vals else None,
        criticality_rank=min(crit) if crit else None,
        exposed=any(exp) if exp else None,
    )

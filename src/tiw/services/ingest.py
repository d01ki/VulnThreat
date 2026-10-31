"""Import orchestration: limits, raw storage, idempotency, transactional writes (DESIGN §6, §8).

Every successful import ends with a recompute of the affected vulnerabilities so that
"observation added → assessment → decision change → evidence diff" happens in one step.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from tiw.adapters.claims import CLAIMS_ADAPTER_VERSION, parse_claims
from tiw.adapters.common import (
    InputMalformed,
    InputTooLarge,
    ParseContext,
    ParseResult,
    RowError,
    check_size,
)
from tiw.adapters.feeds import EPSS_ADAPTER_VERSION, KEV_ADAPTER_VERSION, parse_epss, parse_kev
from tiw.adapters.inventory import (
    ASSETS_ADAPTER_VERSION,
    FINDINGS_ADAPTER_VERSION,
    parse_assets,
    parse_findings,
)
from tiw.adapters.observations import OBSERVATIONS_ADAPTER_VERSION, parse_observations
from tiw.storage import db
from tiw.storage.models import (
    ApplicabilityReview,
    Asset,
    AssetRevision,
    AuditEvent,
    Claim,
    ClaimRelation,
    ClaimReview,
    Finding,
    ImportRun,
    Observation,
    SensorWindow,
    Source,
    SourceRevision,
    Vulnerability,
)

KINDS = ("kev", "epss", "assets", "findings", "observations", "claims")

ADAPTERS: dict[str, tuple[str, Callable[[bytes, ParseContext], ParseResult]]] = {
    "kev": (KEV_ADAPTER_VERSION, parse_kev),
    "epss": (EPSS_ADAPTER_VERSION, parse_epss),
    "assets": (ASSETS_ADAPTER_VERSION, parse_assets),
    "findings": (FINDINGS_ADAPTER_VERSION, parse_findings),
    "observations": (OBSERVATIONS_ADAPTER_VERSION, parse_observations),
    "claims": (CLAIMS_ADAPTER_VERSION, parse_claims),
}


@dataclass
class ImportOutcome:
    run_id: str | None
    kind: str
    status: str  # succeeded / failed / duplicate / validated
    accepted: int = 0
    rejected: int = 0
    duplicates: int = 0
    quarantined: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    affected_vulnerabilities: list[str] = field(default_factory=list)
    recompute: dict[str, Any] = field(default_factory=dict)
    input_sha256: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.run_id,
            "kind": self.kind,
            "status": self.status,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "duplicates": self.duplicates,
            "quarantined": self.quarantined,
            "errors": self.errors,
            "affected_vulnerabilities": self.affected_vulnerabilities,
            "recompute": self.recompute,
            "input_sha256": self.input_sha256,
        }


def next_seq(s: Session, model: Any) -> int:
    return int(s.execute(select(func.coalesce(func.max(model.seq), 0))).scalar_one()) + 1


def store_raw(ws: db.Workspace, data: bytes) -> tuple[str, str]:
    """Content-addressed storage. Upload names are never used for paths."""
    sha = hashlib.sha256(data).hexdigest()
    rel = f"objects/{sha[:2]}/{sha}"
    path = ws.data_dir / rel
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return sha, rel


def audit(s: Session, actor: str, operation: str, object_type: str, object_id: str, detail: dict[str, Any]) -> None:
    s.add(
        AuditEvent(
            actor=actor,
            operation=operation,
            object_type=object_type,
            object_id=object_id,
            timestamp=db.now(s),
            detail_json=detail,
        )
    )


def get_or_create_source(s: Session, name: str, kind: str, **extra: Any) -> Source:
    src = s.execute(select(Source).where(Source.name == name)).scalar_one_or_none()
    if src is None:
        src = Source(name=name, kind=kind, **extra)
        s.add(src)
        s.flush()
    return src


def ensure_vulnerability(s: Session, vid: str, synthetic: bool, title: str | None = None) -> None:
    v = s.get(Vulnerability, vid)
    if v is None:
        s.add(Vulnerability(id=vid, synthetic=synthetic, title=title, first_seen_at=db.now(s)))
        s.flush()
    elif title and not v.title:
        v.title = title


def _new_revision(
    s: Session,
    *,
    source: Source,
    external_id: str,
    sha: str,
    raw_path: str,
    parser_version: str,
    synthetic: bool,
    run_id: str,
    published_at: datetime | None = None,
    title: str | None = None,
) -> tuple[SourceRevision, bool]:
    """Return (revision, created). Identical content for the same document is not duplicated."""
    existing = s.execute(
        select(SourceRevision).where(
            SourceRevision.source_id == source.id,
            SourceRevision.external_id == external_id,
            SourceRevision.sha256 == sha,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing, False
    prev = s.execute(
        select(SourceRevision)
        .where(SourceRevision.source_id == source.id, SourceRevision.external_id == external_id)
        .order_by(SourceRevision.seq.desc())
        .limit(1)
    ).scalar_one_or_none()
    rev = SourceRevision(
        source_id=source.id,
        external_id=external_id,
        sha256=sha,
        published_at=published_at,
        fetched_at=db.now(s),
        raw_path=raw_path,
        parser_version=parser_version,
        supersedes_id=prev.id if prev else None,
        synthetic=synthetic,
        title=title,
        import_run_id=run_id,
        seq=next_seq(s, SourceRevision),
    )
    s.add(rev)
    s.flush()
    return rev, True


def _canonical_hash(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


# --------------------------------------------------------------------------- writers


class _Writer:
    def __init__(self, s: Session, ws: db.Workspace, sha: str, raw_path: str, run: ImportRun, actor: str):
        self.s = s
        self.ws = ws
        self.sha = sha
        self.raw_path = raw_path
        self.run = run
        self.actor = actor
        self.errors: list[RowError] = []
        self.accepted = 0
        self.duplicates = 0
        self.quarantined = 0
        self.vulns: set[str] = set()

    # KEV ---------------------------------------------------------------
    def kev(self, pr: ParseResult) -> None:
        m = pr.meta
        name = "Synthetic KEV feed" if m["synthetic"] else "CISA KEV"
        src = get_or_create_source(
            self.s,
            name,
            "kev",
            canonical_url=None if m["synthetic"] else "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            license_note="Synthetic demo data" if m["synthetic"] else "CISA KEV catalog",
        )
        rev, created = _new_revision(
            self.s,
            source=src,
            external_id=f"catalog:{m['catalog_version']}",
            sha=self.sha,
            raw_path=self.raw_path,
            parser_version=KEV_ADAPTER_VERSION,
            synthetic=m["synthetic"],
            run_id=self.run.id,
            published_at=m["released"],
            title=f"{m['title']} {m['catalog_version']}",
        )
        if not created:
            self.duplicates += len(pr.records)
            return
        for r in pr.records:
            ensure_vulnerability(self.s, r["vulnerability_id"], m["synthetic"], r["name"] or None)
            self.s.add(
                Claim(
                    claim_key=f"kev:{r['vulnerability_id']}",
                    revision_id=rev.id,
                    subject_id=r["vulnerability_id"],
                    predicate="exploited_in_wild",
                    value_json={
                        "value": True,
                        "date_added": r["date_added"].date().isoformat(),
                        "required_action": r["required_action"],
                        "due_date_reference": r["due_date_reference"],
                        "ransomware_use": r["ransomware_use"],
                        "vendor_project": r["vendor_project"],
                        "product": r["product"],
                    },
                    quote=r["short_description"] or None,
                    locator=r["locator"],
                    origin="kev",
                    review_state="reviewed",
                    valid_from=r["date_added"],
                    created_at=db.now(self.s),
                )
            )
            self.vulns.add(r["vulnerability_id"])
            self.accepted += 1
        # Previously listed vulnerabilities must be re-evaluated (missing ≠ retracted).
        prior = self.s.execute(
            select(Claim.subject_id).join(SourceRevision, Claim.revision_id == SourceRevision.id).where(
                SourceRevision.source_id == src.id
            )
        ).scalars()
        self.vulns.update(prior)

    # EPSS --------------------------------------------------------------
    def epss(self, pr: ParseResult) -> None:
        m = pr.meta
        name = "Synthetic EPSS scores" if m["synthetic"] else "FIRST EPSS"
        src = get_or_create_source(
            self.s,
            name,
            "epss",
            canonical_url=None if m["synthetic"] else "https://api.first.org/data/v1/epss",
            license_note="Synthetic demo data" if m["synthetic"] else "FIRST EPSS",
        )
        sd = m.get("score_date")
        rev, created = _new_revision(
            self.s,
            source=src,
            external_id=f"scores:{sd.date().isoformat() if sd else 'undated'}",
            sha=self.sha,
            raw_path=self.raw_path,
            parser_version=EPSS_ADAPTER_VERSION,
            synthetic=m["synthetic"],
            run_id=self.run.id,
            published_at=sd,
            title="EPSS scores",
        )
        if not created:
            self.duplicates += len(pr.records)
            return
        for r in pr.records:
            ensure_vulnerability(self.s, r["vulnerability_id"], m["synthetic"])
            self.s.add(
                Claim(
                    claim_key=f"epss:{r['vulnerability_id']}",
                    revision_id=rev.id,
                    subject_id=r["vulnerability_id"],
                    predicate="epss_score",
                    value_json={
                        "probability": r["probability"],
                        "percentile": r["percentile"],
                        "score_date": r["score_date"].date().isoformat(),
                    },
                    quote=None,
                    locator=r["locator"],
                    origin="epss",
                    review_state="reviewed",
                    valid_from=r["score_date"],
                    created_at=db.now(self.s),
                )
            )
            self.vulns.add(r["vulnerability_id"])
            self.accepted += 1

    # Assets ------------------------------------------------------------
    def assets(self, pr: ParseResult) -> None:
        synthetic = any(r["synthetic"] for r in pr.records)
        src = get_or_create_source(self.s, "Asset inventory (CSV)", "asset_inventory")
        rev, _ = _new_revision(
            self.s,
            source=src,
            external_id=f"file:{self.sha}",
            sha=self.sha,
            raw_path=self.raw_path,
            parser_version=ASSETS_ADAPTER_VERSION,
            synthetic=synthetic,
            run_id=self.run.id,
            title="Asset inventory import",
        )
        for r in pr.records:
            asset = self.s.get(Asset, r["asset_id"])
            if asset is None:
                asset = Asset(
                    id=r["asset_id"],
                    name=r["name"],
                    owner=r["owner"],
                    criticality=r["criticality"],
                    synthetic=r["synthetic"],
                )
                self.s.add(asset)
            else:
                # The asset registry row is mutable metadata; history lives in asset_revisions.
                asset.name, asset.owner, asset.criticality = r["name"], r["owner"], r["criticality"]
            content = {
                "internet_exposed": r["internet_exposed"],
                "observed_at": r["observed_at"].isoformat(),
                "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
                "context": r["context"],
                "criticality": r["criticality"],
            }
            h = _canonical_hash(content)
            latest = self.s.execute(
                select(AssetRevision)
                .where(AssetRevision.asset_id == r["asset_id"])
                .order_by(AssetRevision.seq.desc())
                .limit(1)
            ).scalar_one_or_none()
            if latest is not None and latest.content_hash == h:
                self.duplicates += 1
                continue
            self.s.flush()
            self.s.add(
                AssetRevision(
                    asset_id=r["asset_id"],
                    recorded_at=db.now(self.s),
                    observed_at=r["observed_at"],
                    internet_exposed=r["internet_exposed"],
                    context_json={**r["context"], "criticality": r["criticality"]},
                    expires_at=r["expires_at"],
                    content_hash=h,
                    source_revision_id=rev.id,
                    seq=next_seq(self.s, AssetRevision),
                )
            )
            self.s.flush()
            self.accepted += 1
            self.vulns.update(
                self.s.execute(select(Finding.vulnerability_id).where(Finding.asset_id == r["asset_id"])).scalars()
            )

    # Findings ----------------------------------------------------------
    def findings(self, pr: ParseResult) -> None:
        synthetic = any(r["synthetic"] for r in pr.records)
        src = get_or_create_source(self.s, "Findings (CSV)", "scanner")
        rev, _ = _new_revision(
            self.s,
            source=src,
            external_id=f"file:{self.sha}",
            sha=self.sha,
            raw_path=self.raw_path,
            parser_version=FINDINGS_ADAPTER_VERSION,
            synthetic=synthetic,
            run_id=self.run.id,
            title="Findings import",
        )
        for r in pr.records:
            if self.s.get(Asset, r["asset_id"]) is None:
                self.errors.append(RowError(r["line"], "asset_id", f"unknown asset_id {r['asset_id'][:60]}; import assets first"))
                continue
            f = self.s.get(Finding, r["finding_id"])
            if f is None:
                f = Finding(
                    id=r["finding_id"],
                    asset_id=r["asset_id"],
                    vulnerability_id=r["vulnerability_id"],
                    scanner_ref=r["scanner_ref"],
                    created_at=db.now(self.s),
                )
                self.s.add(f)
                ensure_vulnerability(self.s, r["vulnerability_id"], r["synthetic"])
            elif f.asset_id != r["asset_id"] or f.vulnerability_id != r["vulnerability_id"]:
                self.errors.append(
                    RowError(r["line"], "finding_id", "finding_id already exists with a different asset/vulnerability (409)")
                )
                continue
            content = {
                "status": r["applicability"],
                "rationale": r["rationale"],
                "evidence_ref": r["evidence_ref"],
                "reviewer": r["reviewer"],
                "observed_at": r["observed_at"].isoformat(),
                "expires_at": r["expires_at"].isoformat() if r["expires_at"] else None,
            }
            h = _canonical_hash(content)
            latest = self.s.execute(
                select(ApplicabilityReview)
                .where(ApplicabilityReview.finding_id == r["finding_id"])
                .order_by(ApplicabilityReview.seq.desc())
                .limit(1)
            ).scalar_one_or_none()
            if latest is not None and latest.content_hash == h:
                self.duplicates += 1
                continue
            self.s.flush()
            self.s.add(
                ApplicabilityReview(
                    finding_id=r["finding_id"],
                    status=r["applicability"],
                    rationale=r["rationale"],
                    evidence_ids=[r["evidence_ref"]] if r["evidence_ref"] else [],
                    reviewer=r["reviewer"],
                    recorded_at=db.now(self.s),
                    observed_at=r["observed_at"],
                    expires_at=r["expires_at"],
                    content_hash=h,
                    source_revision_id=rev.id,
                    seq=next_seq(self.s, ApplicabilityReview),
                )
            )
            self.s.flush()
            self.accepted += 1
            self.vulns.add(r["vulnerability_id"])

    # Observations ------------------------------------------------------
    def observations(self, pr: ParseResult) -> None:
        src = get_or_create_source(self.s, "Local observations (JSONL)", "sensor")
        rev, _ = _new_revision(
            self.s,
            source=src,
            external_id=f"file:{self.sha}",
            sha=self.sha,
            raw_path=self.raw_path,
            parser_version=OBSERVATIONS_ADAPTER_VERSION,
            synthetic=bool(pr.meta.get("synthetic")),
            run_id=self.run.id,
            title="Observation import",
        )
        for w in pr.meta.get("windows", []):
            exists = self.s.execute(
                select(SensorWindow).where(
                    SensorWindow.sensor_id == w["sensor_id"],
                    SensorWindow.start == w["start"],
                    SensorWindow.end == w["end"],
                    SensorWindow.status == w["status"],
                )
            ).scalar_one_or_none()
            if exists is None:
                self.s.add(
                    SensorWindow(
                        sensor_id=w["sensor_id"],
                        start=w["start"],
                        end=w["end"],
                        status=w["status"],
                        coverage_json=w["coverage"],
                        source_revision_id=rev.id,
                    )
                )
                self.accepted += 1
            else:
                self.duplicates += 1
        seen: set[tuple[str, str]] = set()
        for r in pr.records:
            key = (r["sensor_id"], r["dedup_key"])
            if key in seen or self.s.execute(
                select(Observation.id).where(Observation.sensor_id == key[0], Observation.dedup_key == key[1])
            ).first():
                self.duplicates += 1
                continue
            seen.add(key)
            if r["vulnerability_id"]:
                ensure_vulnerability(self.s, r["vulnerability_id"], r["synthetic"])
            self.s.add(
                Observation(
                    source_revision_id=rev.id,
                    sensor_id=r["sensor_id"],
                    external_event_id=r["external_event_id"],
                    dedup_key=r["dedup_key"],
                    observed_at=r["observed_at"],
                    observed_precision=r["precision"],
                    ingested_at=db.now(self.s),
                    asset_id=r["asset_id"],
                    cve_id=r["vulnerability_id"],
                    event_type=r["event_type"],
                    mapping_status=r["mapping_status"],
                    status="quarantined" if r["quarantine"] else "accepted",
                    quarantine_reason=r["quarantine"],
                    reviewer=r["reviewer"],
                    rationale=r["rationale"],
                    synthetic=r["synthetic"],
                    evidence_json=r["evidence"],
                )
            )
            if r["quarantine"]:
                self.quarantined += 1
            else:
                self.accepted += 1
                if r["vulnerability_id"]:
                    self.vulns.add(r["vulnerability_id"])

    # Claims ------------------------------------------------------------
    def claims(self, pr: ParseResult) -> None:
        m = pr.meta
        src = get_or_create_source(
            self.s,
            m["source"]["name"],
            m["source"]["kind"],
            canonical_url=m["source"]["canonical_url"],
            license_note=m["source"]["license_note"],
        )
        pending_relations: list[tuple[Claim, dict[str, Any], int]] = []
        new_claims_by_key: dict[str, Claim] = {}
        for di, d in enumerate(pr.records, start=1):
            doc_bytes = json.dumps(d, sort_keys=True, default=str).encode()
            doc_sha = hashlib.sha256(doc_bytes).hexdigest()
            rev, created = _new_revision(
                self.s,
                source=src,
                external_id=d["external_id"],
                sha=doc_sha,
                raw_path=self.raw_path,
                parser_version=CLAIMS_ADAPTER_VERSION,
                synthetic=m["synthetic"],
                run_id=self.run.id,
                published_at=d["published_at"],
                title=d["title"],
            )
            if not created:
                self.duplicates += max(1, len(d["claims"]))
                continue
            for c in d["claims"]:
                ensure_vulnerability(self.s, c["subject_id"], m["synthetic"])
                claim = Claim(
                    claim_key=c["claim_key"],
                    revision_id=rev.id,
                    subject_id=c["subject_id"],
                    predicate=c["predicate"],
                    value_json=c["value"],
                    quote=c["quote"],
                    locator=c["locator"],
                    origin=c["origin"],
                    review_state=c["review_state"],
                    valid_from=d["published_at"],
                    created_at=db.now(self.s),
                )
                self.s.add(claim)
                self.s.flush()
                new_claims_by_key[c["claim_key"]] = claim
                if c["review_state"] == "reviewed":
                    self._review(claim, c["reviewer"], "reviewed", c["review_reason"])
                for rel in c["relations"]:
                    pending_relations.append((claim, rel, di))
                self.vulns.add(c["subject_id"])
                self.accepted += 1
            for r in d["retractions"]:
                target = self._resolve_key(r["claim_key"], new_claims_by_key)
                if target is None:
                    self.errors.append(RowError(di, "retractions.claim_key", f"unknown claim_key {r['claim_key'][:60]}"))
                    continue
                self._review(target, r["reviewer"] or f"source:{src.name}", "retracted", r["reason"])
                self.vulns.add(target.subject_id)
                self.accepted += 1
        for claim, rel, di in pending_relations:
            target = self._resolve_key(rel["to"], new_claims_by_key)
            if target is None:
                self.errors.append(RowError(di, "relations.to", f"unknown claim_key {rel['to'][:60]}"))
                continue
            self.s.add(
                ClaimRelation(
                    from_claim_id=claim.id,
                    to_claim_id=target.id,
                    kind=rel["kind"],
                    verification=rel["verification"],
                    created_at=db.now(self.s),
                )
            )
            self.vulns.add(target.subject_id)

    def _resolve_key(self, key: str, local: dict[str, Claim]) -> Claim | None:
        if key in local:
            return local[key]
        return self.s.execute(
            select(Claim)
            .join(SourceRevision, Claim.revision_id == SourceRevision.id)
            .where(Claim.claim_key == key)
            .order_by(SourceRevision.seq.desc())
            .limit(1)
        ).scalar_one_or_none()

    def _review(self, claim: Claim, reviewer: str, state: str, reason: str) -> None:
        self.s.add(
            ClaimReview(
                claim_id=claim.id,
                reviewer=str(reviewer)[:120],
                state=state,
                reason=reason,
                recorded_at=db.now(self.s),
                seq=next_seq(self.s, ClaimReview),
            )
        )
        self.s.flush()


# --------------------------------------------------------------------------- entry point


def run_import(
    ws: db.Workspace,
    kind: str,
    data: bytes,
    *,
    actor: str = "cli",
    allow_partial: bool = False,
    dry_run: bool = False,
    recompute: bool = True,
) -> ImportOutcome:
    """Validate and import one file. Whole-file rollback unless allow_partial is set."""
    if kind not in ADAPTERS:
        raise ValueError(f"unknown import kind {kind!r}; expected one of {', '.join(KINDS)}")
    version, parser = ADAPTERS[kind]
    check_size(data)
    sha = hashlib.sha256(data).hexdigest()

    with db.session_scope(ws) as s:
        prior = s.execute(
            select(ImportRun)
            .where(
                ImportRun.adapter == kind,
                ImportRun.adapter_version == version,
                ImportRun.input_sha256 == sha,
                ImportRun.status == "succeeded",
            )
            .limit(1)
        ).scalar_one_or_none()
        if prior is not None:
            return ImportOutcome(prior.id, kind, "duplicate", input_sha256=sha, errors=[])
        ctx = ParseContext(now=db.now(s), synthetic_workspace=db.is_synthetic_workspace(s))

    try:
        pr = parser(data, ctx)
    except (InputMalformed, InputTooLarge) as exc:
        if isinstance(exc, InputTooLarge):
            raise
        return _failed(ws, kind, version, sha, [RowError(None, None, str(exc))], actor, dry_run)

    if pr.errors and not allow_partial:
        return _failed(ws, kind, version, sha, pr.errors, actor, dry_run, rejected=len(pr.errors))

    session = db.session_factory(ws)()
    try:
        started = db.now(session)
        run = ImportRun(
            adapter=kind,
            adapter_version=version,
            input_sha256=sha,
            status="succeeded",
            errors_json=[],
            started_at=started,
            source_name=None,
        )
        session.add(run)
        session.flush()
        raw_path = f"objects/{sha[:2]}/{sha}"
        writer = _Writer(session, ws, sha, raw_path, run, actor)
        getattr(writer, kind)(pr)
        all_errors = list(pr.errors) + writer.errors
        if writer.errors and not allow_partial:
            session.rollback()
            return _failed(ws, kind, version, sha, all_errors, actor, dry_run, rejected=len(all_errors))
        if dry_run:
            session.rollback()
            return ImportOutcome(
                None,
                kind,
                "validated",
                accepted=writer.accepted,
                rejected=len(all_errors),
                duplicates=writer.duplicates,
                quarantined=writer.quarantined,
                errors=[e.as_dict() for e in all_errors],
                affected_vulnerabilities=sorted(writer.vulns),
                input_sha256=sha,
            )
        store_raw(ws, data)
        run.accepted = writer.accepted
        run.rejected = len(all_errors)
        run.duplicates = writer.duplicates
        run.quarantined = writer.quarantined
        run.errors_json = [e.as_dict() for e in all_errors]
        run.completed_at = db.now(session)
        audit(
            session,
            actor,
            "import",
            "import_run",
            run.id,
            {"kind": kind, "accepted": writer.accepted, "rejected": len(all_errors), "duplicates": writer.duplicates},
        )
        session.commit()
        outcome = ImportOutcome(
            run.id,
            kind,
            "succeeded",
            accepted=writer.accepted,
            rejected=len(all_errors),
            duplicates=writer.duplicates,
            quarantined=writer.quarantined,
            errors=[e.as_dict() for e in all_errors],
            affected_vulnerabilities=sorted(writer.vulns),
            input_sha256=sha,
        )
    except BaseException:
        session.rollback()
        raise
    finally:
        session.close()

    if recompute:
        from tiw.services.pipeline import recompute as do_recompute

        outcome.recompute = do_recompute(ws, vulnerability_ids=None, actor=actor, trigger=f"import:{outcome.run_id}")
    return outcome


def _failed(
    ws: db.Workspace,
    kind: str,
    version: str,
    sha: str,
    errors: list[RowError],
    actor: str,
    dry_run: bool,
    rejected: int = 0,
) -> ImportOutcome:
    errs = [e.as_dict() for e in errors[:500]]
    if dry_run:
        return ImportOutcome(None, kind, "failed", rejected=rejected or len(errs), errors=errs, input_sha256=sha)
    with db.session_scope(ws) as s:
        run = ImportRun(
            adapter=kind,
            adapter_version=version,
            input_sha256=sha,
            status="failed",
            accepted=0,
            rejected=rejected or len(errs),
            errors_json=errs,
            started_at=db.now(s),
            completed_at=db.now(s),
        )
        s.add(run)
        s.flush()
        audit(s, actor, "import_failed", "import_run", run.id, {"kind": kind, "errors": len(errs)})
        run_id = run.id
    return ImportOutcome(run_id, kind, "failed", rejected=rejected or len(errs), errors=errs, input_sha256=sha)

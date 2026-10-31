"""SQLAlchemy 2 data model (DESIGN.md §7).

Append-only tables: source_revisions, claims, claim_relations, claim_reviews,
observations, asset_revisions, applicability_reviews, threat_assessments,
intelligence_deltas, decisions, audit_events. Application code never issues
UPDATE/DELETE against them (enforced by tests and by ``guard_append_only``).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def new_id() -> str:
    return str(uuid.uuid4())


class UTCDateTime(TypeDecorator):
    """Timezone-aware UTC datetimes stored as ISO-8601 strings (sortable)."""

    impl = String(32)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> str | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime rejected; all times must be timezone-aware")
        return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def process_result_value(self, value: str | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[Any]: JSON}


class AppMeta(Base):
    __tablename__ = "app_meta"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text)


class Source(Base):
    __tablename__ = "sources"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    kind: Mapped[str] = mapped_column(String(32))  # kev/epss/advisory/sensor/asset_inventory/scanner
    canonical_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    license_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class SourceRevision(Base):
    __tablename__ = "source_revisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    source_id: Mapped[str] = mapped_column(ForeignKey("sources.id"))
    external_id: Mapped[str] = mapped_column(String(300))
    sha256: Mapped[str] = mapped_column(String(64))
    published_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    fetched_at: Mapped[datetime] = mapped_column(UTCDateTime)
    raw_path: Mapped[str] = mapped_column(String(300))
    parser_version: Mapped[str] = mapped_column(String(32))
    supersedes_id: Mapped[str | None] = mapped_column(ForeignKey("source_revisions.id"), nullable=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    title: Mapped[str | None] = mapped_column(String(500), nullable=True)
    import_run_id: Mapped[str | None] = mapped_column(ForeignKey("import_runs.id"), nullable=True)
    __table_args__ = (UniqueConstraint("source_id", "external_id", "sha256", name="uq_revision_content"),)


class Vulnerability(Base):
    """Registry of vulnerability identifiers known to the workbench (addition, see STATUS)."""

    __tablename__ = "vulnerabilities"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    title: Mapped[str | None] = mapped_column(String(300), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(UTCDateTime)


class Claim(Base):
    __tablename__ = "claims"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    claim_key: Mapped[str] = mapped_column(String(200))  # stable external key used for relations
    revision_id: Mapped[str] = mapped_column(ForeignKey("source_revisions.id"))
    subject_id: Mapped[str] = mapped_column(String(64), index=True)
    predicate: Mapped[str] = mapped_column(String(64))
    value_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    quote: Mapped[str | None] = mapped_column(Text, nullable=True)
    locator: Mapped[str | None] = mapped_column(String(200), nullable=True)
    origin: Mapped[str] = mapped_column(String(32))  # primary/secondary/kev/epss/vendor/model
    review_state: Mapped[str] = mapped_column(String(32))  # initial state: unreviewed/reviewed/candidate
    valid_from: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    __table_args__ = (UniqueConstraint("revision_id", "claim_key", name="uq_claim_key_in_revision"),)


class ClaimRelation(Base):
    __tablename__ = "claim_relations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    from_claim_id: Mapped[str] = mapped_column(ForeignKey("claims.id"), index=True)
    to_claim_id: Mapped[str] = mapped_column(ForeignKey("claims.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16))  # cites/duplicates/supports/contradicts/supersedes
    verification: Mapped[str] = mapped_column(String(24))  # explicit/reviewer_confirmed/candidate
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    __table_args__ = (UniqueConstraint("from_claim_id", "to_claim_id", "kind", name="uq_claim_relation"),)


class ClaimReview(Base):
    __tablename__ = "claim_reviews"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    claim_id: Mapped[str] = mapped_column(ForeignKey("claims.id"), index=True)
    reviewer: Mapped[str] = mapped_column(String(120))
    state: Mapped[str] = mapped_column(String(32))  # reviewed/rejected/retracted/unreviewed
    reason: Mapped[str] = mapped_column(Text)
    recorded_at: Mapped[datetime] = mapped_column(UTCDateTime)


class Observation(Base):
    __tablename__ = "observations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    source_revision_id: Mapped[str] = mapped_column(ForeignKey("source_revisions.id"))
    sensor_id: Mapped[str] = mapped_column(String(120))
    external_event_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    dedup_key: Mapped[str] = mapped_column(String(300))
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    observed_precision: Mapped[str] = mapped_column(String(8), default="second")  # second/day
    ingested_at: Mapped[datetime] = mapped_column(UTCDateTime)
    asset_id: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    cve_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    event_type: Mapped[str] = mapped_column(String(32))  # scan/exploit_attempt/compromise_confirmed
    mapping_status: Mapped[str] = mapped_column(String(32))  # reviewer_confirmed/explicit/unconfirmed
    status: Mapped[str] = mapped_column(String(16), default="accepted")  # accepted/quarantined
    quarantine_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewer: Mapped[str | None] = mapped_column(String(120), nullable=True)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("sensor_id", "dedup_key", name="uq_observation_dedup"),)


class SensorWindow(Base):
    __tablename__ = "sensor_windows"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    sensor_id: Mapped[str] = mapped_column(String(120), index=True)
    start: Mapped[datetime] = mapped_column(UTCDateTime)
    end: Mapped[datetime] = mapped_column(UTCDateTime)
    coverage_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    status: Mapped[str] = mapped_column(String(16))  # ok/outage
    source_revision_id: Mapped[str] = mapped_column(ForeignKey("source_revisions.id"))
    __table_args__ = (UniqueConstraint("sensor_id", "start", "end", "status", name="uq_sensor_window"),)


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    owner: Mapped[str | None] = mapped_column(String(200), nullable=True)
    criticality: Mapped[str] = mapped_column(String(16))  # critical/high/normal
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    synthetic: Mapped[bool] = mapped_column(Boolean, default=False)


class AssetRevision(Base):
    __tablename__ = "asset_revisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    recorded_at: Mapped[datetime] = mapped_column(UTCDateTime)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime)
    internet_exposed: Mapped[str] = mapped_column(String(8))  # true/false/unknown
    context_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    source_revision_id: Mapped[str] = mapped_column(ForeignKey("source_revisions.id"))


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id"), index=True)
    vulnerability_id: Mapped[str] = mapped_column(String(64), index=True)
    scanner_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)


class ApplicabilityReview(Base):
    __tablename__ = "applicability_reviews"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    status: Mapped[str] = mapped_column(String(16))  # affected/not_affected/unknown
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence_ids: Mapped[list[Any]] = mapped_column(JSON)
    reviewer: Mapped[str | None] = mapped_column(String(120), nullable=True)
    recorded_at: Mapped[datetime] = mapped_column(UTCDateTime)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    content_hash: Mapped[str] = mapped_column(String(64))
    source_revision_id: Mapped[str] = mapped_column(ForeignKey("source_revisions.id"))


class VulnerabilityAlias(Base):
    __tablename__ = "vulnerability_aliases"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    canonical_id: Mapped[str] = mapped_column(String(64), index=True)
    alias: Mapped[str] = mapped_column(String(64))
    source_revision_id: Mapped[str] = mapped_column(ForeignKey("source_revisions.id"))


class ThreatAssessment(Base):
    __tablename__ = "threat_assessments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    vulnerability_id: Mapped[str] = mapped_column(String(64), index=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    evidence_cutoff: Mapped[datetime] = mapped_column(UTCDateTime)
    engine_version: Mapped[str] = mapped_column(String(32))
    state_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    state_hash: Mapped[str] = mapped_column(String(64))
    evidence_ids: Mapped[list[Any]] = mapped_column(JSON)
    seq: Mapped[int] = mapped_column(Integer)


class IntelligenceDelta(Base):
    __tablename__ = "intelligence_deltas"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    vulnerability_id: Mapped[str] = mapped_column(String(64), index=True)
    old_assessment_id: Mapped[str | None] = mapped_column(ForeignKey("threat_assessments.id"), nullable=True)
    new_assessment_id: Mapped[str | None] = mapped_column(ForeignKey("threat_assessments.id"), nullable=True)
    change_type: Mapped[str] = mapped_column(String(48))
    reasons_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)


class Decision(Base):
    __tablename__ = "decisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), index=True)
    assessment_id: Mapped[str | None] = mapped_column(ForeignKey("threat_assessments.id"), nullable=True)
    asset_revision_id: Mapped[str | None] = mapped_column(ForeignKey("asset_revisions.id"), nullable=True)
    applicability_review_id: Mapped[str | None] = mapped_column(ForeignKey("applicability_reviews.id"), nullable=True)
    policy_version: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(32))
    urgency: Mapped[str] = mapped_column(String(16))
    rule: Mapped[int] = mapped_column(Integer)
    reason_codes: Mapped[list[Any]] = mapped_column(JSON)
    evidence_ids: Mapped[list[Any]] = mapped_column(JSON)
    unknowns_json: Mapped[list[Any]] = mapped_column(JSON)
    inputs_json: Mapped[dict[str, Any]] = mapped_column(JSON)
    outcome_hash: Mapped[str] = mapped_column(String(64))
    previous_id: Mapped[str | None] = mapped_column(ForeignKey("decisions.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    trigger_delta_ids: Mapped[list[Any]] = mapped_column(JSON)


class InvestigationTask(Base):
    __tablename__ = "investigation_tasks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    task_key: Mapped[str] = mapped_column(String(300), unique=True)
    finding_id: Mapped[str | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    vulnerability_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    question: Mapped[str] = mapped_column(Text)
    affected_finding_ids: Mapped[list[Any]] = mapped_column(JSON)
    required_evidence: Mapped[str] = mapped_column(Text)
    check_type: Mapped[str] = mapped_column(String(48))
    estimated_effort: Mapped[int] = mapped_column(Integer)
    urgent_high_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[str] = mapped_column(String(24))  # open/resolved
    decision_id: Mapped[str | None] = mapped_column(ForeignKey("decisions.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    actor: Mapped[str] = mapped_column(String(120))
    operation: Mapped[str] = mapped_column(String(64))
    object_type: Mapped[str] = mapped_column(String(64))
    object_id: Mapped[str] = mapped_column(String(120))
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    detail_json: Mapped[dict[str, Any]] = mapped_column(JSON)


class ImportRun(Base):
    __tablename__ = "import_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    adapter: Mapped[str] = mapped_column(String(32))
    adapter_version: Mapped[str] = mapped_column(String(16))
    input_sha256: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))  # succeeded/failed/duplicate
    accepted: Mapped[int] = mapped_column(Integer, default=0)
    rejected: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    quarantined: Mapped[int] = mapped_column(Integer, default=0)
    errors_json: Mapped[list[Any]] = mapped_column(JSON)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    source_name: Mapped[str | None] = mapped_column(String(200), nullable=True)


Index("ix_import_runs_hash", ImportRun.input_sha256, ImportRun.adapter_version, ImportRun.adapter)

APPEND_ONLY_TABLES = {
    "source_revisions",
    "claims",
    "claim_relations",
    "claim_reviews",
    "observations",
    "asset_revisions",
    "applicability_reviews",
    "threat_assessments",
    "intelligence_deltas",
    "decisions",
    "audit_events",
}


def _reject_mutation(mapper: Any, connection: Any, target: Any) -> None:
    raise PermissionError(f"{target.__tablename__} is append-only; write a new record instead")


for _cls in Base.__subclasses__():
    if getattr(_cls, "__tablename__", None) in APPEND_ONLY_TABLES:
        event.listen(_cls, "before_update", _reject_mutation)
        event.listen(_cls, "before_delete", _reject_mutation)

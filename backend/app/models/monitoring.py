import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class MonitoringConfig(Base):
    __tablename__ = "monitoring_configs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    target_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    enabled: Mapped[bool] = mapped_column(
        nullable=False,
        default=True,
        server_default="1",
    )

    frequency: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="daily",
    )

    profile: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="quick",
    )

    target_scope: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="all",
        server_default="all",
    )

    created_by: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    baseline_established: Mapped[bool] = mapped_column(
        nullable=False,
        default=False,
        server_default="0",
    )

    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )

    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    last_scan_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )

    last_status: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    consecutive_failures: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    paused_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    pause_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    schedule: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        onupdate=datetime.utcnow,
    )


class MonitoringRun(Base):
    __tablename__ = "monitoring_runs"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    monitoring_config_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("monitoring_configs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="queued",
        index=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    assets_discovered: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    assets_changed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    assets_stale: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    findings_created: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    scan_ids: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    scanner_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    successful_scanners: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    failed_scanners: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    correlation_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )

    change_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="skipped",
        server_default="skipped",
        index=True,
    )

    change_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    change_events_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=datetime.utcnow,
    )


class MonitoringObservationBaseline(Base):
    """D2 trusted-observation snapshot: one row per monitoring config.

    Replaced only by completed runs with usable content; partial runs never
    replace it and failed runs never touch it. Stores canonical observation
    summaries (bounded), never raw scanner output.
    """

    __tablename__ = "monitoring_observation_baselines"

    config_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("monitoring_configs.id", ondelete="CASCADE"),
        primary_key=True,
    )

    run_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
    )

    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    assets: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    findings: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    relationships: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    scanners: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )


class MonitoringChangeEvent(Base):
    """D2 run-level change record: durable, explainable, idempotent.

    Identity is the deterministic ``event_key`` (UNIQUE): reprocessing the
    same run re-emits the same keys and ``ON CONFLICT DO NOTHING`` drops
    duplicates at the database level. Provenance is bounded summaries only.
    """

    __tablename__ = "monitoring_change_events"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    monitoring_config_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("monitoring_configs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    prev_run_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )

    curr_run_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True,
    )

    change_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    asset_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("assets.id", ondelete="SET NULL"),
        nullable=True,
    )

    finding_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("findings.id", ondelete="SET NULL"),
        nullable=True,
    )

    scan_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="SET NULL"),
        nullable=True,
    )

    previous_state: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    current_state: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    scanners: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    scan_ids: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    completeness: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="complete",
        server_default="complete",
    )

    event_key: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        unique=True,
        index=True,
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
    )

    extra_data: Mapped[dict] = mapped_column(
        "metadata",
        JSON,
        nullable=False,
        default=dict,
    )

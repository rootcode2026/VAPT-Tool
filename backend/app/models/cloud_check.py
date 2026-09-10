import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CloudCheckRun(Base):
    """E2 check execution record (evaluation tracking, not a job system).

    One row per evaluated discovery run: UNIQUE(discovery_run_id) makes repeat
    evaluation of the same run a deterministic no-op. Individual FAILs become
    findings (existing Findings table); PASS/NOT_ASSESSED/ERROR aggregate here
    with a per-check breakdown. No separate results table in MMP-1.
    """

    __tablename__ = "cloud_check_runs"
    __table_args__ = (
        UniqueConstraint("discovery_run_id", name="uq_cloud_check_runs_discovery"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
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

    connection_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("cloud_connections.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    discovery_run_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("cloud_discoveries.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="completed",
        index=True,
    )

    checks_executed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    resources_evaluated: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    passed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    failed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    not_assessed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    errors: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    findings_created: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    # Bounded per-check breakdown {check_id: {pass, fail, not_assessed, error}}.
    breakdown: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    check_pack_version: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    requested_by: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        onupdate=datetime.utcnow,
    )

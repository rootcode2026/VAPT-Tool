import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CloudDiscovery(Base):
    """E1 discovery run record (execution tracking, not a job system).

    The run is executed by the existing Celery worker
    (``app.tasks.cloud_discovery.discover_cloud``). Status distinguishes
    queued/running/completed/partial/failed: a single regional API failure
    yields partial, never silent success.
    """

    __tablename__ = "cloud_discoveries"

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

    provider: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="queued",
        index=True,
    )

    regions_attempted: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    regions_succeeded: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    regions_failed: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    assets_discovered: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    relationships_discovered: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    # Bounded per-region outcome list [{region, status, resources, warning}].
    region_results: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    # Bounded resource-type counts {resource_type: count}.
    resource_counts: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    # Bounded discovery warnings (permission/service failures are warnings,
    # never reported as absence).
    warnings: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    # Sanitized, bounded terminal error.
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

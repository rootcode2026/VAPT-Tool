from datetime import datetime
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ScanResult(Base):
    __tablename__ = "scan_results"
    __table_args__ = (
        Index("ix_scan_results_status", "status"),
        Index("ix_scan_results_scan_id_scanner", "scan_id", "scanner"),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id"),
        nullable=False,
        index=True,
    )

    scanner: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="completed",
    )

    raw_output: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    duration_ms: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    attempt: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )

    max_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=2,
    )

    error_type: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    error_message: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    error_phase: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    retryable: Mapped[bool | None] = mapped_column(
        Boolean,
        nullable=True,
    )

    findings_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    assets_count: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    extra_data: Mapped[dict] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
    )

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, String, Integer, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    target_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("targets.id"),
        nullable=False,
        index=True,
    )

    profile: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="created",
        index=True,
    )

    phase: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="queued",
        index=True,
    )

    risk_score: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    risk_grade: Mapped[str | None] = mapped_column(
        String(1),
        nullable=True,
    )

    risk_level: Mapped[str | None] = mapped_column(
        String(30),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    progress: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    scanner_version: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    scanner_image_digest: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
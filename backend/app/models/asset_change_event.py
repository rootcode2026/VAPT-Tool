import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AssetChangeEvent(Base):
    __tablename__ = "asset_change_events"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "asset_id",
            "change_type",
            name="uq_asset_change_events_idempotency",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id"),
        nullable=False,
        index=True,
    )

    asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id"),
        nullable=False,
        index=True,
    )

    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id"),
        nullable=False,
        index=True,
    )

    change_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    previous_state: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        default=None,
    )

    current_state: Mapped[dict | None] = mapped_column(
        JSONB,
        nullable=True,
        default=None,
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        server_default=func.now(),
    )

    extra_data: Mapped[dict] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AssetRelationship(Base):
    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name="uq_asset_relationships_identity",
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

    source_asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id"),
        nullable=False,
        index=True,
    )

    target_asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id"),
        nullable=False,
        index=True,
    )

    relationship_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    last_seen_scan_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("scans.id"),
        nullable=True,
        index=True,
    )

    extra_data: Mapped[dict] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        server_default=func.now(),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        server_default=func.now(),
    )

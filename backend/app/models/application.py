"""E16 Application Security Intelligence — Application + ApplicationAsset models."""
import uuid
from datetime import datetime
from sqlalchemy import String, Text, DateTime, ForeignKey, UniqueConstraint, func, Index
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import JSONB
from app.db.base import Base

VALID_APP_TYPES = {"WEB","API","MOBILE_BACKEND","SERVICE","WORKER","LIBRARY","CLI","UNKNOWN"}
VALID_LIFECYCLES = {"DEVELOPMENT","TESTING","STAGING","PRODUCTION","DEPRECATED","UNKNOWN"}
VALID_STATUSES = {"ACTIVE","INACTIVE","ARCHIVED"}
VALID_CRITICALITIES = {"critical","high","medium","low","unknown"}
VALID_LINK_TYPES = {"owns","exposes","depends_on","builds","deploys_to","contains","has_finding","uses"}
VALID_CONFIDENCES = {"CONFIRMED","HIGH","MEDIUM","LOW","UNKNOWN"}

class Application(Base):
    __tablename__ = "applications"
    __table_args__ = (
        UniqueConstraint("project_id", "name", name="uq_applications_project_name"),
        Index("ix_applications_project", "project_id"),
        Index("ix_applications_org", "organization_id"),
        Index("ix_applications_status", "status"),
        Index("ix_applications_lifecycle", "lifecycle"),
        Index("ix_applications_criticality", "criticality"),
        Index("ix_applications_owner", "owner_user_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    application_type: Mapped[str] = mapped_column(String(30), nullable=False, default="UNKNOWN", server_default="UNKNOWN")
    lifecycle: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN", server_default="UNKNOWN")
    criticality: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown", server_default="unknown")
    owner_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    owner_team_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    repository_asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    primary_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", server_default="ACTIVE")
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict, server_default="'{}'::jsonb")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=datetime.utcnow, default=datetime.utcnow)

class ApplicationAsset(Base):
    __tablename__ = "application_assets"
    __table_args__ = (
        UniqueConstraint("application_id", "asset_id", name="uq_app_asset"),
        Index("ix_app_assets_app", "application_id"),
        Index("ix_app_assets_asset", "asset_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    application_id: Mapped[str] = mapped_column(String(36), ForeignKey("applications.id", ondelete="CASCADE"), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(30), nullable=False, default="contains")
    confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM", server_default="MEDIUM")
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict, server_default="'{}'::jsonb")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)

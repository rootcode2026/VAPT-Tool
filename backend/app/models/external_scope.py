"""E15 External Attack Surface — scope, entries, discovery runs."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, Integer, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ExternalScope(Base):
    __tablename__ = "external_scopes"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active", server_default="active")
    created_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=datetime.utcnow, default=datetime.utcnow)


class ExternalScopeEntry(Base):
    __tablename__ = "external_scope_entries"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    external_scope_id: Mapped[str] = mapped_column(String(36), ForeignKey("external_scopes.id", ondelete="CASCADE"), nullable=False, index=True)
    entry_type: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    authorization_status: Mapped[str] = mapped_column(String(20), nullable=False, default="PENDING_REVIEW", server_default="PENDING_REVIEW")
    ownership_confidence: Mapped[str] = mapped_column(String(20), nullable=False, default="UNKNOWN", server_default="UNKNOWN")
    source: Mapped[str | None] = mapped_column(String(50), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=datetime.utcnow, default=datetime.utcnow)


class ExternalDiscoveryRun(Base):
    __tablename__ = "external_discovery_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    external_scope_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("external_scopes.id", ondelete="SET NULL"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="QUEUED", server_default="QUEUED")
    profile: Mapped[str] = mapped_column(String(20), nullable=False, default="QUICK", server_default="QUICK")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    assets_discovered: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    assets_changed: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    assets_new: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    assets_removed: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    findings_created: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    error_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    partial: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="0")
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)

"""E10 Cloud Attack Path persistence models — minimal durable identity + observations."""

import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, Index, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class CloudAttackPath(Base):
    """Durable logical attack path identity (per project fingerprint)."""

    __tablename__ = "cloud_attack_paths"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", name="uq_cloud_attack_path_project_fingerprint"),
        Index("ix_cloud_attack_paths_project_status", "project_id", "status"),
        Index("ix_cloud_attack_paths_project_provider", "project_id", "provider"),
        Index("ix_cloud_attack_paths_project_type", "project_id", "path_type"),
        Index("ix_cloud_attack_paths_project_fingerprint", "project_id", "fingerprint"),
        Index("ix_cloud_attack_paths_organization", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    path_type: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    priority_score: Mapped[int] = mapped_column(Integer, nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    entry_asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    target_asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="ACTIVE", server_default="ACTIVE")
    asset_ids: Mapped[list | None] = mapped_column(JSON, nullable=True)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=datetime.utcnow, default=datetime.utcnow)


class CloudAttackPathObservation(Base):
    """Lightweight time series per monitoring run / observation."""

    __tablename__ = "cloud_attack_path_observations"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", "monitoring_run_id", name="uq_observation_project_fingerprint_run"),
        Index("ix_observations_project_path_observed", "project_id", "attack_path_id", "observed_at"),
        Index("ix_observations_project_observed", "project_id", "observed_at"),
        Index("ix_observations_run", "monitoring_run_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    attack_path_id: Mapped[str] = mapped_column(String(36), ForeignKey("cloud_attack_paths.id", ondelete="CASCADE"), nullable=False, index=True)
    monitoring_run_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("monitoring_runs.id", ondelete="SET NULL"), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    priority_score: Mapped[int] = mapped_column(Integer, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)

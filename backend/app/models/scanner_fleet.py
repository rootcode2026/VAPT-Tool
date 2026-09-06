import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ScannerDefinition(Base):
    __tablename__ = "scanner_definitions"
    __table_args__ = (
        UniqueConstraint("scanner_key", name="uq_scanner_definitions_key"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scanner_key: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    family: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="1")
    current_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    previous_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    capabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    requirements: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    supported_profiles: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    requires_workspace: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    execution_type: Mapped[str] = mapped_column(String(20), nullable=False, default="docker", server_default="docker")
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    default_image: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=datetime.utcnow)


class ScannerVersion(Base):
    __tablename__ = "scanner_versions"
    __table_args__ = (
        UniqueConstraint("definition_id", "version", name="uq_scanner_versions_def_version"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    definition_id: Mapped[str] = mapped_column(String(36), ForeignKey("scanner_definitions.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    channel: Mapped[str] = mapped_column(String(20), nullable=False, default="candidate", index=True)
    image_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    image_digest: Mapped[str | None] = mapped_column(String(128), nullable=True)
    compatibility: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    release_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    health_status: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=datetime.utcnow)


class ScannerHealth(Base):
    __tablename__ = "scanner_health"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    definition_id: Mapped[str] = mapped_column(String(36), ForeignKey("scanner_definitions.id", ondelete="CASCADE"), nullable=False, index=True)
    version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="unknown", index=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    capabilities_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    version_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="0")
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)


class WorkerPool(Base):
    __tablename__ = "worker_pools"
    __table_args__ = (
        UniqueConstraint("name", name="uq_worker_pools_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    scanner_families: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    total_capacity: Mapped[int] = mapped_column(Integer, nullable=False, default=4)
    reserved_buffer: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="healthy", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=datetime.utcnow)


class ScannerRollout(Base):
    __tablename__ = "scanner_rollouts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    definition_id: Mapped[str] = mapped_column(String(36), ForeignKey("scanner_definitions.id", ondelete="CASCADE"), nullable=False, index=True)
    target_version: Mapped[str] = mapped_column(String(50), nullable=False)
    previous_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    operation: Mapped[str] = mapped_column(String(20), nullable=False, default="upgrade")
    canary_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    health_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now(), default=datetime.utcnow)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=datetime.utcnow)

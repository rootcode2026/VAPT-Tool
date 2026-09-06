import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, Integer, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

class DASTConfig(Base):
    __tablename__ = "dast_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    profile: Mapped[str] = mapped_column(String(50), nullable=False, default="web")  # web, api, advanced_dast, database_security, api_authenticated
    target_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("targets.id", ondelete="SET NULL"), nullable=True)
    openapi_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_secret_reference: Mapped[str | None] = mapped_column(String(36), nullable=True)  # reference to connector_secrets
    allowed_domains: Mapped[dict] = mapped_column(JSONB, nullable=False, default=list)
    max_endpoints: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    max_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=500)
    rate_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=5)  # req/sec
    active_testing_enabled: Mapped[bool] = mapped_column(String(5), nullable=False, default="false")
    database_testing_enabled: Mapped[bool] = mapped_column(String(5), nullable=False, default="false")
    created_by: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=datetime.utcnow)

class DASTEndpoint(Base):
    __tablename__ = "dast_endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(1024), nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False, default="GET")
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    discovered_via: Mapped[str] = mapped_column(String(50), nullable=False, default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

class DASTParameter(Base):
    __tablename__ = "dast_parameters"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    endpoint_id: Mapped[str] = mapped_column(String(36), ForeignKey("dast_endpoints.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    location: Mapped[str] = mapped_column(String(20), nullable=False)  # query, path, form, json, header
    http_method: Mapped[str] = mapped_column(String(10), nullable=False)
    content_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

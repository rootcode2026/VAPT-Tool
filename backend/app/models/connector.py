import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ConnectorSecret(Base):
    __tablename__ = "connector_secrets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ciphertext: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class RepositoryConnection(Base):
    __tablename__ = "repository_connections"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # github/gitlab/bitbucket/azure_devops
    external_account_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    credential_reference: Mapped[str | None] = mapped_column(String(36), ForeignKey("connector_secrets.id", ondelete="SET NULL"), nullable=True)
    credential_type: Mapped[str] = mapped_column(String(50), nullable=False, default="token")  # token/pat/oauth
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active", index=True)  # active/inactive/failed
    webhook_secret_reference: Mapped[str | None] = mapped_column(String(36), ForeignKey("connector_secrets.id", ondelete="SET NULL"), nullable=True)
    webhook_status: Mapped[str] = mapped_column(String(20), nullable=False, default="inactive")
    last_validation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=datetime.utcnow)


class CloudConnection(Base):
    __tablename__ = "cloud_connections"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(20), nullable=False, index=True)  # aws/gcp/azure
    account_id: Mapped[str] = mapped_column(String(255), nullable=False)  # account/subscription/project id
    credential_reference: Mapped[str | None] = mapped_column(String(36), ForeignKey("connector_secrets.id", ondelete="SET NULL"), nullable=True)
    credential_type: Mapped[str] = mapped_column(String(50), nullable=False, default="role")  # role/service_account/managed_identity
    regions: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active", index=True)
    last_validation_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_discovery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, onupdate=datetime.utcnow)
    # E1 AWS cross-account role assumption. ARNs/account IDs are identifiers,
    # not secrets; temporary credentials are never persisted.
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    role_arn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(256), nullable=True)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    connection_id: Mapped[str] = mapped_column(String(36), ForeignKey("repository_connections.id", ondelete="CASCADE"), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(20), nullable=False)
    event_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="received")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

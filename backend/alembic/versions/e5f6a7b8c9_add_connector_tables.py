"""add connector tables

Revision ID: e5f6a7b8c9
Revises: d4e5f6a7b8c9
Create Date: 2026-09-12
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "e5f6a7b8c9"
down_revision: Union[str, Sequence[str], None] = "d4e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "connector_secrets",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("ciphertext", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "repository_connections",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("external_account_id", sa.String(length=255), nullable=True),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("credential_reference", sa.String(length=36), nullable=True),
        sa.Column("credential_type", sa.String(length=50), nullable=False, server_default="token"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("webhook_secret_reference", sa.String(length=36), nullable=True),
        sa.Column("webhook_status", sa.String(length=20), nullable=False, server_default="inactive"),
        sa.Column("last_validation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_sync_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["credential_reference"], ["connector_secrets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["webhook_secret_reference"], ["connector_secrets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_repository_connections_project", "repository_connections", ["project_id"])
    op.create_index("ix_repository_connections_provider", "repository_connections", ["provider"])
    op.create_table(
        "cloud_connections",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("account_id", sa.String(length=255), nullable=False),
        sa.Column("credential_reference", sa.String(length=36), nullable=True),
        sa.Column("credential_type", sa.String(length=50), nullable=False, server_default="role"),
        sa.Column("regions", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("last_validation_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_discovery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["credential_reference"], ["connector_secrets.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_cloud_connections_project", "cloud_connections", ["project_id"])
    op.create_index("ix_cloud_connections_provider", "cloud_connections", ["provider"])
    op.create_table(
        "webhook_deliveries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("connection_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("event_id", sa.String(length=255), nullable=False),
        sa.Column("payload_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="received"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["connection_id"], ["repository_connections.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_webhook_deliveries_event", "webhook_deliveries", ["event_id"])

def downgrade() -> None:
    op.drop_index("ix_webhook_deliveries_event", table_name="webhook_deliveries")
    op.drop_table("webhook_deliveries")
    op.drop_index("ix_cloud_connections_provider", table_name="cloud_connections")
    op.drop_index("ix_cloud_connections_project", table_name="cloud_connections")
    op.drop_table("cloud_connections")
    op.drop_index("ix_repository_connections_provider", table_name="repository_connections")
    op.drop_index("ix_repository_connections_project", table_name="repository_connections")
    op.drop_table("repository_connections")
    op.drop_table("connector_secrets")

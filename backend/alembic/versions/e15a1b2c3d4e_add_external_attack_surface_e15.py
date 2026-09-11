"""add external attack surface e15

Revision ID: e15a1b2c3d4e
Revises: f14a2b3c4d5e
Create Date: 2026-09-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e15a1b2c3d4e"
down_revision: Union[str, Sequence[str], None] = "f14a2b3c4d5e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "external_scopes",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="active"),
        sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_external_scopes_project", "external_scopes", ["project_id"])
    op.create_index("ix_external_scopes_org", "external_scopes", ["organization_id"])

    op.create_table(
        "external_scope_entries",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("external_scope_id", sa.String(length=36), sa.ForeignKey("external_scopes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entry_type", sa.String(length=20), nullable=False),
        sa.Column("value", sa.String(length=500), nullable=False),
        sa.Column("authorization_status", sa.String(length=20), nullable=False, server_default="PENDING_REVIEW"),
        sa.Column("ownership_confidence", sa.String(length=20), nullable=False, server_default="UNKNOWN"),
        sa.Column("source", sa.String(length=50), nullable=True),
        sa.Column("notes", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_external_scope_entries_scope", "external_scope_entries", ["external_scope_id"])
    op.create_index("ix_external_scope_entries_value", "external_scope_entries", ["value"])

    op.create_table(
        "external_discovery_runs",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("external_scope_id", sa.String(length=36), sa.ForeignKey("external_scopes.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="QUEUED"),
        sa.Column("profile", sa.String(length=20), nullable=False, server_default="QUICK"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assets_discovered", sa.Integer, nullable=False, server_default="0"),
        sa.Column("assets_changed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("assets_new", sa.Integer, nullable=False, server_default="0"),
        sa.Column("assets_removed", sa.Integer, nullable=False, server_default="0"),
        sa.Column("findings_created", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("partial", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("failure_reason", sa.Text, nullable=True),
        sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_external_discovery_runs_project", "external_discovery_runs", ["project_id"])
    op.create_index("ix_external_discovery_runs_scope", "external_discovery_runs", ["external_scope_id"])


def downgrade() -> None:
    op.drop_index("ix_external_discovery_runs_scope", table_name="external_discovery_runs")
    op.drop_index("ix_external_discovery_runs_project", table_name="external_discovery_runs")
    op.drop_table("external_discovery_runs")
    op.drop_index("ix_external_scope_entries_value", table_name="external_scope_entries")
    op.drop_index("ix_external_scope_entries_scope", table_name="external_scope_entries")
    op.drop_table("external_scope_entries")
    op.drop_index("ix_external_scopes_org", table_name="external_scopes")
    op.drop_index("ix_external_scopes_project", table_name="external_scopes")
    op.drop_table("external_scopes")

"""add attack surface asset fields and monitoring tables

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-09-10
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, Sequence[str], None] = "b2c3d4e5f6a7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("assets", sa.Column("criticality", sa.String(length=20), nullable=False, server_default="unknown"))
    op.add_column("assets", sa.Column("owner_user_id", sa.String(length=36), nullable=True))
    op.create_index("ix_assets_criticality", "assets", ["criticality"], unique=False)
    op.create_index("ix_assets_owner", "assets", ["owner_user_id"], unique=False)
    op.create_foreign_key("fk_assets_owner_users", "assets", "users", ["owner_user_id"], ["id"], ondelete="SET NULL")

    op.create_table(
        "monitoring_configs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("frequency", sa.String(length=20), nullable=False, server_default="daily"),
        sa.Column("profile", sa.String(length=50), nullable=False, server_default="quick"),
        sa.Column("target_scope", sa.String(length=20), nullable=False, server_default="all"),
        sa.Column("created_by", sa.String(length=36), nullable=True),
        sa.Column("baseline_established", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_monitoring_configs_org", "monitoring_configs", ["organization_id"], unique=False)
    op.create_index("ix_monitoring_configs_project", "monitoring_configs", ["project_id"], unique=False)

    op.create_table(
        "monitoring_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("monitoring_config_id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("assets_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assets_changed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assets_stale", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["monitoring_config_id"], ["monitoring_configs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_monitoring_runs_config", "monitoring_runs", ["monitoring_config_id"], unique=False)
    op.create_index("ix_monitoring_runs_project", "monitoring_runs", ["project_id"], unique=False)
    op.create_index("ix_monitoring_runs_status", "monitoring_runs", ["status"], unique=False)
    op.create_index("ix_monitoring_runs_created", "monitoring_runs", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_monitoring_runs_created", table_name="monitoring_runs")
    op.drop_index("ix_monitoring_runs_status", table_name="monitoring_runs")
    op.drop_index("ix_monitoring_runs_project", table_name="monitoring_runs")
    op.drop_index("ix_monitoring_runs_config", table_name="monitoring_runs")
    op.drop_table("monitoring_runs")
    op.drop_index("ix_monitoring_configs_project", table_name="monitoring_configs")
    op.drop_index("ix_monitoring_configs_org", table_name="monitoring_configs")
    op.drop_table("monitoring_configs")
    op.drop_constraint("fk_assets_owner_users", "assets", type_="foreignkey")
    op.drop_index("ix_assets_owner", table_name="assets")
    op.drop_index("ix_assets_criticality", table_name="assets")
    op.drop_column("assets", "owner_user_id")
    op.drop_column("assets", "criticality")

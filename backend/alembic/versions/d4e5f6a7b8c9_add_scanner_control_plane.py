"""add scanner control plane tables

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-09-11
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, Sequence[str], None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scanner_definitions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scanner_key", sa.String(length=50), nullable=False),
        sa.Column("display_name", sa.String(length=100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=50), nullable=False),
        sa.Column("family", sa.String(length=50), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("current_version", sa.String(length=50), nullable=True),
        sa.Column("previous_version", sa.String(length=50), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("requirements", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("supported_profiles", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("requires_workspace", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("execution_type", sa.String(length=20), nullable=False, server_default="docker"),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("default_image", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scanner_key", name="uq_scanner_definitions_key"),
    )
    op.create_index("ix_scanner_definitions_key", "scanner_definitions", ["scanner_key"], unique=False)
    op.create_index("ix_scanner_definitions_category", "scanner_definitions", ["category"], unique=False)
    op.create_index("ix_scanner_definitions_family", "scanner_definitions", ["family"], unique=False)

    op.create_table(
        "scanner_versions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("definition_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.String(length=50), nullable=False),
        sa.Column("channel", sa.String(length=20), nullable=False, server_default="candidate"),
        sa.Column("image_ref", sa.String(length=255), nullable=False),
        sa.Column("image_digest", sa.String(length=128), nullable=True),
        sa.Column("compatibility", sa.JSON(), nullable=True),
        sa.Column("release_notes", sa.Text(), nullable=True),
        sa.Column("health_status", sa.String(length=20), nullable=False, server_default="unknown"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["definition_id"], ["scanner_definitions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("definition_id", "version", name="uq_scanner_versions_def_version"),
    )
    op.create_index("ix_scanner_versions_def", "scanner_versions", ["definition_id"], unique=False)
    op.create_index("ix_scanner_versions_channel", "scanner_versions", ["channel"], unique=False)

    op.create_table(
        "scanner_health",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("definition_id", sa.String(length=36), nullable=False),
        sa.Column("version", sa.String(length=50), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="unknown"),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("failure_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("capabilities_verified", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("version_verified", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["definition_id"], ["scanner_definitions.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scanner_health_def", "scanner_health", ["definition_id"], unique=False)
    op.create_index("ix_scanner_health_status", "scanner_health", ["status"], unique=False)

    op.create_table(
        "worker_pools",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("scanner_families", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("total_capacity", sa.Integer(), nullable=False, server_default="4"),
        sa.Column("reserved_buffer", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="healthy"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", name="uq_worker_pools_name"),
    )
    op.create_index("ix_worker_pools_name", "worker_pools", ["name"], unique=False)

    op.create_table(
        "scanner_rollouts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("definition_id", sa.String(length=36), nullable=False),
        sa.Column("target_version", sa.String(length=50), nullable=False),
        sa.Column("previous_version", sa.String(length=50), nullable=True),
        sa.Column("state", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("operation", sa.String(length=20), nullable=False, server_default="upgrade"),
        sa.Column("canary_count", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("health_threshold", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("failure_reason", sa.Text(), nullable=True),
        sa.Column("initiated_by", sa.String(length=36), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["definition_id"], ["scanner_definitions.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["initiated_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scanner_rollouts_def", "scanner_rollouts", ["definition_id"], unique=False)
    op.create_index("ix_scanner_rollouts_state", "scanner_rollouts", ["state"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_scanner_rollouts_state", table_name="scanner_rollouts")
    op.drop_index("ix_scanner_rollouts_def", table_name="scanner_rollouts")
    op.drop_table("scanner_rollouts")
    op.drop_index("ix_worker_pools_name", table_name="worker_pools")
    op.drop_table("worker_pools")
    op.drop_index("ix_scanner_health_status", table_name="scanner_health")
    op.drop_index("ix_scanner_health_def", table_name="scanner_health")
    op.drop_table("scanner_health")
    op.drop_index("ix_scanner_versions_channel", table_name="scanner_versions")
    op.drop_index("ix_scanner_versions_def", table_name="scanner_versions")
    op.drop_table("scanner_versions")
    op.drop_index("ix_scanner_definitions_family", table_name="scanner_definitions")
    op.drop_index("ix_scanner_definitions_category", table_name="scanner_definitions")
    op.drop_index("ix_scanner_definitions_key", table_name="scanner_definitions")
    op.drop_table("scanner_definitions")

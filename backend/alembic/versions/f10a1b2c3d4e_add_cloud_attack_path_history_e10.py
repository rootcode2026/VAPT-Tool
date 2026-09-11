"""add cloud attack path history e10

Revision ID: f10a1b2c3d4e
Revises: z2a3b4c5d6e7
Create Date: 2026-09-11

E10 minimal persistence: attack path identity + observations.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "f10a1b2c3d4e"
down_revision: Union[str, Sequence[str], None] = "z2a3b4c5d6e7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cloud_attack_paths",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=20), nullable=False),
        sa.Column("path_type", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("priority_score", sa.Integer, nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column("entry_asset_id", sa.String(length=36), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("target_asset_id", sa.String(length=36), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="ACTIVE"),
        sa.Column("asset_ids", sa.JSON, nullable=True),
        sa.Column("evidence", sa.JSON, nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("project_id", "fingerprint", name="uq_cloud_attack_path_project_fingerprint"),
    )
    op.create_index("ix_cloud_attack_paths_project_status", "cloud_attack_paths", ["project_id", "status"])
    op.create_index("ix_cloud_attack_paths_project_provider", "cloud_attack_paths", ["project_id", "provider"])
    op.create_index("ix_cloud_attack_paths_project_type", "cloud_attack_paths", ["project_id", "path_type"])
    op.create_index("ix_cloud_attack_paths_project_fingerprint", "cloud_attack_paths", ["project_id", "fingerprint"])
    op.create_index("ix_cloud_attack_paths_organization", "cloud_attack_paths", ["organization_id"])

    op.create_table(
        "cloud_attack_path_observations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("attack_path_id", sa.String(length=36), sa.ForeignKey("cloud_attack_paths.id", ondelete="CASCADE"), nullable=False),
        sa.Column("monitoring_run_id", sa.String(length=36), sa.ForeignKey("monitoring_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("priority_score", sa.Integer, nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("project_id", "fingerprint", "monitoring_run_id", name="uq_observation_project_fingerprint_run"),
    )
    op.create_index("ix_observations_project_path_observed", "cloud_attack_path_observations", ["project_id", "attack_path_id", "observed_at"])
    op.create_index("ix_observations_project_observed", "cloud_attack_path_observations", ["project_id", "observed_at"])
    op.create_index("ix_observations_run", "cloud_attack_path_observations", ["monitoring_run_id"])


def downgrade() -> None:
    op.drop_index("ix_observations_run", table_name="cloud_attack_path_observations")
    op.drop_index("ix_observations_project_observed", table_name="cloud_attack_path_observations")
    op.drop_index("ix_observations_project_path_observed", table_name="cloud_attack_path_observations")
    op.drop_table("cloud_attack_path_observations")
    op.drop_index("ix_cloud_attack_paths_organization", table_name="cloud_attack_paths")
    op.drop_index("ix_cloud_attack_paths_project_fingerprint", table_name="cloud_attack_paths")
    op.drop_index("ix_cloud_attack_paths_project_type", table_name="cloud_attack_paths")
    op.drop_index("ix_cloud_attack_paths_project_provider", table_name="cloud_attack_paths")
    op.drop_index("ix_cloud_attack_paths_project_status", table_name="cloud_attack_paths")
    op.drop_table("cloud_attack_paths")

"""add AWS security checks E2 run tracking + nullable finding scan linkage

Revision ID: z2a3b4c5d6e7
Revises: y1z2a3b4c5d6
Create Date: 2026-09-10

E2 (AWS Security Checks), additive only:

- cloud_check_runs: one row per evaluated discovery run with
  UNIQUE(discovery_run_id) for idempotent re-evaluation.
- findings.scan_id / findings.target_id: nullable widening so cloud findings
  (asset-linked, no scan/target context) can persist through the existing
  Findings table. Existing rows always carry values; readers already handle
  the asset-linked path.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "z2a3b4c5d6e7"
down_revision: Union[str, Sequence[str], None] = "y1z2a3b4c5d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "cloud_check_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("cloud_connections.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("discovery_run_id", sa.String(36), sa.ForeignKey("cloud_discoveries.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="completed", index=True),
        sa.Column("checks_executed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("resources_evaluated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("passed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("not_assessed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("errors", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("breakdown", sa.JSON(), nullable=True),
        sa.Column("check_pack_version", sa.String(20), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("discovery_run_id", name="uq_cloud_check_runs_discovery"),
    )
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("scan_id", existing_type=sa.String(36), nullable=True)
        batch.alter_column("target_id", existing_type=sa.String(36), nullable=True)


def downgrade() -> None:
    op.drop_table("cloud_check_runs")
    with op.batch_alter_table("findings") as batch:
        batch.alter_column("scan_id", existing_type=sa.String(36), nullable=False)
        batch.alter_column("target_id", existing_type=sa.String(36), nullable=False)

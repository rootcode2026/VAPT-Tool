"""add AWS live discovery E1 columns + discovery runs

Revision ID: y1z2a3b4c5d6
Revises: x0y1z2a3b4c5
Create Date: 2026-09-10

E1 (AWS Live Discovery) schema, additive only:

- cloud_connections.name / role_arn / external_id (identifiers, not secrets)
- cloud_discoveries run table (status, region results, counts, warnings, error)
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "y1z2a3b4c5d6"
down_revision: Union[str, Sequence[str], None] = "x0y1z2a3b4c5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("cloud_connections") as batch:
        batch.add_column(sa.Column("name", sa.String(255), nullable=True))
        batch.add_column(sa.Column("role_arn", sa.String(512), nullable=True))
        batch.add_column(sa.Column("external_id", sa.String(256), nullable=True))
    op.create_table(
        "cloud_discoveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("connection_id", sa.String(36), sa.ForeignKey("cloud_connections.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("provider", sa.String(20), nullable=False, index=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="queued", index=True),
        sa.Column("regions_attempted", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("regions_succeeded", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("regions_failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("assets_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("relationships_discovered", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("region_results", sa.JSON(), nullable=True),
        sa.Column("resource_counts", sa.JSON(), nullable=True),
        sa.Column("warnings", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("requested_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    try:
        op.create_index("ix_discoveries_connection_status", "cloud_discoveries", ["connection_id", "status"])
    except Exception:
        pass


def downgrade() -> None:
    try:
        op.drop_index("ix_discoveries_connection_status", table_name="cloud_discoveries")
    except Exception:
        pass
    op.drop_table("cloud_discoveries")
    with op.batch_alter_table("cloud_connections") as batch:
        for col in ("external_id", "role_arn", "name"):
            try:
                batch.drop_column(col)
            except Exception:
                pass

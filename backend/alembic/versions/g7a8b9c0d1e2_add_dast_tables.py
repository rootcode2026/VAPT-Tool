"""add dast tables

Revision ID: g7a8b9c0d1e2
Revises: f6a7b8c9d0e1
Create Date: 2026-09-13
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "g7a8b9c0d1e2"
down_revision: Union[str, Sequence[str], None] = "f6a7b8c9d0e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "dast_configs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("profile", sa.String(length=50), nullable=False, server_default="web"),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("openapi_ref", sa.Text(), nullable=True),
        sa.Column("auth_secret_reference", sa.String(length=36), nullable=True),
        sa.Column("allowed_domains", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("max_endpoints", sa.Integer(), nullable=False, server_default="50"),
        sa.Column("max_requests", sa.Integer(), nullable=False, server_default="500"),
        sa.Column("rate_limit", sa.Integer(), nullable=False, server_default="5"),
        sa.Column("active_testing_enabled", sa.String(length=5), nullable=False, server_default="false"),
        sa.Column("database_testing_enabled", sa.String(length=5), nullable=False, server_default="false"),
        sa.Column("created_by", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["target_id"], ["targets.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dast_configs_project", "dast_configs", ["project_id"])
    op.create_table(
        "dast_endpoints",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("url", sa.String(length=1024), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False, server_default="GET"),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("path", sa.String(length=1024), nullable=False),
        sa.Column("discovered_via", sa.String(length=50), nullable=False, server_default="manual"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dast_endpoints_project", "dast_endpoints", ["project_id"])
    op.create_table(
        "dast_parameters",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("endpoint_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("location", sa.String(length=20), nullable=False),
        sa.Column("http_method", sa.String(length=10), nullable=False),
        sa.Column("content_type", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["endpoint_id"], ["dast_endpoints.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dast_parameters_endpoint", "dast_parameters", ["endpoint_id"])

def downgrade() -> None:
    op.drop_index("ix_dast_parameters_endpoint", table_name="dast_parameters")
    op.drop_table("dast_parameters")
    op.drop_index("ix_dast_endpoints_project", table_name="dast_endpoints")
    op.drop_table("dast_endpoints")
    op.drop_index("ix_dast_configs_project", table_name="dast_configs")
    op.drop_table("dast_configs")

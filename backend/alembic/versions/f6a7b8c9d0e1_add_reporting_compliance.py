"""add reporting compliance

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9
Create Date: 2026-09-12
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, Sequence[str], None] = "e5f6a7b8c9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("report_type", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("generated_by", sa.String(length=36), nullable=True),
        sa.Column("parameters", postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("summary", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("content", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("data_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("version", sa.String(length=20), nullable=False, server_default="1.0"),
        sa.Column("data_as_of", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["generated_by"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_reports_org", "reports", ["organization_id"])
    op.create_index("ix_reports_project", "reports", ["project_id"])
    op.create_index("ix_reports_type", "reports", ["report_type"])
    op.create_table(
        "compliance_frameworks",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("framework", sa.String(length=50), nullable=False),
        sa.Column("version", sa.String(length=20), nullable=False, server_default="1.0"),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_compliance_frameworks_framework", "compliance_frameworks", ["framework"])
    op.create_table(
        "compliance_controls",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("framework_id", sa.String(length=36), nullable=False),
        sa.Column("control_id", sa.String(length=50), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(length=100), nullable=True),
        sa.Column("parent_control", sa.String(length=50), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="not_assessed"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["framework_id"], ["compliance_frameworks.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_compliance_controls_framework", "compliance_controls", ["framework_id"])
    op.create_table(
        "compliance_mappings",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("control_id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("source_id", sa.String(length=36), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["control_id"], ["compliance_controls.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

def downgrade() -> None:
    op.drop_table("compliance_mappings")
    op.drop_index("ix_compliance_controls_framework", table_name="compliance_controls")
    op.drop_table("compliance_controls")
    op.drop_index("ix_compliance_frameworks_framework", table_name="compliance_frameworks")
    op.drop_table("compliance_frameworks")
    op.drop_index("ix_reports_type", table_name="reports")
    op.drop_index("ix_reports_project", table_name="reports")
    op.drop_index("ix_reports_org", table_name="reports")
    op.drop_table("reports")

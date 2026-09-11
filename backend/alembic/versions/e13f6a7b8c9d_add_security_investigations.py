"""add security investigations e13

Revision ID: e13f6a7b8c9d
Revises: f10a1b2c3d4e
Create Date: 2026-09-12
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "e13f6a7b8c9d"
down_revision: Union[str, Sequence[str], None] = "f10a1b2c3d4e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "security_investigations",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("subject_type", sa.String(length=30), nullable=False),
        sa.Column("subject_id", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="OPEN"),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("priority", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="medium"),
        sa.Column("assigned_to", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_by", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_security_investigations_project_status", "security_investigations", ["project_id", "status"])
    op.create_index("ix_security_investigations_project_priority", "security_investigations", ["project_id", "priority"])
    op.create_index("ix_security_investigations_project_assigned", "security_investigations", ["project_id", "assigned_to"])
    op.create_index("ix_security_investigations_project_created", "security_investigations", ["project_id", "created_at"])
    op.create_index("ix_security_investigations_subject", "security_investigations", ["subject_type", "subject_id"])

    op.create_table(
        "investigation_notes",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("investigation_id", sa.String(length=36), sa.ForeignKey("security_investigations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("author_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_investigation_notes_investigation", "investigation_notes", ["investigation_id"])


def downgrade() -> None:
    op.drop_index("ix_investigation_notes_investigation", table_name="investigation_notes")
    op.drop_table("investigation_notes")
    op.drop_index("ix_security_investigations_subject", table_name="security_investigations")
    op.drop_index("ix_security_investigations_project_created", table_name="security_investigations")
    op.drop_index("ix_security_investigations_project_assigned", table_name="security_investigations")
    op.drop_index("ix_security_investigations_project_priority", table_name="security_investigations")
    op.drop_index("ix_security_investigations_project_status", table_name="security_investigations")
    op.drop_table("security_investigations")

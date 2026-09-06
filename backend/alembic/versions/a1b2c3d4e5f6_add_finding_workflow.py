"""add finding workflow fields and tables

Revision ID: a1b2c3d4e5f6
Revises: f7a6b5c4d3e2
Create Date: 2026-09-08
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, Sequence[str], None] = "f7a6b5c4d3e2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("assigned_to", sa.String(length=36), nullable=True))
    op.add_column("findings", sa.Column("owner_user_id", sa.String(length=36), nullable=True))
    op.add_column("findings", sa.Column("severity_override", sa.String(length=20), nullable=True))
    op.add_column("findings", sa.Column("updated_at", sa.DateTime(), nullable=True))
    op.create_index("ix_findings_assigned_to", "findings", ["assigned_to"], unique=False)
    op.create_index("ix_findings_owner_user_id", "findings", ["owner_user_id"], unique=False)
    op.create_foreign_key("fk_findings_assigned_to_users", "findings", "users", ["assigned_to"], ["id"], ondelete="SET NULL")
    op.create_foreign_key("fk_findings_owner_users", "findings", "users", ["owner_user_id"], ["id"], ondelete="SET NULL")

    op.create_table(
        "finding_comments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("author_user_id", sa.String(length=36), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["author_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_comments_finding_id", "finding_comments", ["finding_id"], unique=False)

    op.create_table(
        "finding_history",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("actor_user_id", sa.String(length=36), nullable=True),
        sa.Column("action", sa.String(length=50), nullable=False),
        sa.Column("old_value", sa.Text(), nullable=True),
        sa.Column("new_value", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_history_finding_id", "finding_history", ["finding_id"], unique=False)

    op.create_table(
        "finding_tags",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("tag", sa.String(length=50), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["finding_id"], ["findings.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("finding_id", "tag", name="uq_finding_tags_finding_tag"),
    )
    op.create_index("ix_finding_tags_finding_id", "finding_tags", ["finding_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_finding_tags_finding_id", table_name="finding_tags")
    op.drop_table("finding_tags")
    op.drop_index("ix_finding_history_finding_id", table_name="finding_history")
    op.drop_table("finding_history")
    op.drop_index("ix_finding_comments_finding_id", table_name="finding_comments")
    op.drop_table("finding_comments")
    op.drop_constraint("fk_findings_owner_users", "findings", type_="foreignkey")
    op.drop_constraint("fk_findings_assigned_to_users", "findings", type_="foreignkey")
    op.drop_index("ix_findings_owner_user_id", table_name="findings")
    op.drop_index("ix_findings_assigned_to", table_name="findings")
    op.drop_column("findings", "updated_at")
    op.drop_column("findings", "severity_override")
    op.drop_column("findings", "owner_user_id")
    op.drop_column("findings", "assigned_to")

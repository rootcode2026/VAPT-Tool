"""add user onboarding

Revision ID: k6l7m8n9o0p1
Revises: j5k6l7m8n9o0
Create Date: 2026-09-19
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "k6l7m8n9o0p1"
down_revision: Union[str, Sequence[str], None] = "j5k6l7m8n9o0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "user_onboarding",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tour_version", sa.String(length=20), nullable=False, server_default="1"),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="not_started"),
        sa.Column("current_step", sa.Integer, nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("skipped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("user_id", "tour_version", name="uq_user_onboarding_user_version"),
    )
    op.create_index("ix_user_onboarding_user_id", "user_onboarding", ["user_id"])
    op.create_index("ix_user_onboarding_tour_version", "user_onboarding", ["tour_version"])


def downgrade() -> None:
    op.drop_index("ix_user_onboarding_tour_version", table_name="user_onboarding")
    op.drop_index("ix_user_onboarding_user_id", table_name="user_onboarding")
    op.drop_table("user_onboarding")

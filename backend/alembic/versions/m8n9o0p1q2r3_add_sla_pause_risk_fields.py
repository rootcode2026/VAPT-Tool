"""add sla pause and risk revocation fields

Revision ID: m8n9o0p1q2r3
Revises: l7m8n9o0p1q2
Create Date: 2026-09-21
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "m8n9o0p1q2r3"
down_revision: Union[str, Sequence[str], None] = "l7m8n9o0p1q2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("finding_slas") as batch:
        batch.add_column(sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("resumed_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("pause_reason", sa.Text, nullable=True))
        batch.add_column(sa.Column("remaining_hours", sa.Integer, nullable=True))

    with op.batch_alter_table("finding_risk_acceptances") as batch:
        batch.add_column(sa.Column("rejected_by", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("revoked_by", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("requested_at", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("finding_risk_acceptances") as batch:
        batch.drop_column("requested_at")
        batch.drop_column("revoked_at")
        batch.drop_column("revoked_by")
        batch.drop_column("rejected_at")
        batch.drop_column("rejected_by")
    with op.batch_alter_table("finding_slas") as batch:
        batch.drop_column("remaining_hours")
        batch.drop_column("pause_reason")
        batch.drop_column("cancelled_at")
        batch.drop_column("resumed_at")
        batch.drop_column("paused_at")

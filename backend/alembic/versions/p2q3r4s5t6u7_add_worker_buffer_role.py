"""add worker buffer role

Revision ID: p2q3r4s5t6u7
Revises: o1p2q3r4s5t6
Create Date: 2026-09-20
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "p2q3r4s5t6u7"
down_revision: Union[str, Sequence[str], None] = "o1p2q3r4s5t6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("workers") as batch:
        batch.add_column(sa.Column("role", sa.String(length=20), nullable=False, server_default="normal"))
        batch.add_column(sa.Column("failover_count", sa.Integer, nullable=False, server_default="0"))
        batch.add_column(sa.Column("failure_reason", sa.Text, nullable=True))

    op.create_index("ix_workers_role", "workers", ["role"])


def downgrade() -> None:
    op.drop_index("ix_workers_role", table_name="workers")
    with op.batch_alter_table("workers") as batch:
        batch.drop_column("failure_reason")
        batch.drop_column("failover_count")
        batch.drop_column("role")

"""add worker pools

Revision ID: o1p2q3r4s5t6
Revises: n8o0p1q2r3s4
Create Date: 2026-09-20
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "o1p2q3r4s5t6"
down_revision: Union[str, Sequence[str], None] = "n8o0p1q2r3s4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Worker table (minimal for C9)
    op.create_table(
        "workers",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("pool_id", sa.String(length=36), sa.ForeignKey("worker_pools.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("worker_key", sa.String(length=100), nullable=False, index=True),
        sa.Column("status", sa.String(length=20), nullable=False, default="healthy", server_default="healthy", index=True),
        sa.Column("enabled", sa.Boolean, nullable=False, default=True, server_default="1"),
        sa.Column("capabilities", sa.JSON, nullable=False, default=list),
        sa.Column("current_job_id", sa.String(length=36), nullable=True),
        sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("pool_id", "worker_key", name="uq_workers_pool_key"),
    )
    # ix_workers_status already created via column index=True; skip explicit create to avoid DuplicateTable on PostgreSQL
    pass


def downgrade() -> None:
    op.drop_index("ix_workers_status", table_name="workers")
    op.drop_table("workers")

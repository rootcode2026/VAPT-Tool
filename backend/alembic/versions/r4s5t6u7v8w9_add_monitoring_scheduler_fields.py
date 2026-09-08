"""add monitoring scheduler fields

Revision ID: r4s5t6u7v8w9
Revises: q3r4s5t6u7v8
Create Date: 2026-09-20
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "r4s5t6u7v8w9"
down_revision: Union[str, Sequence[str], None] = "q3r4s5t6u7v8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("scans") as batch:
        batch.add_column(sa.Column("metadata", sa.JSON, nullable=True))

    with op.batch_alter_table("monitoring_configs") as batch:
        batch.add_column(
            sa.Column(
                "target_id",
                sa.String(length=36),
                sa.ForeignKey("targets.id", ondelete="CASCADE"),
                nullable=True,
            )
        )

    op.create_index("ix_monitoring_configs_target_id", "monitoring_configs", ["target_id"])
    op.create_index("ix_monitoring_configs_due", "monitoring_configs", ["enabled", "next_run_at"])


def downgrade() -> None:
    op.drop_index("ix_monitoring_configs_due", table_name="monitoring_configs")
    op.drop_index("ix_monitoring_configs_target_id", table_name="monitoring_configs")

    with op.batch_alter_table("monitoring_configs") as batch:
        batch.drop_column("target_id")

    with op.batch_alter_table("scans") as batch:
        batch.drop_column("metadata")
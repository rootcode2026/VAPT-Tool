"""add monitoring D1 fields

Revision ID: q3r4s5t6u7v8
Revises: p2q3r4s5t6u7
Create Date: 2026-09-20
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "q3r4s5t6u7v8"
down_revision: Union[str, Sequence[str], None] = "p2q3r4s5t6u7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("monitoring_configs") as batch:
        batch.add_column(sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("last_scan_id", sa.String(length=36), nullable=True))
        batch.add_column(sa.Column("last_status", sa.String(length=20), nullable=True))
        batch.add_column(sa.Column("consecutive_failures", sa.Integer, nullable=False, server_default="0"))
        batch.add_column(sa.Column("paused_at", sa.DateTime(timezone=True), nullable=True))
        batch.add_column(sa.Column("pause_reason", sa.Text, nullable=True))
        batch.add_column(sa.Column("schedule", sa.String(length=50), nullable=True))

    with op.batch_alter_table("monitoring_runs") as batch:
        batch.add_column(sa.Column("scan_ids", sa.JSON, nullable=True))
        batch.add_column(sa.Column("scanner_count", sa.Integer, nullable=True))
        batch.add_column(sa.Column("successful_scanners", sa.Integer, nullable=True))
        batch.add_column(sa.Column("failed_scanners", sa.Integer, nullable=True))
        batch.add_column(sa.Column("correlation_id", sa.String(length=100), nullable=True))

    op.create_index("ix_monitoring_configs_next_run", "monitoring_configs", ["next_run_at"])
    op.create_index("ix_monitoring_configs_enabled", "monitoring_configs", ["enabled"])
    # NOTE: ix_monitoring_runs_status already exists from c3d4e5f6a7b8 — do not recreate.


def downgrade() -> None:
    op.drop_index("ix_monitoring_configs_enabled", table_name="monitoring_configs")
    op.drop_index("ix_monitoring_configs_next_run", table_name="monitoring_configs")
    with op.batch_alter_table("monitoring_runs") as batch:
        batch.drop_column("correlation_id")
        batch.drop_column("failed_scanners")
        batch.drop_column("successful_scanners")
        batch.drop_column("scanner_count")
        batch.drop_column("scan_ids")
    with op.batch_alter_table("monitoring_configs") as batch:
        batch.drop_column("schedule")
        batch.drop_column("pause_reason")
        batch.drop_column("paused_at")
        batch.drop_column("consecutive_failures")
        batch.drop_column("last_status")
        batch.drop_column("last_scan_id")
        batch.drop_column("last_run_at")
        batch.drop_column("next_run_at")

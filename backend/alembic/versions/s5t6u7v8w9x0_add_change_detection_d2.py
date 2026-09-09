"""add change detection D2 tables and run bookkeeping

Revision ID: s5t6u7v8w9x0
Revises: r4s5t6u7v8w9
Create Date: 2026-09-09

D2 (Change Detection) schema, additive only:

- monitoring_runs: change_status / change_error / change_events_count.
  Pre-D2 rows default to 'skipped' (history predates change detection);
  new runs set 'pending' (has scans) or 'skipped' (terminal at creation)
  explicitly at creation time.
- asset_relationships: last_seen_scan_id so run-scoped relationship
  observations can be built (relationships previously had no scan linkage).
- monitoring_observation_baselines: one trusted-observation snapshot row per
  monitoring config (replaced only by completed runs).
- monitoring_change_events: durable run-level change records with
  deterministic event_key UNIQUE for idempotent reprocessing.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "s5t6u7v8w9x0"
down_revision: Union[str, Sequence[str], None] = "r4s5t6u7v8w9"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("monitoring_runs") as batch:
        batch.add_column(
            sa.Column("change_status", sa.String(length=20), nullable=False, server_default="skipped")
        )
        batch.add_column(sa.Column("change_error", sa.Text, nullable=True))
        batch.add_column(
            sa.Column("change_events_count", sa.Integer, nullable=False, server_default="0")
        )

    with op.batch_alter_table("asset_relationships") as batch:
        batch.add_column(sa.Column("last_seen_scan_id", sa.String(length=36), nullable=True))

    op.create_table(
        "monitoring_observation_baselines",
        sa.Column("config_id", sa.String(length=36), sa.ForeignKey("monitoring_configs.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assets", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("findings", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("relationships", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("scanners", sa.JSON, nullable=False, server_default="{}"),
    )

    op.create_table(
        "monitoring_change_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("monitoring_config_id", sa.String(length=36), sa.ForeignKey("monitoring_configs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("prev_run_id", sa.String(length=36), nullable=True),
        sa.Column("curr_run_id", sa.String(length=36), nullable=False),
        sa.Column("change_type", sa.String(length=50), nullable=False),
        sa.Column("asset_id", sa.String(length=36), sa.ForeignKey("assets.id", ondelete="SET NULL"), nullable=True),
        sa.Column("finding_id", sa.String(length=36), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("previous_state", sa.JSON, nullable=True),
        sa.Column("current_state", sa.JSON, nullable=True),
        sa.Column("scanners", sa.JSON, nullable=True),
        sa.Column("scan_ids", sa.JSON, nullable=True),
        sa.Column("completeness", sa.String(length=20), nullable=False, server_default="complete"),
        sa.Column("event_key", sa.String(length=128), nullable=False, unique=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=False),
        # ORM attribute is `extra_data`; physical column is "metadata"
        # (same convention as AssetChangeEvent / AuditLog).
        sa.Column("metadata", sa.JSON, nullable=False, server_default="{}"),
    )

    op.create_index("ix_monitoring_changes_project", "monitoring_change_events", ["project_id"])
    op.create_index("ix_monitoring_changes_config", "monitoring_change_events", ["monitoring_config_id"])
    op.create_index("ix_monitoring_changes_curr_run", "monitoring_change_events", ["curr_run_id"])
    op.create_index("ix_monitoring_changes_type", "monitoring_change_events", ["change_type"])
    op.create_index("ix_monitoring_changes_detected", "monitoring_change_events", ["detected_at"])
    op.create_index("ix_monitoring_changes_event_key", "monitoring_change_events", ["event_key"], unique=True)
    op.create_index("ix_asset_relationships_last_seen_scan", "asset_relationships", ["last_seen_scan_id"])
    op.create_index("ix_monitoring_runs_change_status", "monitoring_runs", ["change_status"])


def downgrade() -> None:
    op.drop_index("ix_monitoring_runs_change_status", table_name="monitoring_runs")
    op.drop_index("ix_asset_relationships_last_seen_scan", table_name="asset_relationships")
    op.drop_index("ix_monitoring_changes_event_key", table_name="monitoring_change_events")
    op.drop_index("ix_monitoring_changes_detected", table_name="monitoring_change_events")
    op.drop_index("ix_monitoring_changes_type", table_name="monitoring_change_events")
    op.drop_index("ix_monitoring_changes_curr_run", table_name="monitoring_change_events")
    op.drop_index("ix_monitoring_changes_config", table_name="monitoring_change_events")
    op.drop_index("ix_monitoring_changes_project", table_name="monitoring_change_events")
    op.drop_table("monitoring_change_events")
    op.drop_table("monitoring_observation_baselines")
    with op.batch_alter_table("asset_relationships") as batch:
        batch.drop_column("last_seen_scan_id")
    with op.batch_alter_table("monitoring_runs") as batch:
        batch.drop_column("change_events_count")
        batch.drop_column("change_error")
        batch.drop_column("change_status")

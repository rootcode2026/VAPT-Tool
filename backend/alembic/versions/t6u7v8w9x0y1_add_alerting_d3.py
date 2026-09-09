"""add alerting D3 tables and run bookkeeping

Revision ID: t6u7v8w9x0y1
Revises: s5t6u7v8w9x0
Create Date: 2026-09-09

D3 (Alerting) schema, additive only:

- alert_policies: one minimal policy row per project (auto-created with
  safe defaults on first evaluation).
- alerts: durable operational signals derived from D2 change events with
  deterministic dedup_key UNIQUE for idempotent evaluation and simple
  operational deduplication (one open alert per canonical object+type).
- monitoring_runs: alert_status / alert_error / alerts_created run
  bookkeeping (pre-D3 rows default to 'skipped'; new runs set 'pending'
  or 'skipped' explicitly at creation time).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "t6u7v8w9x0y1"
down_revision: Union[str, Sequence[str], None] = "s5t6u7v8w9x0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "alert_policies",
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("min_severity", sa.String(length=20), nullable=False, server_default="high"),
        sa.Column("alert_critical_findings", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("alert_high_findings", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("alert_reopened", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("alert_asset_exposure", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("alert_relationships", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("alert_metadata_changes", sa.Boolean, nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "alerts",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("organization_id", sa.String(length=36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.String(length=36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("monitoring_config_id", sa.String(length=36), nullable=True),
        sa.Column("alert_type", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="open"),
        sa.Column("title", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("source_change_event_id", sa.String(length=36), nullable=True),
        sa.Column("source_finding_id", sa.String(length=36), nullable=True),
        sa.Column("source_asset_id", sa.String(length=36), nullable=True),
        sa.Column("finding_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("asset_key", sa.String(length=1100), nullable=True),
        sa.Column("monitoring_run_id", sa.String(length=36), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("acknowledged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(length=36), nullable=True),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.String(length=36), nullable=True),
        sa.Column("event_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("dedup_key", sa.String(length=128), nullable=False, unique=True),
        # ORM attribute is `extra_data`; physical column is "metadata"
        # (same convention as AssetChangeEvent / MonitoringChangeEvent).
        sa.Column("metadata", sa.JSON, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_index("ix_alerts_project", "alerts", ["project_id"])
    op.create_index("ix_alerts_org", "alerts", ["organization_id"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_type", "alerts", ["alert_type"])
    op.create_index("ix_alerts_fingerprint", "alerts", ["finding_fingerprint"])
    op.create_index("ix_alerts_dedup_key", "alerts", ["dedup_key"], unique=True)

    with op.batch_alter_table("monitoring_runs") as batch:
        batch.add_column(
            sa.Column("alert_status", sa.String(length=20), nullable=False, server_default="skipped")
        )
        batch.add_column(sa.Column("alert_error", sa.Text, nullable=True))
        batch.add_column(
            sa.Column("alerts_created", sa.Integer, nullable=False, server_default="0")
        )


def downgrade() -> None:
    with op.batch_alter_table("monitoring_runs") as batch:
        batch.drop_column("alerts_created")
        batch.drop_column("alert_error")
        batch.drop_column("alert_status")
    op.drop_index("ix_alerts_dedup_key", table_name="alerts")
    op.drop_index("ix_alerts_fingerprint", table_name="alerts")
    op.drop_index("ix_alerts_type", table_name="alerts")
    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_index("ix_alerts_status", table_name="alerts")
    op.drop_index("ix_alerts_org", table_name="alerts")
    op.drop_index("ix_alerts_project", table_name="alerts")
    op.drop_table("alerts")
    op.drop_table("alert_policies")

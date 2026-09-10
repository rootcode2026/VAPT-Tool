"""add notifications D9 tables (policy, deliveries, inbox, local outbox)

Revision ID: w9x0y1z2a3b4
Revises: v8w9x0y1z2a3
Create Date: 2026-09-10

D9 (Notifications) schema, additive only:

- notification_policies: one row per project (project PK, like AlertPolicy)
- notification_deliveries: one logical notification per occurrence with
  UNIQUE(alert_id, recipient_user_id, channel, notification_type, occurrence)
- notifications: in-app inbox with UNIQUE(alert_id, user_id)
- notification_outbox: bounded local/test provider sink (no network)
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "w9x0y1z2a3b4"
down_revision: Union[str, Sequence[str], None] = "v8w9x0y1z2a3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notification_policies",
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("channel", sa.String(20), nullable=False, server_default="in_app"),
        sa.Column("min_severity", sa.String(20), nullable=False, server_default="high"),
        sa.Column("alert_types", sa.JSON(), nullable=True),
        sa.Column("recipient_mode", sa.String(30), nullable=False, server_default="finding_owner"),
        sa.Column("explicit_user_ids", sa.JSON(), nullable=True),
        sa.Column("cooldown_seconds", sa.Integer(), nullable=False, server_default="3600"),
        sa.Column("notify_on_redetection", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("provider_config", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("updated_by", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "notification_deliveries",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("recipient_user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("channel", sa.String(20), nullable=False, index=True),
        sa.Column("notification_type", sa.String(50), nullable=False, index=True),
        sa.Column("occurrence", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(20), nullable=False, server_default="pending", index=True),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("provider_message_id", sa.String(200), nullable=True),
        sa.Column("last_error", sa.String(500), nullable=True),
        sa.Column("subject", sa.String(255), nullable=True),
        sa.Column("body", sa.String(2000), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), index=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("alert_id", "recipient_user_id", "channel", "notification_type", "occurrence", name="uq_notification_delivery_identity"),
    )
    op.create_index("ix_delivery_project_status", "notification_deliveries", ["project_id", "status"])
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("organization_id", sa.String(36), sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("project_id", sa.String(36), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("user_id", sa.String(36), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True),
        sa.Column("alert_id", sa.String(36), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True),
        sa.Column("notification_type", sa.String(50), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.String(1000), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now(), index=True),
        sa.UniqueConstraint("alert_id", "user_id", name="uq_notification_alert_user"),
    )
    op.create_index("ix_notifications_user_unread", "notifications", ["user_id", "read_at"])
    op.create_table(
        "notification_outbox",
        sa.Column("delivery_id", sa.String(36), sa.ForeignKey("notification_deliveries.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("channel", sa.String(20), nullable=False),
        sa.Column("recipient_user_id", sa.String(36), nullable=True),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("body", sa.String(2000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("notification_outbox")
    op.drop_index("ix_notifications_user_unread", table_name="notifications")
    op.drop_table("notifications")
    op.drop_index("ix_delivery_project_status", table_name="notification_deliveries")
    op.drop_table("notification_deliveries")
    op.drop_table("notification_policies")

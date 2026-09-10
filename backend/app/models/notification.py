import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class NotificationPolicy(Base):
    """D9 lightweight project-scoped notification policy (delivery, not alerting).

    D3 AlertPolicy remains authoritative for whether an alert exists; this policy
    decides only whether that alert is delivered, to whom, and through which
    channel. One row per project (project PK, like AlertPolicy).
    """

    __tablename__ = "notification_policies"

    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="CASCADE"),
        primary_key=True,
    )

    enabled: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="1",
    )

    channel: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="in_app",
        server_default="in_app",
    )

    min_severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="high",
        server_default="high",
    )

    # Null/empty = all D3 alert types. Otherwise an explicit allowlist.
    alert_types: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    recipient_mode: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="finding_owner",
        server_default="finding_owner",
    )

    # Validated project-member user IDs; used only for explicit_users mode.
    explicit_user_ids: Mapped[list | None] = mapped_column(
        JSON,
        nullable=True,
    )

    # Each new alert occurrence within this window reuses the existing delivery.
    cooldown_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3600,
        server_default="3600",
    )

    # False (default): only the first detection notifies. True: every new
    # alert occurrence (event_count increment, incl. reopen) may notify.
    notify_on_redetection: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default="0",
    )

    # Local/test provider knobs only (allowlisted keys, no secrets).
    provider_config: Mapped[dict | None] = mapped_column(
        JSON,
        nullable=True,
    )

    created_by: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    updated_by: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=datetime.utcnow,
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        onupdate=datetime.utcnow,
    )


class NotificationDelivery(Base):
    """D9 delivery record: one logical notification per occurrence.

    Identity (alert, recipient, channel, type, occurrence) is enforced by a
    database UNIQUE constraint — duplicate evaluation cannot duplicate delivery.
    """

    __tablename__ = "notification_deliveries"
    __table_args__ = (
        UniqueConstraint(
            "alert_id", "recipient_user_id", "channel", "notification_type", "occurrence",
            name="uq_notification_delivery_identity",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    alert_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    recipient_user_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    channel: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        index=True,
    )

    notification_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        index=True,
    )

    # Alert occurrence generation (alert.event_count at creation).
    occurrence: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="pending",
        index=True,
    )

    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    # Bounded, sanitized provider message ID (never a secret).
    provider_message_id: Mapped[str | None] = mapped_column(
        String(200),
        nullable=True,
    )

    # Bounded, sanitized failure classification (never provider internals).
    last_error: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    # Pre-rendered bounded content fixed at evaluation time (auditable,
    # identical for inbox and async providers; no re-rendering in workers).
    subject: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    body: Mapped[str | None] = mapped_column(
        String(2000),
        nullable=True,
    )

    sent_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=datetime.utcnow,
        index=True,
    )

    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        onupdate=datetime.utcnow,
    )


class Notification(Base):
    """D9 in-app inbox record (alert inbox, not chat)."""

    __tablename__ = "notifications"
    __table_args__ = (
        UniqueConstraint(
            "alert_id", "user_id",
            name="uq_notification_alert_user",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )

    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    alert_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    notification_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    summary: Mapped[str | None] = mapped_column(
        String(1000),
        nullable=True,
    )

    severity: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    read_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=datetime.utcnow,
        index=True,
    )


class NotificationOutbox(Base):
    """D9 local/test provider sink: bounded accepted payloads, no network.

    The `local` channel exists for development/testing verification. It never
    performs network I/O. Production email/webhook providers are deferred.
    """

    __tablename__ = "notification_outbox"

    delivery_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("notification_deliveries.id", ondelete="CASCADE"),
        primary_key=True,
    )

    channel: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    recipient_user_id: Mapped[str | None] = mapped_column(
        String(36),
        nullable=True,
    )

    subject: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    body: Mapped[str] = mapped_column(
        String(2000),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        default=datetime.utcnow,
    )

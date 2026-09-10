"""D9 notification policy, recipients, content, and evaluation.

D3 remains authoritative for alert creation. This module decides only whether
an existing alert is delivered, to whom, and through which channel.

Channels: `in_app` (synchronous inbox, no network) and `local` (async Celery
task to a bounded local outbox sink for development/testing, no network).
Production email/webhooks are deferred (see docs/NOTIFICATIONS_D9.md).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

NOTIFICATION_CHANNELS = ("in_app", "local")
RECIPIENT_MODES = ("finding_owner", "project_analysts", "explicit_users")
NOTIFICATION_STATUSES = ("pending", "sending", "sent", "failed", "cancelled")
DELIVERY_RESULTS = ("sent", "failed", "cancelled")

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

MAX_RECIPIENTS = 50
MAX_EXPLICIT_USERS = 20
MAX_ATTEMPTS = 5
DEFAULT_COOLDOWN_SECONDS = 3600
PROJECT_HOURLY_CAP = 50

SUBJECT_MAX = 255
BODY_MAX = 2000
SUMMARY_MAX = 1000
TITLE_MAX = 255

# Allowlisted local-provider test knobs (no secrets, no network, no URLs).
LOCAL_FAIL_MODES = ("none", "temporary", "permanent")

_SECRET_PATTERNS = (
    "BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE", "BEGIN OPENSSH",
    "aws_secret", "sk_live", "ghp_", "AKIA",
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _redact(text: str | None, limit: int) -> str | None:
    if text is None:
        return None
    s = str(text).strip()
    if not s:
        return None
    upper = s.upper()
    for pat in _SECRET_PATTERNS:
        if pat in s or pat.upper() in upper:
            return "[REDACTED]"
    # Never leak password-like assignments.
    s = re.sub(r"(?i)(password|passwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*\S+", r"\1=[REDACTED]", s)
    return s[:limit]


def severity_rank(severity: str | None) -> int:
    return SEVERITY_RANK.get(str(severity or "").strip().lower(), 5)


def dedup_key(alert_id: str, recipient_user_id: str | None, channel: str, notification_type: str, occurrence: int) -> str:
    raw = f"{alert_id}:{(recipient_user_id or '')}:{channel}:{notification_type}:{occurrence}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def render_notification_content(alert, project_name: str | None) -> tuple[str, str]:
    """Deterministic bounded subject/body from alert fields only.

    Never includes raw scanner output, evidence bodies, credentials, or secrets:
    only identifiers, severity/type, truncated title/description, timestamps,
    and a platform link path (no sensitive query params).
    """
    atype = str(getattr(alert, "alert_type", "") or "security_alert")
    sev = str(getattr(alert, "severity", "") or "unknown").upper()
    title = _redact(getattr(alert, "title", ""), 200) or "Security alert"
    subject = f"[{sev}] {atype}: {title}"[:SUBJECT_MAX]
    desc = _redact(getattr(alert, "description", ""), 500)
    asset = _redact(getattr(alert, "asset_key", None), 200)
    finding_id = getattr(alert, "source_finding_id", None)
    seen = getattr(alert, "last_seen_at", None) or getattr(alert, "first_seen_at", None)
    lines = [
        "SECURITY ALERT",
        "",
        f"Project: {(project_name or '—')[:100]}",
        f"Severity: {sev}",
        f"Type: {atype}",
        "",
        "Title:",
        title,
    ]
    if asset:
        lines += ["", "Asset:", asset]
    if finding_id:
        lines += ["", f"Finding: {finding_id}"]
    if desc:
        lines += ["", "Summary:", desc]
    if seen:
        try:
            lines += ["", f"Detected: {seen.isoformat() if hasattr(seen, 'isoformat') else seen}"]
        except Exception:
            pass
    lines += ["", f"Review: /projects/{getattr(alert, 'project_id', '')}/alerts/{getattr(alert, 'id', '')}"]
    return subject, "\n".join(lines)[:BODY_MAX]


def validate_policy_payload(data: dict) -> dict:
    """Validate PUT policy body. Returns sanitized fields or raises ValueError."""
    if not isinstance(data, dict):
        raise ValueError("policy body must be an object")
    out: dict[str, Any] = {}
    if "enabled" in data:
        out["enabled"] = bool(data["enabled"])
    if "channel" in data:
        ch = str(data["channel"] or "").strip().lower()
        if ch not in NOTIFICATION_CHANNELS:
            raise ValueError(f"Invalid channel: {data['channel']}")
        out["channel"] = ch
    if "min_severity" in data:
        sev = str(data["min_severity"] or "").strip().lower()
        if sev not in SEVERITY_RANK:
            raise ValueError(f"Invalid min_severity: {data['min_severity']}")
        out["min_severity"] = sev
    if "alert_types" in data:
        at = data["alert_types"]
        if at is not None:
            if not isinstance(at, list):
                raise ValueError("alert_types must be a list or null")
        cleaned = sorted({str(t).strip().upper() for t in (at or []) if str(t).strip()}) or None
        if cleaned is not None and len(cleaned) > 20:
            raise ValueError("Too many alert types")
        out["alert_types"] = cleaned
    if "recipient_mode" in data:
        mode = str(data["recipient_mode"] or "").strip().lower()
        if mode not in RECIPIENT_MODES:
            raise ValueError(f"Invalid recipient_mode: {data['recipient_mode']}")
        out["recipient_mode"] = mode
    if "explicit_user_ids" in data:
        ids = data["explicit_user_ids"]
        if ids is not None:
            if not isinstance(ids, list):
                raise ValueError("explicit_user_ids must be a list or null")
            cleaned_ids = []
            for uid in ids:
                s = str(uid or "").strip()
                if s:
                    cleaned_ids.append(s[:36])
            if len(cleaned_ids) > MAX_EXPLICIT_USERS:
                raise ValueError(f"Too many explicit users (max {MAX_EXPLICIT_USERS})")
            out["explicit_user_ids"] = cleaned_ids or None
        else:
            out["explicit_user_ids"] = None
    if "cooldown_seconds" in data:
        try:
            cd = int(data["cooldown_seconds"])
        except Exception:
            raise ValueError("cooldown_seconds must be an integer")
        if cd < 60 or cd > 86400:
            raise ValueError("cooldown_seconds must be between 60 and 86400")
        out["cooldown_seconds"] = cd
    if "notify_on_redetection" in data:
        out["notify_on_redetection"] = bool(data["notify_on_redetection"])
    if "provider_config" in data:
        cfg = data["provider_config"]
        if cfg is not None:
            if not isinstance(cfg, dict):
                raise ValueError("provider_config must be an object or null")
            # Allowlist only: local test fail mode. No secrets, URLs, or credentials.
            allowed = {"fail_mode"}
            unknown = set(cfg) - allowed
            if unknown:
                raise ValueError(f"Unsupported provider_config keys: {sorted(unknown)}")
            if "fail_mode" in cfg and str(cfg["fail_mode"]) not in LOCAL_FAIL_MODES:
                raise ValueError(f"Invalid fail_mode: {cfg['fail_mode']}")
            out["provider_config"] = {"fail_mode": str(cfg.get("fail_mode", "none"))} if cfg else None
        else:
            out["provider_config"] = None
    return out


def default_policy_values() -> dict:
    return {
        "enabled": True,
        "channel": "in_app",
        "min_severity": "high",
        "alert_types": None,
        "recipient_mode": "finding_owner",
        "explicit_user_ids": None,
        "cooldown_seconds": DEFAULT_COOLDOWN_SECONDS,
        "notify_on_redetection": False,
        "provider_config": None,
    }


def get_or_create_policy(db: Session, project_id: str, organization_id: str, actor_user_id: str | None = None):
    """Fetch the project policy, creating deterministic defaults if absent."""
    from app.models.notification import NotificationPolicy

    policy = db.query(NotificationPolicy).filter(NotificationPolicy.project_id == project_id).first()
    if policy is not None:
        return policy, False
    policy = NotificationPolicy(project_id=project_id, created_by=actor_user_id, **default_policy_values())
    db.add(policy)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        policy = db.query(NotificationPolicy).filter(NotificationPolicy.project_id == project_id).first()
        return policy, False
    return policy, True


def _active_org_user(db: Session, user_id: str, organization_id: str):
    """Return the user iff active and inside the organization (tenant-safe)."""
    from app.models.organization_membership import OrganizationMembership
    from app.models.user import User

    user = db.query(User).filter(User.id == user_id).first()
    if user is None or getattr(user, "status", "active") != "active":
        return None
    if getattr(user, "organization_id", None) == organization_id:
        return user
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.status == "active",
        )
        .first()
    )
    return user if membership is not None else None


def _has_project_access(db: Session, user_id: str, project_id: str, organization_id: str) -> bool:
    from app.models.project_membership import ProjectMembership

    pm = (
        db.query(ProjectMembership)
        .filter(
            ProjectMembership.project_id == project_id,
            ProjectMembership.user_id == user_id,
            ProjectMembership.status == "active",
        )
        .first()
    )
    if pm is not None:
        return True
    # Org admins inherit project visibility (mirrors API conventions).
    from app.api.deps import _effective_org_role, _is_super_admin
    from app.models.user import User

    user = db.query(User).filter(User.id == user_id).first()
    if user is not None and _is_super_admin(user):
        return True
    return _effective_org_role(user, organization_id, db) in ("org_admin", "organization_admin") if user is not None else False


def resolve_recipients(db: Session, policy, alert, project) -> list:
    """Resolve recipient users inside the project/organization boundary.

    Bounded, deterministic (sorted by id), tenant-isolated. Returns User rows.
    """
    from app.models.finding import Finding
    from app.models.project_membership import ProjectMembership
    from app.models.user import User

    organization_id = project.organization_id
    project_id = project.id
    mode = (getattr(policy, "recipient_mode", "") or "").strip().lower()
    users: dict[str, Any] = {}

    def _add(user):
        if user is not None and len(users) < MAX_RECIPIENTS:
            users[user.id] = user

    if mode == "finding_owner":
        finding_id = getattr(alert, "source_finding_id", None)
        if finding_id:
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
            if finding is not None:
                for owner_id in (getattr(finding, "assigned_to", None), getattr(finding, "owner_user_id", None)):
                    if owner_id:
                        candidate = _active_org_user(db, str(owner_id), organization_id)
                        if candidate is not None and _has_project_access(db, candidate.id, project_id, organization_id):
                            _add(candidate)
                            break
    elif mode == "project_analysts":
        memberships = (
            db.query(ProjectMembership)
            .filter(
                ProjectMembership.project_id == project_id,
                ProjectMembership.status == "active",
                ProjectMembership.role.in_(["analyst", "project_admin", "security_analyst", "security_admin"]),
            )
            .order_by(ProjectMembership.user_id)
            .limit(MAX_RECIPIENTS)
            .all()
        )
        for pm in memberships:
            _add(_active_org_user(db, pm.user_id, organization_id))
    elif mode == "explicit_users":
        for uid in (getattr(policy, "explicit_user_ids", None) or [])[:MAX_EXPLICIT_USERS]:
            candidate = _active_org_user(db, str(uid), organization_id)
            if candidate is not None and _has_project_access(db, candidate.id, project_id, organization_id):
                _add(candidate)
    return [users[k] for k in sorted(users)]


def _policy_allows(policy, alert) -> str | None:
    """Gate an alert against the policy. Returns None if allowed, else a reason."""
    if not getattr(policy, "enabled", False):
        return "policy disabled"
    if str(getattr(alert, "status", "") or "").lower() not in ("open", "acknowledged"):
        return "alert not active"
    if severity_rank(getattr(alert, "severity", None)) > severity_rank(getattr(policy, "min_severity", "high")):
        return "below minimum severity"
    allowed = getattr(policy, "alert_types", None)
    if allowed:
        if str(getattr(alert, "alert_type", "") or "").upper() not in {str(t).upper() for t in allowed}:
            return "alert type excluded"
    return None


def _project_hourly_count(db: Session, project_id: str) -> int:
    from datetime import timedelta

    from app.models.notification import NotificationDelivery

    cutoff = utcnow().replace(tzinfo=None) - timedelta(hours=1)
    try:
        return (
            db.query(NotificationDelivery)
            .filter(NotificationDelivery.project_id == project_id, NotificationDelivery.created_at >= cutoff)
            .count()
        )
    except Exception:
        return 0


def evaluate_alert_notifications(
    db: Session,
    alert,
    project,
    actor_user_id: str | None = None,
    project_name: str | None = None,
) -> list[dict]:
    """Evaluate one alert against the project policy; create/resolve deliveries.

    Idempotent: repeated evaluation returns existing deliveries (database UNIQUE
    identity). Returns delivery payload dicts.
    """
    from app.models.notification import Notification, NotificationDelivery

    from app.services.audit import (
        EVENT_NOTIFICATION_FAILED,
        EVENT_NOTIFICATION_REQUESTED,
        EVENT_NOTIFICATION_SENT,
        RESOURCE_NOTIFICATION_DELIVERY,
        RESULT_SUCCESS,
        AuditService,
    )

    policy, _ = get_or_create_policy(db, project.id, project.organization_id, actor_user_id)
    gate = _policy_allows(policy, alert)
    if gate is not None:
        return []
    if _project_hourly_count(db, project.id) >= PROJECT_HOURLY_CAP:
        return []
    recipients = resolve_recipients(db, policy, alert, project)
    if not recipients:
        return []

    channel = (getattr(policy, "channel", "in_app") or "in_app").strip().lower()
    if channel not in NOTIFICATION_CHANNELS:
        channel = "in_app"
    notification_type = str(getattr(alert, "alert_type", "") or "security_alert").upper()[:50]
    subject, body = render_notification_content(alert, project_name or getattr(project, "name", None))
    cooldown = int(getattr(policy, "cooldown_seconds", DEFAULT_COOLDOWN_SECONDS) or DEFAULT_COOLDOWN_SECONDS)
    redetect = bool(getattr(policy, "notify_on_redetection", False))
    event_count = int(getattr(alert, "event_count", 1) or 1)

    results: list[dict] = []
    for user in recipients:
        # Existing delivery for this identity (any occurrence)?
        existing = (
            db.query(NotificationDelivery)
            .filter(
                NotificationDelivery.alert_id == alert.id,
                NotificationDelivery.recipient_user_id == user.id,
                NotificationDelivery.channel == channel,
                NotificationDelivery.notification_type == notification_type,
            )
            .order_by(NotificationDelivery.occurrence.desc())
            .first()
        )
        if existing is not None:
            if not redetect or event_count <= (existing.occurrence or 1):
                results.append(_delivery_payload(existing))
                continue
            # New occurrence allowed: cooldown since the last delivery?
            try:
                age = (utcnow().replace(tzinfo=None) - (existing.created_at.replace(tzinfo=None) if existing.created_at and existing.created_at.tzinfo else existing.created_at)).total_seconds()
            except Exception:
                age = cooldown
            if age < cooldown:
                results.append(_delivery_payload(existing))
                continue
            occurrence = event_count
        else:
            occurrence = 1

        delivery = NotificationDelivery(
            id=str(uuid.uuid4()),
            organization_id=project.organization_id,
            project_id=project.id,
            alert_id=alert.id,
            recipient_user_id=user.id,
            channel=channel,
            notification_type=notification_type,
            occurrence=occurrence,
            status="pending",
            subject=subject,
            body=body,
        )
        db.add(delivery)
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            existing = (
                db.query(NotificationDelivery)
                .filter(
                    NotificationDelivery.alert_id == alert.id,
                    NotificationDelivery.recipient_user_id == user.id,
                    NotificationDelivery.channel == channel,
                    NotificationDelivery.notification_type == notification_type,
                    NotificationDelivery.occurrence == occurrence,
                )
                .first()
            )
            if existing is not None:
                results.append(_delivery_payload(existing))
            continue
        AuditService.record(
            db, event_type=EVENT_NOTIFICATION_REQUESTED, action=EVENT_NOTIFICATION_REQUESTED,
            result=RESULT_SUCCESS, actor_user_id=actor_user_id,
            organization_id=project.organization_id, project_id=project.id,
            resource_type=RESOURCE_NOTIFICATION_DELIVERY, resource_id=delivery.id,
            metadata={"alert_id": alert.id, "channel": channel, "type": notification_type},
        )
        if channel == "in_app":
            _complete_in_app(db, delivery, alert, user, project, actor_user_id)
        else:
            _enqueue_local(db, delivery, project, actor_user_id)
        results.append(_delivery_payload(delivery))
    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return results


def _delivery_payload(d) -> dict:
    return {
        "id": d.id,
        "project_id": d.project_id,
        "alert_id": d.alert_id,
        "recipient_user_id": d.recipient_user_id,
        "channel": d.channel,
        "notification_type": d.notification_type,
        "occurrence": d.occurrence,
        "status": d.status,
        "attempt_count": d.attempt_count,
        "provider_message_id": d.provider_message_id,
        "last_error": d.last_error,
        "subject": getattr(d, "subject", None),
        "sent_at": d.sent_at.isoformat() if d.sent_at else None,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


def _complete_in_app(db: Session, delivery, alert, user, project, actor_user_id: str | None) -> None:
    """Synchronous in-app delivery: inbox row + SENT (no network)."""
    from app.models.notification import Notification

    from app.services.audit import (
        EVENT_NOTIFICATION_SENT,
        RESOURCE_NOTIFICATION_DELIVERY,
        RESULT_SUCCESS,
        AuditService,
    )

    inbox = Notification(
        id=str(uuid.uuid4()),
        organization_id=project.organization_id,
        project_id=project.id,
        user_id=user.id,
        alert_id=alert.id,
        notification_type=delivery.notification_type,
        title=(delivery.subject or "Security alert")[:TITLE_MAX],
        summary=(delivery.body or "")[:SUMMARY_MAX] or None,
        severity=str(getattr(alert, "severity", "") or "").lower() or None,
    )
    # Savepoint: an inbox duplicate must not roll back the delivery itself.
    try:
        nested = db.begin_nested()
    except Exception:
        nested = None
    try:
        db.add(inbox)
        db.flush()
        if nested is not None:
            nested.commit()
    except IntegrityError:
        # Inbox already has this alert for the user: still SENT, no duplicate.
        if nested is not None:
            try:
                nested.rollback()
            except Exception:
                pass
        else:
            try:
                db.rollback()
            except Exception:
                pass
            db.add(delivery)
            db.flush()
    now = utcnow().replace(tzinfo=None)
    delivery.status = "sent"
    delivery.attempt_count = 1
    delivery.provider_message_id = f"inapp-{delivery.id[:8]}"
    delivery.sent_at = now
    AuditService.record(
        db, event_type=EVENT_NOTIFICATION_SENT, action=EVENT_NOTIFICATION_SENT,
        result=RESULT_SUCCESS, actor_user_id=actor_user_id,
        organization_id=project.organization_id, project_id=project.id,
        resource_type=RESOURCE_NOTIFICATION_DELIVERY, resource_id=delivery.id,
        metadata={"alert_id": alert.id, "channel": "in_app"},
    )


def _enqueue_local(db: Session, delivery, project, actor_user_id: str | None) -> None:
    """Enqueue async local delivery; queue failure becomes explicit FAILED."""
    from app.services.audit import (
        EVENT_NOTIFICATION_FAILED,
        RESOURCE_NOTIFICATION_DELIVERY,
        RESULT_SUCCESS,
        AuditService,
    )

    try:
        from app.core.celery import celery_app as _celery

        _celery.send_task("app.notifications.deliver_notification", args=[delivery.id])
    except Exception as exc:
        delivery.status = "failed"
        delivery.attempt_count = 1
        delivery.last_error = f"queue_failed: {str(exc)[:200]}"
        AuditService.record(
            db, event_type=EVENT_NOTIFICATION_FAILED, action=EVENT_NOTIFICATION_FAILED,
            result=RESULT_SUCCESS, actor_user_id=actor_user_id,
            organization_id=project.organization_id, project_id=project.id,
            resource_type=RESOURCE_NOTIFICATION_DELIVERY, resource_id=delivery.id,
            metadata={"alert_id": delivery.alert_id, "channel": "local", "reason": "queue_failed"},
        )


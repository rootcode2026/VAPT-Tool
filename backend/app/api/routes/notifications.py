"""Project-scoped notification APIs (D9): inbox, policy, deliveries, notify.

D3 remains authoritative for alert creation; these endpoints only evaluate the
notification policy, resolve in-project recipients, and record deliveries.
Provider secrets are never accepted or exposed: the local/test provider needs
none, and production email/webhooks are deferred.
"""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import (
    _effective_org_role,
    _effective_project_role,
    _is_super_admin,
    get_current_user,
    require_project_access,
)
from app.db.database import get_db
from app.models.alert import Alert
from app.models.notification import Notification, NotificationDelivery, NotificationPolicy
from app.models.project import Project
from app.models.user import User
from app.services.audit import (
    EVENT_NOTIFICATION_CANCELLED,
    EVENT_NOTIFICATION_POLICY_CREATED,
    EVENT_NOTIFICATION_POLICY_UPDATED,
    RESOURCE_NOTIFICATION_DELIVERY,
    RESOURCE_NOTIFICATION_POLICY,
    RESULT_SUCCESS,
    AuditService,
)
from app.services.notifications import (
    MAX_EXPLICIT_USERS,
    NOTIFICATION_CHANNELS,
    RECIPIENT_MODES,
    default_policy_values,
    get_or_create_policy,
    validate_policy_payload,
)

router = APIRouter(prefix="/api/v1", tags=["Notifications"])


def _utcnow():
    return datetime.now(timezone.utc)


def _require_policy_manage(project_id: str, db: Session, current_user: User) -> None:
    """Notification policy: project_admin, org_admin, super_admin (mirrors D3)."""
    if _is_super_admin(current_user):
        return
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj:
        org_role = _effective_org_role(current_user, proj.organization_id, db)
        if org_role == "org_admin":
            return
    role = _effective_project_role(current_user, project_id, db)
    if role != "project_admin":
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires project_admin to manage notification policy")


def _require_notify(project_id: str, db: Session, current_user: User) -> None:
    """Explicit notify: analyst, project_admin, org_admin, super_admin."""
    if _is_super_admin(current_user):
        return
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj:
        org_role = _effective_org_role(current_user, proj.organization_id, db)
        if org_role == "org_admin":
            return
    role = _effective_project_role(current_user, project_id, db)
    if role not in ("analyst", "project_admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires analyst to request notifications")


def _is_project_admin(project_id: str, db: Session, current_user: User) -> bool:
    if _is_super_admin(current_user):
        return True
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj and _effective_org_role(current_user, proj.organization_id, db) == "org_admin":
        return True
    return _effective_project_role(current_user, project_id, db) == "project_admin"


def _policy_payload(p: NotificationPolicy, project_id: str) -> dict:
    return {
        "project_id": getattr(p, "project_id", project_id),
        "enabled": bool(getattr(p, "enabled", True)),
        "channel": getattr(p, "channel", "in_app"),
        "min_severity": getattr(p, "min_severity", "high"),
        "alert_types": getattr(p, "alert_types", None),
        "recipient_mode": getattr(p, "recipient_mode", "finding_owner"),
        "explicit_user_ids": getattr(p, "explicit_user_ids", None),
        "cooldown_seconds": getattr(p, "cooldown_seconds", 3600),
        "notify_on_redetection": bool(getattr(p, "notify_on_redetection", False)),
        "provider_config": getattr(p, "provider_config", None),
        "created_at": p.created_at.isoformat() if getattr(p, "created_at", None) else None,
        "updated_at": p.updated_at.isoformat() if getattr(p, "updated_at", None) else None,
    }


def _notification_payload(n: Notification) -> dict:
    return {
        "id": n.id,
        "project_id": n.project_id,
        "alert_id": n.alert_id,
        "notification_type": n.notification_type,
        "title": n.title,
        "summary": n.summary,
        "severity": n.severity,
        "read": n.read_at is not None,
        "read_at": n.read_at.isoformat() if n.read_at else None,
        "created_at": n.created_at.isoformat() if n.created_at else None,
    }


def _delivery_payload(d: NotificationDelivery) -> dict:
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
        "sent_at": d.sent_at.isoformat() if d.sent_at else None,
        "created_at": d.created_at.isoformat() if d.created_at else None,
    }


@router.get("/projects/{project_id}/notification-policies")
def get_notification_policy(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    policy = db.query(NotificationPolicy).filter(NotificationPolicy.project_id == project_id).first()
    if policy is None:
        return _policy_payload(type("DefaultPolicy", (), default_policy_values())(), project_id)
    return _policy_payload(policy, project_id)


@router.put("/projects/{project_id}/notification-policies")
def put_notification_policy(
    project_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_policy_manage(project_id, db, current_user)
    try:
        fields = validate_policy_payload(payload or {})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # Explicit recipients must be validated project members (tenant-safe).
    if "explicit_user_ids" in fields and fields["explicit_user_ids"]:
        from app.services.notifications import _active_org_user, _has_project_access

        proj = db.query(Project).filter(Project.id == project_id).first()
        if proj is None:
            raise HTTPException(status_code=404, detail="Project not found")
        valid = []
        for uid in fields["explicit_user_ids"][:MAX_EXPLICIT_USERS]:
            candidate = _active_org_user(db, uid, proj.organization_id)
            if candidate is None or not _has_project_access(db, candidate.id, project_id, proj.organization_id):
                raise HTTPException(status_code=400, detail="Explicit recipient must be an active project member")
            valid.append(candidate.id)
        fields["explicit_user_ids"] = valid
    policy = db.query(NotificationPolicy).filter(NotificationPolicy.project_id == project_id).first()
    created = policy is None
    if created:
        policy = NotificationPolicy(project_id=project_id, created_by=current_user.id)
        db.add(policy)
    for key, value in fields.items():
        setattr(policy, key, value)
    policy.updated_by = current_user.id
    try:
        proj = db.query(Project).filter(Project.id == project_id).first()
        org_id = proj.organization_id if proj else current_user.organization_id
        AuditService.record(
            db,
            event_type=EVENT_NOTIFICATION_POLICY_CREATED if created else EVENT_NOTIFICATION_POLICY_UPDATED,
            action=EVENT_NOTIFICATION_POLICY_CREATED if created else EVENT_NOTIFICATION_POLICY_UPDATED,
            result=RESULT_SUCCESS, actor_user_id=current_user.id,
            organization_id=org_id, project_id=project_id,
            resource_type=RESOURCE_NOTIFICATION_POLICY, resource_id=project_id,
            metadata={"channel": getattr(policy, "channel", None), "recipient_mode": getattr(policy, "recipient_mode", None)},
        )
        db.commit()
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=f"Policy update failed: {str(exc)[:200]}")
    db.refresh(policy)
    return _policy_payload(policy, project_id)


@router.get("/projects/{project_id}/notifications")
def list_notifications(
    project_id: str,
    unread: bool | None = Query(default=None),
    notification_type: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    alert_id: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    # Users see their own inbox; project admins may filter by user.
    if user_id and user_id.strip() != current_user.id and not _is_project_admin(project_id, db, current_user):
        raise HTTPException(status_code=403, detail="Insufficient permissions to view other users' notifications")
    owner = user_id.strip() if user_id else current_user.id
    q = db.query(Notification).filter(Notification.project_id == project_id, Notification.user_id == owner)
    if unread is True:
        q = q.filter(Notification.read_at.is_(None))
    elif unread is False:
        q = q.filter(Notification.read_at.is_not(None))
    if notification_type:
        q = q.filter(Notification.notification_type == notification_type.strip().upper()[:50])
    if severity:
        q = q.filter(Notification.severity == severity.strip().lower()[:20])
    if alert_id:
        q = q.filter(Notification.alert_id == alert_id.strip())
    rows = q.order_by(Notification.created_at.desc()).offset(offset).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    unread_count = (
        db.query(Notification)
        .filter(Notification.project_id == project_id, Notification.user_id == owner, Notification.read_at.is_(None))
        .count()
    )
    return {"items": [_notification_payload(n) for n in rows], "total": len(rows), "unread_count": unread_count, "limit": limit, "offset": offset, "has_more": has_more}


@router.post("/projects/{project_id}/notifications/{notification_id}/read")
def mark_notification_read(
    project_id: str,
    notification_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    note = db.query(Notification).filter(Notification.id == notification_id, Notification.project_id == project_id).first()
    if note is None:
        raise HTTPException(status_code=404, detail="Notification not found")
    if note.user_id != current_user.id and not _is_project_admin(project_id, db, current_user):
        raise HTTPException(status_code=404, detail="Notification not found")
    if note.read_at is None:
        note.read_at = _utcnow().replace(tzinfo=None)
        db.commit()
        db.refresh(note)
    return _notification_payload(note)


@router.get("/projects/{project_id}/notification-deliveries")
def list_deliveries(
    project_id: str,
    status: str | None = Query(default=None),
    channel: str | None = Query(default=None),
    notification_type: str | None = Query(default=None),
    alert_id: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.services.notifications import DELIVERY_RESULTS, NOTIFICATION_CHANNELS, NOTIFICATION_STATUSES

    require_project_access(project_id, db, current_user)
    q = db.query(NotificationDelivery).filter(NotificationDelivery.project_id == project_id)
    if status:
        s = status.strip().lower()
        if s not in NOTIFICATION_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status filter")
        q = q.filter(NotificationDelivery.status == s)
    if channel:
        c = channel.strip().lower()
        if c not in NOTIFICATION_CHANNELS:
            raise HTTPException(status_code=400, detail="Invalid channel filter")
        q = q.filter(NotificationDelivery.channel == c)
    if notification_type:
        q = q.filter(NotificationDelivery.notification_type == notification_type.strip().upper()[:50])
    if alert_id:
        q = q.filter(NotificationDelivery.alert_id == alert_id.strip())
    rows = q.order_by(NotificationDelivery.created_at.desc()).offset(offset).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    return {"items": [_delivery_payload(d) for d in rows], "total": len(rows), "limit": limit, "offset": offset, "has_more": has_more}


@router.post("/projects/{project_id}/alerts/{alert_id}/notify", status_code=201)
def notify_alert(
    project_id: str,
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Explicitly evaluate one alert (idempotent; duplicate calls reuse deliveries)."""
    from app.services.notifications import evaluate_alert_notifications

    require_project_access(project_id, db, current_user)
    _require_notify(project_id, db, current_user)
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None or alert.project_id != project_id:
        raise HTTPException(status_code=404, detail="Alert not found in this project")
    project = db.query(Project).filter(Project.id == project_id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    items = evaluate_alert_notifications(db, alert, project, actor_user_id=current_user.id)
    return {"items": items, "total": len(items)}


@router.post("/projects/{project_id}/notification-deliveries/{delivery_id}/cancel")
def cancel_delivery(
    project_id: str,
    delivery_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_policy_manage(project_id, db, current_user)
    delivery = (
        db.query(NotificationDelivery)
        .filter(NotificationDelivery.id == delivery_id, NotificationDelivery.project_id == project_id)
        .first()
    )
    if delivery is None:
        raise HTTPException(status_code=404, detail="Delivery not found")
    if delivery.status not in ("pending", "sending"):
        raise HTTPException(status_code=400, detail=f"Delivery already {delivery.status}")
    delivery.status = "cancelled"
    AuditService.record(
        db, event_type=EVENT_NOTIFICATION_CANCELLED, action=EVENT_NOTIFICATION_CANCELLED,
        result=RESULT_SUCCESS, actor_user_id=current_user.id,
        organization_id=delivery.organization_id, project_id=project_id,
        resource_type=RESOURCE_NOTIFICATION_DELIVERY, resource_id=delivery.id,
        metadata={"alert_id": delivery.alert_id, "channel": delivery.channel},
    )
    db.commit()
    db.refresh(delivery)
    return _delivery_payload(delivery)




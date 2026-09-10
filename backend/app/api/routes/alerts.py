"""Project-scoped alert APIs (D3): list/detail/acknowledge/resolve + policy.

All ownership is derived server-side: the path project is resolved via
``require_project_access`` and every alert/policy row is verified against
it (unknown/cross-project IDs return 404, never cross-tenant data).
Read is any project member; acknowledge/resolve require analyst or above;
policy management requires project_admin/org_admin/super_admin.
Lifecycle actions are audited; automatic alert creation is not (alerts
are the operational record).
"""

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
from app.models.alert import Alert, AlertPolicy
from app.models.project import Project
from app.models.user import User
from app.services.audit import (
    EVENT_ALERT_ACKNOWLEDGED,
    EVENT_ALERT_POLICY_UPDATED,
    EVENT_ALERT_RESOLVED,
    RESOURCE_ALERT,
    RESOURCE_ALERT_POLICY,
    RESULT_SUCCESS,
    AuditService,
)

router = APIRouter(prefix="/api/v1", tags=["Alerts"])


def _utcnow():
    return datetime.now(timezone.utc)


def _require_alert_manage(project_id: str, db: Session, current_user: User) -> None:
    """Acknowledge/resolve: analyst, project_admin, org_admin, super_admin."""
    if _is_super_admin(current_user):
        return
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj:
        org_role = _effective_org_role(current_user, proj.organization_id, db)
        if org_role == "org_admin":
            return
    role = _effective_project_role(current_user, project_id, db)
    if role not in ("analyst", "project_admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires analyst to manage alerts")


def _require_policy_manage(project_id: str, db: Session, current_user: User) -> None:
    """Policy management: project_admin, org_admin, super_admin."""
    if _is_super_admin(current_user):
        return
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj:
        org_role = _effective_org_role(current_user, proj.organization_id, db)
        if org_role == "org_admin":
            return
    role = _effective_project_role(current_user, project_id, db)
    if role != "project_admin":
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires project_admin to manage alert policy")


def _parse_dt(value: str | None, field: str):
    if value is None:
        return None
    try:
        s = value.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid {field}")


def _alert_payload(a: Alert) -> dict:
    return {
        "id": a.id,
        "organization_id": a.organization_id,
        "project_id": a.project_id,
        "monitoring_config_id": a.monitoring_config_id,
        "alert_type": a.alert_type,
        "severity": a.severity,
        "status": a.status,
        "title": a.title,
        "description": a.description,
        "source_change_event_id": a.source_change_event_id,
        "source_finding_id": a.source_finding_id,
        "source_asset_id": a.source_asset_id,
        "finding_fingerprint": a.finding_fingerprint,
        "asset_key": a.asset_key,
        "monitoring_run_id": a.monitoring_run_id,
        "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
        "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        "acknowledged_at": a.acknowledged_at.isoformat() if a.acknowledged_at else None,
        "acknowledged_by": a.acknowledged_by,
        "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
        "resolved_by": a.resolved_by,
        "event_count": a.event_count,
        "extra_data": a.extra_data or {},
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


def _policy_payload(p: AlertPolicy) -> dict:
    return {
        "project_id": p.project_id,
        "enabled": bool(p.enabled),
        "min_severity": p.min_severity,
        "alert_critical_findings": bool(p.alert_critical_findings),
        "alert_high_findings": bool(p.alert_high_findings),
        "alert_reopened": bool(p.alert_reopened),
        "alert_asset_exposure": bool(p.alert_asset_exposure),
        "alert_relationships": bool(p.alert_relationships),
        "alert_metadata_changes": bool(p.alert_metadata_changes),
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


def _default_policy_payload(project_id: str) -> dict:
    return {
        "project_id": project_id,
        "enabled": True,
        "min_severity": "high",
        "alert_critical_findings": True,
        "alert_high_findings": True,
        "alert_reopened": True,
        "alert_asset_exposure": True,
        "alert_relationships": False,
        "alert_metadata_changes": False,
        "created_at": None,
        "updated_at": None,
    }


def _get_alert_or_404(project_id: str, alert_id: str, db: Session) -> Alert:
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert or alert.project_id != project_id:
        raise HTTPException(status_code=404, detail="Alert not found in this project")
    return alert


@router.get("/projects/{project_id}/alerts")
def list_alerts(
    project_id: str,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    alert_type: str | None = Query(default=None),
    monitoring_run_id: str | None = Query(default=None),
    asset_id: str | None = Query(default=None),
    finding_id: str | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    q = db.query(Alert).filter(Alert.project_id == project_id)
    if status:
        q = q.filter(Alert.status == str(status).strip().lower()[:20])
    if severity:
        q = q.filter(Alert.severity == str(severity).strip().lower()[:20])
    if alert_type:
        q = q.filter(Alert.alert_type == str(alert_type).strip().upper()[:50])
    if monitoring_run_id:
        q = q.filter(Alert.monitoring_run_id == str(monitoring_run_id).strip()[:36])
    if asset_id:
        q = q.filter(Alert.source_asset_id == str(asset_id).strip()[:36])
    if finding_id:
        q = q.filter(Alert.source_finding_id == str(finding_id).strip()[:36])
    if since:
        q = q.filter(Alert.last_seen_at >= _parse_dt(since, "since"))
    if until:
        q = q.filter(Alert.last_seen_at <= _parse_dt(until, "until"))
    q = q.order_by(Alert.last_seen_at.desc())
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    rows = q.offset((page - 1) * page_size).limit(page_size).all()
    # D9: lazy notification evaluation for the returned page only (bounded,
    # idempotent; D3 alert semantics untouched).
    try:
        from app.models.project import Project as _Project
        from app.services.notifications import evaluate_alert_notifications as _evaluate

        _project = db.query(_Project).filter(_Project.id == project_id).first()
        if _project is not None:
            for _alert in rows:
                try:
                    _evaluate(db, _alert, _project, actor_user_id=current_user.id, project_name=_project.name)
                except Exception:
                    try:
                        db.rollback()
                    except Exception:
                        pass
    except Exception:
        pass
    return {"items": [_alert_payload(r) for r in rows], "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}


@router.get("/projects/{project_id}/alerts/{alert_id}")
def get_alert(
    project_id: str,
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    alert = _get_alert_or_404(project_id, alert_id, db)
    try:
        from app.models.project import Project as _Project
        from app.services.notifications import evaluate_alert_notifications as _evaluate

        _project = db.query(_Project).filter(_Project.id == project_id).first()
        if _project is not None:
            try:
                _evaluate(db, alert, _project, actor_user_id=current_user.id, project_name=_project.name)
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
    except Exception:
        pass
    return _alert_payload(alert)


@router.post("/projects/{project_id}/alerts/{alert_id}/acknowledge", status_code=200)
def acknowledge_alert(
    project_id: str,
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_alert_manage(project_id, db, current_user)
    alert = _get_alert_or_404(project_id, alert_id, db)
    if alert.status == "open":
        alert.status = "acknowledged"
        alert.acknowledged_at = _utcnow().replace(tzinfo=None)
        alert.acknowledged_by = current_user.id
        AuditService.record(db, event_type=EVENT_ALERT_ACKNOWLEDGED, action=EVENT_ALERT_ACKNOWLEDGED,
                            result=RESULT_SUCCESS, actor_user_id=current_user.id,
                            organization_id=alert.organization_id, project_id=project_id,
                            resource_type=RESOURCE_ALERT, resource_id=alert.id,
                            metadata={"alert_type": alert.alert_type, "severity": alert.severity})
    db.commit()
    db.refresh(alert)
    return _alert_payload(alert)


@router.post("/projects/{project_id}/alerts/{alert_id}/resolve", status_code=200)
def resolve_alert(
    project_id: str,
    alert_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_alert_manage(project_id, db, current_user)
    alert = _get_alert_or_404(project_id, alert_id, db)
    if alert.status in ("open", "acknowledged"):
        alert.status = "resolved"
        alert.resolved_at = _utcnow().replace(tzinfo=None)
        alert.resolved_by = current_user.id
        AuditService.record(db, event_type=EVENT_ALERT_RESOLVED, action=EVENT_ALERT_RESOLVED,
                            result=RESULT_SUCCESS, actor_user_id=current_user.id,
                            organization_id=alert.organization_id, project_id=project_id,
                            resource_type=RESOURCE_ALERT, resource_id=alert.id,
                            metadata={"alert_type": alert.alert_type, "severity": alert.severity})
    db.commit()
    db.refresh(alert)
    return _alert_payload(alert)


@router.get("/projects/{project_id}/alert-policy")
def get_alert_policy(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    policy = db.query(AlertPolicy).filter(AlertPolicy.project_id == project_id).first()
    if not policy:
        return _default_policy_payload(project_id)
    return _policy_payload(policy)


_ALLOWED_POLICY_KEYS = {
    "enabled", "min_severity", "alert_critical_findings", "alert_high_findings",
    "alert_reopened", "alert_asset_exposure", "alert_relationships", "alert_metadata_changes",
}
_ALLOWED_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@router.put("/projects/{project_id}/alert-policy")
def update_alert_policy(
    project_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_policy_manage(project_id, db, current_user)
    data = payload if isinstance(payload, dict) else {}
    policy = db.query(AlertPolicy).filter(AlertPolicy.project_id == project_id).first()
    if not policy:
        policy = AlertPolicy(project_id=project_id)
        db.add(policy)
        db.flush()
    changed: dict = {}
    for key in _ALLOWED_POLICY_KEYS:
        if key not in data or data[key] is None:
            continue
        if key == "min_severity":
            val = str(data[key]).strip().lower()[:20]
            if val not in _ALLOWED_SEVERITIES:
                raise HTTPException(status_code=400, detail="Invalid min_severity")
            if policy.min_severity != val:
                policy.min_severity = val
                changed[key] = val
        else:
            val = bool(data[key])
            if bool(getattr(policy, key)) != val:
                setattr(policy, key, val)
                changed[key] = val
    policy.updated_at = _utcnow().replace(tzinfo=None)
    if changed:
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type=EVENT_ALERT_POLICY_UPDATED, action=EVENT_ALERT_POLICY_UPDATED,
                            result=RESULT_SUCCESS, actor_user_id=current_user.id,
                            organization_id=proj.organization_id if proj else None,
                            project_id=project_id, resource_type=RESOURCE_ALERT_POLICY,
                            resource_id=project_id, metadata={"changed": sorted(changed.keys())})
    db.commit()
    db.refresh(policy)
    return _policy_payload(policy)

"""Project-scoped enterprise audit APIs (D10): search, detail, export, verify.

Complements the global read API (`audit_logs.py`, organization-scoped): these
endpoints are project-scoped, support integrity status, bounded export, and
bounded chain verification. Audit records are append-only (no update/delete).
Export and verification are themselves audited; plain list/detail reads are
not (noise/recursion).
"""

import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import (
    _effective_org_role,
    _effective_project_role,
    _is_super_admin,
    get_current_user,
    require_project_access,
)
from app.core.permissions import ORG_ROLE_PERMISSIONS
from app.db.database import get_db
from app.models.audit_log import AuditLog
from app.models.project import Project
from app.models.user import User
from app.services.audit import (
    EVENT_AUDIT_EXPORTED,
    EVENT_AUDIT_INTEGRITY_VERIFIED,
    RESOURCE_AUDIT,
    RESULT_SUCCESS,
    AuditService,
    verify_audit_chain,
    verify_record_integrity,
)

router = APIRouter(prefix="/api/v1", tags=["Project Audit"])

EXPORT_MAX_ROWS = 5000
EXPORT_DEFAULT_DAYS = 7
EXPORT_MAX_DAYS = 90
VERIFY_DEFAULT_LIMIT = 200
VERIFY_MAX_LIMIT = 1000


def _utcnow():
    return datetime.now(timezone.utc)


def _require_audit_read(db: Session, current_user: User):
    if _is_super_admin(current_user):
        return
    role = _effective_org_role(current_user, current_user.organization_id, db)
    perms = ORG_ROLE_PERMISSIONS.get(role or "", set())
    if "audit.read" not in perms:
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires audit.read")


def _require_audit_manage(project_id: str, db: Session, current_user: User):
    """Export/verify: project_admin, org_admin, super_admin (sensitive ops)."""
    if _is_super_admin(current_user):
        return
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj and _effective_org_role(current_user, proj.organization_id, db) == "org_admin":
        return
    if _effective_project_role(current_user, project_id, db) != "project_admin":
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires project_admin for audit export/verification")


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


def _apply_filters(q, project_id: str, event_type=None, action=None, result=None,
                   resource_type=None, resource_id=None, actor_user_id=None,
                   correlation_id=None, since=None, until=None):
    q = q.filter(AuditLog.project_id == project_id)
    if event_type:
        q = q.filter(AuditLog.event_type == str(event_type).strip()[:100])
    if action:
        q = q.filter(AuditLog.action == str(action).strip()[:100])
    if result:
        r = str(result).strip().upper()
        if r not in ("SUCCESS", "FAILURE", "DENIED", "PARTIAL"):
            raise HTTPException(status_code=400, detail="Invalid result")
        q = q.filter(AuditLog.result == r)
    if resource_type:
        q = q.filter(AuditLog.resource_type == str(resource_type).strip()[:100])
    if resource_id:
        q = q.filter(AuditLog.resource_id == str(resource_id).strip()[:100])
    if actor_user_id:
        q = q.filter(AuditLog.actor_user_id == str(actor_user_id).strip()[:36])
    if correlation_id:
        q = q.filter(AuditLog.correlation_id == str(correlation_id).strip()[:100])
    since_dt = _parse_dt(since, "since") if since else None
    until_dt = _parse_dt(until, "until") if until else None
    if since_dt:
        q = q.filter(AuditLog.created_at >= (since_dt.replace(tzinfo=None) if since_dt.tzinfo else since_dt))
    if until_dt:
        q = q.filter(AuditLog.created_at <= (until_dt.replace(tzinfo=None) if until_dt.tzinfo else until_dt))
    return q


def _item_payload(r: AuditLog, integrity: str | None = None) -> dict:
    item = {
        "id": r.id,
        "organization_id": r.organization_id,
        "project_id": r.project_id,
        "actor_user_id": r.actor_user_id,
        "target_user_id": r.target_user_id,
        "event_type": r.event_type,
        "action": r.action,
        "result": r.result,
        "resource_type": r.resource_type,
        "resource_id": r.resource_id,
        "request_id": r.request_id,
        "correlation_id": r.correlation_id,
        "ip_address": r.ip_address,
        "user_agent": r.user_agent,
        "metadata": r.extra_data,
        "prev_hash": getattr(r, "prev_hash", None),
        "event_hash": getattr(r, "event_hash", None),
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }
    if integrity is not None:
        item["integrity"] = integrity
    return item


@router.get("/projects/{project_id}/audit")
def list_project_audit(
    project_id: str,
    event_type: str | None = Query(default=None, max_length=100),
    action: str | None = Query(default=None, max_length=100),
    result: str | None = Query(default=None, max_length=20),
    resource_type: str | None = Query(default=None, max_length=100),
    resource_id: str | None = Query(default=None, max_length=100),
    actor_user_id: str | None = Query(default=None, max_length=36),
    correlation_id: str | None = Query(default=None, max_length=100),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_audit_read(db, current_user)
    q = _apply_filters(
        db.query(AuditLog), project_id, event_type, action, result,
        resource_type, resource_id, actor_user_id, correlation_id, since, until,
    )
    rows = q.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    return {"items": [_item_payload(r) for r in rows], "total": len(rows), "limit": limit, "offset": offset, "has_more": has_more}


@router.get("/projects/{project_id}/audit/export")
def export_project_audit(
    project_id: str,
    format: str = Query(default="json", max_length=10),
    event_type: str | None = Query(default=None, max_length=100),
    result: str | None = Query(default=None, max_length=20),
    actor_user_id: str | None = Query(default=None, max_length=36),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_audit_manage(project_id, db, current_user)
    fmt = (format or "json").strip().lower()
    if fmt not in ("json", "csv"):
        raise HTTPException(status_code=400, detail="Invalid format. Use json or csv.")
    now = _utcnow().replace(tzinfo=None)
    until_dt = _parse_dt(until, "until") if until else now
    if until_dt.tzinfo:
        until_dt = until_dt.replace(tzinfo=None)
    since_dt = _parse_dt(since, "since") if since else (until_dt - timedelta(days=EXPORT_DEFAULT_DAYS))
    if since_dt.tzinfo:
        since_dt = since_dt.replace(tzinfo=None)
    if (until_dt - since_dt).total_seconds() < 0:
        raise HTTPException(status_code=400, detail="Invalid date range")
    if (until_dt - since_dt).days > EXPORT_MAX_DAYS:
        raise HTTPException(status_code=400, detail=f"Date range exceeds {EXPORT_MAX_DAYS} days")
    q = _apply_filters(db.query(AuditLog), project_id, event_type, None, result, None, None, actor_user_id, None, None, None)
    q = q.filter(AuditLog.created_at >= since_dt, AuditLog.created_at <= until_dt)
    rows = q.order_by(AuditLog.created_at.desc()).limit(EXPORT_MAX_ROWS + 1).all()
    truncated = len(rows) > EXPORT_MAX_ROWS
    rows = rows[:EXPORT_MAX_ROWS]
    proj = db.query(Project).filter(Project.id == project_id).first()
    AuditService.record(
        db, event_type=EVENT_AUDIT_EXPORTED, action=EVENT_AUDIT_EXPORTED, result=RESULT_SUCCESS,
        actor_user_id=current_user.id, organization_id=proj.organization_id if proj else current_user.organization_id,
        project_id=project_id, resource_type=RESOURCE_AUDIT, resource_id=project_id,
        metadata={"format": fmt, "rows": len(rows), "truncated": truncated},
    )
    db.commit()
    stamp = _utcnow().strftime("%Y%m%dT%H%M%SZ")
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "created_at", "organization_id", "project_id", "actor_user_id",
                         "event_type", "action", "resource_type", "resource_id", "result",
                         "request_id", "correlation_id", "prev_hash", "event_hash"])
        for r in rows:
            writer.writerow([r.id, r.created_at.isoformat() if r.created_at else "", r.organization_id or "",
                             r.project_id or "", r.actor_user_id or "", r.event_type, r.action,
                             r.resource_type or "", r.resource_id or "", r.result, r.request_id or "",
                             r.correlation_id or "", getattr(r, "prev_hash", "") or "", getattr(r, "event_hash", "") or ""])
        return Response(
            content=buf.getvalue(), media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename=audit-{project_id}-{stamp}.csv"},
        )
    payload = [_item_payload(r) for r in rows]
    import json as _json

    return Response(
        content=_json.dumps({"project_id": project_id, "exported_at": stamp, "truncated": truncated, "items": payload}),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=audit-{project_id}-{stamp}.json"},
    )


@router.post("/projects/{project_id}/audit/verify-integrity")
def verify_project_audit(
    project_id: str,
    payload: dict | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_audit_manage(project_id, db, current_user)
    data = payload or {}
    try:
        limit = int(data.get("limit", VERIFY_DEFAULT_LIMIT))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid limit")
    limit = max(1, min(limit, VERIFY_MAX_LIMIT))
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj is None:
        raise HTTPException(status_code=404, detail="Project not found")
    result = verify_audit_chain(db, proj.organization_id, limit=limit)
    AuditService.record(
        db, event_type=EVENT_AUDIT_INTEGRITY_VERIFIED, action=EVENT_AUDIT_INTEGRITY_VERIFIED, result=RESULT_SUCCESS,
        actor_user_id=current_user.id, organization_id=proj.organization_id, project_id=project_id,
        resource_type=RESOURCE_AUDIT, resource_id=project_id,
        metadata={"checked": result["checked"], "valid": result["valid"], "failures": result["failure_count"]},
    )
    db.commit()
    return result


# NOTE: defined last so literal sub-paths (/export, /verify-integrity) match
# their own routes instead of this parameterized one.
@router.get("/projects/{project_id}/audit/{audit_id}")
def get_project_audit(
    project_id: str,
    audit_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_audit_read(db, current_user)
    row = db.query(AuditLog).filter(AuditLog.id == audit_id, AuditLog.project_id == project_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Audit record not found")
    return _item_payload(row, integrity=verify_record_integrity(db, row))

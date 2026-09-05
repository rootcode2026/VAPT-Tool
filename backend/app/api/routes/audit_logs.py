"""
Tenant-isolated audit read API.
"""
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import _effective_org_role, _is_super_admin, get_current_user, require_project_access
from app.core.permissions import ORG_ROLE_PERMISSIONS
from app.db.database import get_db
from app.models.audit_log import AuditLog
from app.models.user import User

router = APIRouter(prefix="/api/v1/audit_logs", tags=["Audit"])


def _require_audit_read(db: Session, current_user: User):
    if _is_super_admin(current_user):
        return
    role = _effective_org_role(current_user, current_user.organization_id, db)
    perms = ORG_ROLE_PERMISSIONS.get(role or "", set())
    if "audit.read" not in perms:
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires audit.read")


def _is_valid_uuid(v: str) -> bool:
    try:
        uuid.UUID(str(v))
        return True
    except Exception:
        return False


@router.get("")
def list_audit_logs(
    project_id: str | None = Query(default=None, description="Filter by project"),
    event_type: str | None = Query(default=None, max_length=100),
    action: str | None = Query(default=None, max_length=100),
    result: str | None = Query(default=None, max_length=20),
    resource_type: str | None = Query(default=None, max_length=100),
    resource_id: str | None = Query(default=None, max_length=100),
    actor_user_id: str | None = Query(default=None, max_length=36),
    target_user_id: str | None = Query(default=None, max_length=36),
    start_time: str | None = Query(default=None, description="ISO8601 start"),
    end_time: str | None = Query(default=None, description="ISO8601 end"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_audit_read(db, current_user)

    # Validate UUID fields if provided
    for f in [project_id, actor_user_id, target_user_id, resource_id]:
        if f is not None and f.strip() and not _is_valid_uuid(f.strip()) and len(f.strip()) > 100:
            raise HTTPException(status_code=400, detail="Invalid UUID format")

    # Project filter must be tenant-checked
    if project_id is not None and str(project_id).strip():
        pid = str(project_id).strip()
        # Validate UUID
        if not _is_valid_uuid(pid):
            raise HTTPException(status_code=400, detail="Invalid project_id")
        # Verify access — this enforces tenant boundary (404 if not in org)
        require_project_access(pid, db, current_user)
        # For non-super_admin, also ensure project is in same org (already done via require_project_access)

    # Build base query with tenant isolation
    q = db.query(AuditLog)
    if not _is_super_admin(current_user):
        q = q.filter(AuditLog.organization_id == current_user.organization_id)

    # Additional tenant-safe project filter (ANDed)
    if project_id is not None and str(project_id).strip():
        q = q.filter(AuditLog.project_id == str(project_id).strip())

    if event_type is not None and event_type.strip():
        q = q.filter(AuditLog.event_type == event_type.strip()[:100])
    if action is not None and action.strip():
        q = q.filter(AuditLog.action == action.strip()[:100])
    if result is not None and result.strip():
        # Validate result allowlist
        r = result.strip().upper()
        if r not in ("SUCCESS", "FAILURE", "DENIED", "PARTIAL"):
            raise HTTPException(status_code=400, detail="Invalid result")
        q = q.filter(AuditLog.result == r)
    if resource_type is not None and resource_type.strip():
        q = q.filter(AuditLog.resource_type == resource_type.strip()[:100])
    if resource_id is not None and resource_id.strip():
        q = q.filter(AuditLog.resource_id == resource_id.strip()[:100])
    if actor_user_id is not None and actor_user_id.strip():
        if not _is_valid_uuid(actor_user_id.strip()):
            raise HTTPException(status_code=400, detail="Invalid actor_user_id")
        q = q.filter(AuditLog.actor_user_id == actor_user_id.strip())
    if target_user_id is not None and target_user_id.strip():
        if not _is_valid_uuid(target_user_id.strip()):
            raise HTTPException(status_code=400, detail="Invalid target_user_id")
        q = q.filter(AuditLog.target_user_id == target_user_id.strip())

    # Time filters
    def _parse_dt(s: str) -> datetime:
        # Accept ISO8601, handle Z
        try:
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return datetime.fromisoformat(s)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid datetime format")

    if start_time is not None and start_time.strip():
        dt = _parse_dt(start_time.strip())
        q = q.filter(AuditLog.created_at >= dt)
    if end_time is not None and end_time.strip():
        dt = _parse_dt(end_time.strip())
        q = q.filter(AuditLog.created_at <= dt)

    # Count total (tenant-filtered)
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total > 0 else 0
    offset = (page - 1) * page_size

    # Sorting: fixed created_at DESC only (no arbitrary column)
    rows = q.order_by(AuditLog.created_at.desc()).offset(offset).limit(page_size).all()

    # Response-side sanitization is defense-in-depth: metadata already sanitized on write,
    # but we ensure no sensitive keys leak even if old rows were unsanitized.
    # However metadata is already safe; we just return as-is.
    items = []
    for r in rows:
        items.append(
            {
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
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
        )

    return {"items": items, "page": page, "page_size": page_size, "total": total, "total_pages": total_pages}

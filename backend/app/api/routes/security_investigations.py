"""E13 Security Investigation API — project-scoped, bounded."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.services.security_investigation import (
    create_investigation,
    list_investigations,
    get_investigation_detail,
    update_investigation,
    add_note,
    get_timeline,
    get_summary,
)

router = APIRouter(prefix="/api/v1/projects/{project_id}/security/investigations", tags=["Security Investigations"])


def _set_rls(db: Session, project_id: str, user: User):
    try:
        from app.db.rls import set_tenant_context
        org_id = getattr(user, "organization_id", None)
        if org_id and str(org_id).strip():
            if db.in_transaction():
                set_tenant_context(db, organization_id=str(org_id), project_id=str(project_id), user_id=str(user.id))
    except Exception:
        pass

def _require_analyst(project_id: str, db: Session, user: User):
    # Use effective project role
    from app.api.deps import _effective_project_role, _is_super_admin
    if _is_super_admin(user):
        return
    role = _effective_project_role(user, project_id, db)
    if role not in ("analyst", "project_admin"):
        # Fallback: if viewer, deny
        raise HTTPException(status_code=403, detail="Analyst or project_admin required")

class CreateInvestigationsRequest(BaseModel):
    subject_type: str
    subject_id: str

class UpdateInvestigationRequest(BaseModel):
    status: str | None = None
    assigned_to: str | None = None

class AddNoteRequest(BaseModel):
    content: str


@router.get("")
def list_investigations_endpoint(
    project_id: str,
    status: str | None = Query(None, max_length=20),
    priority: str | None = Query(None, max_length=20),
    subject_type: str | None = Query(None, max_length=30),
    assigned_to: str | None = Query(None, max_length=36),
    severity: str | None = Query(None, max_length=20),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    try:
        rows = list_investigations(project_id, db, status=status, priority=priority, subject_type=subject_type, assigned_to=assigned_to, severity=severity, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"project_id": project_id, "count": len(rows), "investigations": [
        {
            "id": r.id,
            "project_id": r.project_id,
            "subject_type": r.subject_type,
            "subject_id": r.subject_id,
            "status": r.status,
            "title": r.title,
            "priority": r.priority,
            "severity": r.severity,
            "assigned_to": r.assigned_to,
            "created_by": r.created_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        } for r in rows
    ]}


@router.get("/summary")
def investigations_summary(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    return get_summary(project_id, db)


@router.get("/{investigation_id}")
def get_investigation(
    project_id: str,
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    detail = get_investigation_detail(project_id, db, investigation_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return detail


@router.post("")
def create_investigation_endpoint(
    project_id: str,
    body: CreateInvestigationsRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_analyst(project_id, db, current_user)
    try:
        inv = create_investigation(project_id, db, body.subject_type, body.subject_id, created_by=current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "id": inv.id,
        "project_id": inv.project_id,
        "subject_type": inv.subject_type,
        "subject_id": inv.subject_id,
        "status": inv.status,
        "title": inv.title,
        "priority": inv.priority,
        "severity": inv.severity,
        "assigned_to": inv.assigned_to,
        "created_by": inv.created_by,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
    }


@router.patch("/{investigation_id}")
def update_investigation_endpoint(
    project_id: str,
    investigation_id: str,
    body: UpdateInvestigationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_analyst(project_id, db, current_user)
    if body.status is None and body.assigned_to is None:
        raise HTTPException(status_code=400, detail="Nothing to update")
    try:
        inv = update_investigation(project_id, db, investigation_id, status=body.status, assigned_to=body.assigned_to, actor_id=current_user.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {
        "id": inv.id,
        "status": inv.status,
        "assigned_to": inv.assigned_to,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
    }


@router.post("/{investigation_id}/notes")
def add_note_endpoint(
    project_id: str,
    investigation_id: str,
    body: AddNoteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_analyst(project_id, db, current_user)
    try:
        note = add_note(project_id, db, investigation_id, author_id=current_user.id, content=body.content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"id": note.id, "investigation_id": note.investigation_id, "author_id": note.author_id, "content": note.content[:500], "created_at": note.created_at.isoformat() if note.created_at else None}


@router.get("/{investigation_id}/timeline")
def investigation_timeline(
    project_id: str,
    investigation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    # Verify investigation exists
    detail = get_investigation_detail(project_id, db, investigation_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Investigation not found")
    timeline = get_timeline(project_id, db, investigation_id)
    return {"project_id": project_id, "investigation_id": investigation_id, "count": len(timeline), "timeline": timeline}

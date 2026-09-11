"""E8 CSPM API — provider-neutral, project-scoped, read-only."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.services.cspm import evaluate_cspm, get_control_detail, list_controls

router = APIRouter(prefix="/api/v1/projects/{project_id}/cspm", tags=["CSPM"])


def _set_rls_context(db: Session, project_id: str, current_user: User):
    """Best-effort RLS: set transaction-local context if enabled (SQLite no-op)."""
    try:
        from app.db.rls import set_tenant_context

        # Use transaction if already in one; otherwise no-op via helper validation
        proj = require_project_access  # silence unused
        _ = proj
        # RLS requires organization_id; derive from user's org
        org_id = getattr(current_user, "organization_id", None)
        if org_id and str(org_id).strip():
            try:
                # Only set if inside transaction; otherwise skip (no pool leakage)
                if db.in_transaction():
                    set_tenant_context(db, organization_id=str(org_id), project_id=str(project_id), user_id=str(current_user.id))
            except Exception:
                pass
    except Exception:
        pass


@router.get("")
def get_cspm_summary(
    project_id: str,
    provider: str | None = Query(None, max_length=20),
    category: str | None = Query(None, max_length=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    proj = require_project_access(project_id, db, current_user)
    _set_rls_context(db, project_id, current_user)
    try:
        data = evaluate_cspm(project_id, db, provider_filter=provider, category_filter=category)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # Bounded response
    return {
        "project_id": project_id,
        "score": data["score"],
        "grade": data["grade"],
        "compliance_percent": data["compliance_percent"],
        "coverage_percent": data["coverage_percent"],
        "controls": data["controls"],
        "providers": data["providers"],
        "categories": data["categories"],
        "top_failures": data["top_failures"][:20],
        "evaluated": data["evaluated"],
    }


@router.get("/controls")
def list_cspm_controls(
    project_id: str,
    provider: str | None = Query(None, max_length=20),
    category: str | None = Query(None, max_length=20),
    status: str | None = Query(None, max_length=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    proj = require_project_access(project_id, db, current_user)
    _set_rls_context(db, project_id, current_user)
    try:
        controls = list_controls(project_id, db, provider=provider, category=category, status=status)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # Bounded
    return {"project_id": project_id, "count": len(controls), "controls": controls[:50]}


@router.get("/controls/{control_id}")
def get_cspm_control(
    project_id: str,
    control_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    proj = require_project_access(project_id, db, current_user)
    _set_rls_context(db, project_id, current_user)
    detail = get_control_detail(project_id, db, control_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Control not found")
    return detail

"""E11 Cloud Exposure Intelligence API — project-scoped, bounded."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.services.cloud_exposure_intelligence import (
    get_exposure_detail,
    get_exposure_intelligence,
    get_top_exposures,
)

router = APIRouter(prefix="/api/v1/projects/{project_id}/cloud-security/exposure-intelligence", tags=["Cloud Exposure"])


def _set_rls(db: Session, project_id: str, user: User):
    try:
        from app.db.rls import set_tenant_context
        org_id = getattr(user, "organization_id", None)
        if org_id and str(org_id).strip():
            if db.in_transaction():
                set_tenant_context(db, organization_id=str(org_id), project_id=str(project_id), user_id=str(user.id))
    except Exception:
        pass


@router.get("")
def exposure_intelligence(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    return get_exposure_intelligence(project_id, db)


@router.get("/top")
def top_exposures(
    project_id: str,
    provider: str | None = Query(None, max_length=20),
    severity: str | None = Query(None, max_length=20),
    exposure_type: str | None = Query(None, max_length=30),
    limit: int = Query(20, ge=1, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    try:
        top = get_top_exposures(project_id, db, provider=provider, severity=severity, exposure_type=exposure_type, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"project_id": project_id, "count": len(top), "top_exposures": top}


@router.get("/{exposure_id}")
def exposure_detail(
    project_id: str,
    exposure_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    detail = get_exposure_detail(project_id, db, exposure_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Exposure not found")
    return detail

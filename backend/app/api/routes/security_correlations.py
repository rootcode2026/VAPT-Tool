"""E12 Security Signal Correlation API — project-scoped, bounded, on-read."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.services.security_correlation import get_correlations, get_correlation_detail, get_correlation_summary

router = APIRouter(prefix="/api/v1/projects/{project_id}/security/correlations", tags=["Security Correlations"])


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
def list_correlations(
    project_id: str,
    type: str | None = Query(None, alias="type", max_length=30),
    confidence: str | None = Query(None, max_length=20),
    scanner: str | None = Query(None, max_length=30),
    asset_id: str | None = Query(None, max_length=36),
    finding_id: str | None = Query(None, max_length=36),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    try:
        groups = get_correlations(project_id, db, ctype=type, confidence=confidence, scanner=scanner, asset_id=asset_id, finding_id=finding_id, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"project_id": project_id, "count": len(groups), "correlations": groups}


@router.get("/summary")
def correlation_summary(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    return get_correlation_summary(project_id, db)


@router.get("/{correlation_id}")
def correlation_detail(
    project_id: str,
    correlation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    detail = get_correlation_detail(project_id, db, correlation_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Correlation not found")
    return detail

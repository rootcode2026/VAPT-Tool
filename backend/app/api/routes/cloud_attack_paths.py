"""E9 Cloud Attack Paths API — provider-neutral, project-scoped, read-only, bounded."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.services.cloud_attack_paths import (
    MAX_API_LIMIT,
    VALID_CONFIDENCES,
    VALID_PATH_TYPES,
    VALID_PROVIDERS,
    VALID_SEVERITIES,
    build_cloud_attack_paths,
    get_attack_path_detail,
)

router = APIRouter(prefix="/api/v1/projects/{project_id}/cloud-security/attack-paths", tags=["Cloud Attack Paths"])


def _set_rls_context(db: Session, project_id: str, current_user: User):
    try:
        from app.db.rls import set_tenant_context
        org_id = getattr(current_user, "organization_id", None)
        if org_id and str(org_id).strip():
            try:
                if db.in_transaction():
                    set_tenant_context(db, organization_id=str(org_id), project_id=str(project_id), user_id=str(current_user.id))
            except Exception:
                pass
    except Exception:
        pass


@router.get("")
def list_attack_paths(
    project_id: str,
    provider: str | None = Query(None, max_length=20),
    severity: str | None = Query(None, max_length=20),
    confidence: str | None = Query(None, max_length=20),
    path_type: str | None = Query(None, max_length=50),
    status: str | None = Query(None, max_length=20),
    limit: int = Query(50, ge=1, le=MAX_API_LIMIT),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls_context(db, project_id, current_user)
    # Validate filters
    if provider and provider.strip().lower() not in VALID_PROVIDERS:
        raise HTTPException(status_code=400, detail=f"Invalid provider: {provider}")
    if severity and severity.strip().lower() not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
    if confidence and confidence.strip().upper() not in VALID_CONFIDENCES:
        raise HTTPException(status_code=400, detail=f"Invalid confidence: {confidence}")
    if path_type and path_type.strip().upper() not in VALID_PATH_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid path_type: {path_type}")
    if status and status.strip().upper() not in ("ACTIVE", "RESOLVED"):
        raise HTTPException(status_code=400, detail=f"Invalid status: {status}")
    try:
        paths = build_cloud_attack_paths(
            project_id, db, limit=limit,
            provider_filter=provider.strip().lower() if provider else None,
            severity_filter=severity.strip().lower() if severity else None,
            confidence_filter=confidence.strip().upper() if confidence else None,
            path_type_filter=path_type.strip().upper() if path_type else None,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # status filter: all are ACTIVE on-read
    if status and status.strip().upper() == "RESOLVED":
        paths = []
    return {"project_id": project_id, "count": len(paths), "paths": paths[:limit]}


@router.get("/{path_id}")
def get_attack_path(
    project_id: str,
    path_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls_context(db, project_id, current_user)
    detail = get_attack_path_detail(project_id, db, path_id)
    if not detail:
        raise HTTPException(status_code=404, detail="Attack path not found")
    return detail

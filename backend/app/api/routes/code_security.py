"""Code Security API — project-scoped, integrates existing SAST/SCA/Secrets/Container/IaC/API scanners via FindingEngine/Assets."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.services.code_security import list_code_findings, list_code_targets, get_code_security_summary

router = APIRouter(prefix="/api/v1/projects/{project_id}/code-security", tags=["Code Security"])

@router.get("/summary")
def code_security_summary(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return get_code_security_summary(project_id, db)

@router.get("/findings")
def code_security_findings(
    project_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    scanner: str | None = Query(None, max_length=20),
    severity: str | None = Query(None, max_length=20),
    status: str | None = Query(None, max_length=30),
    search: str | None = Query(None, max_length=256),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return list_code_findings(project_id, db, page=page, page_size=page_size, scanner=scanner, severity=severity, status=status, search=search)

@router.get("/targets")
def code_security_targets(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return {"project_id": project_id, "targets": list_code_targets(project_id, db)}

@router.get("/assets")
def code_security_assets(
    project_id: str,
    asset_type: str | None = Query(None, max_length=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    from app.models.asset import Asset
    q = db.query(Asset).filter(Asset.project_id == project_id)
    if asset_type:
        q = q.filter(Asset.asset_type == asset_type.strip().lower())
    else:
        q = q.filter(Asset.asset_type.in_(["repository", "source_file", "package", "container_image", "iac_resource", "api_endpoint"]))
    rows = q.limit(100).all()
    return {"project_id": project_id, "count": len(rows), "assets": [{"id": a.id, "value": a.value, "asset_type": a.asset_type, "metadata": a.extra_data if isinstance(a.extra_data, dict) else {}} for a in rows]}

@router.get("/relationships")
def code_security_relationships(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    from app.services.code_security import get_asset_relationships
    return {"project_id": project_id, "relationships": get_asset_relationships(project_id, db)}

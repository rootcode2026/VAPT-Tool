"""Cloud Security API — project-scoped, provider-neutral, extends existing cloud foundation."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.services.cloud_security import (
    cross_domain_relationships,
    get_azure_summary,
    get_cloud_summary,
    get_gcp_summary,
    get_network_summary,
    get_storage_summary,
    list_cloud_accounts,
    list_cloud_checks,
    list_cloud_findings,
    list_cloud_resources,
    list_iam_identities,
)

router = APIRouter(prefix="/api/v1/projects/{project_id}/cloud-security", tags=["Cloud Security"])

@router.get("/summary")
def cloud_security_summary(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return get_cloud_summary(project_id, db)

@router.get("/accounts")
def cloud_security_accounts(
    project_id: str,
    provider: str | None = Query(None, max_length=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return {"project_id": project_id, "accounts": list_cloud_accounts(project_id, db, provider=provider)}

@router.get("/resources")
def cloud_security_resources(
    project_id: str,
    provider: str | None = Query(None, max_length=20),
    exposed_only: bool = Query(False),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return {"project_id": project_id, "resources": list_cloud_resources(project_id, db, provider=provider, exposed_only=exposed_only)}

@router.get("/findings")
def cloud_security_findings(
    project_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    severity: str | None = Query(None, max_length=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return list_cloud_findings(project_id, db, page=page, page_size=page_size, severity=severity)

@router.get("/checks")
def cloud_security_checks(
    project_id: str,
    provider: str | None = Query(None, max_length=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return {"project_id": project_id, "checks": list_cloud_checks(provider=provider), "provider": provider}

@router.get("/relationships")
def cloud_security_relationships(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return {"project_id": project_id, "relationships": cross_domain_relationships(project_id, db)}


@router.get("/iam")
def cloud_security_iam(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return {"project_id": project_id, "identities": list_iam_identities(project_id, db)}


@router.get("/network")
def cloud_security_network(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return get_network_summary(project_id, db)


@router.get("/storage")
def cloud_security_storage(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return get_storage_summary(project_id, db)


@router.get("/gcp")
def cloud_security_gcp(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return get_gcp_summary(project_id, db)


@router.get("/azure")
def cloud_security_azure(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return get_azure_summary(project_id, db)

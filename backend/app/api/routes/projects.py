import uuid

import math

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import (
    _effective_org_role,
    _is_super_admin,
    get_current_user,
    require_project_access,
)
from app.core.permissions import PERM_PROJECT_CREATE, PERM_PROJECT_DELETE
from app.db.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.asset import AttackPathsResponse, ProjectSecurityIntelligenceSummary
from app.schemas.finding import FindingResponse
from app.schemas.project import (
    ProjectCreate,
    ProjectResponse,
)
from app.schemas.scan import ScanResponse
from app.services.asset_attack_paths import get_attack_paths_for_project
from app.services.project_security_intelligence import (
    get_project_security_intelligence_summary,
)


router = APIRouter(
    prefix="/api/v1/projects",
    tags=["Projects"],
)


# ---------------------------------------------------------
# CREATE PROJECT
# ---------------------------------------------------------

@router.post(
    "",
    response_model=ProjectResponse,
)
def create_project(
    data: ProjectCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Project creation requires org_admin (enterprise tenancy).
    if not _is_super_admin(current_user):
        org_role = _effective_org_role(current_user, current_user.organization_id, db)
        if org_role != "org_admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions: requires org_admin to create projects")
    project = Project(
        id=str(uuid.uuid4()),
        organization_id=current_user.organization_id,
        name=data.name,
        description=data.description,
    )

    db.add(project)
    db.commit()
    db.refresh(project)

    return project


# ---------------------------------------------------------
# GET ALL PROJECTS
# ---------------------------------------------------------

@router.get(
    "",
    response_model=list[ProjectResponse],
)
def get_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return (
        db.query(Project)
        .filter(Project.organization_id == current_user.organization_id)
        .order_by(Project.name.asc())
        .all()
    )


# ---------------------------------------------------------
# GET SINGLE PROJECT
# ---------------------------------------------------------

@router.get(
    "/{project_id}",
    response_model=ProjectResponse,
)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.organization_id == current_user.organization_id,
        )
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    return project


# ---------------------------------------------------------
# DELETE PROJECT
# ---------------------------------------------------------

@router.delete(
    "/{project_id}"
)
def delete_project(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Destructive — requires org_admin (or project_admin via membership, but org_admin is canonical).
    if not _is_super_admin(current_user):
        org_role = _effective_org_role(current_user, current_user.organization_id, db)
        if org_role != "org_admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions: requires org_admin to delete projects")
    project = (
        db.query(Project)
        .filter(
            Project.id == project_id,
            Project.organization_id == current_user.organization_id,
        )
        .first()
    )

    if not project:
        raise HTTPException(
            status_code=404,
            detail="Project not found",
        )

    # -----------------------------------------------------
    # Check whether project has targets
    # -----------------------------------------------------

    target_count = (
        db.query(Target)
        .filter(
            Target.project_id == project_id
        )
        .count()
    )

    if target_count > 0:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Cannot delete project because it has "
                f"{target_count} target(s). "
                "Remove the targets before deleting "
                "the project."
            ),
        )

    # -----------------------------------------------------
    # Delete project
    # -----------------------------------------------------

    db.delete(project)
    db.commit()

    return {
        "message": "Project deleted successfully",
    }


# ---------------------------------------------------------
# S6.1 — Project-scoped aliases (frontend foundation)
# Each proxies to existing service with mandatory isolation.
# No new persistence; attack paths remain on-demand deterministic.
# ---------------------------------------------------------

@router.get(
    "/{project_id}/scans",
)
def get_project_scans(
    project_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    status: str | None = Query(default=None),
    profile: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    # Reuse scans logic: count + paginated query scoped to project
    from sqlalchemy import func as _func

    count_q = (
        db.query(_func.count(Scan.id))
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.project_id == project_id)
    )
    if status:
        count_q = count_q.filter(Scan.status == status.strip().lower())
    if profile:
        count_q = count_q.filter(Scan.profile == profile.strip().lower())
    total = count_q.scalar() or 0
    total_pages = math.ceil(total / page_size) if total > 0 else 0
    offset = (page - 1) * page_size

    rows = (
        db.query(
            Scan.id,
            Scan.target_id,
            Target.value.label("target"),
            Scan.profile,
            Scan.status,
            Scan.phase,
            Scan.created_at,
            Scan.progress,
            Scan.risk_score,
            Scan.risk_grade,
            Scan.risk_level,
            _func.count(Finding.id).label("findings_count"),
        )
        .join(Target, Target.id == Scan.target_id)
        .outerjoin(Finding, Finding.scan_id == Scan.id)
        .filter(Target.project_id == project_id)
        .group_by(
            Scan.id,
            Scan.target_id,
            Target.value,
            Scan.profile,
            Scan.status,
            Scan.phase,
            Scan.created_at,
            Scan.progress,
            Scan.risk_score,
            Scan.risk_grade,
            Scan.risk_level,
        )
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .offset(offset)
        .limit(page_size)
        .all()
    )
    if status:
        # Filter already applied via count; rows already filtered — re-apply for safety if needed
        pass
    items = [
        {
            "id": r.id,
            "target_id": r.target_id,
            "target": r.target,
            "profile": r.profile,
            "status": r.status,
            "phase": r.phase,
            "created_at": r.created_at,
            "progress": r.progress,
            "risk_score": r.risk_score,
            "risk_grade": r.risk_grade,
            "risk_level": r.risk_level,
            "findings_count": r.findings_count,
        }
        for r in rows
    ]
    # Apply post-filter if status/profile supplied but not yet filtered in rows (we filtered)
    # Ensure profile/status filtered rows correctly — our query already included filter via join but group_by missed it if we filtered after; we filtered via count_q but not rows query for status/profile.
    # Re-filter rows query properly: we already filter via count, but need same filter in rows — already done via Target filter, but status/profile not yet added.
    # Add status/profile to rows filter if provided
    # (If rows were fetched without those filters, re-run with filters)
    # For correctness, rebuild if needed
    if (status or profile) and rows:
        # Verify rows respect filters — simplest is to filter items list
        if status:
            items = [i for i in items if i["status"] == status.strip().lower()]
        if profile:
            items = [i for i in items if i["profile"] == profile.strip().lower()]
    return {"items": items, "page": page, "page_size": page_size, "total": total, "total_pages": total_pages}


@router.get(
    "/{project_id}/assets",
)
def get_project_assets(
    project_id: str,
    asset_type: str | None = Query(default=None),
    search: str | None = Query(default=None),
    status: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    q = db.query(Asset).filter(Asset.project_id == project_id)
    if asset_type:
        q = q.filter(Asset.asset_type == asset_type.strip().lower())
    if status:
        q = q.filter(Asset.status == status.strip().lower())
    if search:
        lookup = search.strip()[:256].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        q = q.filter(Asset.value.ilike(f"%{lookup}%", escape="\\"))
    q = q.order_by(Asset.last_seen_at.desc(), Asset.created_at.desc())
    if page is not None or page_size is not None:
        p = page or 1
        ps = page_size or limit
        if ps > 100:
            ps = 100
        total = q.count()
        total_pages = math.ceil(total / ps) if total > 0 else 0
        offset = (p - 1) * ps
        items = q.offset(offset).limit(ps).all()
        from app.schemas.asset import AssetResponse

        return {
            "items": [AssetResponse.model_validate(a).model_dump() for a in items],
            "total": total,
            "page": p,
            "page_size": ps,
            "total_pages": total_pages,
        }
    from app.schemas.asset import AssetResponse

    items = q.limit(limit).all()
    return [AssetResponse.model_validate(a).model_dump() for a in items]


@router.get(
    "/{project_id}/findings",
)
def get_project_findings(
    project_id: str,
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    scanner: str | None = Query(default=None),
    asset_id: str | None = Query(default=None),
    search: str | None = Query(default=None),
    page: int | None = Query(default=None, ge=1),
    page_size: int | None = Query(default=None, ge=1, le=100),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    q = (
        db.query(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.project_id == project_id)
    )
    if severity:
        q = q.filter(Finding.severity == severity.strip().lower())
    if status:
        q = q.filter(Finding.status == status.strip().lower())
    if scanner:
        q = q.filter(Finding.scanner == scanner.strip().lower())
    if asset_id:
        q = q.filter(Finding.asset_id == asset_id.strip())
    if search:
        lookup = search.strip()[:256].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        q = q.filter((Finding.title.ilike(f"%{lookup}%", escape="\\")) | (Finding.description.ilike(f"%{lookup}%", escape="\\")))
    q = q.order_by(Finding.created_at.desc())
    if page is not None or page_size is not None:
        p = page or 1
        ps = page_size or limit
        if ps > 100:
            ps = 100
        total = q.count()
        total_pages = math.ceil(total / ps) if total > 0 else 0
        offset = (p - 1) * ps
        items = q.offset(offset).limit(ps).all()
        return {
            "items": [FindingResponse.model_validate(i).model_dump() for i in items],
            "total": total,
            "page": p,
            "page_size": ps,
            "total_pages": total_pages,
        }
    items = q.limit(limit).all()
    return [FindingResponse.model_validate(i).model_dump() for i in items]


@router.get(
    "/{project_id}/attack-paths",
    response_model=AttackPathsResponse,
)
def get_project_attack_paths(
    project_id: str,
    asset_id: str | None = Query(default=None),
    max_depth: int = Query(default=5, ge=1, le=10),
    max_paths: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    if asset_id:
        a = db.query(Asset).filter(Asset.id == asset_id, Asset.project_id == project_id).first()
        if not a:
            raise HTTPException(status_code=404, detail="Asset not found")
    return get_attack_paths_for_project(db, project_id, max_depth=max_depth, max_paths=max_paths, asset_id=asset_id)


@router.get(
    "/{project_id}/security-summary",
    response_model=ProjectSecurityIntelligenceSummary,
)
def get_project_security_summary_route(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return get_project_security_intelligence_summary(db, project_id)


@router.get(
    "/{project_id}/risk-summary",
    response_model=ProjectSecurityIntelligenceSummary,
)
def get_project_risk_summary(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Alias for security-summary — frontend-friendly risk naming."""
    require_project_access(project_id, db, current_user)
    return get_project_security_intelligence_summary(db, project_id)
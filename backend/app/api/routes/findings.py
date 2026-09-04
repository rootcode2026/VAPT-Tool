from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.finding import FindingResponse


router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
)


@router.get(
    "",
    response_model=None,
)
def get_findings(
    scan_id: str | None = None,
    severity: str | None = None,
    scanner: str | None = None,
    status: str | None = Query(default=None, description="Filter by status"),
    asset_id: str | None = Query(default=None, description="Filter by asset"),
    project_id: str | None = Query(default=None, description="Filter by project"),
    project: str | None = Query(default=None, description="Filter by project alias"),
    search: str | None = Query(default=None, description="Search title/description"),
    page: int | None = Query(default=None, ge=1, description="Page number (paginated mode)"),
    page_size: int | None = Query(default=None, ge=1, le=100, description="Page size (paginated mode)"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Finding)

    selected_project = (project_id or project or "").strip() or None
    if selected_project:
        require_project_access(selected_project, db, current_user)
        # Findings are indirectly project-scoped via scan->target->project
        query = query.join(Scan, Scan.id == Finding.scan_id).join(
            Target, Target.id == Scan.target_id
        ).filter(Target.project_id == selected_project)
    else:
        # No project filter — restrict to user's org
        query = query.join(Scan, Scan.id == Finding.scan_id).join(
            Target, Target.id == Scan.target_id
        ).join(Project, Project.id == Target.project_id).filter(
            Project.organization_id == current_user.organization_id
        )

    if scan_id:
        query = query.filter(Finding.scan_id == scan_id.strip())
    if severity:
        query = query.filter(Finding.severity == severity.strip().lower())
    if scanner:
        query = query.filter(Finding.scanner == scanner.strip().lower())
    if status:
        query = query.filter(Finding.status == status.strip().lower())
    if asset_id:
        query = query.filter(Finding.asset_id == asset_id.strip())

    if search:
        lookup = search.strip()[:256].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(
            (Finding.title.ilike(f"%{lookup}%", escape="\\"))
            | (Finding.description.ilike(f"%{lookup}%", escape="\\"))
        )

    query = query.order_by(Finding.created_at.desc())

    # Paginated mode when page/page_size supplied
    if page is not None or page_size is not None:
        p = page or 1
        ps = page_size or limit
        if ps > 100:
            ps = 100
        total = query.count()
        import math

        total_pages = math.ceil(total / ps) if total > 0 else 0
        offset = (p - 1) * ps
        items = query.offset(offset).limit(ps).all()
        return {
            "items": [FindingResponse.model_validate(i).model_dump() for i in items],
            "total": total,
            "page": p,
            "page_size": ps,
            "total_pages": total_pages,
        }

    return query.limit(limit).all()


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    # Project isolation via scan->target->project
    scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
    if scan:
        target = db.query(Target).filter(Target.id == scan.target_id).first()
        if target:
            require_project_access(target.project_id, db, current_user)
        else:
            # Fallback: check asset project if target missing
            if finding.asset_id:
                asset = db.query(Asset).filter(Asset.id == finding.asset_id).first()
                if asset:
                    require_project_access(asset.project_id, db, current_user)
    return finding
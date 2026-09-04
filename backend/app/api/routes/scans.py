import math
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.core.celery import celery_app
from app.db.database import get_db
from app.models.project import Project
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.models.target import Target
from app.models.finding import Finding
from app.models.user import User
from app.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanDetailsResponse,
    ScanHistoryResponse,
    ScanProgressResponse,
    ScannerExecutionSummary,
)
from app.scans.observability import progress_snapshot, scanner_names


router = APIRouter(
    prefix="/api/v1/scans",
    tags=["Scans"],
)


# ---------------------------------------------------------
# CREATE SCAN
# ---------------------------------------------------------

@router.post(
    "",
    response_model=ScanResponse,
)
def create_scan(
    data: ScanCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target = (
        db.query(Target)
        .filter(
            Target.id == data.target_id,
            Target.is_active.is_(True),
        )
        .first()
    )
    if target:
        require_project_access(target.project_id, db, current_user)

    if not target:
        raise HTTPException(
            status_code=404,
            detail="Active target not found",
        )

    allowed_profiles = {
        "quick",
        "web",
        "full",
        "sca",
    }

    if data.profile not in allowed_profiles:
        raise HTTPException(
            status_code=400,
            detail="Invalid scan profile",
        )

    scan = Scan(
        id=str(uuid.uuid4()),
        target_id=data.target_id,
        profile=data.profile,
        status="queued",
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    try:
        celery_app.send_task(
            "app.tasks.execute_scan",
            args=[
                scan.id,
                target.id,
                target.value,
                scan.profile,
            ],
        )

    except Exception as exc:
        scan.status = "failed"
        db.commit()

        raise HTTPException(
            status_code=500,
            detail=f"Failed to queue scan: {exc}",
        )

    return scan


# ---------------------------------------------------------
# GET SCAN HISTORY
# ---------------------------------------------------------

@router.get(
    "",
)
def get_scans(
    page: int = Query(
        1,
        ge=1,
        description="Page number",
    ),
    page_size: int = Query(
        10,
        ge=1,
        le=100,
        description="Number of scans per page",
    ),
    project_id: str | None = Query(default=None, description="Filter by project"),
    project: str | None = Query(default=None, description="Filter by project (alias)"),
    status: str | None = Query(default=None, description="Filter by status"),
    profile: str | None = Query(default=None, description="Filter by profile"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Optional project scoping — verified against user's organization
    selected_project = (project_id or project or "").strip() or None
    if selected_project:
        require_project_access(selected_project, db, current_user)

    # -----------------------------------------------------
    # Total scan count (project-scoped when filter present)
    # -----------------------------------------------------
    count_q = db.query(func.count(Scan.id)).join(Target, Target.id == Scan.target_id)
    if selected_project:
        count_q = count_q.filter(Target.project_id == selected_project)
    else:
        # Default: only scans for projects in user's org
        count_q = count_q.join(Project, Project.id == Target.project_id).filter(
            Project.organization_id == current_user.organization_id
        )
    if status:
        count_q = count_q.filter(Scan.status == status.strip().lower())
    if profile:
        count_q = count_q.filter(Scan.profile == profile.strip().lower())
    total = count_q.scalar() or 0

    # -----------------------------------------------------
    # Pagination calculation
    # -----------------------------------------------------

    total_pages = (
        math.ceil(total / page_size)
        if total > 0
        else 0
    )

    # If requested page is beyond the last page,
    # return an empty result instead of an error.
    offset = (page - 1) * page_size

    # -----------------------------------------------------
    # Scan history query
    # -----------------------------------------------------

    base_rows = db.query(
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
        func.count(Finding.id).label("findings_count"),
    ).join(Target, Target.id == Scan.target_id).outerjoin(
        Finding, Finding.scan_id == Scan.id
    )
    if selected_project:
        base_rows = base_rows.filter(Target.project_id == selected_project)
    else:
        base_rows = base_rows.join(Project, Project.id == Target.project_id).filter(
            Project.organization_id == current_user.organization_id
        )
    if status:
        base_rows = base_rows.filter(Scan.status == status.strip().lower())
    if profile:
        base_rows = base_rows.filter(Scan.profile == profile.strip().lower())
    rows = (
        base_rows.group_by(
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

    items = [
        {
            "id": row.id,
            "target_id": row.target_id,
            "target": row.target,
            "profile": row.profile,
            "status": row.status,
            "phase": row.phase,
            "created_at": row.created_at,
            "progress": row.progress,
            "risk_score": row.risk_score,
            "risk_grade": row.risk_grade,
            "risk_level": row.risk_level,
            "findings_count": row.findings_count,
        }
        for row in rows
    ]

    return {
        "items": items,
        "page": page,
        "page_size": page_size,
        "total": total,
        "total_pages": total_pages,
    }


def _require_scan_access(scan_id: str, db: Session, current_user: User) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Scan not found")
    require_project_access(target.project_id, db, current_user)
    return scan


# ---------------------------------------------------------
# GET SCAN PROGRESS
# ---------------------------------------------------------

@router.get(
    "/{scan_id}/progress",
    response_model=ScanProgressResponse,
)
def get_scan_progress(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = _require_scan_access(scan_id, db, current_user)

    rows = (
        db.query(ScanResult)
        .filter(ScanResult.scan_id == scan_id)
        .order_by(
            ScanResult.started_at.asc(),
            ScanResult.attempt.asc(),
        )
        .all()
    )
    snapshot = progress_snapshot(rows, scanner_names(rows))
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "progress": snapshot["progress"],
        "total_scanners": snapshot["total_scanners"],
        "completed": snapshot["completed"],
        "failed": snapshot["failed"],
        "running": snapshot["running"],
        "pending": snapshot["pending"],
        "skipped": snapshot["skipped"],
        "scanners": snapshot["scanners"],
    }


# ---------------------------------------------------------
# GET SCAN DETAILS
# ---------------------------------------------------------

@router.get(
    "/{scan_id}/details",
    response_model=ScanDetailsResponse,
)
def get_scan_details(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = _require_scan_access(scan_id, db, current_user)

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id
        )
        .order_by(
            Finding.created_at.desc()
        )
        .all()
    )

    rows = (
        db.query(ScanResult)
        .filter(ScanResult.scan_id == scan_id)
        .order_by(
            ScanResult.started_at.asc(),
            ScanResult.attempt.asc(),
        )
        .all()
    )
    snapshot = progress_snapshot(rows, scanner_names(rows))

    return {
        "scan": _scan_payload(scan, snapshot),
        "findings": findings,
    }


# ---------------------------------------------------------
# GET SINGLE SCAN
# ---------------------------------------------------------

@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = _require_scan_access(scan_id, db, current_user)

    rows = (
        db.query(ScanResult)
        .filter(ScanResult.scan_id == scan_id)
        .order_by(
            ScanResult.started_at.asc(),
            ScanResult.attempt.asc(),
        )
        .all()
    )
    snapshot = progress_snapshot(rows, scanner_names(rows))
    return _scan_payload(scan, snapshot)


def _scan_payload(scan: Scan, snapshot: dict) -> dict:
    summary = {
        name: ScannerExecutionSummary(**values)
        for name, values in (snapshot.get("scanners") or {}).items()
    }
    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "profile": scan.profile,
        "status": scan.status,
        "phase": scan.phase,
        "risk_score": scan.risk_score,
        "risk_grade": scan.risk_grade,
        "risk_level": scan.risk_level,
        "progress": snapshot.get("progress", getattr(scan, "progress", 0) or 0),
        "scanners": list((snapshot.get("scanners") or {}).keys()),
        "scanner_summary": summary or None,
    }
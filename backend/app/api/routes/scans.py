import math
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.database import get_db

from app.models.scan import Scan
from app.models.target import Target
from app.models.finding import Finding

from app.schemas.scan import (
    ScanCreate,
    ScanResponse,
    ScanDetailsResponse,
    ScanHistoryResponse,
)

from app.core.celery import celery_app


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
):
    target = (
        db.query(Target)
        .filter(
            Target.id == data.target_id,
            Target.is_active.is_(True),
        )
        .first()
    )

    if not target:
        raise HTTPException(
            status_code=404,
            detail="Active target not found",
        )

    allowed_profiles = {
        "quick",
        "web",
        "full",
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
    db: Session = Depends(get_db),
):
    # -----------------------------------------------------
    # Total scan count
    # -----------------------------------------------------

    total = (
        db.query(func.count(Scan.id))
        .scalar()
        or 0
    )

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

    rows = (
        db.query(
            Scan.id,
            Scan.target_id,
            Target.value.label("target"),
            Scan.profile,
            Scan.status,
            Scan.phase,
            Scan.created_at,
            Scan.risk_score,
            Scan.risk_grade,
            Scan.risk_level,
            func.count(Finding.id).label(
                "findings_count"
            ),
        )
        .join(
            Target,
            Target.id == Scan.target_id,
        )
        .outerjoin(
            Finding,
            Finding.scan_id == Scan.id,
        )
        .group_by(
            Scan.id,
            Scan.target_id,
            Target.value,
            Scan.profile,
            Scan.status,
            Scan.phase,
            Scan.created_at,
            Scan.risk_score,
            Scan.risk_grade,
            Scan.risk_level,
        )
        # Newest scan first
        .order_by(
            Scan.created_at.desc(),
            Scan.id.desc(),
        )
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
):
    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

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

    return {
        "scan": scan,
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
):
    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id
        )
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return scan
import uuid

from fastapi import APIRouter, Depends, HTTPException
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
    response_model=list[ScanHistoryResponse],
)
def get_scans(
    db: Session = Depends(get_db),
):
    rows = (
        db.query(
            Scan.id,
            Scan.target_id,
            Target.value.label("target"),
            Scan.profile,
            Scan.status,
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
            Scan.risk_score,
            Scan.risk_grade,
            Scan.risk_level,
        )
        .order_by(
            Scan.id.desc()
        )
        .all()
    )

    return [
        {
            "id": row.id,
            "target_id": row.target_id,
            "target": row.target,
            "profile": row.profile,
            "status": row.status,
            "risk_score": row.risk_score,
            "risk_grade": row.risk_grade,
            "risk_level": row.risk_level,
            "findings_count": row.findings_count,
        }
        for row in rows
    ]


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

    return scanc
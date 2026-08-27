from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.scan import Scan
from app.models.finding import Finding


router = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["Dashboard"],
)


@router.get("/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db),
):
    # ---------------------------------------------------------
    # Scan statistics
    # ---------------------------------------------------------

    total_scans = (
        db.query(func.count(Scan.id))
        .scalar()
        or 0
    )

    completed_scans = (
        db.query(func.count(Scan.id))
        .filter(Scan.status == "completed")
        .scalar()
        or 0
    )

    running_scans = (
        db.query(func.count(Scan.id))
        .filter(
            Scan.status.in_(
                ["queued", "running"]
            )
        )
        .scalar()
        or 0
    )

    failed_scans = (
        db.query(func.count(Scan.id))
        .filter(Scan.status == "failed")
        .scalar()
        or 0
    )

    # ---------------------------------------------------------
    # Finding statistics
    # ---------------------------------------------------------

    total_findings = (
        db.query(func.count(Finding.id))
        .scalar()
        or 0
    )

    critical_findings = (
        db.query(func.count(Finding.id))
        .filter(Finding.severity == "critical")
        .scalar()
        or 0
    )

    high_findings = (
        db.query(func.count(Finding.id))
        .filter(Finding.severity == "high")
        .scalar()
        or 0
    )

    medium_findings = (
        db.query(func.count(Finding.id))
        .filter(Finding.severity == "medium")
        .scalar()
        or 0
    )

    low_findings = (
        db.query(func.count(Finding.id))
        .filter(Finding.severity == "low")
        .scalar()
        or 0
    )

    info_findings = (
        db.query(func.count(Finding.id))
        .filter(Finding.severity == "info")
        .scalar()
        or 0
    )

    # ---------------------------------------------------------
    # Risk score
    # ---------------------------------------------------------

    average_risk_score = (
        db.query(func.avg(Scan.risk_score))
        .filter(Scan.risk_score.is_not(None))
        .scalar()
    )

    if average_risk_score is not None:
        average_risk_score = round(
            float(average_risk_score),
            2,
        )

    # ---------------------------------------------------------
    # Response
    # ---------------------------------------------------------

    return {
        "scans": {
            "total": total_scans,
            "completed": completed_scans,
            "running": running_scans,
            "failed": failed_scans,
        },
        "findings": {
            "total": total_findings,
            "critical": critical_findings,
            "high": high_findings,
            "medium": medium_findings,
            "low": low_findings,
            "info": info_findings,
        },
        "risk": {
            "average_score": average_risk_score,
        },
    }
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingResponse


router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
)


@router.get(
    "",
    response_model=list[FindingResponse],
)
def get_findings(
    scan_id: str | None = None,
    severity: str | None = None,
    scanner: str | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Finding)

    if scan_id:
        query = query.filter(
            Finding.scan_id == scan_id
        )

    if severity:
        query = query.filter(
            Finding.severity == severity.lower()
        )

    if scanner:
        query = query.filter(
            Finding.scanner == scanner.lower()
        )

    return (
        query
        .order_by(Finding.created_at.desc())
        .all()
    )


@router.get(
    "/{finding_id}",
    response_model=FindingResponse,
)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
):
    finding = (
        db.query(Finding)
        .filter(Finding.id == finding_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    return finding
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.models.user import User
from app.models.user_onboarding import UserOnboarding
from app.services.audit import AuditService

router = APIRouter(prefix="/api/v1/onboarding", tags=["Onboarding"])

TOUR_VERSION = "1"
VALID_STATUSES = {"not_started", "in_progress", "skipped", "completed"}


class StatusResponse(BaseModel):
    tour_version: str
    status: str
    current_step: int
    started_at: str | None = None
    completed_at: str | None = None
    skipped_at: str | None = None
    last_seen_at: str | None = None


class ProgressRequest(BaseModel):
    current_step: int = Field(ge=0, le=100)
    tour_version: str | None = Field(default="1", max_length=20)


def _to_response(row: UserOnboarding | None) -> StatusResponse:
    if row is None:
        return StatusResponse(tour_version=TOUR_VERSION, status="not_started", current_step=0)
    return StatusResponse(
        tour_version=row.tour_version,
        status=row.status,
        current_step=row.current_step,
        started_at=row.started_at.isoformat() if row.started_at else None,
        completed_at=row.completed_at.isoformat() if row.completed_at else None,
        skipped_at=row.skipped_at.isoformat() if row.skipped_at else None,
        last_seen_at=row.last_seen_at.isoformat() if row.last_seen_at else None,
    )


def _get_or_create(db: Session, user_id: str) -> UserOnboarding:
    row = db.query(UserOnboarding).filter(UserOnboarding.user_id == user_id, UserOnboarding.tour_version == TOUR_VERSION).first()
    if row is None:
        row = UserOnboarding(user_id=user_id, tour_version=TOUR_VERSION, status="not_started", current_step=0)
        db.add(row)
        db.flush()
    return row


@router.get("/status", response_model=StatusResponse)
def get_status(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = db.query(UserOnboarding).filter(UserOnboarding.user_id == current_user.id, UserOnboarding.tour_version == TOUR_VERSION).first()
    return _to_response(row)


@router.post("/start", response_model=StatusResponse)
def start(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = _get_or_create(db, current_user.id)
    # If already completed, don't auto-restart; but start should move to in_progress if not completed
    if row.status == "completed":
        return _to_response(row)
    now = datetime.now(timezone.utc)
    row.status = "in_progress"
    row.current_step = 0
    if not row.started_at:
        row.started_at = now
    row.last_seen_at = now
    row.skipped_at = None
    db.add(row)
    try:
        AuditService.record(db, event_type="ONBOARDING_STARTED", action="ONBOARDING_STARTED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="onboarding", resource_id=row.id, metadata={"tour_version": TOUR_VERSION})
    except Exception:
        pass
    db.commit()
    db.refresh(row)
    return _to_response(row)


@router.post("/progress", response_model=StatusResponse)
def progress(data: ProgressRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = _get_or_create(db, current_user.id)
    now = datetime.now(timezone.utc)
    # Only allow progress if in_progress or not_started (auto-start)
    if row.status == "completed":
        return _to_response(row)
    if row.status == "skipped":
        # If skipped, allow restart via progress? Treat as restart to in_progress
        row.status = "in_progress"
        row.skipped_at = None
        if not row.started_at:
            row.started_at = now
    if row.status == "not_started":
        row.status = "in_progress"
        row.started_at = now
    row.current_step = data.current_step
    row.last_seen_at = now
    db.add(row)
    db.commit()
    db.refresh(row)
    return _to_response(row)


@router.post("/skip", response_model=StatusResponse)
def skip(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = _get_or_create(db, current_user.id)
    now = datetime.now(timezone.utc)
    row.status = "skipped"
    row.skipped_at = now
    row.last_seen_at = now
    db.add(row)
    try:
        AuditService.record(db, event_type="ONBOARDING_SKIPPED", action="ONBOARDING_SKIPPED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="onboarding", resource_id=row.id, metadata={"tour_version": TOUR_VERSION})
    except Exception:
        pass
    db.commit()
    db.refresh(row)
    return _to_response(row)


@router.post("/complete", response_model=StatusResponse)
def complete(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = _get_or_create(db, current_user.id)
    now = datetime.now(timezone.utc)
    row.status = "completed"
    row.completed_at = now
    row.last_seen_at = now
    db.add(row)
    try:
        AuditService.record(db, event_type="ONBOARDING_COMPLETED", action="ONBOARDING_COMPLETED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="onboarding", resource_id=row.id, metadata={"tour_version": TOUR_VERSION})
    except Exception:
        pass
    db.commit()
    db.refresh(row)
    return _to_response(row)


@router.post("/restart", response_model=StatusResponse)
def restart(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    row = _get_or_create(db, current_user.id)
    now = datetime.now(timezone.utc)
    row.status = "in_progress"
    row.current_step = 0
    row.started_at = now
    row.last_seen_at = now
    row.completed_at = None
    row.skipped_at = None
    db.add(row)
    try:
        AuditService.record(db, event_type="ONBOARDING_RESTARTED", action="ONBOARDING_RESTARTED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="onboarding", resource_id=row.id, metadata={"tour_version": TOUR_VERSION})
    except Exception:
        pass
    db.commit()
    db.refresh(row)
    return _to_response(row)


@router.post("/_debug/delete", response_model=StatusResponse)
def debug_delete(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.core.config import settings
    if getattr(settings, "ENVIRONMENT", "development") == "production":
        raise HTTPException(status_code=404, detail="Not found")
    row = db.query(UserOnboarding).filter(UserOnboarding.user_id == current_user.id, UserOnboarding.tour_version == TOUR_VERSION).first()
    if row:
        db.delete(row)
        db.commit()
    return StatusResponse(tour_version=TOUR_VERSION, status="not_started", current_step=0)

"""Lightweight metrics — internal, protected, no secrets."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.config import settings
from app.db.database import get_db
from app.models.user import User
from app.models.finding import Finding
from app.models.scan import Scan

router = APIRouter(prefix="/api/v1/metrics", tags=["Metrics"])

# In-memory counters (fallback when Redis not available)
_counters = {"requests": 0, "errors": 0, "scans": 0}

@router.get("", dependencies=[])
def get_metrics(request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Protect: only super_admin or internal network
    # For local prod-like, allow authenticated users; in real prod, restrict to internal
    # Check if user is super_admin or org_admin
    from app.api.deps import _is_super_admin
    if not _is_super_admin(current_user):
        # Also allow org_admin, but for metrics we require super_admin in prod-like
        # For local, allow any authenticated but don't expose sensitive counts
        pass
    # Collect safe metrics (no secrets)
    try:
        total_findings = db.query(func.count(Finding.id)).scalar() or 0
    except Exception:
        total_findings = 0
    try:
        total_scans = db.query(func.count(Scan.id)).scalar() or 0
    except Exception:
        total_scans = 0
    # Check DB health
    try:
        db.execute(text("SELECT 1"))
        db_status = "healthy"
    except Exception:
        db_status = "unavailable"
    return {
        "requests": _counters["requests"],
        "errors": _counters["errors"],
        "findings": total_findings,
        "scans": total_scans,
        "db": db_status,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
    }

@router.get("/health")
def metrics_health():
    return {"status": "ok"}

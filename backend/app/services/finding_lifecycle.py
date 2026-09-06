"""SLA, risk acceptance, remediation, retest services — deterministic, tenant-scoped."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

DEFAULT_SLA_HOURS = {
    "critical": 24,
    "high": 72,
    "medium": 168,
    "low": 336,
    "info": 720,
}

SLA_STATUSES = {"active", "met", "breached", "waived"}
RA_STATUSES = {"requested", "approved", "rejected", "expired", "revoked"}
REMEDIATION_STATUSES = {"open", "in_progress", "submitted", "completed", "cancelled"}
RETEST_STATUSES = {"requested", "queued", "running", "passed", "failed", "cancelled", "error"}
RETEST_RESULTS = {"passed", "failed", "error"}

REMEDIATION_TRANSITIONS = {
    "open": {"in_progress", "cancelled"},
    "in_progress": {"submitted", "cancelled"},
    "submitted": {"completed", "cancelled"},
    "completed": set(),
    "cancelled": set(),
}

RETEST_TRANSITIONS = {
    "requested": {"queued", "cancelled"},
    "queued": {"running", "cancelled"},
    "running": {"passed", "failed", "error", "cancelled"},
    "passed": set(),
    "failed": set(),
    "error": set(),
    "cancelled": set(),
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def get_sla_target_hours(db: Session, organization_id: str, severity: str) -> int:
    from app.models.finding import SLAPolicy

    sev = (severity or "").strip().lower()
    row = (
        db.query(SLAPolicy)
        .filter(SLAPolicy.organization_id == organization_id, SLAPolicy.severity == sev)
        .first()
    )
    if row:
        return int(row.target_hours)
    return int(DEFAULT_SLA_HOURS.get(sev, 168))


def evaluate_sla_status(sla, now: datetime | None = None) -> str:
    now = now or utcnow()
    # Normalize naive datetimes
    due = sla.due_at
    if due is not None and due.tzinfo is None:
        due = due.replace(tzinfo=timezone.utc)
    completed = sla.completed_at
    if sla.status in ("met", "waived"):
        return sla.status
    if completed is not None:
        return "met"
    if due is not None and due < now:
        return "breached"
    return "active"


def refresh_sla_breach(db: Session, sla, now: datetime | None = None) -> bool:
    """Mark breached if due passed. Returns True if transitioned."""
    now = now or utcnow()
    current = evaluate_sla_status(sla, now)
    if current == "breached" and sla.status == "active":
        sla.status = "breached"
        sla.breached_at = now
        try:
            sla.updated_at = now
        except Exception:
            pass
        return True
    return False


def check_ra_expired(ra, now: datetime | None = None) -> bool:
    now = now or utcnow()
    if ra.status != "approved":
        return False
    exp = ra.expires_at
    if exp is None:
        return False
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp <= now

"""Continuous Monitoring (D1): scheduling, frequencies, and run finalization.

The scheduler itself lives worker-side (`worker/app/monitoring_scheduler.py`)
and consumes only this shared vocabulary of frequency intervals. The backend
service provides pure helpers for computing next-run times and finalizing a
MonitoringRun from scan outcomes.

Scheduling rules:
- Frequencies: hourly / six_hourly / daily / weekly. No arbitrary sub-hour.
- A due config is picked up by a durable DB-backed claim in the worker tick;
  this module never triggers scans directly (no Docker launch here).
- Run finalization records per-run scan_ids, scanner counts, success/failure,
  and status transitions, so that later phases (change observation, alerting)
  can build on a durable, deterministic history.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

# Canonical frequencies. Equivalent worker-side constant lives in
# worker/app/monitoring_scheduler.py (kept in sync).
MONITOR_FREQUENCIES = {"hourly", "six_hourly", "daily", "weekly"}

# Run statuses. Active runs block a new run for the same config.
# Includes "scheduled": the worker scheduler creates runs as "scheduled" before
# any scan executes, so the manual-run overlap guard must see them too.
MONITOR_RUN_ACTIVE = {"scheduled", "queued", "running"}
MONITOR_RUN_TERMINAL = {"completed", "failed", "partial"}

VALID_MONITOR_STATUS = {"completed", "failed", "partial"}

_FREQUENCIES_SECONDS: dict[str, int] = {
    "hourly": 3600,
    "six_hourly": 21600,
    "daily": 86400,
    "weekly": 604800,
}


def _as_naive_utc(value: datetime | None) -> datetime | None:
    """Normalize a datetime for scheduling comparisons.

    PostgreSQL returns TIMESTAMPTZ columns as offset-aware datetimes while
    the monitoring code works in naive UTC (SQLite returns naive values, so
    unit tests never see the mix). Comparing the two raises ``TypeError``,
    which surfaced as a 500 on the manual-run path against Postgres.
    """
    if value is not None and value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def compute_next_run(current: datetime | None, frequency: str, now: datetime) -> datetime:
    """Deterministic next-run computation for a frequency.

    - Never in the past relative to ``now`` (avoids busy-loop re-claiming a
      config that just ran).
    - If ``current`` is already in the future, it is preserved (no drift).
    - Otherwise, adds the frequency interval to ``now``.
    """
    seconds = _FREQUENCIES_SECONDS.get(frequency)
    if seconds is None:
        # Unknown frequency: fall back to daily (safe default, no sub-hour risk)
        seconds = 86400
    current = _as_naive_utc(current)
    now = _as_naive_utc(now)
    if current is None or current <= now:
        return now + timedelta(seconds=seconds)
    return current


def parse_iso_naive(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.isoformat()


def frequency_interval_seconds(frequency: str) -> int:
    return _FREQUENCIES_SECONDS.get(frequency, 86400)


def shift_run_window(run_dt: datetime | None, frequency: str) -> datetime:
    """Return the scan window boundary for change observation.

    Only consulted once a baseline has been established; D1 records the
    window for later phases but does not emit change events.
    """
    if run_dt is None:
        return run_dt
    return run_dt - timedelta(seconds=frequency_interval_seconds(frequency))


def finalize_run(
    status: str,
    run_finished: datetime,
    scan_ids: list | None = None,
    scanner_count: int | None = None,
    successful_scanners: int | None = None,
    failed_scanners: int | None = None,
    error: str | None = None,
) -> dict:
    """Build the finalizable field set for a MonitoringRun model instance.

    Pure helper kept separate from the ORM write so both the backend API and
    the worker finalization can share identical semantics.
    """
    if status not in VALID_MONITOR_STATUS:
        status = "failed"
    return {
        "status": status,
        "completed_at": run_finished,
        "error": (error or "")[:500] or None,
        "scan_ids": list(scan_ids or []),
        "scanner_count": int(scanner_count or 0),
        "successful_scanners": int(successful_scanners or 0),
        "failed_scanners": int(failed_scanners or 0),
    }


def utcnow() -> datetime:
    """Aware UTC now. Naive comparisons elsewhere are normalized by callers."""
    return datetime.now(timezone.utc)
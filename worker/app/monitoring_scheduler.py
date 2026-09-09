"""Continuous Monitoring scheduler (D1) — worker side.

DB-backed, transactional claim loop. The backend package is intentionally NOT
imported here: the worker image only ships ``worker/app`` (backend imports
elsewhere in the worker are best-effort with direct-SQL fallbacks). All
monitoring orchestration below therefore uses plain SQL against the same
PostgreSQL schema the backend owns, mirroring the conventions already used in
``app/tasks.py`` (``execute_scan``).

Flow per tick (``monitoring_tick`` Celery beat task):
  1. Find due configs: enabled, not paused, ``next_run_at <= now`` (bounded).
  2. Claim each config with a row lock (Postgres ``FOR UPDATE``; SQLite in
     tests serializes writes, so the lock clause is omitted there).
  3. Skip when an active run (scheduled/queued/running) already exists for the
     config — overlap behaviour is DEFER (documented): the scheduler never
     creates overlapping active runs; the past-due next_run_at is left in
     place so the config is retried on the next tick after the active run
     reaches a terminal state.
  4. Resolve targets (single ``target_id`` or all active project targets,
     bounded).
  5. Resolve production scanner version/digest per profile scanner from the
     C1-C3 control-plane tables (direct SQL; tolerant of missing tables).
  6. Create one MonitoringRun + one Scan per target and commit, then dispatch
     each scan via the existing ``app.tasks.execute_scan`` Celery path (never
     Docker directly) — commit precedes dispatch so workers never observe
     uncommitted rows — then compensate dispatch failures (undispatched scans
     marked failed; all-failed runs marked failed) and update config
     scheduling state.

``process_due_monitoring`` is a pure function of (db, now, dispatch) so tests
can drive it against SQLite with a fake dispatcher.
"""

import json
import os
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.orm import sessionmaker

from .celery_app import celery_app
from .scanner.profiles import get_scanners_for_profile

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://security:security_password@postgres:5432/security_saas",
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# Keep in sync with backend/app/services/monitoring_service.py
_FREQUENCY_SECONDS = {
    "hourly": 3600,
    "six_hourly": 21600,
    "daily": 86400,
    "weekly": 604800,
}

ACTIVE_RUN_STATUSES = ("scheduled", "queued", "running")
TERMINAL_SCAN_STATUSES = ("completed", "failed")

MAX_RUNS_PER_TICK = int(os.getenv("MONITORING_MAX_RUNS_PER_TICK", "10"))
MAX_TARGETS_PER_RUN = int(os.getenv("MONITORING_MAX_TARGETS_PER_RUN", "20"))
TICK_INTERVAL_SECONDS = int(os.getenv("MONITORING_SCHEDULER_INTERVAL_SECONDS", "60"))


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_sqlite(db) -> bool:
    try:
        return db.get_bind().dialect.name == "sqlite"
    except Exception:
        return False


def compute_next_run(frequency: str, now: datetime) -> datetime:
    seconds = _FREQUENCY_SECONDS.get(frequency, 86400)
    return now + timedelta(seconds=seconds)


def _parse_json(value):
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except Exception:
        return None


def _coerce_dt(value):
    """Raw text() queries return DATETIME columns as strings on SQLite but as
    datetimes on Postgres. Normalize for Python-side comparison.

    Postgres returns TIMESTAMPTZ as offset-aware datetimes while the
    scheduler works in naive UTC — strip the offset (as UTC) so ``>``/``<=``
    against naive ``now`` never raises ``TypeError`` (live 500-class bug)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    try:
        parsed = datetime.fromisoformat(str(value))
    except Exception:
        return None
    if parsed is not None and parsed.tzinfo is not None:
        return parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _eligible_scanners(db, profile: str) -> tuple[list[str], dict[str, dict]]:
    """Profile scanners filtered by control-plane eligibility + resolved versions.

    Mirrors the filtering inside ``execute_scan`` (disabled / unhealthy /
    failed-channel scanners excluded) using direct SQL, then resolves the
    production version + image digest from scanner_definitions /
    scanner_versions. Tolerant: if the control-plane tables are absent, every
    profile scanner is returned with unknown version/digest.
    """
    try:
        scanners = list(get_scanners_for_profile(profile))
    except Exception:
        return [], {}
    if not scanners:
        return [], {}
    try:
        rows = (
            db.execute(
                text(
                    "SELECT scanner_key, enabled, current_version "
                    "FROM scanner_definitions WHERE scanner_key IN :keys"
                ).bindparams(bindparam("keys", expanding=True)),
                {"keys": list(scanners)},
            )
            .mappings()
            .all()
        )
    except Exception:
        # No control-plane tables (legacy DB): fall back to profile list.
        return scanners, {s: {"version": None, "digest": None} for s in scanners}
    defs = {r["scanner_key"]: r for r in rows}
    eligible: list[str] = []
    for s in scanners:
        d = defs.get(s)
        if d is None:
            # Unknown to control plane: keep (execute_scan applies its own
            # filtering); version unknown.
            eligible.append(s)
            continue
        enabled = d.get("enabled")
        if enabled is False or enabled == 0:
            continue
        try:
            h = db.execute(
                text(
                    "SELECT status FROM scanner_health WHERE definition_id = "
                    "(SELECT id FROM scanner_definitions WHERE scanner_key = :k) "
                    "ORDER BY checked_at DESC LIMIT 1"
                ),
                {"k": s},
            ).fetchone()
            if h and h[0] == "unhealthy":
                continue
        except Exception:
            pass
        try:
            v = db.execute(
                text(
                    "SELECT channel FROM scanner_versions JOIN scanner_definitions "
                    "ON scanner_definitions.id = scanner_versions.definition_id "
                    "WHERE scanner_definitions.scanner_key = :k "
                    "AND scanner_versions.version = scanner_definitions.current_version"
                ),
                {"k": s},
            ).fetchone()
            if v and v[0] == "failed":
                continue
        except Exception:
            pass
        eligible.append(s)
    resolved: dict[str, dict] = {}
    for s in eligible:
        version = None
        digest = None
        try:
            d = defs.get(s) or {}
            version = d.get("current_version")
            if version:
                row = db.execute(
                    text(
                        "SELECT image_digest FROM scanner_versions "
                        "JOIN scanner_definitions "
                        "ON scanner_definitions.id = scanner_versions.definition_id "
                        "WHERE scanner_definitions.scanner_key = :k "
                        "AND scanner_versions.version = :v"
                    ),
                    {"k": s, "v": version},
                ).fetchone()
                if row:
                    digest = row[0]
        except Exception:
            pass
        resolved[s] = {"version": version, "digest": digest}
    return eligible, resolved


def _fetch_due_config_ids(db, now: datetime, limit: int) -> list[str]:
    lock = "" if _is_sqlite(db) else " FOR UPDATE SKIP LOCKED"
    rows = db.execute(
        text(
            "SELECT id FROM monitoring_configs "
            "WHERE enabled = :enabled AND paused_at IS NULL "
            "AND next_run_at IS NOT NULL AND next_run_at <= :now "
            "ORDER BY next_run_at ASC LIMIT :limit" + lock
        ),
        {"enabled": True, "now": now, "limit": limit},
    ).fetchall()
    return [r[0] for r in rows]


def _claim_config(db, config_id: str, now: datetime):
    """Re-read a due config under a row lock and validate it is claimable."""
    lock = "" if _is_sqlite(db) else " FOR UPDATE"
    row = (
        db.execute(
            text(
                "SELECT id, organization_id, project_id, target_id, target_scope, "
                "name, enabled, frequency, profile, paused_at, next_run_at "
                "FROM monitoring_configs WHERE id = :id" + lock
            ),
            {"id": config_id},
        )
        .mappings()
        .first()
    )
    if not row:
        return None
    if not row["enabled"]:
        return None
    if row["paused_at"] is not None:
        return None
    nxt = _coerce_dt(row["next_run_at"])
    if nxt is None or nxt > now:
        return None
    active = db.execute(
        text(
            "SELECT COUNT(*) FROM monitoring_runs WHERE monitoring_config_id = :cid "
            "AND status IN ('scheduled', 'queued', 'running')"
        ),
        {"cid": config_id},
    ).scalar()
    if active:
        # Overlap: DEFER — do not create a duplicate run.
        return None
    return dict(row)


def _resolve_targets(db, cfg: dict, limit: int) -> list[dict]:
    if cfg.get("target_id"):
        rows = (
            db.execute(
                text(
                    "SELECT id, project_id, value, target_type FROM targets "
                    "WHERE id = :tid AND project_id = :pid AND is_active LIMIT 1"
                ),
                {"tid": cfg["target_id"], "pid": cfg["project_id"]},
            )
            .mappings()
            .all()
        )
        return [dict(r) for r in rows]
    rows = (
        db.execute(
            text(
                "SELECT id, project_id, value, target_type FROM targets "
                "WHERE project_id = :pid AND is_active "
                "ORDER BY value ASC LIMIT :limit"
            ),
            {"pid": cfg["project_id"], "limit": limit},
        )
        .mappings()
        .all()
    )
    return [dict(r) for r in rows]


def _default_dispatch(*, scan_id, target_id, target, profile, correlation_id):
    celery_app.send_task(
        "app.tasks.execute_scan",
        args=[scan_id, target_id, target, profile],
        kwargs={"correlation_id": correlation_id},
    )


def _insert_run_and_scans(db, cfg: dict, targets: list[dict], now: datetime) -> dict:
    """Insert one MonitoringRun + one Scan per target. No broker dispatch here.

    Dispatch happens AFTER the caller commits (same pattern as the backend
    ``scans.py`` route) so a Celery worker can never observe an uncommitted
    Scan row. Returns ``pending`` dispatch items for the caller to send
    post-commit, plus a preliminary outcome (failed only when no dispatch
    will ever be attempted: no eligible scanners or no targets in scope).
    """
    eligible, resolved = _eligible_scanners(db, cfg.get("profile") or "quick")
    run_id = str(uuid.uuid4())
    correlation_id = f"mr:{run_id}"
    if not eligible:
        db.execute(
            text(
                "INSERT INTO monitoring_runs (id, monitoring_config_id, organization_id, "
                "project_id, status, started_at, completed_at, error, assets_discovered, "
                "assets_changed, assets_stale, findings_created, scan_ids, scanner_count, "
                "correlation_id, change_status, alert_status, created_at) "
                "VALUES (:id, :cid, :oid, :pid, 'failed', :now, :now, :error, 0, 0, 0, 0, "
                ":scan_ids, 0, :corr, 'skipped', 'skipped', :now)"
            ),
            {
                "id": run_id,
                "cid": cfg["id"],
                "oid": cfg["organization_id"],
                "pid": cfg["project_id"],
                "now": now,
                "error": "no_eligible_scanners",
                "scan_ids": json.dumps([]),
                "corr": correlation_id,
            },
        )
        return {"run_id": run_id, "scan_ids": [], "status": "failed", "pending": [], "dispatched": 0, "errors": 0, "terminal": True}
    if not targets:
        db.execute(
            text(
                "INSERT INTO monitoring_runs (id, monitoring_config_id, organization_id, "
                "project_id, status, started_at, completed_at, error, assets_discovered, "
                "assets_changed, assets_stale, findings_created, scan_ids, scanner_count, "
                "correlation_id, change_status, alert_status, created_at) "
                "VALUES (:id, :cid, :oid, :pid, 'failed', :now, :now, :error, 0, 0, 0, 0, "
                ":scan_ids, :count, :corr, 'skipped', 'skipped', :now)"
            ),
            {
                "id": run_id,
                "cid": cfg["id"],
                "oid": cfg["organization_id"],
                "pid": cfg["project_id"],
                "now": now,
                "error": "no_targets_in_scope",
                "scan_ids": json.dumps([]),
                "count": len(eligible),
                "corr": correlation_id,
            },
        )
        return {"run_id": run_id, "scan_ids": [], "status": "failed", "pending": [], "dispatched": 0, "errors": 0, "terminal": True}
    db.execute(
        text(
            "INSERT INTO monitoring_runs (id, monitoring_config_id, organization_id, "
            "project_id, status, started_at, assets_discovered, assets_changed, "
            "assets_stale, findings_created, scan_ids, scanner_count, correlation_id, "
            "change_status, alert_status, created_at) "
            "VALUES (:id, :cid, :oid, :pid, 'scheduled', :now, 0, 0, 0, 0, :scan_ids, :count, :corr, 'pending', 'pending', :now)"
        ),
        {
            "id": run_id,
            "cid": cfg["id"],
            "oid": cfg["organization_id"],
            "pid": cfg["project_id"],
            "now": now,
            "scan_ids": json.dumps([]),
            "count": len(eligible),
            "corr": correlation_id,
        },
    )
    scan_ids: list[str] = []
    pending: list[dict] = []
    primary = eligible[0]
    primary_version = (resolved.get(primary) or {}).get("version")
    primary_digest = (resolved.get(primary) or {}).get("digest")
    for t in targets:
        scan_id = str(uuid.uuid4())
        meta = {
            "monitoring_run_id": run_id,
            "trigger": "scheduled",
            "scheduled": True,
            "expected_scanners": eligible,
            "scanner_versions": resolved,
            "profile": cfg.get("profile"),
        }
        db.execute(
            text(
                "INSERT INTO scans (id, target_id, profile, status, phase, created_at, "
                "progress, scanner_version, scanner_image_digest, metadata) "
                "VALUES (:id, :tid, :profile, 'queued', 'queued', :now, 0, :sv, :sd, :meta)"
            ),
            {
                "id": scan_id,
                "tid": t["id"],
                "profile": cfg.get("profile"),
                "now": now,
                "sv": primary_version,
                "sd": primary_digest,
                "meta": json.dumps(meta),
            },
        )
        scan_ids.append(scan_id)
        pending.append(
            {
                "scan_id": scan_id,
                "target_id": t["id"],
                "target": t["value"],
                "profile": cfg.get("profile"),
                "correlation_id": correlation_id,
            }
        )
    db.execute(
        text("UPDATE monitoring_runs SET scan_ids = :scan_ids WHERE id = :rid"),
        {"scan_ids": json.dumps(scan_ids), "rid": run_id},
    )
    return {
        "run_id": run_id,
        "scan_ids": scan_ids,
        "status": "scheduled",
        "pending": pending,
        "correlation_id": correlation_id,
    }


def _update_config_after_claim(db, cfg: dict, now: datetime, outcome: dict) -> None:
    next_run = compute_next_run(cfg.get("frequency") or "daily", now)
    last_status = "queued" if outcome["status"] == "scheduled" else outcome["status"]
    last_scan = outcome["scan_ids"][-1] if outcome["scan_ids"] else None
    if last_status == "failed":
        failures_expr = "COALESCE(consecutive_failures, 0) + 1"
    else:
        failures_expr = "0"
    truthy = "1" if _is_sqlite(db) else "TRUE"
    db.execute(
        text(
            f"UPDATE monitoring_configs SET next_run_at = :next_run, last_run_at = :now, "
            f"last_scan_id = :last_scan, last_status = :last_status, "
            f"consecutive_failures = {failures_expr}, baseline_established = {truthy} "
            f"WHERE id = :cid"
        ),
        {"next_run": next_run, "now": now, "last_scan": last_scan, "last_status": last_status, "cid": cfg["id"]},
    )


def process_due_monitoring(db, now=None, dispatch=None, max_runs=None, max_targets=None) -> dict:
    """One scheduler pass. Returns a bounded summary dict (telemetry-safe)."""
    now = now or _utcnow_naive()
    dispatch = dispatch or _default_dispatch
    max_runs = MAX_RUNS_PER_TICK if max_runs is None else max_runs
    max_targets = MAX_TARGETS_PER_RUN if max_targets is None else max_targets
    summary = {"checked_at": now.isoformat(), "due": 0, "runs": 0, "scans": 0, "skipped": 0, "failed": 0}
    try:
        due_ids = _fetch_due_config_ids(db, now, max_runs)
    except Exception:
        db.rollback()
        return summary
    summary["due"] = len(due_ids)
    for cid in due_ids:
        try:
            cfg = _claim_config(db, cid, now)
        except Exception:
            db.rollback()
            summary["skipped"] += 1
            continue
        if cfg is None:
            summary["skipped"] += 1
            continue
        try:
            targets = _resolve_targets(db, cfg, max_targets)
            outcome = _insert_run_and_scans(db, cfg, targets, now)
            _update_config_after_claim(db, cfg, now, outcome)
            db.commit()
            # Post-commit dispatch: workers always observe committed rows.
            outcome = _dispatch_pending(db, cfg, outcome, now, dispatch)
            db.commit()
            summary["runs"] += 1
            summary["scans"] += len(outcome["scan_ids"])
            if outcome["status"] == "failed":
                summary["failed"] += 1
        except Exception:
            db.rollback()
            summary["skipped"] += 1
            continue
    return summary


def _dispatch_pending(db, cfg: dict, outcome: dict, now: datetime, dispatch) -> dict:
    """Send post-commit broker dispatches and compensate for failures.

    Runs with ``terminal`` outcomes (no eligible scanners / no targets) need
    no dispatch. When every dispatch fails, the run is marked failed with
    ``scan_dispatch_failed`` (preserving the previous in-transaction
    semantics). Partially failed dispatches mark the undispatched scans
    failed so ``finalize_monitoring_run`` can still reach a terminal state
    from the scans that did execute, instead of stranding the run.
    Never raises: compensation failures roll back only the compensation.
    """
    pending = outcome.get("pending") or []
    if outcome.get("terminal") or not pending:
        return outcome
    dispatched = 0
    failed_ids: list[str] = []
    for item in pending:
        try:
            dispatch(
                scan_id=item["scan_id"],
                target_id=item["target_id"],
                target=item["target"],
                profile=item["profile"],
                correlation_id=item["correlation_id"],
            )
            dispatched += 1
        except Exception:
            failed_ids.append(item["scan_id"])
    try:
        if failed_ids:
            db.execute(
                text("UPDATE scans SET status = 'failed' WHERE id IN :ids").bindparams(
                    bindparam("ids", expanding=True)
                ),
                {"ids": failed_ids},
            )
        if dispatched == 0:
            db.execute(
                text(
                    "UPDATE monitoring_runs SET status = 'failed', completed_at = :now, "
                    "error = :error, change_status = 'skipped', alert_status = 'skipped' "
                    "WHERE id = :rid"
                ),
                {"now": now, "error": "scan_dispatch_failed", "rid": outcome["run_id"]},
            )
            db.execute(
                text(
                    "UPDATE monitoring_configs SET last_status = 'failed', "
                    "consecutive_failures = COALESCE(consecutive_failures, 0) + 1 "
                    "WHERE id = :cid"
                ),
                {"cid": cfg["id"]},
            )
            outcome = dict(
                outcome, status="failed", dispatched=0, errors=len(failed_ids)
            )
        else:
            outcome = dict(
                outcome, dispatched=dispatched, errors=len(failed_ids)
            )
    except Exception:
        db.rollback()
    return outcome


def finalize_monitoring_run(db, scan_id: str):
    """Reconcile the MonitoringRun owning ``scan_id`` from scan outcomes.

    Called by ``execute_scan`` on terminal scan state (success and failure
    paths). Aggregates per-scanner latest attempt outcomes across ALL scans in
    the run; transitions scheduled/queued/running runs to
    completed/partial/failed; updates config last_status / consecutive_failures.
    On a completed/partial transition it additionally triggers D2 change
    detection (best-effort); failed runs are marked change-skipped.
    Never raises (scheduler bookkeeping must not break scan persistence).
    Returns the run status string, or None when no linked active run exists.
    """
    try:
        srow = (
            db.execute(
                text("SELECT id, status, metadata FROM scans WHERE id = :sid"),
                {"sid": scan_id},
            )
            .mappings()
            .first()
        )
        if not srow:
            return None
        meta = _parse_json(srow.get("metadata")) or {}
        run_id = meta.get("monitoring_run_id") if isinstance(meta, dict) else None
        if not run_id:
            return None
        run = (
            db.execute(
                text(
                    "SELECT id, monitoring_config_id, status, scan_ids, change_status "
                    "FROM monitoring_runs WHERE id = :rid"
                ),
                {"rid": run_id},
            )
            .mappings()
            .first()
        )
        if not run:
            return None
        if run["status"] not in ACTIVE_RUN_STATUSES:
            return _maybe_process_terminal_run(db, run)
        scan_ids = _parse_json(run.get("scan_ids")) or []
        if not isinstance(scan_ids, list):
            scan_ids = []
        if scan_id not in scan_ids:
            scan_ids.append(scan_id)
        now = _utcnow_naive()
        total_success = 0
        total_failed = 0
        all_terminal = True
        for sid in scan_ids:
            s = (
                db.execute(text("SELECT status FROM scans WHERE id = :sid"), {"sid": sid}).fetchone()
            )
            if not s or s[0] not in TERMINAL_SCAN_STATUSES:
                all_terminal = False
            try:
                att = (
                    db.execute(
                        text(
                            "SELECT scanner, status, attempt FROM scan_results WHERE scan_id = :sid"
                        ),
                        {"sid": sid},
                    )
                    .mappings()
                    .all()
                )
            except Exception:
                att = []
            latest: dict[str, dict] = {}
            for r in att:
                prev = latest.get(r["scanner"])
                cur_att = r.get("attempt") or 0
                if prev is None or cur_att >= (prev.get("attempt") or 0):
                    latest[r["scanner"]] = r
            ok_here = sum(1 for r in latest.values() if r["status"] == "completed")
            bad_here = sum(1 for r in latest.values() if r["status"] == "failed")
            total_success += ok_here
            total_failed += bad_here
            if s and s[0] == "failed" and ok_here == 0 and bad_here == 0:
                # Terminal-failed scan that produced no scanner outcomes at
                # all (died before any attempt row, e.g. pipeline setup
                # failure): counting nothing would misreport the run as
                # completed. Count the silent scan itself as failed.
                total_failed += 1
        if not all_terminal:
            db.execute(
                text(
                    "UPDATE monitoring_runs SET status = 'running', successful_scanners = :ok, "
                    "failed_scanners = :bad WHERE id = :rid AND status IN "
                    "('scheduled', 'queued', 'running')"
                ),
                {"ok": total_success, "bad": total_failed, "rid": run_id},
            )
            db.commit()
            return "running"
        if total_failed == 0:
            status = "completed"
        elif total_success > 0:
            status = "partial"
        else:
            status = "failed"
        transitioned = db.execute(
            text(
                "UPDATE monitoring_runs SET status = :status, completed_at = :now, "
                "successful_scanners = :ok, failed_scanners = :bad, "
                "change_status = CASE WHEN :status = 'failed' THEN 'skipped' "
                "ELSE change_status END, "
                "alert_status = CASE WHEN :status = 'failed' THEN 'skipped' "
                "ELSE alert_status END "
                "WHERE id = :rid AND status IN ('scheduled', 'queued', 'running')"
            ),
            {"status": status, "now": now, "ok": total_success, "bad": total_failed, "rid": run_id},
        )
        try:
            transitioned_count = transitioned.rowcount
        except Exception:
            transitioned_count = 1
        if not transitioned_count:
            # Lost a concurrent transition race: another worker already moved
            # this run to terminal (and owns change detection). Re-read it.
            try:
                db.rollback()
            except Exception:
                pass
            try:
                cur = (
                    db.execute(
                        text("SELECT status FROM monitoring_runs WHERE id = :rid"),
                        {"rid": run_id},
                    ).fetchone()
                )
                return cur[0] if cur else None
            except Exception:
                return None
        if status == "completed":
            fail_expr = "0"
        else:
            fail_expr = "COALESCE(consecutive_failures, 0) + 1"
        db.execute(
            text(
                f"UPDATE monitoring_configs SET last_status = :status, last_scan_id = :sid, "
                f"last_run_at = COALESCE(last_run_at, :now), consecutive_failures = {fail_expr} "
                f"WHERE id = :cid"
            ),
            {"status": status, "sid": scan_id, "now": now, "cid": run["monitoring_config_id"]},
        )
        db.commit()
        if status in ("completed", "partial"):
            _run_change_detection_best_effort(db, run_id)
            _run_alert_evaluation_best_effort(db, run_id)
        return status
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return None


def _run_change_detection_best_effort(db, run_id: str) -> None:
    """Trigger D2 run comparison without ever breaking scan persistence."""
    try:
        from .change_detection import process_run_changes

        process_run_changes(db, run_id)
    except Exception:
        pass


def _run_alert_evaluation_best_effort(db, run_id: str) -> None:
    """Trigger D3 alert evaluation without ever breaking scan persistence
    or D2 change records. Runs after D2 commits, in its own transaction."""
    try:
        from .alerting import evaluate_run_alerts

        evaluate_run_alerts(db, run_id)
    except Exception:
        pass


def _maybe_process_terminal_run(db, run) -> str | None:
    """D2 entry for runs already terminal (e.g. manual runs, which complete
    synchronously at dispatch while their scans still execute).

    Waits until ALL run scans are terminal, then claims the run for change
    detection exactly once (pending->processing CAS). Failed runs are marked
    change-skipped. Never raises. Returns the run status when change
    detection was triggered, else None (preserving the historical contract
    that terminal runs yield None).
    """
    try:
        run_id = run["id"]
        if (run.get("change_status") or "") != "pending":
            return None
        scan_ids = _parse_json(run.get("scan_ids")) or []
        if not isinstance(scan_ids, list):
            scan_ids = []
        if not scan_ids:
            db.execute(
                text("UPDATE monitoring_runs SET change_status = 'skipped' WHERE id = :rid"),
                {"rid": run_id},
            )
            db.commit()
            return None
        for sid in scan_ids:
            s = (
                db.execute(text("SELECT status FROM scans WHERE id = :sid"), {"sid": sid}).fetchone()
            )
            if not s or s[0] not in TERMINAL_SCAN_STATUSES:
                return None
        if run["status"] == "failed":
            db.execute(
                text("UPDATE monitoring_runs SET change_status = 'skipped' WHERE id = :rid"),
                {"rid": run_id},
            )
            db.commit()
            return None
        if run["status"] not in ("completed", "partial"):
            return None
        _run_change_detection_best_effort(db, run_id)
        _run_alert_evaluation_best_effort(db, run_id)
        return run["status"]
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return None


@celery_app.task(name="app.monitoring_scheduler.monitoring_tick")
def monitoring_tick(max_runs=None, max_targets=None):
    """Celery beat entrypoint: one bounded scheduling pass."""
    db = SessionLocal()
    try:
        return process_due_monitoring(db, max_runs=max_runs, max_targets=max_targets)
    finally:
        db.close()

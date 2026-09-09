"""D1 worker-side scheduler tests: claiming, runs, finalize, provenance.

Uses an isolated in-memory SQLite DB with a minimal DDL mirror of the tables
the scheduler touches. The scheduler is dialect-aware (FOR UPDATE only on
Postgres), so SQLite exercises the same logic single-threaded.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import monitoring_scheduler as sched
from app.celery_app import celery_app
from app.monitoring_scheduler import (
    compute_next_run,
    finalize_monitoring_run,
    process_due_monitoring,
)
from app.scanner.profiles import get_scanners_for_profile


DDL = [
    """
    CREATE TABLE monitoring_configs (
        id TEXT PRIMARY KEY, organization_id TEXT, project_id TEXT, target_id TEXT,
        name TEXT, enabled INTEGER, frequency TEXT, profile TEXT, target_scope TEXT,
        created_by TEXT, baseline_established INTEGER, next_run_at DATETIME,
        last_run_at DATETIME, last_scan_id TEXT, last_status TEXT,
        consecutive_failures INTEGER, paused_at DATETIME, pause_reason TEXT,
        schedule TEXT, created_at DATETIME, updated_at DATETIME
    )
    """,
    """
    CREATE TABLE monitoring_runs (
        id TEXT PRIMARY KEY, monitoring_config_id TEXT, organization_id TEXT,
        project_id TEXT, status TEXT, started_at DATETIME, completed_at DATETIME,
        error TEXT, assets_discovered INTEGER, assets_changed INTEGER,
        assets_stale INTEGER, findings_created INTEGER, scan_ids TEXT,
        scanner_count INTEGER, successful_scanners INTEGER, failed_scanners INTEGER,
        correlation_id TEXT, change_status TEXT, change_error TEXT,
        change_events_count INTEGER, created_at DATETIME
    )
    """,
    """
    CREATE TABLE scans (
        id TEXT PRIMARY KEY, target_id TEXT, profile TEXT, status TEXT, phase TEXT,
        risk_score INTEGER, risk_grade TEXT, risk_level TEXT, created_at DATETIME,
        progress INTEGER, scanner_version TEXT, scanner_image_digest TEXT, metadata TEXT
    )
    """,
    """
    CREATE TABLE targets (
        id TEXT PRIMARY KEY, project_id TEXT, value TEXT, target_type TEXT, is_active INTEGER
    )
    """,
    """
    CREATE TABLE scan_results (
        id TEXT PRIMARY KEY, scan_id TEXT, scanner TEXT, status TEXT, raw_output TEXT,
        started_at DATETIME, completed_at DATETIME, duration_ms INTEGER, attempt INTEGER,
        max_attempts INTEGER, error_type TEXT, error_message TEXT, error_phase TEXT,
        retryable INTEGER, findings_count INTEGER, assets_count INTEGER, metadata TEXT
    )
    """,
    """
    CREATE TABLE scanner_definitions (
        id TEXT PRIMARY KEY, scanner_key TEXT, enabled INTEGER, current_version TEXT
    )
    """,
    """
    CREATE TABLE scanner_versions (
        id TEXT PRIMARY KEY, definition_id TEXT, version TEXT, channel TEXT,
        image_ref TEXT, image_digest TEXT
    )
    """,
    """
    CREATE TABLE scanner_health (
        id TEXT PRIMARY KEY, definition_id TEXT, version TEXT, status TEXT, checked_at DATETIME
    )
    """,
]


def _db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with engine.begin() as conn:
        for stmt in DDL:
            conn.execute(text(stmt))
    return sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _cfg(db, pid="proj-1", oid="org-1", profile="quick", frequency="daily",
         next_run=None, enabled=1, paused=None, target_id=None, failures=0):
    cid = f"cfg-{uuid.uuid4()}"
    db.execute(
        text(
            "INSERT INTO monitoring_configs (id, organization_id, project_id, target_id, name, "
            "enabled, frequency, profile, target_scope, baseline_established, next_run_at, "
            "consecutive_failures, paused_at, created_at) VALUES (:id, :oid, :pid, :tid, 'M', "
            ":en, :freq, :prof, 'all', 0, :nxt, :fail, :paused, :now)"
        ),
        {"id": cid, "oid": oid, "pid": pid, "tid": target_id, "en": enabled,
         "freq": frequency, "prof": profile, "nxt": next_run, "fail": failures,
         "paused": paused, "now": _now()},
    )
    db.commit()
    return cid


def _target(db, pid="proj-1", value="example.com", active=1):
    tid = f"tgt-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO targets (id, project_id, value, target_type, is_active) "
             "VALUES (:id, :pid, :v, 'domain', :a)"),
        {"id": tid, "pid": pid, "v": value, "a": active},
    )
    db.commit()
    return tid


class _Dispatch:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def __call__(self, **kwargs):
        if self.fail:
            raise RuntimeError("no broker")
        self.calls.append(kwargs)


def _runs(db, cid):
    return db.execute(
        text("SELECT * FROM monitoring_runs WHERE monitoring_config_id = :c"), {"c": cid}
    ).mappings().all()


def _scans(db):
    return db.execute(text("SELECT * FROM scans")).mappings().all()


# --- frequency math -------------------------------------------------------

def test_compute_next_run_intervals():
    now = _now()
    assert compute_next_run("hourly", now) == now + timedelta(hours=1)
    assert compute_next_run("six_hourly", now) == now + timedelta(hours=6)
    assert compute_next_run("daily", now) == now + timedelta(days=1)
    assert compute_next_run("weekly", now) == now + timedelta(days=7)


def test_compute_next_run_unknown_defaults_daily():
    now = _now()
    assert compute_next_run("minutely", now) == now + timedelta(days=1)


def test_coerce_dt_normalizes_aware_to_naive_utc():
    """Postgres TIMESTAMPTZ arrives aware; the scheduler compares against a
    naive now, which raises TypeError unless normalized (live 500-class bug
    in the backend twin of this logic)."""
    from app.monitoring_scheduler import _coerce_dt

    aware = datetime.now(timezone.utc) - timedelta(minutes=5)
    coerced = _coerce_dt(aware)
    assert coerced is not None and coerced.tzinfo is None
    assert coerced == aware.astimezone(timezone.utc).replace(tzinfo=None)
    assert _coerce_dt(None) is None
    naive = _now()
    assert _coerce_dt(naive) == naive


# --- due detection + run creation ------------------------------------------

def test_due_schedule_detected_and_run_created():
    Session = _db()
    db = Session()
    past = _now() - timedelta(hours=2)
    cid = _cfg(db, next_run=past)
    _target(db)
    d = _Dispatch()
    out = process_due_monitoring(db, dispatch=d)
    assert out["due"] == 1 and out["runs"] == 1 and out["scans"] == 1
    runs = _runs(db, cid)
    assert len(runs) == 1
    assert runs[0]["status"] == "scheduled"
    assert json.loads(runs[0]["scan_ids"]) and len(json.loads(runs[0]["scan_ids"])) == 1
    assert runs[0]["correlation_id"].startswith("mr:")
    assert runs[0]["scanner_count"] == 1  # quick profile
    scans = _scans(db)
    assert len(scans) == 1 and scans[0]["status"] == "queued"
    meta = json.loads(scans[0]["metadata"])
    assert meta["monitoring_run_id"] == runs[0]["id"]
    assert meta["trigger"] == "scheduled" and meta["expected_scanners"] == ["nmap"]
    assert len(d.calls) == 1 and d.calls[0]["profile"] == "quick"
    cfg = db.execute(text("SELECT * FROM monitoring_configs WHERE id = :c"), {"c": cid}).mappings().first()
    assert cfg["last_status"] == "queued"
    assert cfg["last_scan_id"] == scans[0]["id"]
    assert cfg["consecutive_failures"] == 0
    assert datetime.fromisoformat(str(cfg["next_run_at"])) > _now()
    db.close()


def test_web_profile_scanner_count():
    Session = _db()
    db = Session()
    _cfg(db, profile="web", next_run=_now() - timedelta(minutes=1))
    _target(db)
    process_due_monitoring(db, dispatch=_Dispatch())
    scans = _scans(db)
    meta = json.loads(scans[0]["metadata"])
    assert meta["expected_scanners"] == get_scanners_for_profile("web")
    assert len(meta["expected_scanners"]) == 8
    db.close()


def test_second_tick_does_not_duplicate():
    Session = _db()
    db = Session()
    _cfg(db, next_run=_now() - timedelta(minutes=5))
    _target(db)
    d = _Dispatch()
    process_due_monitoring(db, dispatch=d)
    out2 = process_due_monitoring(db, dispatch=d)
    assert out2["due"] == 0 and out2["runs"] == 0
    assert len(d.calls) == 1
    db.close()


def test_overlapping_active_run_defers():
    Session = _db()
    db = Session()
    cid = _cfg(db, next_run=_now() - timedelta(minutes=5))
    _target(db)
    rid = f"run-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO monitoring_runs (id, monitoring_config_id, organization_id, project_id, "
             "status, started_at, assets_discovered, assets_changed, assets_stale, findings_created, "
             "scan_ids, created_at) VALUES (:id, :c, 'org-1', 'proj-1', 'running', :n, 0,0,0,0,'[]', :n)"),
        {"id": rid, "c": cid, "n": _now()},
    )
    db.commit()
    out = process_due_monitoring(db, dispatch=_Dispatch())
    assert out["runs"] == 0 and out["skipped"] == 1
    assert len(_runs(db, cid)) == 1
    db.close()


def test_paused_config_not_scheduled():
    Session = _db()
    db = Session()
    _cfg(db, next_run=_now() - timedelta(hours=1), paused=_now())
    _target(db)
    out = process_due_monitoring(db, dispatch=_Dispatch())
    assert out["due"] == 0 and out["runs"] == 0
    db.close()


def test_disabled_config_not_scheduled():
    Session = _db()
    db = Session()
    _cfg(db, next_run=_now() - timedelta(hours=1), enabled=0)
    _target(db)
    out = process_due_monitoring(db, dispatch=_Dispatch())
    assert out["due"] == 0
    db.close()


def test_future_next_run_not_scheduled():
    Session = _db()
    db = Session()
    _cfg(db, next_run=_now() + timedelta(hours=5))
    _target(db)
    out = process_due_monitoring(db, dispatch=_Dispatch())
    assert out["due"] == 0
    db.close()


def test_empty_scope_marks_failed_run():
    Session = _db()
    db = Session()
    cid = _cfg(db, next_run=_now() - timedelta(minutes=1))
    out = process_due_monitoring(db, dispatch=_Dispatch())
    assert out["runs"] == 1 and out["failed"] == 1
    runs = _runs(db, cid)
    assert runs[0]["status"] == "failed" and runs[0]["error"] == "no_targets_in_scope"
    cfg = db.execute(text("SELECT consecutive_failures, last_status FROM monitoring_configs WHERE id=:c"), {"c": cid}).mappings().first()
    assert cfg["consecutive_failures"] == 1 and cfg["last_status"] == "failed"
    db.close()


def test_target_id_scope_only_that_target():
    Session = _db()
    db = Session()
    want = _target(db, value="one.example.com")
    _target(db, value="two.example.com")
    cid = _cfg(db, next_run=_now() - timedelta(minutes=1), target_id=want)
    process_due_monitoring(db, dispatch=_Dispatch())
    scans = _scans(db)
    assert len(scans) == 1 and scans[0]["target_id"] == want
    db.close()


def test_max_targets_bound():
    Session = _db()
    db = Session()
    _cfg(db, next_run=_now() - timedelta(minutes=1))
    for i in range(5):
        _target(db, value=f"h{i}.example.com")
    out = process_due_monitoring(db, dispatch=_Dispatch(), max_targets=2)
    assert out["scans"] == 2
    db.close()


def test_max_runs_bound():
    Session = _db()
    db = Session()
    for _ in range(3):
        _cfg(db, next_run=_now() - timedelta(minutes=1))
    _target(db)
    out = process_due_monitoring(db, dispatch=_Dispatch(), max_runs=2)
    assert out["runs"] == 2
    db.close()


def test_dispatch_failure_marks_run_failed_but_advances_schedule():
    Session = _db()
    db = Session()
    cid = _cfg(db, next_run=_now() - timedelta(minutes=1))
    _target(db)
    out = process_due_monitoring(db, dispatch=_Dispatch(fail=True))
    assert out["failed"] == 1
    runs = _runs(db, cid)
    assert runs[0]["status"] == "failed" and runs[0]["error"] == "scan_dispatch_failed"
    cfg = db.execute(text("SELECT next_run_at FROM monitoring_configs WHERE id=:c"), {"c": cid}).mappings().first()
    assert datetime.fromisoformat(str(cfg["next_run_at"])) > _now()
    # retry is idempotent: no duplicate run
    out2 = process_due_monitoring(db, dispatch=_Dispatch(fail=True))
    assert out2["runs"] == 0
    db.close()


# --- control-plane eligibility ----------------------------------------------

def _seed_definition(db, key, enabled=1, version="9.0.0", channel="stable", digest=None, health=None):
    did = f"def-{key}"
    db.execute(text("INSERT INTO scanner_definitions (id, scanner_key, enabled, current_version) VALUES (:id,:k,:e,:v)"),
               {"id": did, "k": key, "e": enabled, "v": version})
    db.execute(text("INSERT INTO scanner_versions (id, definition_id, version, channel, image_ref, image_digest) VALUES (:id,:d,:v,:c,'img',:dg)"),
               {"id": f"ver-{key}", "d": did, "v": version, "c": channel, "dg": digest})
    if health:
        db.execute(text("INSERT INTO scanner_health (id, definition_id, version, status, checked_at) VALUES (:id,:d,:v,:s,:n)"),
                   {"id": f"h-{key}", "d": did, "v": version, "s": health, "n": _now()})
    db.commit()


def test_disabled_scanner_excluded():
    Session = _db()
    db = Session()
    cid = _cfg(db, profile="quick", next_run=_now() - timedelta(minutes=1))
    _target(db)
    _seed_definition(db, "nmap", enabled=0)
    out = process_due_monitoring(db, dispatch=_Dispatch())
    assert out["failed"] == 1
    assert _runs(db, cid)[0]["error"] == "no_eligible_scanners"
    db.close()


def test_unhealthy_scanner_excluded():
    Session = _db()
    db = Session()
    cid = _cfg(db, profile="quick", next_run=_now() - timedelta(minutes=1))
    _target(db)
    _seed_definition(db, "nmap", health="unhealthy")
    out = process_due_monitoring(db, dispatch=_Dispatch())
    assert _runs(db, cid)[0]["error"] == "no_eligible_scanners"
    db.close()


def test_failed_channel_version_excluded():
    Session = _db()
    db = Session()
    cid = _cfg(db, profile="quick", next_run=_now() - timedelta(minutes=1))
    _target(db)
    _seed_definition(db, "nmap", channel="failed")
    out = process_due_monitoring(db, dispatch=_Dispatch())
    assert _runs(db, cid)[0]["error"] == "no_eligible_scanners"
    db.close()


def test_version_and_digest_resolved_and_preserved():
    Session = _db()
    db = Session()
    _cfg(db, profile="quick", next_run=_now() - timedelta(minutes=1))
    _target(db)
    _seed_definition(db, "nmap", version="7.95", digest="sha256:abc123")
    process_due_monitoring(db, dispatch=_Dispatch())
    scans = _scans(db)
    assert scans[0]["scanner_version"] == "7.95"
    assert scans[0]["scanner_image_digest"] == "sha256:abc123"
    meta = json.loads(scans[0]["metadata"])
    assert meta["scanner_versions"]["nmap"] == {"version": "7.95", "digest": "sha256:abc123"}
    db.close()


# --- finalize -----------------------------------------------------------------

def _mk_run_with_scan(db, cid, status="scheduled", scan_status="completed", attempts=(("nmap", "completed", 1),)):
    rid = f"run-{uuid.uuid4()}"
    sid = f"scan-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO monitoring_runs (id, monitoring_config_id, organization_id, project_id, status, "
             "started_at, assets_discovered, assets_changed, assets_stale, findings_created, scan_ids, "
             "scanner_count, correlation_id, created_at) VALUES (:id,:c,'org-1','proj-1',:st,:n,0,0,0,0,:sids,1,:corr,:n)"),
        {"id": rid, "c": cid, "st": status, "n": _now(), "sids": json.dumps([sid]), "corr": f"mr:{rid}"},
    )
    db.execute(
        text("INSERT INTO scans (id, target_id, profile, status, phase, created_at, progress, metadata) "
             "VALUES (:id,'t1','quick',:st,'done',:n,100,:m)"),
        {"id": sid, "st": scan_status, "n": _now(),
         "m": json.dumps({"monitoring_run_id": rid})},
    )
    for scanner, st, att in attempts:
        db.execute(
            text("INSERT INTO scan_results (id, scan_id, scanner, status, attempt) VALUES (:id,:s,:sc,:st,:a)"),
            {"id": f"r-{uuid.uuid4()}", "s": sid, "sc": scanner, "st": st, "a": att},
        )
    db.commit()
    return rid, sid


def test_finalize_completed_resets_failures():
    Session = _db()
    db = Session()
    cid = _cfg(db, next_run=_now() + timedelta(hours=1), failures=3)
    rid, sid = _mk_run_with_scan(db, cid)
    assert finalize_monitoring_run(db, sid) == "completed"
    run = db.execute(text("SELECT status, successful_scanners, failed_scanners FROM monitoring_runs WHERE id=:r"), {"r": rid}).mappings().first()
    assert run["status"] == "completed" and run["successful_scanners"] == 1 and run["failed_scanners"] == 0
    cfg = db.execute(text("SELECT consecutive_failures, last_status FROM monitoring_configs WHERE id=:c"), {"c": cid}).mappings().first()
    assert cfg["consecutive_failures"] == 0 and cfg["last_status"] == "completed"
    db.close()


def test_finalize_partial():
    Session = _db()
    db = Session()
    cid = _cfg(db, next_run=_now() + timedelta(hours=1))
    rid, sid = _mk_run_with_scan(db, cid, attempts=(("nmap", "completed", 1), ("tls", "failed", 2)))
    # single-scan run: scan_results has 2 scanners (web-style partial on one scan)
    assert finalize_monitoring_run(db, sid) == "partial"
    run = db.execute(text("SELECT status, successful_scanners, failed_scanners FROM monitoring_runs WHERE id=:r"), {"r": rid}).mappings().first()
    assert run["status"] == "partial" and run["successful_scanners"] == 1 and run["failed_scanners"] == 1
    db.close()


def test_finalize_all_failed():
    Session = _db()
    db = Session()
    cid = _cfg(db, next_run=_now() + timedelta(hours=1))
    rid, sid = _mk_run_with_scan(db, cid, attempts=(("nmap", "failed", 2),))
    assert finalize_monitoring_run(db, sid) == "failed"
    cfg = db.execute(text("SELECT consecutive_failures FROM monitoring_configs WHERE id=:c"), {"c": cid}).mappings().first()
    assert cfg["consecutive_failures"] == 1
    db.close()


def test_finalize_non_terminal_marks_running():
    Session = _db()
    db = Session()
    cid = _cfg(db, next_run=_now() + timedelta(hours=1))
    rid, sid = _mk_run_with_scan(db, cid, scan_status="running", attempts=(("nmap", "running", 1),))
    assert finalize_monitoring_run(db, sid) == "running"
    run = db.execute(text("SELECT status FROM monitoring_runs WHERE id=:r"), {"r": rid}).mappings().first()
    assert run["status"] == "running"
    db.close()


def test_finalize_unlinked_scan_returns_none():
    Session = _db()
    db = Session()
    db.execute(text("INSERT INTO scans (id, target_id, profile, status, phase, created_at, progress) VALUES ('sx','t1','quick','completed','done',:n,100)"), {"n": _now()})
    db.commit()
    assert finalize_monitoring_run(db, "sx") is None
    db.close()


def test_finalize_terminal_run_not_overwritten():
    Session = _db()
    db = Session()
    cid = _cfg(db, next_run=_now() + timedelta(hours=1))
    rid, sid = _mk_run_with_scan(db, cid, status="completed")
    assert finalize_monitoring_run(db, sid) is None
    db.close()


def test_finalize_failed_scan_without_outcomes_is_failed():
    """A terminal-failed scan that died before any scan_results row (e.g.
    pipeline setup failure, observed live) must fail the run — counting
    nothing would misreport it as completed."""
    Session = _db()
    db = Session()
    cid = _cfg(db, next_run=_now() + timedelta(hours=1))
    rid, sid = _mk_run_with_scan(db, cid, scan_status="failed", attempts=())
    assert finalize_monitoring_run(db, sid) == "failed"
    run = db.execute(text("SELECT status, successful_scanners, failed_scanners FROM monitoring_runs WHERE id=:r"), {"r": rid}).mappings().first()
    assert run["status"] == "failed" and run["successful_scanners"] == 0 and run["failed_scanners"] == 1
    cfg = db.execute(text("SELECT consecutive_failures, last_status FROM monitoring_configs WHERE id=:c"), {"c": cid}).mappings().first()
    assert cfg["consecutive_failures"] == 1 and cfg["last_status"] == "failed"
    db.close()


# --- beat + safety --------------------------------------------------------------

def test_beat_schedule_registered():
    beat = celery_app.conf.beat_schedule or {}
    assert "monitoring-tick" in beat
    entry = beat["monitoring-tick"]
    assert entry["task"] == "app.monitoring_scheduler.monitoring_tick"
    assert int(entry["schedule"]) >= 60


def test_monitoring_tick_task_registered_on_worker():
    """Beat sends the tick by name; the worker must have the task registered
    or every tick is rejected as unregistered (live failure). The worker app
    imports the scheduler module via celery include at startup."""
    assert "app.monitoring_scheduler" in list(celery_app.conf.include or [])
    import app.monitoring_scheduler  # noqa: F401  (what worker include does)
    assert "app.monitoring_scheduler.monitoring_tick" in celery_app.tasks


def test_summary_contains_no_customer_data():
    Session = _db()
    db = Session()
    _cfg(db, next_run=_now() - timedelta(minutes=1))
    _target(db, value="secret-internal.example.com")
    out = process_due_monitoring(db, dispatch=_Dispatch())
    blob = json.dumps(out)
    assert "secret-internal.example.com" not in blob
    assert set(out) == {"checked_at", "due", "runs", "scans", "skipped", "failed"}
    db.close()


def test_scheduler_module_never_touches_docker():
    import pathlib
    src = pathlib.Path(sched.__file__).read_text()
    for banned in ("DockerRunner", "docker.from_env", "containers.run", "subprocess", "os.system"):
        assert banned not in src


def test_dispatch_happens_after_commit():
    """Commit/dispatch ordering: the scheduler must commit run+scan rows
    before any broker dispatch so a worker never observes uncommitted rows."""
    from sqlalchemy import event as sa_event

    Session = _db()
    commits: list = []

    def _on_commit(session):
        commits.append(True)

    sa_event.listen(Session, "after_commit", _on_commit)
    try:
        db = Session()
        _cfg(db, next_run=_now() - timedelta(minutes=1))
        _target(db)
        seen: list = []

        def _recording(**kwargs):
            seen.append(len(commits) > 0)

        out = process_due_monitoring(db, dispatch=_recording)
        assert out["runs"] == 1 and out["scans"] == 1
        assert seen, "expected at least one dispatch"
        assert all(seen), "scheduler dispatch issued before commit"
        db.close()
    finally:
        sa_event.remove(Session, "after_commit", _on_commit)


def test_partial_dispatch_marks_undispatched_failed():
    """Partial broker failure: the undispatched scan is marked failed so
    finalize can still reach a terminal state from executed scans instead
    of stranding the run on a forever-queued scan."""
    Session = _db()
    db = Session()
    cid = _cfg(db, next_run=_now() - timedelta(minutes=1))
    _target(db, value="h0.example.com")
    _target(db, value="h1.example.com")
    calls: list = []

    def _flaky(**kwargs):
        calls.append(kwargs)
        if len(calls) == 2:
            raise RuntimeError("broker lost it")

    out = process_due_monitoring(db, dispatch=_flaky, max_targets=2)
    assert out["runs"] == 1 and out["scans"] == 2 and out["failed"] == 0
    runs = _runs(db, cid)
    assert len(runs) == 1 and runs[0]["status"] == "scheduled"
    scans = sorted(_scans(db), key=lambda r: r["id"])
    by_status = sorted(s["status"] for s in scans)
    assert by_status == ["failed", "queued"]
    db.close()

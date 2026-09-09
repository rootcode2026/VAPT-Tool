"""D2 change-detection engine tests: observations, comparison, idempotency.

Isolated in-memory SQLite with a minimal DDL mirror of every table the
engine touches. All comparison inputs go through the same code paths as
production (raw SQL + pure compare + deterministic event keys).
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.change_detection import (
    ASSET_CREATED,
    ASSET_METADATA_CHANGED,
    ASSET_REMOVED,
    FINDING_CREATED,
    FINDING_REOPENED,
    FINDING_RESOLVED,
    FINDING_SEVERITY_CHANGED,
    FINDING_STATUS_CHANGED,
    RELATIONSHIP_CREATED,
    RELATIONSHIP_REMOVED,
    compare_observations,
    process_run_changes,
)


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
        change_events_count INTEGER, alert_status TEXT, alert_error TEXT,
        alerts_created INTEGER, created_at DATETIME
    )
    """,
    """
    CREATE TABLE monitoring_observation_baselines (
        config_id TEXT PRIMARY KEY, run_id TEXT, observed_at DATETIME,
        assets TEXT, findings TEXT, relationships TEXT, scanners TEXT
    )
    """,
    """
    CREATE TABLE monitoring_change_events (
        id TEXT PRIMARY KEY, project_id TEXT, monitoring_config_id TEXT,
        prev_run_id TEXT, curr_run_id TEXT, change_type TEXT, asset_id TEXT,
        finding_id TEXT,         scan_id TEXT, previous_state TEXT, current_state TEXT,
        scanners TEXT, scan_ids TEXT, completeness TEXT, event_key TEXT UNIQUE,
        detected_at DATETIME, metadata TEXT
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
    CREATE TABLE scan_results (
        id TEXT PRIMARY KEY, scan_id TEXT, scanner TEXT, status TEXT, raw_output TEXT,
        started_at DATETIME, completed_at DATETIME, duration_ms INTEGER, attempt INTEGER,
        max_attempts INTEGER, error_type TEXT, error_message TEXT, error_phase TEXT,
        retryable INTEGER, findings_count INTEGER, assets_count INTEGER, metadata TEXT
    )
    """,
    """
    CREATE TABLE assets (
        id TEXT PRIMARY KEY, project_id TEXT, asset_type TEXT, value TEXT,
        status TEXT, metadata TEXT, first_seen_scan_id TEXT, last_seen_scan_id TEXT,
        first_seen_at DATETIME, last_seen_at DATETIME, created_at DATETIME, updated_at DATETIME
    )
    """,
    """
    CREATE TABLE asset_relationships (
        id TEXT PRIMARY KEY, project_id TEXT, source_asset_id TEXT,
        target_asset_id TEXT, relationship_type TEXT, last_seen_scan_id TEXT,
        metadata TEXT, created_at DATETIME, updated_at DATETIME
    )
    """,
    """
    CREATE TABLE findings (
        id TEXT PRIMARY KEY, scan_id TEXT, target_id TEXT, asset_id TEXT,
        scanner TEXT, title TEXT, severity TEXT, severity_override TEXT,
        status TEXT, cve TEXT, cwe TEXT, score INTEGER, evidence TEXT,
        metadata TEXT, created_at DATETIME
    )
    """,
    """
    CREATE TABLE targets (
        id TEXT PRIMARY KEY, project_id TEXT, value TEXT, target_type TEXT, is_active INTEGER
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


def _cfg(db, profile="quick"):
    cid = f"cfg-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO monitoring_configs (id, organization_id, project_id, name, enabled, "
             "frequency, profile, target_scope, baseline_established, created_at) "
             "VALUES (:id, 'org-1', 'proj-1', 'M', 1, 'daily', :prof, 'all', 0, :now)"),
        {"id": cid, "prof": profile, "now": _now()},
    )
    db.commit()
    return cid


def _scan(db, status="completed", target="tgt-1"):
    sid = f"scan-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO scans (id, target_id, profile, status, phase, created_at, progress, metadata) "
             "VALUES (:id, :t, 'quick', :st, 'done', :now, 100, :m)"),
        {"id": sid, "t": target, "st": status, "now": _now(),
         "m": json.dumps({"monitoring_run_id": "run-placeholder"})},
    )
    db.commit()
    return sid


def _run(db, cid, status="completed", scan_ids=None, change="pending"):
    rid = f"run-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO monitoring_runs (id, monitoring_config_id, organization_id, project_id, "
             "status, started_at, assets_discovered, assets_changed, assets_stale, findings_created, "
             "scan_ids, scanner_count, correlation_id, change_status, change_events_count, created_at) "
             "VALUES (:id, :c, 'org-1', 'proj-1', :st, :now, 0,0,0,0, :sids, 1, :corr, :ch, 0, :now)"),
        {"id": rid, "c": cid, "st": status, "now": _now(),
         "sids": json.dumps(scan_ids or []), "corr": f"mr:{rid}", "ch": change},
    )
    db.commit()
    # link scans to this run
    for sid in (scan_ids or []):
        db.execute(text("UPDATE scans SET metadata = :m WHERE id = :sid"),
                   {"m": json.dumps({"monitoring_run_id": rid}), "sid": sid})
    db.commit()
    return rid


def _asset(db, atype="ip", value="10.0.0.1", scan_id="sx", status="active", meta=None, aid=None):
    aid = aid or f"a-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata, "
             "first_seen_scan_id, last_seen_scan_id, first_seen_at, last_seen_at, created_at) "
             "VALUES (:id,'proj-1',:t,:v,:st,:m,:s,:s,:n,:n,:n)"),
        {"id": aid, "t": atype, "v": value, "st": status,
         "m": json.dumps(meta or {"ports": [80]}), "s": scan_id, "n": _now()},
    )
    db.commit()
    return aid


def _finding(db, scan_id, title="TLS weak cipher", severity="high", status="open",
             scanner="nuclei", rule="TLS-WEAK", override=None, fid=None):
    fid = fid or f"f-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, "
             "severity_override, status, metadata, created_at) "
             "VALUES (:id,:s,'tgt-1',:sc,:t,:sev,:ovr,:st,:m,:n)"),
        {"id": fid, "s": scan_id, "sc": scanner, "t": title, "sev": severity,
         "ovr": override, "st": status, "m": json.dumps({"rule_id": rule}), "n": _now()},
    )
    db.commit()
    return fid


def _rel(db, src, dst, rtype="resolves_to", scan_id="sx"):
    rid = f"r-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO asset_relationships (id, project_id, source_asset_id, target_asset_id, "
             "relationship_type, last_seen_scan_id, metadata, created_at) "
             "VALUES (:id,'proj-1',:s,:d,:t,:scan,'{}',:n)"),
        {"id": rid, "s": src, "d": dst, "t": rtype, "scan": scan_id, "n": _now()},
    )
    db.commit()
    return rid


def _events(db, run_id=None):
    q = "SELECT * FROM monitoring_change_events"
    args = {}
    if run_id:
        q += " WHERE curr_run_id = :r"
        args["r"] = run_id
    return db.execute(text(q), args).mappings().all()


def _baseline(db, cid):
    return db.execute(text("SELECT * FROM monitoring_observation_baselines WHERE config_id = :c"),
                      {"c": cid}).mappings().first()


def _change_status(db, rid):
    return db.execute(text("SELECT change_status, change_events_count FROM monitoring_runs WHERE id=:r"),
                      {"r": rid}).mappings().first()


# --- baseline + identical ----------------------------------------------------

def test_first_observation_establishes_baseline_no_events():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    sid = _scan(db)
    _asset(db, scan_id=sid)
    _finding(db, sid)
    rid = _run(db, cid, "completed", [sid])
    out = process_run_changes(db, rid)
    assert out["change_status"] == "completed" and out["events"] == 0
    assert out["baseline"] == "established"
    assert _baseline(db, cid)["run_id"] == rid
    assert _events(db, rid) == []
    db.close()


def test_identical_second_observation_no_events():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    a = _asset(db, scan_id=s1)
    _finding(db, s1)
    r1 = _run(db, cid, "completed", [s1])
    process_run_changes(db, r1)
    s2 = _scan(db)
    # same canonical asset re-observed by a different scan: update linkage
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s WHERE id = :a"), {"s": s2, "a": a})
    db.commit()
    _finding(db, s2)  # same title/severity/scanner/rule -> same fingerprint
    r2 = _run(db, cid, "completed", [s2])
    out = process_run_changes(db, r2)
    assert out["events"] == 0
    assert _events(db, r2) == []
    assert _baseline(db, cid)["run_id"] == r2
    db.close()


# --- assets ------------------------------------------------------------------

def test_new_asset_detected():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, value="10.0.0.1", scan_id=s1)
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s"), {"s": s2})
    _asset(db, value="10.0.0.2", scan_id=s2)
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    out = process_run_changes(db, r2)
    assert out["events"] == 1
    evs = _events(db, r2)
    assert evs[0]["change_type"] == ASSET_CREATED
    assert json.loads(evs[0]["current_state"])["value"] == "10.0.0.2"
    assert evs[0]["prev_run_id"] is not None and evs[0]["curr_run_id"] == r2
    db.close()


def test_metadata_change_detected():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    a = _asset(db, scan_id=s1, meta={"ports": [80]})
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s, metadata = :m WHERE id = :a"),
               {"s": s2, "m": json.dumps({"ports": [80, 443]}), "a": a})
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    out = process_run_changes(db, r2)
    assert out["events"] == 1
    assert _events(db, r2)[0]["change_type"] == ASSET_METADATA_CHANGED
    db.close()


def test_removal_detected_when_complete():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, value="10.0.0.1", scan_id=s1)
    _asset(db, value="10.0.0.9", scan_id=s1)
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    # only .1 re-observed; .9 gone from a completed observation
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s WHERE value = '10.0.0.1'"), {"s": s2})
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    out = process_run_changes(db, r2)
    assert out["events"] == 1
    ev = _events(db, r2)[0]
    assert ev["change_type"] == ASSET_REMOVED
    assert json.loads(ev["previous_state"])["value"] == "10.0.0.9"
    db.close()


def test_inactive_asset_not_re_removed():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, value="10.0.0.1", scan_id=s1)
    _asset(db, value="10.0.0.9", scan_id=s1, status="inactive")
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s WHERE value = '10.0.0.1'"), {"s": s2})
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    assert process_run_changes(db, r2)["events"] == 0
    db.close()


def test_scan_id_change_alone_creates_nothing():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    a = _asset(db, scan_id=s1, meta={"ports": [443], "service": "https"})
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s WHERE id = :a"), {"s": s2, "a": a})
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    assert process_run_changes(db, r2)["events"] == 0
    db.close()


def test_timestamp_only_metadata_ignored():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    a = _asset(db, scan_id=s1, meta={"ports": [80], "last_seen_at": "2026-01-01"})
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s, metadata = :m WHERE id = :a"),
               {"s": s2, "m": json.dumps({"ports": [80], "last_seen_at": "2026-09-09",
                                           "scan_id": s2, "sources": ["nmap", "dns"]}), "a": a})
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    assert process_run_changes(db, r2)["events"] == 0
    db.close()


def test_ordering_only_metadata_ignored():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    a = _asset(db, scan_id=s1, meta={"ports": [80, 443]})
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s, metadata = :m WHERE id = :a"),
               {"s": s2, "m": json.dumps({"ports": [443, 80]}), "a": a})
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    assert process_run_changes(db, r2)["events"] == 0
    db.close()


def test_secret_adjacent_metadata_never_stored():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, scan_id=s1, meta={"ports": [80]})
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    _asset(db, value="10.0.0.2", scan_id=s2,
           meta={"ports": [80], "api_key": "sk-live-123", "password": "hunter2",
                 "raw_output": "x" * 9000})
    # re-link baseline asset to current scan
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s WHERE value = '10.0.0.1'"), {"s": s2})
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    out = process_run_changes(db, r2)
    assert out["events"] == 1
    blob = json.dumps([dict(e) for e in _events(db, r2)])
    assert "sk-live-123" not in blob and "hunter2" not in blob
    assert len(blob) < 5000
    db.close()


# --- relationships -------------------------------------------------------------

def test_relationship_created_and_removed():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    a = _asset(db, value="10.0.0.1", scan_id=s1)
    b = _asset(db, atype="domain", value="example.com", scan_id=s1)
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s"), {"s": s2})
    _rel(db, a, b, scan_id=s2)
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    assert process_run_changes(db, r2)["events"] == 1
    assert _events(db, r2)[0]["change_type"] == RELATIONSHIP_CREATED
    # third run: relationship no longer observed -> removed
    s3 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s"), {"s": s3})
    db.execute(text("UPDATE asset_relationships SET last_seen_scan_id = NULL"))
    db.commit()
    r3 = _run(db, cid, "completed", [s3])
    out = process_run_changes(db, r3)
    assert out["events"] == 1
    assert _events(db, r3)[0]["change_type"] == RELATIONSHIP_REMOVED
    db.close()


# --- findings ------------------------------------------------------------------

def test_finding_created_resolved():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, scan_id=s1)
    _finding(db, s1, title="TLS weak cipher")
    _finding(db, s1, title="Open port banner", rule="BANNER")
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s"), {"s": s2})
    _finding(db, s2, title="TLS weak cipher")  # persists
    # banner gone from a completed observation -> resolved
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    out = process_run_changes(db, r2)
    assert out["events"] == 1
    ev = _events(db, r2)[0]
    assert ev["change_type"] == FINDING_RESOLVED
    assert json.loads(ev["previous_state"])["title"] == "Open port banner"
    db.close()


def test_finding_reopened_and_status_changed():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, scan_id=s1)
    _finding(db, s1, title="TLS weak cipher", status="resolved")
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s"), {"s": s2})
    _finding(db, s2, title="TLS weak cipher", status="open")
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    out = process_run_changes(db, r2)
    assert out["events"] == 1
    assert _events(db, r2)[0]["change_type"] == FINDING_REOPENED
    # status open -> triaged
    s3 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s"), {"s": s3})
    _finding(db, s3, title="TLS weak cipher", status="triaged")
    db.commit()
    r3 = _run(db, cid, "completed", [s3])
    out = process_run_changes(db, r3)
    assert out["events"] == 1
    assert _events(db, r3)[0]["change_type"] == FINDING_STATUS_CHANGED
    db.close()


def test_finding_severity_changed_with_override():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, scan_id=s1)
    _finding(db, s1, title="TLS weak cipher", severity="medium")
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s"), {"s": s2})
    _finding(db, s2, title="TLS weak cipher", severity="medium", override="critical")
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    out = process_run_changes(db, r2)
    assert out["events"] == 1
    ev = _events(db, r2)[0]
    assert ev["change_type"] == FINDING_SEVERITY_CHANGED
    assert json.loads(ev["current_state"])["severity"] == "critical"
    db.close()


def test_scanner_version_only_no_finding_change():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, scan_id=s1)
    _finding(db, s1, title="TLS weak cipher", scanner="nuclei")
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    # same issue reported by a different scanner build: fingerprint is
    # scanner-independent, so no infrastructure change is fabricated
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s"), {"s": s2})
    db.execute(text("UPDATE scans SET scanner_version = '9.1.0', scanner_image_digest = 'sha256:zzz' WHERE id = :s"), {"s": s2})
    _finding(db, s2, title="TLS weak cipher", scanner="nuclei")
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    assert process_run_changes(db, r2)["events"] == 0
    db.close()


# --- partial / failed / empty ----------------------------------------------------

def test_failed_scanner_causes_no_removals():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, value="10.0.0.1", scan_id=s1)
    _asset(db, value="10.0.0.9", scan_id=s1)
    _finding(db, s1, title="TLS weak cipher")
    _finding(db, s1, title="Gone finding", rule="GONE")
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    # partial run: only .1 re-observed, .9 + banner missing because their
    # scanner failed -> must NOT emit removals/resolutions
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s WHERE value = '10.0.0.1'"), {"s": s2})
    _finding(db, s2, title="TLS weak cipher")
    db.execute(text("INSERT INTO scan_results (id, scan_id, scanner, status, attempt) "
                    "VALUES (:id, :s, 'nmap', 'completed', 1)"), {"id": f"r-{uuid.uuid4()}", "s": s2})
    s3 = _scan(db, status="failed")
    db.execute(text("INSERT INTO scan_results (id, scan_id, scanner, status, attempt) "
                    "VALUES (:id, :s, 'tls', 'failed', 2)"), {"id": f"r-{uuid.uuid4()}", "s": s3})
    db.commit()
    r2 = _run(db, cid, "partial", [s2, s3])
    out = process_run_changes(db, r2)
    evs = _events(db, r2)
    types = {e["change_type"] for e in evs}
    assert ASSET_REMOVED not in types and FINDING_RESOLVED not in types
    assert RELATIONSHIP_REMOVED not in types
    # baseline must NOT advance on partial
    assert _baseline(db, cid)["run_id"] != r2
    db.close()


def test_partial_run_still_reports_created():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, value="10.0.0.1", scan_id=s1)
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s WHERE value = '10.0.0.1'"), {"s": s2})
    _asset(db, value="10.0.0.7", scan_id=s2)
    s3 = _scan(db, status="failed")
    db.commit()
    r2 = _run(db, cid, "partial", [s2, s3])
    out = process_run_changes(db, r2)
    assert out["events"] == 1
    assert _events(db, r2)[0]["change_type"] == ASSET_CREATED
    db.close()


def test_failed_run_skipped_baseline_kept():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, scan_id=s1)
    r1 = _run(db, cid, "completed", [s1])
    process_run_changes(db, r1)
    base_before = _baseline(db, cid)["run_id"]
    s2 = _scan(db, status="failed")
    r2 = _run(db, cid, "failed", [s2])
    out = process_run_changes(db, r2)
    assert out["change_status"] == "skipped"
    assert _events(db, r2) == []
    assert _baseline(db, cid)["run_id"] == base_before
    st = _change_status(db, r2)
    assert st["change_status"] == "skipped"
    db.close()


def test_empty_observation_safe():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    r1 = _run(db, cid, "completed", [s1])  # no assets/findings at all
    out = process_run_changes(db, r1)
    assert out["change_status"] == "completed" and out["events"] == 0
    assert _baseline(db, cid) is None  # emptiness never becomes baseline
    db.close()


# --- idempotency / concurrency ----------------------------------------------------

def test_reprocessing_is_idempotent():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, scan_id=s1)
    r1 = _run(db, cid, "completed", [s1])
    process_run_changes(db, r1)
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s"), {"s": s2})
    _asset(db, value="10.0.0.2", scan_id=s2)
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    first = process_run_changes(db, r2)
    assert first["events"] == 1
    second = process_run_changes(db, r2)
    assert second["events"] == 0
    assert len(_events(db, r2)) == 1
    st = _change_status(db, r2)
    assert st["change_status"] == "completed" and st["change_events_count"] == 1
    db.close()


def test_concurrent_claim_single_winner():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, scan_id=s1)
    r1 = _run(db, cid, "completed", [s1])
    # another worker already claimed it
    db.execute(text("UPDATE monitoring_runs SET change_status = 'processing' WHERE id = :r"), {"r": r1})
    db.commit()
    out = process_run_changes(db, r1)
    assert out["events"] == 0
    assert _events(db, r1) == []
    db.close()


def test_event_key_unique_constraint():
    Session = _db()
    db = Session()
    dup = "0" * 64
    db.execute(
        text("INSERT INTO monitoring_change_events (id, project_id, monitoring_config_id, curr_run_id, "
             "change_type, completeness, event_key, detected_at, metadata) "
             "VALUES ('e1','proj-1', 'cfg-x', 'run-x', 'ASSET_CREATED', 'complete', :k, :n, '{}')"),
        {"k": dup, "n": _now()},
    )
    db.commit()
    with pytest.raises(Exception):
        db.execute(
            text("INSERT INTO monitoring_change_events (id, project_id, monitoring_config_id, curr_run_id, "
                 "change_type, completeness, event_key, detected_at, metadata) "
                 "VALUES ('e2','proj-1', 'cfg-x', 'run-x', 'ASSET_CREATED', 'complete', :k, :n, '{}')"),
            {"k": dup, "n": _now()},
        )
        db.commit()
    db.rollback()
    db.close()


# --- provenance / bounds -----------------------------------------------------------

def test_provenance_recorded():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, scan_id=s1)
    process_run_changes(db, _run(db, cid, "completed", [s1]))
    s2 = _scan(db)
    db.execute(text("UPDATE assets SET last_seen_scan_id = :s"), {"s": s2})
    _finding(db, s2)
    db.execute(text("INSERT INTO scan_results (id, scan_id, scanner, status, attempt) "
                    "VALUES (:id, :s, 'nmap', 'completed', 1)"), {"id": f"r-{uuid.uuid4()}", "s": s2})
    db.commit()
    r2 = _run(db, cid, "completed", [s2])
    # version provenance is written at scan insert time in production (before
    # run processing); set it after run creation so the helper linkage update
    # does not clobber it
    db.execute(text("UPDATE scans SET scanner_version = '7.95', scanner_image_digest = 'sha256:abc', "
                    "metadata = :m WHERE id = :s"),
               {"s": s2, "m": json.dumps({"monitoring_run_id": r2,
                                          "scanner_versions": {"nmap": {"version": "7.95", "digest": "sha256:abc"}}})})
    db.commit()
    process_run_changes(db, r2)
    ev = _events(db, r2)[0]
    assert ev["curr_run_id"] == r2 and ev["prev_run_id"] is not None
    assert json.loads(ev["scan_ids"]) == [s2]
    assert "nmap" in json.loads(ev["scanners"])
    meta = json.loads(ev["metadata"])
    assert meta["curr_run_id"] == r2
    assert meta["scanner_versions"]["nmap"] == {"version": "7.95", "digest": "sha256:abc"}
    assert ev["completeness"] == "complete"
    db.close()


def test_failure_preserves_everything():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    aid = _asset(db, scan_id=s1)
    fid = _finding(db, s1)
    r1 = _run(db, cid, "completed", [s1])
    process_run_changes(db, r1)
    base_before = _baseline(db, cid)["run_id"]
    # break the baseline table so comparison raises mid-flight
    db.execute(text("DROP TABLE monitoring_observation_baselines"))
    db.commit()
    s2 = _scan(db)
    r2 = _run(db, cid, "completed", [s2])
    out = process_run_changes(db, r2)
    assert out["change_status"] == "failed" and out.get("error")
    st = _change_status(db, r2)
    assert st["change_status"] == "failed"
    # nothing destroyed
    assert db.execute(text("SELECT count(*) FROM assets")).scalar() == 1
    assert db.execute(text("SELECT count(*) FROM findings")).scalar() == 1
    assert db.execute(text("SELECT count(*) FROM scans")).scalar() == 2
    assert db.execute(text("SELECT id FROM assets WHERE id = :a"), {"a": aid}).fetchone()
    assert db.execute(text("SELECT id FROM findings WHERE id = :f"), {"f": fid}).fetchone()
    db.close()


def test_completed_run_without_scans_no_events():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    r1 = _run(db, cid, "completed", [])
    out = process_run_changes(db, r1)
    assert out["change_status"] == "completed" and out["events"] == 0
    db.close()


def test_unknown_run_skipped():
    Session = _db()
    db = Session()
    out = process_run_changes(db, "run-does-not-exist")
    assert out["change_status"] == "skipped"
    db.close()


def test_pause_resume_cycle_creates_no_duplicate_changes():
    Session = _db()
    db = Session()
    cid = _cfg(db)
    s1 = _scan(db)
    _asset(db, scan_id=s1)
    r1 = _run(db, cid, "completed", [s1])
    assert process_run_changes(db, r1)["events"] == 0
    # pause/resume touches only config scheduling state, never runs
    db.execute(text("UPDATE monitoring_configs SET paused_at = :n, next_run_at = NULL WHERE id = :c"),
               {"n": _now(), "c": cid})
    db.execute(text("UPDATE monitoring_configs SET paused_at = NULL, next_run_at = :n WHERE id = :c"),
               {"n": _now(), "c": cid})
    db.commit()
    out = process_run_changes(db, r1)
    assert out["events"] == 0
    assert _events(db, r1) == []
    st = _change_status(db, r1)
    assert st["change_status"] == "completed"
    db.close()


def test_compare_is_deterministic_and_sorted():
    base = {"assets": {}, "findings": {}, "relationships": {}}
    curr = {
        "assets": {
            ("ip", "10.0.0.2"): {"asset_id": "b", "asset_type": "ip", "value": "10.0.0.2",
                                 "status": "active", "scan_id": "s", "metadata": {}, "metadata_digest": "d"},
            ("ip", "10.0.0.1"): {"asset_id": "a", "asset_type": "ip", "value": "10.0.0.1",
                                 "status": "active", "scan_id": "s", "metadata": {}, "metadata_digest": "d"},
        },
        "findings": {},
        "relationships": {},
    }
    evs = compare_observations(base, curr, True)
    assert [e["change_type"] for e in evs] == [ASSET_CREATED, ASSET_CREATED]
    again = compare_observations(base, curr, True)
    assert [e["current_state"] for e in evs] == [e["current_state"] for e in again]

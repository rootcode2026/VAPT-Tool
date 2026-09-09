"""D3 alerting tests: mapping, policy, idempotency, dedup, resolution.

Isolated in-memory SQLite with a minimal DDL mirror. Covers the evaluator
end to end (evaluate_run_alerts) plus the pure mapping function.
"""

import json
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.alerting import evaluate_run_alerts, map_event_to_alerts


DDL = [
    """
    CREATE TABLE alert_policies (
        project_id TEXT PRIMARY KEY, enabled INTEGER, min_severity TEXT,
        alert_critical_findings INTEGER, alert_high_findings INTEGER,
        alert_reopened INTEGER, alert_asset_exposure INTEGER,
        alert_relationships INTEGER, alert_metadata_changes INTEGER,
        created_at DATETIME, updated_at DATETIME
    )
    """,
    """
    CREATE TABLE alerts (
        id TEXT PRIMARY KEY, organization_id TEXT, project_id TEXT,
        monitoring_config_id TEXT, alert_type TEXT, severity TEXT, status TEXT,
        title TEXT, description TEXT, source_change_event_id TEXT,
        source_finding_id TEXT, source_asset_id TEXT, finding_fingerprint TEXT,
        asset_key TEXT, monitoring_run_id TEXT, first_seen_at DATETIME,
        last_seen_at DATETIME, acknowledged_at DATETIME, acknowledged_by TEXT,
        resolved_at DATETIME, resolved_by TEXT, event_count INTEGER,
        dedup_key TEXT UNIQUE, metadata TEXT, created_at DATETIME, updated_at DATETIME
    )
    """,
    """
    CREATE TABLE monitoring_runs (
        id TEXT PRIMARY KEY, monitoring_config_id TEXT, organization_id TEXT,
        project_id TEXT, status TEXT, started_at DATETIME, completed_at DATETIME,
        error TEXT, scan_ids TEXT, correlation_id TEXT,
        alert_status TEXT, alert_error TEXT, alerts_created INTEGER, created_at DATETIME
    )
    """,
    """
    CREATE TABLE monitoring_change_events (
        id TEXT PRIMARY KEY, project_id TEXT, monitoring_config_id TEXT,
        prev_run_id TEXT, curr_run_id TEXT, change_type TEXT, asset_id TEXT,
        finding_id TEXT, scan_id TEXT, previous_state TEXT, current_state TEXT,
        scanners TEXT, scan_ids TEXT, completeness TEXT, event_key TEXT UNIQUE,
        detected_at DATETIME, metadata TEXT
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


def _run(db, status="completed", alert="pending", rid=None):
    rid = rid or f"run-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO monitoring_runs (id, monitoring_config_id, organization_id, project_id, "
             "status, started_at, scan_ids, correlation_id, alert_status, alerts_created, created_at) "
             "VALUES (:id, 'cfg-1', 'org-1', 'proj-1', :st, :now, '[]', :corr, :al, 0, :now)"),
        {"id": rid, "st": status, "now": _now(), "corr": f"mr:{rid}", "al": alert},
    )
    db.commit()
    return rid


def _ev(db, run_id, ctype, curr=None, prev=None, scanners=None, eid=None, proj="proj-1"):
    eid = eid or f"ev-{uuid.uuid4()}"
    db.execute(
        text("INSERT INTO monitoring_change_events (id, project_id, monitoring_config_id, prev_run_id, "
             "curr_run_id, change_type, asset_id, finding_id, scan_id, previous_state, current_state, "
             "scanners, scan_ids, completeness, event_key, detected_at, metadata) "
             "VALUES (:id, :p, 'cfg-1', 'run-prev', :r, :t, :aid, :fid, 'scan-1', :ps, :cs, "
             ":sc, '[\"scan-1\"]', 'complete', :ek, :now, '{}')"),
        {"id": eid, "p": proj, "r": run_id, "t": ctype,
         "aid": None,
         "fid": None,
         "ps": json.dumps(prev) if prev is not None else None,
         "cs": json.dumps(curr) if curr is not None else None,
         "sc": json.dumps(scanners or ["nuclei"]),
         "ek": f"ek-{uuid.uuid4()}", "now": _now()},
    )
    db.commit()
    return eid


def _finding_state(fp="fp1", title="TLS weak cipher", sev="critical", status="open", scanner="nuclei"):
    return {"fingerprint": fp, "title": title, "severity": sev, "status": status, "scanner": scanner}


def _all_alerts(db):
    return db.execute(text("SELECT * FROM alerts")).mappings().all()


def _run_alerts(db, run_id):
    return db.execute(text("SELECT * FROM alerts WHERE monitoring_run_id = :r"), {"r": run_id}).mappings().all()


# --- mapping -------------------------------------------------------------------

def _base_policy(**kw):
    p = {"enabled": True, "min_severity": "high", "alert_critical_findings": True,
         "alert_high_findings": True, "alert_reopened": True, "alert_asset_exposure": True,
         "alert_relationships": False, "alert_metadata_changes": False}
    p.update(kw)
    return p


def _event(ctype, curr=None, prev=None):
    return {"id": "ev-1", "curr_run_id": "run-1", "prev_run_id": "run-0",
            "change_type": ctype, "scan_id": "scan-1",
            "scanners": ["nuclei"], "scan_ids": ["scan-1"],
            "previous_state": prev, "current_state": curr,
            "finding_id": None, "asset_id": None}


def test_critical_finding_creates_critical_alert():
    out = map_event_to_alerts(_event("FINDING_CREATED", _finding_state(sev="critical")), _base_policy())
    assert len(out) == 1
    assert out[0]["alert_type"] == "NEW_CRITICAL_FINDING" and out[0]["severity"] == "critical"
    assert "Critical vulnerability detected" in out[0]["title"]


def test_high_finding_creates_high_alert():
    out = map_event_to_alerts(_event("FINDING_CREATED", _finding_state(sev="high")), _base_policy())
    assert len(out) == 1 and out[0]["alert_type"] == "NEW_HIGH_FINDING"


def test_reopened_creates_reopened_alert():
    out = map_event_to_alerts(_event("FINDING_REOPENED", _finding_state(sev="critical")), _base_policy())
    assert len(out) == 1 and out[0]["alert_type"] == "CRITICAL_FINDING_REOPENED"
    out = map_event_to_alerts(_event("FINDING_REOPENED", _finding_state(sev="high")), _base_policy())
    assert out[0]["alert_type"] == "HIGH_FINDING_REOPENED"


def test_exposure_asset_creates_high_exposure():
    curr = {"asset_type": "domain", "value": "example.com", "status": "active"}
    out = map_event_to_alerts(_event("ASSET_CREATED", curr), _base_policy())
    assert len(out) == 1 and out[0]["alert_type"] == "HIGH_ASSET_EXPOSURE"
    assert out[0]["severity"] == "high"


def test_non_exposure_asset_creates_relevant_change():
    curr = {"asset_type": "port", "value": "8080", "status": "active"}
    out = map_event_to_alerts(_event("ASSET_CREATED", curr), _base_policy())
    assert len(out) == 1 and out[0]["alert_type"] == "SECURITY_RELEVANT_ASSET_CHANGE"


def test_exposesarris_critical_exposure():
    curr = {"source_type": "domain", "source_value": "example.com",
            "target_type": "port", "target_value": "22",
            "relationship_type": "exposes"}
    out = map_event_to_alerts(_event("RELATIONSHIP_CREATED", curr), _base_policy())
    assert len(out) == 1 and out[0]["alert_type"] == "CRITICAL_ASSET_EXPOSURE"
    assert out[0]["severity"] == "critical"


def test_plain_relationship_gated_by_default():
    curr = {"source_type": "domain", "source_value": "a.example.com",
            "target_type": "ip", "target_value": "10.0.0.1",
            "relationship_type": "resolves_to"}
    assert map_event_to_alerts(_event("RELATIONSHIP_CREATED", curr), _base_policy()) == []
    out = map_event_to_alerts(_event("RELATIONSHIP_CREATED", curr), _base_policy(alert_relationships=True))
    assert len(out) == 1 and out[0]["alert_type"] == "SECURITY_RELEVANT_RELATIONSHIP_CHANGE"


def test_disabled_policy_suppresses():
    ev = _event("FINDING_CREATED", _finding_state(sev="critical"))
    assert map_event_to_alerts(ev, _base_policy(enabled=False)) == []
    assert map_event_to_alerts(ev, _base_policy(alert_critical_findings=False)) == []
    out = map_event_to_alerts(_event("FINDING_CREATED", _finding_state(sev="high")), _base_policy(min_severity="critical"))
    assert out == []


def test_low_info_suppressed_by_default():
    assert map_event_to_alerts(_event("FINDING_CREATED", _finding_state(sev="medium")), _base_policy()) == []
    assert map_event_to_alerts(_event("FINDING_CREATED", _finding_state(sev="info")), _base_policy()) == []


def test_metadata_changes_disabled_by_default():
    curr = {"asset_type": "ip", "value": "10.0.0.1", "metadata": {"ports": [80, 443]}}
    assert map_event_to_alerts(_event("ASSET_METADATA_CHANGED", curr), _base_policy()) == []
    out = map_event_to_alerts(_event("ASSET_METADATA_CHANGED", curr), _base_policy(alert_metadata_changes=True))
    assert len(out) == 1


def test_status_churn_and_retractions_create_nothing():
    assert map_event_to_alerts(_event("FINDING_STATUS_CHANGED", _finding_state()), _base_policy()) == []
    assert map_event_to_alerts(_event("FINDING_RESOLVED", None, _finding_state()), _base_policy()) == []
    assert map_event_to_alerts(_event("ASSET_REMOVED", None, {"asset_type": "ip", "value": "x"}), _base_policy()) == []


# --- evaluation -----------------------------------------------------------------

def test_evaluate_creates_alert_with_provenance():
    Session = _db()
    db = Session()
    rid = _run(db)
    _ev(db, rid, "FINDING_CREATED", _finding_state(sev="critical"))
    out = evaluate_run_alerts(db, rid)
    assert out["alert_status"] == "completed" and out["alerts_created"] == 1
    rows = _run_alerts(db, rid)
    assert len(rows) == 1
    a = rows[0]
    assert a["alert_type"] == "NEW_CRITICAL_FINDING" and a["severity"] == "critical"
    assert a["status"] == "open" and a["event_count"] == 1
    assert a["finding_fingerprint"] == "fp1" and a["monitoring_run_id"] == rid
    assert a["project_id"] == "proj-1" and a["organization_id"] == "org-1"
    db.close()


def test_same_event_twice_one_alert():
    Session = _db()
    db = Session()
    rid = _run(db)
    _ev(db, rid, "FINDING_CREATED", _finding_state(sev="high"))
    assert evaluate_run_alerts(db, rid)["alerts_created"] == 1
    again = evaluate_run_alerts(db, rid)
    assert again["alerts_created"] == 0
    rows = _run_alerts(db, rid)
    assert len(rows) == 1 and rows[0]["event_count"] == 1
    db.close()


def test_dedup_groups_equivalent_events():
    Session = _db()
    db = Session()
    rid = _run(db)
    # 3 equivalent events (same canonical finding, distinct event rows)
    for _ in range(3):
        _ev(db, rid, "FINDING_CREATED", _finding_state(sev="high"))
    out = evaluate_run_alerts(db, rid)
    assert out["alerts_created"] == 1
    rows = _run_alerts(db, rid)
    assert len(rows) == 1 and rows[0]["event_count"] == 3
    db.close()


def test_concurrent_claim_single_evaluation():
    Session = _db()
    db = Session()
    rid = _run(db)
    _ev(db, rid, "FINDING_CREATED", _finding_state(sev="critical"))
    db.execute(text("UPDATE monitoring_runs SET alert_status = 'processing' WHERE id = :r"), {"r": rid})
    db.commit()
    out = evaluate_run_alerts(db, rid)
    assert out["alerts_created"] == 0
    assert _run_alerts(db, rid) == []
    db.close()


def test_failed_run_creates_no_alert():
    Session = _db()
    db = Session()
    rid = _run(db, status="failed")
    out = evaluate_run_alerts(db, rid)
    assert out["alert_status"] == "skipped" and out["alerts_created"] == 0
    assert _run_alerts(db, rid) == []
    db.close()


def test_resolution_resolves_correct_alert_only():
    Session = _db()
    db = Session()
    rid = _run(db)
    _ev(db, rid, "FINDING_CREATED", _finding_state(fp="fpA", sev="critical"))
    _ev(db, rid, "FINDING_CREATED", _finding_state(fp="fpB", title="Other", sev="high"))
    evaluate_run_alerts(db, rid)
    assert len(_run_alerts(db, rid)) == 2
    r2 = _run(db)
    _ev(db, r2, "FINDING_RESOLVED", None, _finding_state(fp="fpA", status="open"))
    out = evaluate_run_alerts(db, r2)
    rows = {r["finding_fingerprint"]: r["status"] for r in _all_alerts(db)}
    assert rows["fpA"] == "resolved" and rows["fpB"] == "open"
    assert out["alerts_created"] == 0
    db.close()


def test_reopen_after_resolve_reopens_in_place():
    Session = _db()
    db = Session()
    rid = _run(db)
    _ev(db, rid, "FINDING_CREATED", _finding_state(fp="fpA", sev="high"))
    evaluate_run_alerts(db, rid)
    r2 = _run(db)
    _ev(db, r2, "FINDING_RESOLVED", None, _finding_state(fp="fpA", status="open"))
    evaluate_run_alerts(db, r2)
    r3 = _run(db)
    _ev(db, r3, "FINDING_CREATED", _finding_state(fp="fpA", sev="high"))
    out = evaluate_run_alerts(db, r3)
    rows = _all_alerts(db)
    assert len(rows) == 1  # no duplicate row
    assert rows[0]["status"] == "open" and rows[0]["event_count"] == 2
    assert out["alerts_created"] == 0
    db.close()


def test_asset_removal_resolves_exposure_alert():
    Session = _db()
    db = Session()
    rid = _run(db)
    _ev(db, rid, "ASSET_CREATED", {"asset_type": "domain", "value": "example.com", "status": "active"})
    evaluate_run_alerts(db, rid)
    assert _run_alerts(db, rid)[0]["alert_type"] == "HIGH_ASSET_EXPOSURE"
    r2 = _run(db)
    _ev(db, r2, "ASSET_REMOVED", None, {"asset_type": "domain", "value": "example.com", "status": "active"})
    evaluate_run_alerts(db, r2)
    rows = _all_alerts(db)
    assert len(rows) == 1 and rows[0]["status"] == "resolved"
    db.close()


def test_evaluation_failure_preserves_events():
    Session = _db()
    db = Session()
    rid = _run(db)
    eid = _ev(db, rid, "FINDING_CREATED", _finding_state(sev="critical"))
    db.execute(text("DROP TABLE alerts"))
    db.commit()
    out = evaluate_run_alerts(db, rid)
    assert out["alert_status"] == "failed" and out.get("alert_error")
    # D2 event intact
    assert db.execute(text("SELECT count(*) FROM monitoring_change_events WHERE id = :e"), {"e": eid}).scalar() == 1
    # run row intact
    assert db.execute(text("SELECT count(*) FROM monitoring_runs WHERE id = :r"), {"r": rid}).scalar() == 1
    db.close()


def test_unique_constraint_blocks_duplicate_source_alert():
    Session = _db()
    db = Session()
    db.execute(
        text("INSERT INTO alerts (id, organization_id, project_id, alert_type, severity, status, title, "
             "first_seen_at, last_seen_at, event_count, dedup_key, metadata) "
             "VALUES ('a1','org-1','proj-1','NEW_HIGH_FINDING','high','open','t',:n,:n,1,'dupkey','{}')"),
        {"n": _now()},
    )
    db.commit()
    with pytest.raises(Exception):
        db.execute(
            text("INSERT INTO alerts (id, organization_id, project_id, alert_type, severity, status, title, "
                 "first_seen_at, last_seen_at, event_count, dedup_key, metadata) "
                 "VALUES ('a2','org-1','proj-1','NEW_HIGH_FINDING','high','open','t',:n,:n,1,'dupkey','{}')"),
            {"n": _now()},
        )
        db.commit()
    db.rollback()
    db.close()


def test_unknown_run_skipped():
    Session = _db()
    db = Session()
    assert evaluate_run_alerts(db, "run-nope")["alert_status"] == "skipped"
    db.close()


def test_secret_material_never_stored():
    Session = _db()
    db = Session()
    rid = _run(db)
    curr = {"asset_type": "domain", "value": "example.com", "status": "active",
            "metadata": {"api_key": "sk-live", "password": "x", "raw": "y" * 5000}}
    _ev(db, rid, "ASSET_CREATED", curr)
    evaluate_run_alerts(db, rid)
    blob = json.dumps([dict(r) for r in _run_alerts(db, rid)])
    assert "sk-live" not in blob and len(blob) < 4000
    db.close()

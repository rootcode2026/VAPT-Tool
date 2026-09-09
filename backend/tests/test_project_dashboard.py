"""D4 project SOC dashboard tests: metrics, isolation, windows, bounds."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event as sa_event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.database import get_db
from app.main import app as fastapi_app

import app.models.organization  # noqa
import app.models.user  # noqa
import app.models.organization_membership  # noqa
import app.models.project  # noqa
import app.models.project_membership  # noqa
import app.models.target  # noqa
import app.models.scan  # noqa
import app.models.audit_log  # noqa
import app.models.monitoring  # noqa
import app.models.alert  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.scan import Scan
from app.models.monitoring import MonitoringConfig, MonitoringRun, MonitoringChangeEvent
from app.models.alert import Alert


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__,
        Scan.__table__, AuditLog.__table__,
        MonitoringConfig.__table__, MonitoringRun.__table__,
        MonitoringChangeEvent.__table__, Alert.__table__,
    ])
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY, project_id TEXT, asset_type TEXT, value TEXT,
                status TEXT, criticality TEXT, owner_user_id TEXT,
                first_seen_scan_id TEXT, last_seen_scan_id TEXT,
                first_seen_at DATETIME, last_seen_at DATETIME,
                metadata TEXT, created_at DATETIME, updated_at DATETIME
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, scan_id TEXT, target_id TEXT, asset_id TEXT,
                scanner TEXT, title TEXT, description TEXT, severity TEXT, score INTEGER,
                status TEXT, evidence TEXT, remediation TEXT, cve TEXT, cwe TEXT,
                assigned_to TEXT, assigned_at DATETIME, assigned_by TEXT,
                owner_user_id TEXT, owner_team_id TEXT, severity_override TEXT,
                workflow_status TEXT, closed_at DATETIME, closed_by TEXT,
                remediation_claimed_at DATETIME, remediation_claimed_by TEXT,
                ready_for_retest_at DATETIME, metadata TEXT,
                created_at DATETIME, updated_at DATETIME
            )
        """))
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-d4", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-d4", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@d4.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@d4.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@d4.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@d4.test", password_hash=pwd, role="admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, admin_b])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin", status="active"))
    proj_a = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A", description="d")
    proj_b = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B", description="d")
    proj_empty = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Empty", description="d")
    db.add_all([proj_a, proj_b, proj_empty])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=admin_a.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=analyst_a.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=viewer_a.id, role="viewer", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_empty.id, user_id=admin_a.id, role="project_admin", status="active"))
    t_a = Target(id=str(uuid.uuid4()), project_id=proj_a.id, value="example.com", target_type="domain", is_active=True)
    t_b = Target(id=str(uuid.uuid4()), project_id=proj_b.id, value="other.com", target_type="domain", is_active=True)
    db.add_all([t_a, t_b])
    db.flush()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    s1 = Scan(id=str(uuid.uuid4()), target_id=t_a.id, profile="quick", status="completed",
              risk_score=92, risk_grade="A", created_at=now - timedelta(hours=2))
    s2 = Scan(id=str(uuid.uuid4()), target_id=t_a.id, profile="web", status="completed",
              risk_score=78, risk_grade="B", created_at=now - timedelta(hours=1))
    s3 = Scan(id=str(uuid.uuid4()), target_id=t_b.id, profile="quick", status="completed",
              risk_score=10, risk_grade="D", created_at=now - timedelta(hours=1))
    db.add_all([s1, s2, s3])
    db.flush()
    # assets: web-exposed domain + internal ip
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, criticality, metadata, created_at) "
                    "VALUES (:a,'" + proj_a.id + "','domain','example.com','active','high','{\"ip\":\"93.184.216.34\"}',:n)"),
               {"a": "asset-web", "n": now})
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, criticality, metadata, created_at) "
                    "VALUES (:a,'" + proj_a.id + "','ip','10.0.0.5','active','medium','{}',:n)"),
               {"a": "asset-ip", "n": now})
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, criticality, metadata, created_at) "
                    "VALUES ('asset-b','" + proj_b.id + "','domain','other.com','active','high','{}',:n)"), {"n": now})
    # findings: critical open, high open, medium triaged, resolved closed, low false_positive, other-project critical
    rows = [
        ("f-crit", s1.id, t_a.id, "asset-web", "nuclei", "Critical TLS issue", "critical", 95, "open", now - timedelta(hours=2)),
        ("f-high", s1.id, t_a.id, "asset-web", "nuclei", "High banner leak", "high", 70, "open", now - timedelta(hours=1)),
        ("f-med", s2.id, t_a.id, "asset-ip", "nmap", "Medium port note", "medium", 45, "triaged", now - timedelta(hours=1)),
        ("f-done", s1.id, t_a.id, "asset-ip", "nmap", "Old resolved", "high", 70, "resolved", now - timedelta(days=2)),
        ("f-fp", s2.id, t_a.id, None, "zap", "Not an issue", "low", 10, "false_positive", now - timedelta(days=2)),
        ("f-re", s2.id, t_a.id, "asset-ip", "zap", "Reopened item", "high", 72, "reopened", now - timedelta(minutes=30)),
        ("f-b", s3.id, t_b.id, "asset-b", "nuclei", "Other org critical", "critical", 99, "open", now - timedelta(hours=1)),
    ]
    for fid, sid, tid, aid, sc, title, sev, score, st, ts in rows:
        db.execute(text("INSERT INTO findings (id, scan_id, target_id, asset_id, scanner, title, severity, score, status, metadata, created_at) "
                        "VALUES (:id,:s,:t,:a,:sc,:ti,:sev,:score,:st,'{}',:n)"),
                   {"id": fid, "s": sid, "t": tid, "a": aid, "sc": sc, "ti": title,
                    "sev": sev, "score": score, "st": st, "n": ts})
    # alerts: open critical + high, acknowledged medium, resolved (excluded from active)
    for aid_, atype, sev, st, age_h in [
        ("al-crit", "NEW_CRITICAL_FINDING", "critical", "open", 1),
        ("al-high", "NEW_HIGH_FINDING", "high", "open", 2),
        ("al-ack", "HIGH_ASSET_EXPOSURE", "high", "acknowledged", 3),
        ("al-res", "NEW_HIGH_FINDING", "high", "resolved", 30),
    ]:
        db.add(Alert(id=aid_, organization_id=org_a.id, project_id=proj_a.id, alert_type=atype,
                     severity=sev, status=st, title=f"Alert {aid_}", first_seen_at=now - timedelta(hours=age_h),
                     last_seen_at=now - timedelta(hours=age_h), event_count=1, dedup_key=f"dk-{aid_}",
                     extra_data={}))
    db.add(Alert(id="al-b", organization_id=org_b.id, project_id=proj_b.id, alert_type="NEW_CRITICAL_FINDING",
                 severity="critical", status="open", title="Other", first_seen_at=now, last_seen_at=now,
                 event_count=1, dedup_key="dk-al-b", extra_data={}))
    # D2 change events: 2 in 24h window, 1 older than 24h but in 7d
    for eid, ctype, age_h in [("ev-new", "ASSET_CREATED", 2), ("ev-res", "FINDING_RESOLVED", 5), ("ev-old", "FINDING_CREATED", 30)]:
        db.add(MonitoringChangeEvent(id=eid, project_id=proj_a.id, monitoring_config_id="cfg-1",
                                     curr_run_id="run-1", change_type=ctype, completeness="complete",
                                     event_key=f"ek-{eid}", detected_at=now - timedelta(hours=age_h),
                                     extra_data={}))
    # monitoring: config + runs (completed recent, failed older)
    cfg = MonitoringConfig(id="cfg-1", organization_id=org_a.id, project_id=proj_a.id, name="M",
                           enabled=True, frequency="hourly", profile="quick", target_scope="all",
                           created_by=admin_a.id, baseline_established=True,
                           next_run_at=now + timedelta(hours=1), last_status="completed")
    db.add(cfg)
    db.flush()
    r_ok = MonitoringRun(id="run-1", monitoring_config_id="cfg-1", organization_id=org_a.id,
                         project_id=proj_a.id, status="completed", scan_ids=[s1.id],
                         started_at=now - timedelta(hours=2), completed_at=now - timedelta(hours=2),
                         successful_scanners=1, failed_scanners=0, correlation_id="mr:1",
                         change_status="completed", alert_status="completed",
                         created_at=now - timedelta(hours=2))
    r_bad = MonitoringRun(id="run-0", monitoring_config_id="cfg-1", organization_id=org_a.id,
                          project_id=proj_a.id, status="failed", scan_ids=[],
                          started_at=now - timedelta(days=2), completed_at=now - timedelta(days=2),
                          error="boom", correlation_id="mr:0",
                          change_status="skipped", alert_status="skipped",
                          created_at=now - timedelta(days=2))
    db.add_all([r_ok, r_bad])
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a": proj_a, "proj_b": proj_b, "proj_empty": proj_empty,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a, "admin_b": admin_b,
            "s1": s1, "s2": s2}
    return engine, Session, tokens, objs


def _client(Session):
    def override():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    fastapi_app.dependency_overrides[get_db] = override
    return TestClient(fastapi_app)


def _auth(tokens, email):
    return {"Authorization": f"Bearer {tokens[email]}"}


def _url(objs, pid=None):
    return f"/api/v1/projects/{pid or objs['proj_a'].id}/dashboard/summary"


def _get(client, Session, tokens, objs, role="admin-a@d4.test", pid=None, window=None):
    params = {"window": window} if window else {}
    return client.get(_url(objs, pid), params=params, headers=_auth(tokens, role))


def test_auth_and_roles_can_read():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert client.get(_url(objs)).status_code == 401
        for role in ("viewer-a@d4.test", "analyst-a@d4.test", "admin-a@d4.test"):
            r = _get(client, Session, tokens, objs, role)
            assert r.status_code == 200, (role, r.text)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_project_and_tenant_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = _get(client, Session, tokens, objs, "admin-b@d4.test")
        assert r.status_code in (403, 404)
        assert client.get(_url(objs, "nope"), headers=_auth(tokens, "admin-a@d4.test")).status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_risk_uses_scan_aggregation_and_grades():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _get(client, Session, tokens, objs).json()
        # AVG(92, 78) = 85.0 -> B; other-project D scan excluded
        assert body["risk"]["score"] == 85.0
        assert body["risk"]["grade"] == "B"
        assert body["risk"]["scans_counted"] == 2
    finally:
        fastapi_app.dependency_overrides.clear()


def test_finding_counts_and_open_semantics():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        f = _get(client, Session, tokens, objs).json()["findings"]
        # open: crit + high + medium(triaged) + high(reopened) = 4; resolved/false_positive excluded
        assert f["open"] == 4
        assert f["critical"] == 1 and f["high"] == 2 and f["medium"] == 1
        assert f["low"] == 0 and f["info"] == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_alert_counts_active_only():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        a = _get(client, Session, tokens, objs).json()["alerts"]
        assert a["active"] == 3 and a["open"] == 2 and a["acknowledged"] == 1
        assert a["critical"] == 1 and a["high"] == 2
    finally:
        fastapi_app.dependency_overrides.clear()


def test_asset_counts_canonical():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        a = _get(client, Session, tokens, objs).json()["assets"]
        assert a["total"] == 2
        assert a["by_type"]["domain"] == 1 and a["by_type"]["ip"] == 1
    finally:
        fastapi_app.dependency_overrides.clear()


def test_top_findings_prioritized():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        top = _get(client, Session, tokens, objs).json()["top_findings"]
        assert [t["severity"] for t in top] == ["critical", "high", "high", "medium"]
        assert top[0]["id"] == "f-crit" and top[0]["asset_value"] == "example.com"
        assert "evidence" not in str(top) and "description" not in str(top[0])
    finally:
        fastapi_app.dependency_overrides.clear()


def test_top_alerts_prioritized():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        top = _get(client, Session, tokens, objs).json()["active_alerts"]
        assert [t["severity"] for t in top] == ["critical", "high", "high"]
        assert top[0]["id"] == "al-crit"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_changes_from_d2_and_windows():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d4.test")
        d24 = client.get(_url(objs), params={"window": "24h"}, headers=h).json()["changes"]
        assert d24["recent"] == 2 and d24["new_assets"] == 1
        assert d24["by_type"]["ASSET_CREATED"] == 1
        assert len(d24["items"]) == 2
        d7 = client.get(_url(objs), params={"window": "7d"}, headers=h).json()["changes"]
        assert d7["recent"] == 3
        assert client.get(_url(objs), params={"window": "forever"}, headers=h).status_code == 400
        assert client.get(_url(objs), params={"window": ""}, headers=h).status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_monitoring_health_correct():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        m = _get(client, Session, tokens, objs).json()["monitoring"]
        assert m["last_run"]["id"] == "run-1" and m["last_run"]["status"] == "completed"
        assert m["last_run"]["successful_scanners"] == 1
        assert m["next_run_at"] is not None
        assert m["last_good_observation"]["run_id"] == "run-1"
        assert [r["status"] for r in m["recent_runs"]] == ["completed", "failed"]
    finally:
        fastapi_app.dependency_overrides.clear()


def test_failed_runs_not_fabricated_as_changes():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _get(client, Session, tokens, objs).json()
        assert body["monitoring"]["last_run"]["status"] == "completed"
        # failed run contributes no change events and no alerts
        assert body["changes"]["recent"] == 2
    finally:
        fastapi_app.dependency_overrides.clear()


def test_empty_project_valid_empty_dashboard():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _get(client, Session, tokens, objs, pid=objs["proj_empty"].id).json()
        assert body["risk"] == {"score": None, "grade": None, "scans_counted": 0}
        assert body["findings"]["open"] == 0 and body["alerts"]["active"] == 0
        assert body["assets"]["total"] == 0 and body["changes"]["recent"] == 0
        assert body["monitoring"]["last_run"] is None and body["top_findings"] == []
    finally:
        fastapi_app.dependency_overrides.clear()


def test_no_cross_project_leakage_and_bounds():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _get(client, Session, tokens, objs).json()
        blob = str(body)
        assert "other.com" not in blob and "Other org critical" not in blob and "al-b" not in blob
        assert body["findings"]["critical"] == 1  # not 2
        assert len(str(body)) < 60000
        assert len(body["top_findings"]) <= 5 and len(body["active_alerts"]) <= 5
        assert len(body["changes"]["items"]) <= 10 and len(body["monitoring"]["recent_runs"]) <= 5
    finally:
        fastapi_app.dependency_overrides.clear()


def test_query_count_bounded():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        count = {"n": 0}

        def _before(conn, cursor, statement, parameters, context, executemany):
            count["n"] += 1

        # resolve engine from a fresh session
        probe = Session()
        eng = probe.get_bind()
        probe.close()
        sa_event.listen(eng, "before_cursor_execute", _before)
        try:
            r = client.get(_url(objs), headers=_auth(tokens, "admin-a@d4.test"))
            assert r.status_code == 200
        finally:
            sa_event.remove(eng, "before_cursor_execute", _before)
        assert count["n"] < 30, count
    finally:
        fastapi_app.dependency_overrides.clear()


def test_existing_d1_d2_d3_rows_untouched():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        db = Session()
        runs_before = db.query(MonitoringRun).count()
        alerts_before = db.query(Alert).count()
        db.close()
        for _ in range(2):
            assert client.get(_url(objs), headers=_auth(tokens, "viewer-a@d4.test")).status_code == 200
        db = Session()
        assert db.query(MonitoringRun).count() == runs_before
        assert db.query(Alert).count() == alerts_before
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()

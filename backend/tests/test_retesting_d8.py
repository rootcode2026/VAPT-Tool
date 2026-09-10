"""D8 retesting & verification tests — evidence-backed, tenant-scoped, bounded.

Verification results are server-computed from verification-scan evidence;
client-asserted pass/fail is rejected. Scanner failures never pass.
"""

import uuid
from datetime import datetime, timezone
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy import JSON as _JSON
from sqlalchemy import create_engine, text
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
import app.models.finding  # noqa
import app.models.scanner_fleet  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.scan import Scan
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.scanner_fleet import ScannerDefinition, ScannerVersion


def _setup(scanner="nmap", seed_version=True):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    # SQLite compat shim (test-only; pre-existing JSONB/fixture drift).
    for _tbl in list(Base.metadata.tables.values()):
        for _col in _tbl.columns:
            if _col.type.__class__.__name__ == "JSONB":
                _col.type = _JSON()
            try:
                _sd = _col.server_default
                if _sd is not None and "jsonb" in str(getattr(_sd, "arg", "")):
                    _col.server_default = None
            except Exception:
                pass
    from app.models.finding import (
        FindingComment, FindingHistory, FindingTag, FindingRemediation,
        FindingRetest, FindingRiskAcceptance, FindingSLA, SLAPolicy,
    )
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__, Scan.__table__,
        AuditLog.__table__, FindingComment.__table__, FindingHistory.__table__, FindingTag.__table__,
        FindingSLA.__table__, FindingRiskAcceptance.__table__, FindingRemediation.__table__,
        FindingRetest.__table__, SLAPolicy.__table__,
        ScannerDefinition.__table__, ScannerVersion.__table__,
    ])
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT, target_id TEXT, asset_id TEXT, scanner TEXT, title TEXT, description TEXT,
                severity TEXT, score INTEGER, status TEXT, evidence TEXT, remediation TEXT, cve TEXT, cwe TEXT,
                assigned_to TEXT, assigned_at DATETIME, assigned_by TEXT,
                owner_user_id TEXT, owner_team_id TEXT, severity_override TEXT,
                workflow_status TEXT, closed_at DATETIME, closed_by TEXT,
                remediation_claimed_at DATETIME, remediation_claimed_by TEXT,
                ready_for_retest_at DATETIME,
                metadata TEXT, created_at DATETIME, updated_at DATETIME
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                project_id TEXT, asset_type TEXT, value TEXT, status TEXT, metadata TEXT,
                first_seen_scan_id TEXT, last_seen_scan_id TEXT,
                first_seen_at DATETIME, last_seen_at DATETIME, created_at DATETIME, updated_at DATETIME
            )
        """))
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-d8", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-d8", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@d8.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@d8.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@d8.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@d8.test", password_hash=pwd, role="admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, admin_b])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin", status="active"))
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A1", description="d")
    proj_b1 = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B1", description="d")
    db.add_all([proj_a1, proj_b1])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=admin_a.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=analyst_a.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=viewer_a.id, role="viewer", status="active"))
    target_a1 = Target(id=str(uuid.uuid4()), project_id=proj_a1.id, value="a1.example.com", target_type="domain", is_active=True)
    target_b1 = Target(id=str(uuid.uuid4()), project_id=proj_b1.id, value="b1.example.com", target_type="domain", is_active=True)
    db.add_all([target_a1, target_b1])
    db.flush()
    scan_a1 = Scan(id=str(uuid.uuid4()), target_id=target_a1.id, profile="quick", status="completed", phase="completed", progress=100)
    scan_b1 = Scan(id=str(uuid.uuid4()), target_id=target_b1.id, profile="quick", status="completed", phase="completed", progress=100)
    db.add_all([scan_a1, scan_b1])
    db.flush()
    fid_a1 = str(uuid.uuid4())
    fid_b1 = str(uuid.uuid4())
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan, :target, :scanner, :title, :sev, :status, :ev, :meta)"),
               {"id": fid_a1, "scan": scan_a1.id, "target": target_a1.id, "scanner": scanner, "title": "Open Telnet port", "sev": "high", "status": "triaged", "ev": "ev", "meta": "{}"})
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan, :target, :scanner, :title, :sev, :status, :ev, :meta)"),
               {"id": fid_b1, "scan": scan_b1.id, "target": target_b1.id, "scanner": "nmap", "title": "F B", "sev": "medium", "status": "open", "ev": "ev", "meta": "{}"})
    if seed_version:
        definition = ScannerDefinition(id=str(uuid.uuid4()), scanner_key=scanner, display_name=scanner.title(), category="recon", family="network", enabled=True, current_version="7.94", capabilities=[], requirements=[], supported_profiles=["quick"])
        db.add(definition)
        db.flush()
        db.add(ScannerVersion(id=str(uuid.uuid4()), definition_id=definition.id, version="7.94", channel="stable", image_ref="vapt-tool-nmap:7.94", image_digest="sha256:" + "a" * 64, lifecycle_status="stable", enabled=True, approved=True, deprecated=False, approved_at=datetime.now(timezone.utc)))
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_b1": proj_b1,
            "fid_a1": fid_a1, "fid_b1": fid_b1, "scan_a1": scan_a1,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a, "admin_b": admin_b}
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


def _request(client, tokens, objs):
    with patch("app.core.celery.celery_app.send_task", return_value=None) as m:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers=_auth(tokens, "analyst-a@d8.test"))
        return r, m


def _set_scan(db_session_factory, scan_id, status):
    s = db_session_factory()
    try:
        scan = s.query(Scan).filter(Scan.id == scan_id).first()
        scan.status = status
        s.commit()
    finally:
        s.close()


def _insert_scan_finding(db_session_factory, scan_id, target_id, title, scanner="nmap", meta="{}"):
    s = db_session_factory()
    try:
        s.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan, :target, :scanner, :title, :sev, :status, :ev, :meta)"),
                  {"id": str(uuid.uuid4()), "scan": scan_id, "target": target_id, "scanner": scanner, "title": title, "sev": "high", "status": "open", "ev": "ev", "meta": meta})
        s.commit()
    finally:
        s.close()


# --- creation ---
def test_d8_request_enqueues_verification_scan():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r, m = _request(client, tokens, objs)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] == "queued"
        assert body["scanner"] == "nmap"
        assert body["scanner_version"] == "7.94"
        assert body["image_digest"] == "sha256:" + "a" * 64
        assert body["scan_id"] is not None
        assert body["baseline_fingerprint"] is not None
        assert body["result"] is None  # no premature verdict
        assert m.call_count == 1
        args, _ = m.call_args
        assert args[0] == "app.tasks.execute_scan"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_duplicate_active_409_single_execution():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        with patch("app.core.celery.celery_app.send_task", return_value=None) as m:
            assert client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers=_auth(tokens, "analyst-a@d8.test")).status_code == 201
            assert client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers=_auth(tokens, "analyst-a@d8.test")).status_code == 409
            assert m.call_count == 1
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_unknown_scanner_rejected():
    _, Session, tokens, objs = _setup(scanner="nope")
    client = _client(Session)
    try:
        with patch("app.core.celery.celery_app.send_task", return_value=None) as m:
            r = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers=_auth(tokens, "analyst-a@d8.test"))
            assert r.status_code == 400
            assert m.call_count == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_workspace_scanner_refused():
    _, Session, tokens, objs = _setup(scanner="sast")
    client = _client(Session)
    try:
        with patch("app.core.celery.celery_app.send_task", return_value=None) as m:
            r = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers=_auth(tokens, "analyst-a@d8.test"))
            # sast is catalogued but not executable for verification (empty-workspace false-pass hazard)
            assert r.status_code in (400, 409), r.text
            assert m.call_count == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_missing_stable_version_refused():
    _, Session, tokens, objs = _setup(seed_version=False)
    client = _client(Session)
    try:
        with patch("app.core.celery.celery_app.send_task", return_value=None) as m:
            r = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers=_auth(tokens, "analyst-a@d8.test"))
            assert r.status_code == 409, r.text
            assert "digest" in r.text or "stable" in r.text
            assert m.call_count == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_saturated_pool_refused():
    _, Session, tokens, objs = _setup()
    from app.models.scanner_fleet import Worker, WorkerPool
    engine = Session.kw.get("bind") if hasattr(Session, "kw") else None
    # Create pool tables on this engine and seed a saturated pool.
    if engine is not None:
        WorkerPool.__table__.create(bind=engine, checkfirst=True)
        Worker.__table__.create(bind=engine, checkfirst=True)
    s = Session()
    try:
        s.add(WorkerPool(id=str(uuid.uuid4()), name="default", scanner_families=["network"], total_capacity=1, reserved_buffer=1, status="healthy", enabled=True))
        s.commit()
    finally:
        s.close()
    client = _client(Session)
    try:
        with patch("app.core.celery.celery_app.send_task", return_value=None) as m:
            r = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers=_auth(tokens, "analyst-a@d8.test"))
            assert r.status_code == 409, r.text
            assert "capacity" in r.text
            assert m.call_count == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_no_silent_latest_provenance():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r, _ = _request(client, tokens, objs)
        body = r.json()
        assert body["image_digest"] and body["image_digest"].startswith("sha256:")
        assert body["scanner_version"] != "latest"
    finally:
        fastapi_app.dependency_overrides.clear()


# --- verification semantics ---
def _complete_scan_clean(Session, scan_id, target_id):
    _set_scan(Session, scan_id, "completed")


def test_d8_pass_resolves_finding():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        body = _request(client, tokens, objs)[0].json()
        scan_id = body["scan_id"]
        # verification scan finds something DIFFERENT (original absent)
        s = Session()
        try:
            tgt = s.query(Target).filter(Target.id == s.query(Scan).filter(Scan.id == scan_id).first().target_id).first()
            tgt_id = tgt.id
        finally:
            s.close()
        _insert_scan_finding(Session, scan_id, tgt_id, "Some unrelated banner")
        _set_scan(Session, scan_id, "completed")
        pid = objs["proj_a1"].id
        c = client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/complete", headers=H)
        assert c.status_code == 200, c.text
        assert c.json()["result"] == "passed"
        assert c.json()["status"] == "passed"
        f = client.get(f"/api/v1/findings/{objs['fid_a1']}", headers=H).json()
        assert f["status"] == "resolved"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_fail_leaves_finding_active():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        body = _request(client, tokens, objs)[0].json()
        scan_id = body["scan_id"]
        s = Session()
        try:
            tgt_id = s.query(Scan).filter(Scan.id == scan_id).first().target_id
        finally:
            s.close()
        # verification scan detects the SAME finding again
        _insert_scan_finding(Session, scan_id, tgt_id, "Open Telnet port")
        _set_scan(Session, scan_id, "completed")
        pid = objs["proj_a1"].id
        c = client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/complete", headers=H)
        assert c.status_code == 200, c.text
        assert c.json()["result"] == "failed"
        assert c.json()["resulting_fingerprint"] == c.json()["baseline_fingerprint"]
        f = client.get(f"/api/v1/findings/{objs['fid_a1']}", headers=H).json()
        assert f["status"] not in ("resolved", "closed", "verified")
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_scan_failure_never_passes():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        body = _request(client, tokens, objs)[0].json()
        _set_scan(Session, body["scan_id"], "failed")
        pid = objs["proj_a1"].id
        c = client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/complete", headers=H)
        assert c.status_code == 200, c.text
        assert c.json()["result"] == "error"
        f = client.get(f"/api/v1/findings/{objs['fid_a1']}", headers=H).json()
        assert f["status"] == "triaged"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_complete_before_scan_terminal_409():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        body = _request(client, tokens, objs)[0].json()
        pid = objs["proj_a1"].id
        c = client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/complete", headers=H)
        assert c.status_code == 409
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_click_to_verify_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        body = _request(client, tokens, objs)[0].json()
        # owner input alone must never verify: advance to running, then attempt
        # click-to-verify while the scan is still queued -> 409, finding unchanged
        assert client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{body['id']}", json={"status": "running"}, headers=H).status_code == 200
        r = client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{body['id']}", json={"status": "passed", "result": "passed"}, headers=H)
        assert r.status_code == 409, r.text
        f = client.get(f"/api/v1/findings/{objs['fid_a1']}", headers=H).json()
        assert f["status"] == "triaged"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_terminal_idempotent():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        body = _request(client, tokens, objs)[0].json()
        _set_scan(Session, body["scan_id"], "completed")
        pid = objs["proj_a1"].id
        c1 = client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/complete", headers=H)
        c2 = client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/complete", headers=H)
        assert c1.status_code == 200 and c2.status_code == 200
        assert c1.json()["result"] == c2.json()["result"] == "passed"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_lazy_sync_on_read():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        body = _request(client, tokens, objs)[0].json()
        _set_scan(Session, body["scan_id"], "completed")
        g = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/retests/{body['id']}", headers=H)
        assert g.status_code == 200
        assert g.json()["status"] == "passed"  # auto-evaluated on read
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_risk_acceptance_retained_on_pass():
    engine, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        s = Session()
        try:
            s.execute(text("UPDATE findings SET status='accepted_risk' WHERE id=:id"), {"id": objs["fid_a1"]})
            s.commit()
        finally:
            s.close()
        body = _request(client, tokens, objs)[0].json()
        _set_scan(Session, body["scan_id"], "completed")
        pid = objs["proj_a1"].id
        c = client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/complete", headers=H)
        assert c.json()["result"] == "passed"
        f = client.get(f"/api/v1/findings/{objs['fid_a1']}", headers=H).json()
        assert f["status"] == "accepted_risk"
    finally:
        fastapi_app.dependency_overrides.clear()


# --- security ---
def test_d8_auth_required():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request").status_code in (401, 403)
        assert client.get(f"/api/v1/projects/{objs['proj_a1'].id}/retests").status_code in (401, 403)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_viewer_read_only():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _request(client, tokens, objs)[0].json()
        assert client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers=_auth(tokens, "viewer-a@d8.test")).status_code == 403
        assert client.get(f"/api/v1/projects/{objs['proj_a1'].id}/retests", headers=_auth(tokens, "viewer-a@d8.test")).status_code == 200
        assert client.post(f"/api/v1/projects/{objs['proj_a1'].id}/retests/{body['id']}/cancel", headers=_auth(tokens, "viewer-a@d8.test")).status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_cross_project_finding_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        with patch("app.core.celery.celery_app.send_task", return_value=None):
            r = client.post(f"/api/v1/findings/{objs['fid_b1']}/retests/request", headers=_auth(tokens, "analyst-a@d8.test"))
            assert r.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_cross_tenant_queue_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        _request(client, tokens, objs)
        r = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/retests", headers=_auth(tokens, "admin-b@d8.test"))
        assert r.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_idor_retest_id_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _request(client, tokens, objs)[0].json()
        r = client.get(f"/api/v1/projects/{objs['proj_b1'].id}/retests/{body['id']}", headers=_auth(tokens, "admin-b@d8.test"))
        assert r.status_code == 404
        r2 = client.post(f"/api/v1/projects/{objs['proj_b1'].id}/retests/{body['id']}/cancel", headers=_auth(tokens, "admin-b@d8.test"))
        assert r2.status_code in (403, 404)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_cancel_flow():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        body = _request(client, tokens, objs)[0].json()
        pid = objs["proj_a1"].id
        c = client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/cancel", json={"reason": "mistake"}, headers=H)
        assert c.status_code == 200 and c.json()["status"] == "cancelled"
        c2 = client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/cancel", headers=H)
        assert c2.status_code == 400
        # new request allowed after cancel
        with patch("app.core.celery.celery_app.send_task", return_value=None):
            assert client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers=H).status_code == 201
    finally:
        fastapi_app.dependency_overrides.clear()


# --- queue / audit / evidence ---
def test_d8_queue_bounded_filtered():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        _request(client, tokens, objs)
        q = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/retests?status=queued&limit=10", headers=H).json()
        assert q["total"] >= 1 and len(q["items"]) <= 10
        assert all(i["status"] == "queued" for i in q["items"])
        qs = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/retests?scanner=nmap", headers=H).json()
        assert all(i["scanner"] == "nmap" for i in qs["items"])
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_audit_bounded_no_secrets():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        body = _request(client, tokens, objs)[0].json()
        _set_scan(Session, body["scan_id"], "completed")
        pid = objs["proj_a1"].id
        client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/complete", headers=H)
        h = client.get(f"/api/v1/findings/{objs['fid_a1']}/history", headers=H).json()
        assert any(x["action"] == "retest_passed" for x in h["items"])
        s = Session()
        try:
            rows = s.query(AuditLog).filter(AuditLog.project_id == pid).all()
            types = {r.event_type for r in rows}
            assert "RETEST_REQUESTED" in types
            assert "RETEST_PASSED" in types
            import json as _json
            for r in rows:
                blob = _json.dumps(getattr(r, "extra_data", None) or {})
                assert "BEGIN PRIVATE" not in blob
                assert len(blob) <= 8192
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d8_sla_untouched_by_retest():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d8.test")
    try:
        assert client.post(f"/api/v1/findings/{objs['fid_a1']}/sla/start", headers=H).status_code == 201
        body = _request(client, tokens, objs)[0].json()
        _set_scan(Session, body["scan_id"], "completed")
        pid = objs["proj_a1"].id
        client.post(f"/api/v1/projects/{pid}/retests/{body['id']}/complete", headers=H)
        sla = client.get(f"/api/v1/findings/{objs['fid_a1']}/sla", headers=H)
        assert sla.status_code == 200
        assert sla.json()["status"] in ("active", "breached")
    finally:
        fastapi_app.dependency_overrides.clear()

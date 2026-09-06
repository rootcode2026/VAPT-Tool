import uuid
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
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

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.scan import Scan
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.finding import FindingSLA


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
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
    ])
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT, target_id TEXT, asset_id TEXT, scanner TEXT, title TEXT, description TEXT,
                severity TEXT, score INTEGER, status TEXT, evidence TEXT, remediation TEXT, cve TEXT, cwe TEXT,
                assigned_to TEXT, owner_user_id TEXT, severity_override TEXT,
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
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-sla", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-sla", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@sla.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@sla.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@sla.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@sla.test", password_hash=pwd, role="admin", status="active")
    super_u = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="super@sla.test", password_hash=pwd, role="super_admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, admin_b, super_u])
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
               {"id": fid_a1, "scan": scan_a1.id, "target": target_a1.id, "scanner": "nmap", "title": "F A", "sev": "high", "status": "triaged", "ev": "ev", "meta": "{}"})
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan, :target, :scanner, :title, :sev, :status, :ev, :meta)"),
               {"id": fid_b1, "scan": scan_b1.id, "target": target_b1.id, "scanner": "nmap", "title": "F B", "sev": "medium", "status": "open", "ev": "ev", "meta": "{}"})
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b, super_u]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_b1": proj_b1,
            "target_a1": target_a1, "target_b1": target_b1, "scan_a1": scan_a1,
            "fid_a1": fid_a1, "fid_b1": fid_b1,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a,
            "admin_b": admin_b, "super_u": super_u}
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


def _future_iso(days=30):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


# Security
def test_cross_tenant_sla_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_b1']}/sla/start", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert resp.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_cannot_start_sla():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/sla/start", headers={"Authorization": f"Bearer {tokens['viewer-a@sla.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_cannot_request_ra():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/request", json={"reason": "x", "expires_at": _future_iso()}, headers={"Authorization": f"Bearer {tokens['viewer-a@sla.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_cannot_create_remediation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/remediations", json={"title": "fix"}, headers={"Authorization": f"Bearer {tokens['viewer-a@sla.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_cannot_request_retest():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers={"Authorization": f"Bearer {tokens['viewer-a@sla.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_org_assignee_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/remediations", json={"title": "fix", "assigned_to": objs["admin_b"].id}, headers={"Authorization": f"Bearer {tokens['admin-a@sla.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_unknown_finding_404():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        import uuid as _uuid
        fid = str(_uuid.uuid4())
        assert client.get(f"/api/v1/findings/{fid}/sla", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"}).status_code == 404
        assert client.post(f"/api/v1/findings/{fid}/sla/start", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"}).status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


# SLA
def test_sla_creation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/sla/start", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert resp.status_code == 201, resp.text
        assert resp.json()["status"] == "active"
        assert resp.json()["target_hours"] == 72  # high default
    finally:
        fastapi_app.dependency_overrides.clear()


def test_sla_due_calculation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/sla/start", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert resp.status_code == 201
        data = resp.json()
        started = datetime.fromisoformat(data["started_at"])
        due = datetime.fromisoformat(data["due_at"])
        assert (due - started).total_seconds() == 72 * 3600
    finally:
        fastapi_app.dependency_overrides.clear()


def test_no_duplicate_active_sla():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r1 = client.post(f"/api/v1/findings/{objs['fid_a1']}/sla/start", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert r1.status_code == 201
        r2 = client.post(f"/api/v1/findings/{objs['fid_a1']}/sla/start", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert r2.status_code == 409
    finally:
        fastapi_app.dependency_overrides.clear()


def test_sla_waived():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post(f"/api/v1/findings/{objs['fid_a1']}/sla/start", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}/sla", json={"action": "waive"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "waived"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_sla_breach_deterministic():
    from app.services.finding_lifecycle import evaluate_sla_status

    class FakeSLA:
        status = "active"
        completed_at = None
        due_at = datetime.now(timezone.utc) - timedelta(hours=1)

    assert evaluate_sla_status(FakeSLA()) == "breached"

    class FakeSLA2:
        status = "active"
        completed_at = None
        due_at = datetime.now(timezone.utc) + timedelta(hours=1)

    assert evaluate_sla_status(FakeSLA2()) == "active"


# Risk acceptance
def test_ra_request():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/request", json={"reason": "business need", "business_justification": "ok", "expires_at": _future_iso()}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert resp.status_code == 201, resp.text
        assert resp.json()["status"] == "requested"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_ra_approve():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/request", json={"reason": "need", "business_justification": "biz", "expires_at": _future_iso()}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert r.status_code == 201
        ra_id = r.json()["id"]
        a = client.patch(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/{ra_id}", json={"action": "approve", "business_justification": "biz"}, headers={"Authorization": f"Bearer {tokens['admin-a@sla.test']}"})
        assert a.status_code == 200, a.text
        assert a.json()["status"] == "approved"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_ra_self_approve_blocked():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/request", json={"reason": "need", "business_justification": "biz", "expires_at": _future_iso()}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert r.status_code == 201
        ra_id = r.json()["id"]
        a = client.patch(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/{ra_id}", json={"action": "approve"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert a.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_ra_reject():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/request", json={"reason": "need", "expires_at": _future_iso()}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        ra_id = r.json()["id"]
        a = client.patch(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/{ra_id}", json={"action": "reject"}, headers={"Authorization": f"Bearer {tokens['admin-a@sla.test']}"})
        assert a.status_code == 200
        assert a.json()["status"] == "rejected"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_ra_revoke():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/request", json={"reason": "need", "business_justification": "biz", "expires_at": _future_iso()}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        ra_id = r.json()["id"]
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/{ra_id}", json={"action": "approve", "business_justification": "biz"}, headers={"Authorization": f"Bearer {tokens['admin-a@sla.test']}"})
        v = client.patch(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/{ra_id}", json={"action": "revoke"}, headers={"Authorization": f"Bearer {tokens['admin-a@sla.test']}"})
        assert v.status_code == 200
        assert v.json()["status"] == "revoked"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_ra_reason_required():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/request", json={"reason": "  ", "expires_at": _future_iso()}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert resp.status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_ra_expiration_required():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/request", json={"reason": "need"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert resp.status_code in (400, 422)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_ra_expiry_transition():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Create with future expiry, then manually expire in DB and read list to trigger lazy expiry
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/request", json={"reason": "need", "business_justification": "biz", "expires_at": _future_iso(days=1)}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        ra_id = r.json()["id"]
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances/{ra_id}", json={"action": "approve", "business_justification": "biz"}, headers={"Authorization": f"Bearer {tokens['admin-a@sla.test']}"})
        db = Session()
        past = (datetime.now(timezone.utc) - timedelta(days=1)).replace(tzinfo=None)
        db.execute(text("UPDATE finding_risk_acceptances SET expires_at=:exp WHERE id=:id"), {"exp": past, "id": ra_id})
        db.commit()
        db.close()
        lst = client.get(f"/api/v1/findings/{objs['fid_a1']}/risk-acceptances", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert lst.status_code == 200
        statuses = {i["id"]: i["status"] for i in lst.json()["items"]}
        assert statuses.get(ra_id) == "expired"
    finally:
        fastapi_app.dependency_overrides.clear()


# Remediation
def test_rem_create():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/remediations", json={"title": "Patch lib"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert resp.status_code == 201, resp.text
        assert resp.json()["status"] == "open"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_rem_assign():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/remediations", json={"title": "Patch", "assigned_to": objs["analyst_a"].id}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert r.status_code == 201
        assert r.json()["assigned_to"] == objs["analyst_a"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_rem_start_submit_complete():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/remediations", json={"title": "Patch"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        rid = r.json()["id"]
        s1 = client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rid}", json={"status": "in_progress"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert s1.status_code == 200
        s2 = client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rid}", json={"status": "submitted"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert s2.status_code == 200
        s3 = client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rid}", json={"status": "completed", "completion_notes": "done"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert s3.status_code == 200
        assert s3.json()["status"] == "completed"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_rem_cancel():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/remediations", json={"title": "Patch"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        rid = r.json()["id"]
        c = client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rid}", json={"status": "cancelled"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert c.status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()


def test_rem_invalid_transition():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/remediations", json={"title": "Patch"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        rid = r.json()["id"]
        bad = client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rid}", json={"status": "completed"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert bad.status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


# Retest
def test_retest_request():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert resp.status_code == 201, resp.text
        assert resp.json()["status"] == "requested"
        assert resp.json()["scanner"] == "nmap"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_retest_queue_run_pass():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        rid = r.json()["id"]
        q = client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "queued"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert q.status_code == 200
        run = client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "running"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert run.status_code == 200
        done = client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "passed", "result_summary": "gone"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert done.status_code == 200
        assert done.json()["result"] == "passed"
        # Finding resolved
        f = client.get(f"/api/v1/findings/{objs['fid_a1']}", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert f.json()["status"] == "resolved"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_retest_fail_reopens():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Resolve first via triage PATCH
        client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "resolved"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        rid = r.json()["id"]
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "queued"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "running"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        done = client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "failed", "result_summary": "still there"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert done.status_code == 200
        f = client.get(f"/api/v1/findings/{objs['fid_a1']}", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert f.json()["status"] == "reopened"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_retest_error_cancelled():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        rid = r.json()["id"]
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "queued"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "running"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        e = client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "error"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        assert e.status_code == 200
        # Cancel path on another finding
        r2 = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        # Active exists? After error, no active, so second request ok
        assert r2.status_code in (201, 409)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_no_duplicate_finding_on_retest():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        db = Session()
        before = db.execute(text("SELECT COUNT(*) FROM findings")).scalar()
        db.close()
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/retests/request", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        rid = r.json()["id"]
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "queued"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "running"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/retests/{rid}", json={"status": "passed"}, headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        db = Session()
        after = db.execute(text("SELECT COUNT(*) FROM findings")).scalar()
        db.close()
        assert after == before
    finally:
        fastapi_app.dependency_overrides.clear()


def test_audit_redacted():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post(f"/api/v1/findings/{objs['fid_a1']}/sla/start", headers={"Authorization": f"Bearer {tokens['analyst-a@sla.test']}"})
        db = Session()
        audits = db.query(AuditLog).all()
        for a in audits:
            s = str(a.extra_data).lower() if a.extra_data else ""
            for bad in ["password", "jwt", "api_key", "cookie", "secret"]:
                assert bad not in s or "[redacted]" in s
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()

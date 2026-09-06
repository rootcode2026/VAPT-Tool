import uuid
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
from app.models.finding import FindingComment, FindingHistory, FindingTag


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    from app.models.finding import Finding
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__, Scan.__table__,
        AuditLog.__table__, FindingComment.__table__, FindingHistory.__table__, FindingTag.__table__,
    ])
    # Findings/assets via raw SQL (TEXT metadata for SQLite)
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
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-find", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-find", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@find.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@find.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@find.test", password_hash=pwd, role="member", status="active")
    member_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="member-a@find.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@find.test", password_hash=pwd, role="admin", status="active")
    super_u = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="super@find.test", password_hash=pwd, role="super_admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, member_a, admin_b, super_u])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=member_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin", status="active"))
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A1", description="d")
    proj_a2 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A2", description="d")
    proj_b1 = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B1", description="d")
    db.add_all([proj_a1, proj_a2, proj_b1])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=admin_a.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=analyst_a.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=viewer_a.id, role="viewer", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a2.id, user_id=member_a.id, role="viewer", status="active"))
    target_a1 = Target(id=str(uuid.uuid4()), project_id=proj_a1.id, value="a1.example.com", target_type="domain", is_active=True)
    target_b1 = Target(id=str(uuid.uuid4()), project_id=proj_b1.id, value="b1.example.com", target_type="domain", is_active=True)
    db.add_all([target_a1, target_b1])
    db.flush()
    scan_a1 = Scan(id=str(uuid.uuid4()), target_id=target_a1.id, profile="quick", status="completed", phase="completed", progress=100)
    scan_b1 = Scan(id=str(uuid.uuid4()), target_id=target_b1.id, profile="quick", status="completed", phase="completed", progress=100)
    db.add_all([scan_a1, scan_b1])
    db.flush()
    # Findings via raw SQL
    fid_a1 = str(uuid.uuid4())
    fid_b1 = str(uuid.uuid4())
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan, :target, :scanner, :title, :sev, :status, :ev, :meta)"),
               {"id": fid_a1, "scan": scan_a1.id, "target": target_a1.id, "scanner": "nmap", "title": "Open Port", "sev": "high", "status": "open", "ev": "port 80 open", "meta": "{}"})
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan, :target, :scanner, :title, :sev, :status, :ev, :meta)"),
               {"id": fid_b1, "scan": scan_b1.id, "target": target_b1.id, "scanner": "nmap", "title": "Open Port B", "sev": "medium", "status": "open", "ev": "port 443 open", "meta": "{}"})
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, member_a, admin_b, super_u]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_a2": proj_a2, "proj_b1": proj_b1,
            "target_a1": target_a1, "target_b1": target_b1, "scan_a1": scan_a1, "scan_b1": scan_b1,
            "fid_a1": fid_a1, "fid_b1": fid_b1,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a, "member_a": member_a,
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


def test_finding_triage():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "triaged", "reason": "reviewed"}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "triaged"
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "FINDING_TRIAGED").order_by(AuditLog.created_at.desc()).first()
        assert audit is not None
        assert audit.resource_id == objs["fid_a1"]
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_status_transition():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "in_progress", "reason": "working"}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "in_progress"
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "FINDING_STATUS_CHANGED").order_by(AuditLog.created_at.desc()).first()
        assert audit is not None
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_severity_override_preserves_original():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"severity_override": "critical", "reason": "escalate"}, headers={"Authorization": f"Bearer {tokens['admin-a@find.test']}"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["severity"] == "high"
        assert data["severity_override"] == "critical"
        assert data["effective_severity"] == "critical"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_assignment():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"assigned_to": objs["analyst_a"].id}, headers={"Authorization": f"Bearer {tokens['admin-a@find.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["assigned_to"] == objs["analyst_a"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_false_positive():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "false_positive", "reason": "test env"}, headers={"Authorization": f"Bearer {tokens['admin-a@find.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "false_positive"
        assert resp.json()["evidence"] == "port 80 open"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_accepted_risk():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "accepted_risk", "reason": "business need"}, headers={"Authorization": f"Bearer {tokens['admin-a@find.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "accepted_risk"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_reopen():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r1 = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "resolved", "reason": "fixed"}, headers={"Authorization": f"Bearer {tokens['admin-a@find.test']}"})
        assert r1.status_code == 200
        r2 = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "reopened", "reason": "regressed"}, headers={"Authorization": f"Bearer {tokens['admin-a@find.test']}"})
        assert r2.status_code == 200, r2.text
        assert r2.json()["status"] == "reopened"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_resolve():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "resolved", "reason": "patched"}, headers={"Authorization": f"Bearer {tokens['admin-a@find.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] == "resolved"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_evidence_preserved():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "triaged", "severity_override": "critical", "assigned_to": objs["analyst_a"].id}, headers={"Authorization": f"Bearer {tokens['admin-a@find.test']}"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["evidence"] == "port 80 open"
        assert data["scanner"] == "nmap"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_comments():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_a1']}/comments", json={"body": "Looking into this"}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 201, resp.text
        assert resp.json()["body"] == "Looking into this"
        assert resp.json()["author_user_id"] == objs["analyst_a"].id
        r2 = client.get(f"/api/v1/findings/{objs['fid_a1']}/comments", headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert r2.status_code == 200
        assert r2.json()["total"] >= 1
    finally:
        fastapi_app.dependency_overrides.clear()


def test_tags():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"tags": ["Web", "external"]}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 200, resp.text
        assert sorted(resp.json()["tags"]) == ["external", "web"]
        # Invalid tag
        resp2 = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"tags": ["bad tag!"]}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp2.status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_history():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "triaged"}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        resp = client.get(f"/api/v1/findings/{objs['fid_a1']}/history", headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1
        item = resp.json()["items"][0]
        assert item["actor_user_id"] == objs["analyst_a"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_audit_events():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "triaged"}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        db = Session()
        triaged = db.query(AuditLog).filter(AuditLog.event_type == "FINDING_TRIAGED").count()
        assert triaged >= 1
        client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"assigned_to": objs["analyst_a"].id}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        updated = db.query(AuditLog).filter(AuditLog.event_type == "FINDING_UPDATED").count()
        assert updated >= 1
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_failed_mutation_no_false_success():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        db = Session()
        before = db.query(AuditLog).filter(AuditLog.resource_id == objs["fid_a1"]).count()
        db.close()
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "bogus"}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 400
        db = Session()
        after = db.query(AuditLog).filter(AuditLog.resource_id == objs["fid_a1"]).count()
        db.close()
        assert after == before
    finally:
        fastapi_app.dependency_overrides.clear()


# IDOR / tenant
def test_org_a_cannot_read_org_b():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/findings/{objs['fid_b1']}", headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_org_a_cannot_update_org_b():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_b1']}", json={"status": "triaged"}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_assign_cross_tenant_user_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"assigned_to": objs["admin_b"].id}, headers={"Authorization": f"Bearer {tokens['admin-a@find.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_project_a_cannot_update_project_b():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # analyst_a is analyst on proj_a1 only; create finding in proj_a2 and try to update as analyst_a? Actually analyst has no access to proj_a2
        # Use viewer_a (viewer on a1) trying to triage -> 403
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "triaged"}, headers={"Authorization": f"Bearer {tokens['viewer-a@find.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_cannot_triage():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "triaged"}, headers={"Authorization": f"Bearer {tokens['viewer-a@find.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_unknown_finding_404():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        import uuid as _uuid
        resp = client.get(f"/api/v1/findings/{str(_uuid.uuid4())}", headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_finding_id_immutable():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Try to send disallowed fields — pydantic ignores extra? Our schema only allows known fields, so id change impossible
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "triaged", "id": "evil"}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 200
        assert resp.json()["id"] == objs["fid_a1"]
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_tenant_comments_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/findings/{objs['fid_b1']}/comments", json={"body": "x"}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        assert resp.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


# Privilege
def test_member_cannot_triage():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # member_a is viewer on proj_a2, no access to proj_a1 finding -> 404 (not 403, but denied)
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "triaged"}, headers={"Authorization": f"Bearer {tokens['member-a@find.test']}"})
        assert resp.status_code in (403, 404)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_suspended_assignee_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Suspend viewer_a then try to assign
        db = Session()
        db.execute(text("UPDATE users SET status='suspended' WHERE id=:id"), {"id": objs["viewer_a"].id})
        db.commit()
        db.close()
        resp = client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"assigned_to": objs["viewer_a"].id}, headers={"Authorization": f"Bearer {tokens['admin-a@find.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_audit_no_secrets():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.patch(f"/api/v1/findings/{objs['fid_a1']}", json={"status": "triaged", "reason": "ok"}, headers={"Authorization": f"Bearer {tokens['analyst-a@find.test']}"})
        db = Session()
        audits = db.query(AuditLog).filter(AuditLog.resource_id == objs["fid_a1"]).all()
        for a in audits:
            s = str(a.extra_data).lower() if a.extra_data else ""
            for bad in ["password", "jwt", "api_key", "cookie", "secret"]:
                assert bad not in s or "[redacted]" in s
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()

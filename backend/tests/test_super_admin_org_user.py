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
import app.models.target  # noqa
import app.models.scan  # noqa

from app.models.organization import Organization
from app.models.user import User
from app.models.audit_log import AuditLog


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    from app.models.project import Project
    from app.models.target import Target
    from app.models.scan import Scan
    from app.models.organization_membership import OrganizationMembership
    from app.models.project_membership import ProjectMembership

    # ORM tables that are SQLite-compatible (Organization/User now include status/created_at)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__,
        User.__table__,
        Project.__table__,
        Target.__table__,
        Scan.__table__,
        OrganizationMembership.__table__,
        ProjectMembership.__table__,
        Base.metadata.tables["audit_logs"],
    ])
    # Create findings/assets tables for admin org detail aggregates (SQLite TEXT instead of JSONB)
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT, target_id TEXT, asset_id TEXT, scanner TEXT, title TEXT, description TEXT,
                    severity TEXT, score INTEGER, status TEXT, evidence TEXT, remediation TEXT, cve TEXT, cwe TEXT,
                    metadata TEXT, created_at DATETIME
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY,
                    project_id TEXT, first_seen_scan_id TEXT, last_seen_scan_id TEXT, asset_type TEXT, value TEXT,
                    status TEXT, metadata TEXT, first_seen_at DATETIME, last_seen_at DATETIME, created_at DATETIME, updated_at DATETIME
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS asset_relationships (
                    id TEXT PRIMARY KEY,
                    project_id TEXT, source_asset_id TEXT, target_asset_id TEXT, relationship_type TEXT,
                    last_seen_scan_id TEXT,
                    metadata TEXT, created_at DATETIME, updated_at DATETIME
                )
            """))
    except Exception:
        pass
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-7b", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-7b", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    super_u = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="super@7b.test", password_hash=pwd, role="super_admin", status="active")
    org_admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@7b.test", password_hash=pwd, role="admin", status="active")
    member_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="member-a@7b.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@7b.test", password_hash=pwd, role="member", status="active")
    org_admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@7b.test", password_hash=pwd, role="admin", status="active")
    db.add_all([super_u, org_admin_a, member_a, viewer_a, org_admin_b])
    db.flush()
    from app.models.organization_membership import OrganizationMembership
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=org_admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=member_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=org_admin_b.id, role="org_admin", status="active"))
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [super_u, org_admin_a, member_a, viewer_a, org_admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "super_u": super_u, "org_admin_a": org_admin_a, "member_a": member_a, "viewer_a": viewer_a, "org_admin_b": org_admin_b}
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


def test_super_admin_can_list_organizations():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/organizations?page=1&page_size=10", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["total"] >= 2
    finally:
        fastapi_app.dependency_overrides.clear()


def test_super_admin_can_create_organization():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/organizations", json={"name": "New Org 7B", "slug": "new-org-7b", "status": "active"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 201, resp.text
        assert resp.json()["slug"] == "new-org-7b"
        # Audit
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "ORGANIZATION_CREATED").order_by(AuditLog.created_at.desc()).first()
        assert audit is not None
        assert audit.organization_id == resp.json()["id"]
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_super_admin_can_view_organization():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/admin/organizations/{objs['org_a'].id}", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["id"] == objs["org_a"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_super_admin_can_update_organization():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/admin/organizations/{objs['org_a'].id}", json={"name": "Org A Updated", "status": "suspended"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["name"] == "Org A Updated"
        assert resp.json()["status"] == "suspended"
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "ORGANIZATION_UPDATED").order_by(AuditLog.created_at.desc()).first()
        assert audit is not None
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_duplicate_slug_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/organizations", json={"name": "Dup", "slug": "org-a-7b", "status": "active"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 409
    finally:
        fastapi_app.dependency_overrides.clear()


def test_invalid_org_data_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/organizations", json={"name": "", "slug": "bad slug!", "status": "evil"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code in (400, 422)
        # Valid name but invalid status should be 400
        resp2 = client.post("/api/v1/admin/organizations", json={"name": "Valid Name", "slug": "valid-slug-7b", "status": "evil"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp2.status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_org_admin_denied_admin_org():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/organizations", headers={"Authorization": f"Bearer {tokens['admin-a@7b.test']}"})
        assert resp.status_code == 403
        resp2 = client.post("/api/v1/admin/organizations", json={"name": "Nope", "slug": "nope", "status": "active"}, headers={"Authorization": f"Bearer {tokens['admin-a@7b.test']}"})
        assert resp2.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_member_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/organizations", headers={"Authorization": f"Bearer {tokens['member-a@7b.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_tenant_org_manipulation_impossible():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Org admin of A cannot update Org B
        resp = client.patch(f"/api/v1/admin/organizations/{objs['org_b'].id}", json={"name": "Hacked"}, headers={"Authorization": f"Bearer {tokens['admin-a@7b.test']}"})
        assert resp.status_code == 403
        # Super admin can
        resp2 = client.patch(f"/api/v1/admin/organizations/{objs['org_b'].id}", json={"name": "Legit Update"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp2.status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()


def test_safe_404():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        fake = str(uuid.uuid4())
        resp = client.get(f"/api/v1/admin/organizations/{fake}", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 404
        resp2 = client.get(f"/api/v1/admin/users/{fake}", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp2.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_super_admin_can_list_users():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/users?page=1&page_size=10", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["total"] >= 5
        for u in resp.json()["items"]:
            assert "password" not in str(u).lower()
            assert "token" not in str(u).lower()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_pagination_users():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/users?page=1&page_size=2", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 200
        assert len(resp.json()["items"]) == 2
        assert resp.json()["total"] >= 5
    finally:
        fastapi_app.dependency_overrides.clear()


def test_org_filter_users():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/admin/users?organization_id={objs['org_a'].id}", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 200
        for u in resp.json()["items"]:
            assert u["organization_id"] == objs["org_a"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_super_admin_can_view_user():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/admin/users/{objs['member_a'].id}", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["id"] == objs["member_a"].id
        assert "password" not in str(resp.json()).lower()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_password_never_returned():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/admin/users/{objs['member_a'].id}", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 200
        txt = str(resp.json()).lower()
        for s in ["password", "password_hash", "jwt", "token", "secret"]:
            assert s not in txt
    finally:
        fastapi_app.dependency_overrides.clear()


def test_org_admin_denied_users():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/users", headers={"Authorization": f"Bearer {tokens['admin-a@7b.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_super_admin_promote_member():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        from app.models.organization_membership import OrganizationMembership
        db = Session()
        new_id = str(uuid.uuid4())
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="promote@7b.test", password_hash=hash_password("x"), role="member", status="active"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=new_id, role="member", status="active"))
        db.commit()
        db.close()
        # Super admin promotes via PATCH organization_members
        resp = client.patch(f"/api/v1/organizations/{objs['org_a'].id}/members/{new_id}", json={"role": "org_admin"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 200, resp.text
        # A plain member cannot self-promote: member_a (member) tries to promote self
        resp2 = client.patch(f"/api/v1/organizations/{objs['org_a'].id}/members/{objs['member_a'].id}", json={"role": "org_admin"}, headers={"Authorization": f"Bearer {tokens['member-a@7b.test']}"})
        assert resp2.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_super_admin_not_via_membership():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Try to grant super_admin via membership API — should be blocked
        db = Session()
        new_id = str(uuid.uuid4())
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="supergrant@7b.test", password_hash=hash_password("x"), role="member", status="active"))
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/organizations/{objs['org_a'].id}/members", json={"user_id": new_id, "role": "super_admin"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code in (400, 403)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_last_admin_protection():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # org_a has only one org_admin (admin-a), try to remove
        resp = client.delete(f"/api/v1/organizations/{objs['org_a'].id}/members/{objs['org_admin_a'].id}", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 409
    finally:
        fastapi_app.dependency_overrides.clear()


def test_add_member_audit():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        db = Session()
        new_id = str(uuid.uuid4())
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="auditadd@7b.test", password_hash=hash_password("x"), role="member", status="active"))
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/organizations/{objs['org_a'].id}/members", json={"user_id": new_id, "role": "member"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 201, resp.text
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "ORGANIZATION_MEMBER_ADDED").order_by(AuditLog.created_at.desc()).first()
        assert audit is not None
        assert audit.organization_id == objs["org_a"].id
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_org_creation_audit():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/organizations", json={"name": "Audit Org", "slug": "audit-org-7b", "status": "active"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 201, resp.text
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "ORGANIZATION_CREATED").order_by(AuditLog.created_at.desc()).first()
        assert audit is not None
        assert audit.organization_id == resp.json()["id"]
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_status_update_super_admin_only():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/admin/organizations/{objs['org_a'].id}", json={"status": "suspended"}, headers={"Authorization": f"Bearer {tokens['admin-a@7b.test']}"})
        assert resp.status_code == 403
        resp2 = client.patch(f"/api/v1/admin/organizations/{objs['org_a'].id}", json={"status": "suspended"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "suspended"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_suspended_behavior_documented():
    # This test documents that suspended org's users cannot access dashboard (via get_current_user)
    # We verify that after suspending, org_admin's token still works for super_admin but org user is blocked
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Suspend org_a
        resp = client.patch(f"/api/v1/admin/organizations/{objs['org_a'].id}", json={"status": "suspended"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 200
        # Org admin trying to access dashboard should now be 403
        resp2 = client.get("/api/v1/dashboard/summary", headers={"Authorization": f"Bearer {tokens['admin-a@7b.test']}"})
        assert resp2.status_code == 403
        # Super admin can still inspect
        resp3 = client.get(f"/api/v1/admin/organizations/{objs['org_a'].id}", headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp3.status_code == 200
        assert resp3.json()["status"] == "suspended"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_denied_admin_users():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/users", headers={"Authorization": f"Bearer {tokens['viewer-a@7b.test']}"})
        assert resp.status_code == 403
        resp2 = client.get(f"/api/v1/admin/users/{objs['member_a'].id}", headers={"Authorization": f"Bearer {tokens['viewer-a@7b.test']}"})
        assert resp2.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_membership_idor_org_b_blocked():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Org admin A tries to list/modify Org B members via organization_members API
        resp = client.get(f"/api/v1/organizations/{objs['org_b'].id}/members", headers={"Authorization": f"Bearer {tokens['admin-a@7b.test']}"})
        assert resp.status_code == 403
        # Try to add member to Org B as Org A admin
        db = Session()
        new_id = str(uuid.uuid4())
        db.add(User(id=new_id, organization_id=objs["org_a"].id, email="idor@7b.test", password_hash=hash_password("x"), role="member", status="active"))
        db.commit()
        db.close()
        resp2 = client.post(f"/api/v1/organizations/{objs['org_b'].id}/members", json={"user_id": new_id, "role": "member"}, headers={"Authorization": f"Bearer {tokens['admin-a@7b.test']}"})
        assert resp2.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_failed_mutation_no_false_success():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        db = Session()
        before = db.query(AuditLog).filter(AuditLog.event_type == "ORGANIZATION_CREATED").count()
        db.close()
        # Duplicate slug should fail and not create SUCCESS audit
        resp = client.post("/api/v1/admin/organizations", json={"name": "Dup2", "slug": "org-a-7b", "status": "active"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 409
        db = Session()
        after = db.query(AuditLog).filter(AuditLog.event_type == "ORGANIZATION_CREATED").count()
        db.close()
        assert after == before
    finally:
        fastapi_app.dependency_overrides.clear()


def test_sensitive_metadata_sanitized():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/organizations", json={"name": "Sens Org", "slug": "sens-org-7b", "status": "active"}, headers={"Authorization": f"Bearer {tokens['super@7b.test']}"})
        assert resp.status_code == 201, resp.text
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "ORGANIZATION_CREATED").order_by(AuditLog.created_at.desc()).first()
        txt = str(audit.extra_data).lower() if audit and audit.extra_data else ""
        for s in ["password", "token", "secret", "cookie", "authorization"]:
            assert s not in txt
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_self_escalation_blocked():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # member_a tries to promote self to org_admin
        resp = client.patch(f"/api/v1/organizations/{objs['org_a'].id}/members/{objs['member_a'].id}", json={"role": "org_admin"}, headers={"Authorization": f"Bearer {tokens['member-a@7b.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()

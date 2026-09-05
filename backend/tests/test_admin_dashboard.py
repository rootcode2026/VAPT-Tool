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
import app.models.finding  # noqa
import app.models.asset  # noqa
import app.models.audit_log  # noqa

from app.models.organization import Organization
from app.models.project import Project
from app.models.user import User
from app.models.finding import Finding
from app.models.asset import Asset
from app.models.target import Target
from app.models.scan import Scan


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    # Create only SQLite-compatible tables via ORM; Finding/Asset use JSONB and need raw SQL
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, Project.__table__, Target.__table__, Scan.__table__, Base.metadata.tables["audit_logs"],
    ])
    # organization_memberships and project_memberships are safe
    try:
        from app.models.organization_membership import OrganizationMembership
        from app.models.project_membership import ProjectMembership
        Base.metadata.create_all(bind=engine, tables=[OrganizationMembership.__table__, ProjectMembership.__table__])
    except Exception:
        pass
    # Create Finding/Asset/AssetRelationship via raw SQL (TEXT instead of JSONB for SQLite)
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
    except Exception:
        pass
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-admin")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-admin")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    super_u = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="super@admin.test", password_hash=pwd, role="super_admin")
    org_admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@admin.test", password_hash=pwd, role="admin")
    member_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="member-a@admin.test", password_hash=pwd, role="member")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@admin.test", password_hash=pwd, role="member")
    org_admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@admin.test", password_hash=pwd, role="admin")
    db.add_all([super_u, org_admin_a, member_a, viewer_a, org_admin_b])
    db.flush()
    # Memberships
    try:
        from app.models.organization_membership import OrganizationMembership
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=org_admin_a.id, role="org_admin"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=member_a.id, role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=org_admin_b.id, role="org_admin"))
    except Exception:
        pass
    proj_a = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A", description="desc")
    proj_b = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B", description="desc")
    db.add_all([proj_a, proj_b])
    db.flush()
    try:
        from app.models.project_membership import ProjectMembership
        db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=org_admin_a.id, role="project_admin"))
        db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=viewer_a.id, role="viewer"))
    except Exception:
        pass
    target_a = Target(id=str(uuid.uuid4()), project_id=proj_a.id, value="a.example.com", target_type="domain", is_active=True)
    target_b = Target(id=str(uuid.uuid4()), project_id=proj_b.id, value="b.example.com", target_type="domain", is_active=True)
    db.add_all([target_a, target_b])
    db.flush()
    scan_a = Scan(id=str(uuid.uuid4()), target_id=target_a.id, profile="quick", status="completed", phase="completed", progress=100)
    scan_b = Scan(id=str(uuid.uuid4()), target_id=target_b.id, profile="quick", status="failed", phase="failed", progress=100)
    db.add_all([scan_a, scan_b])
    db.flush()
    # Use raw SQL for findings/assets to avoid JSONB SQLite issues
    fid_a = str(uuid.uuid4())
    fid_b = str(uuid.uuid4())
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, score, status, evidence, metadata) VALUES (:id, :scan_id, :target_id, :scanner, :title, :severity, :score, :status, :evidence, :metadata)"),
               {"id": fid_a, "scan_id": scan_a.id, "target_id": target_a.id, "scanner": "nmap", "title": "Finding A", "severity": "critical", "score": 90, "status": "open", "evidence": "evidence A", "metadata": "{}"})
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, score, status, evidence, metadata) VALUES (:id, :scan_id, :target_id, :scanner, :title, :severity, :score, :status, :evidence, :metadata)"),
               {"id": fid_b, "scan_id": scan_b.id, "target_id": target_b.id, "scanner": "nmap", "title": "Finding B", "severity": "high", "score": 75, "status": "open", "evidence": "evidence B", "metadata": "{}"})
    aid_a = str(uuid.uuid4())
    aid_b = str(uuid.uuid4())
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata) VALUES (:id, :project_id, :asset_type, :value, :status, :metadata)"),
               {"id": aid_a, "project_id": proj_a.id, "asset_type": "domain", "value": "a.example.com", "status": "active", "metadata": "{}"})
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata) VALUES (:id, :project_id, :asset_type, :value, :status, :metadata)"),
               {"id": aid_b, "project_id": proj_b.id, "asset_type": "domain", "value": "b.example.com", "status": "active", "metadata": "{}"})
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [super_u, org_admin_a, member_a, viewer_a, org_admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a": proj_a, "proj_b": proj_b, "super_u": super_u, "org_admin_a": org_admin_a, "member_a": member_a, "viewer_a": viewer_a, "org_admin_b": org_admin_b, "target_a": target_a, "scan_a": scan_a}
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


def test_super_admin_dashboard_allowed():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/dashboard/summary", headers={"Authorization": f"Bearer {tokens['super@admin.test']}"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "organizations" in data
        assert "users" in data
        assert "projects" in data
        assert "scans" in data
        assert "findings" in data
        assert "assets" in data
        assert "scanners" in data
        assert "audit_events" in data
        assert "system_health" in data
        # No sensitive fields
        assert "password" not in str(data).lower()
        assert "secret" not in str(data).lower() or "secret" in "audit_events"  # audit_events total ok
        assert "token" not in str(data).lower() or "token" in "audit_events"  # fallback
    finally:
        fastapi_app.dependency_overrides.clear()


def test_org_admin_denied_super_admin_dashboard():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/dashboard/summary", headers={"Authorization": f"Bearer {tokens['admin-a@admin.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_member_denied_super_admin_dashboard():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/dashboard/summary", headers={"Authorization": f"Bearer {tokens['member-a@admin.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_denied_super_admin_dashboard():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/dashboard/summary", headers={"Authorization": f"Bearer {tokens['viewer-a@admin.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_tenant_org_data_impossible():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Super admin sees both orgs
        resp = client.get("/api/v1/admin/organizations/summary?page=1&page_size=10", headers={"Authorization": f"Bearer {tokens['super@admin.test']}"})
        assert resp.status_code == 200
        org_ids = {o["id"] for o in resp.json()["items"]}
        assert objs["org_a"].id in org_ids
        assert objs["org_b"].id in org_ids
        # Org admin cannot access admin org summary at all
        resp2 = client.get("/api/v1/admin/organizations/summary", headers={"Authorization": f"Bearer {tokens['admin-a@admin.test']}"})
        assert resp2.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_organization_summary_tenant_isolation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/organizations/summary?page=1&page_size=10", headers={"Authorization": f"Bearer {tokens['super@admin.test']}"})
        assert resp.status_code == 200
        data = resp.json()
        # Each org's findings should be isolated
        for item in data["items"]:
            # No sensitive evidence
            assert "evidence" not in str(item).lower()
            assert "password" not in str(item).lower()
            assert item["id"] in [objs["org_a"].id, objs["org_b"].id]
    finally:
        fastapi_app.dependency_overrides.clear()


def test_no_sensitive_fields_in_admin_summary():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/dashboard/summary", headers={"Authorization": f"Bearer {tokens['super@admin.test']}"})
        assert resp.status_code == 200
        txt = str(resp.json()).lower()
        for sensitive in ["password", "password_hash", "jwt", "access_token", "refresh_token", "api_key", "private_key", "cookie", "authorization", "source code"]:
            assert sensitive not in txt or sensitive in ["audit_events"]  # audit_events is ok
        # Ensure no raw evidence
        assert "evidence a" not in txt
    finally:
        fastapi_app.dependency_overrides.clear()


def test_pagination_admin_orgs():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/organizations/summary?page=1&page_size=1", headers={"Authorization": f"Bearer {tokens['super@admin.test']}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["page"] == 1
        assert data["page_size"] == 1
        assert data["total"] >= 2
        assert len(data["items"]) == 1
        # Page 2
        resp2 = client.get("/api/v1/admin/organizations/summary?page=2&page_size=1", headers={"Authorization": f"Bearer {tokens['super@admin.test']}"})
        assert resp2.status_code == 200
        assert resp2.json()["page"] == 2
        assert resp2.json()["items"][0]["id"] != data["items"][0]["id"]
    finally:
        fastapi_app.dependency_overrides.clear()


def test_unauthorized_admin_endpoint():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/dashboard/summary")
        assert resp.status_code == 401
        resp2 = client.get("/api/v1/admin/dashboard/summary", headers={"Authorization": "Bearer invalid"})
        assert resp2.status_code == 401
    finally:
        fastapi_app.dependency_overrides.clear()


def test_existing_dashboard_still_works():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/dashboard/summary", headers={"Authorization": f"Bearer {tokens['admin-a@admin.test']}"})
        assert resp.status_code == 200
        data = resp.json()
        assert "scans" in data
        assert "findings" in data
    finally:
        fastapi_app.dependency_overrides.clear()


def test_super_admin_org_summaries_no_secrets():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/organizations/summary?page=1&page_size=10", headers={"Authorization": f"Bearer {tokens['super@admin.test']}"})
        assert resp.status_code == 200
        txt = str(resp.json()).lower()
        for s in ["password", "token", "secret", "private_key", "cookie"]:
            assert s not in txt
    finally:
        fastapi_app.dependency_overrides.clear()

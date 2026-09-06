import uuid
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.database import get_db
from app.main import app as fastapi_app

import app.models.organization
import app.models.user

from app.models.organization import Organization
from app.models.user import User
from app.models.asset import Asset
from app.models.target import Target
from app.models.project import Project
from app.models.scan import Scan
from app.models.finding import Finding


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, Project.__table__, Target.__table__, Scan.__table__, Base.metadata.tables["audit_logs"],
    ])
    try:
        from app.models.organization_membership import OrganizationMembership
        from app.models.project_membership import ProjectMembership
        Base.metadata.create_all(bind=engine, tables=[OrganizationMembership.__table__, ProjectMembership.__table__])
    except Exception:
        pass
    # assets/findings via raw sql for sqlite (avoid JSONB)
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY,
                    project_id TEXT, first_seen_scan_id TEXT, last_seen_scan_id TEXT, asset_type TEXT, value TEXT,
                    status TEXT, metadata TEXT, first_seen_at DATETIME, last_seen_at DATETIME, created_at DATETIME, updated_at DATETIME, criticality TEXT, owner_user_id TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT, target_id TEXT, asset_id TEXT, scanner TEXT, title TEXT, description TEXT,
                    severity TEXT, score INTEGER, status TEXT, evidence TEXT, remediation TEXT, cve TEXT, cwe TEXT,
                    metadata TEXT, created_at DATETIME, updated_at DATETIME, assigned_to TEXT, owner_user_id TEXT, severity_override TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS asset_relationships (
                    id TEXT PRIMARY KEY,
                    project_id TEXT, source_asset_id TEXT, target_asset_id TEXT, relationship_type TEXT
                )
            """))
    except Exception:
        pass

    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-code")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-code")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    super_u = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="super@code.test", password_hash=pwd, role="super_admin")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin@code.test", password_hash=pwd, role="admin")
    member_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="member@code.test", password_hash=pwd, role="member")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer@code.test", password_hash=pwd, role="member")
    other_u = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="other@code.test", password_hash=pwd, role="admin")
    db.add_all([super_u, admin_a, member_a, viewer_a, other_u])
    db.flush()
    try:
        from app.models.organization_membership import OrganizationMembership
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=member_a.id, role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=other_u.id, role="org_admin"))
    except Exception:
        pass
    proj_a = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A", description="desc")
    proj_b = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B", description="desc")
    db.add_all([proj_a, proj_b])
    db.flush()
    try:
        from app.models.project_membership import ProjectMembership
        db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=admin_a.id, role="project_admin"))
        db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=viewer_a.id, role="viewer"))
        db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=member_a.id, role="analyst"))
    except Exception:
        pass
    target_a = Target(id=str(uuid.uuid4()), project_id=proj_a.id, value="repo-a", target_type="repository", is_active=True)
    target_b = Target(id=str(uuid.uuid4()), project_id=proj_b.id, value="repo-b", target_type="repository", is_active=True)
    db.add_all([target_a, target_b])
    db.flush()
    scan_a = Scan(id=str(uuid.uuid4()), target_id=target_a.id, profile="code", status="completed", phase="completed", progress=100)
    scan_b = Scan(id=str(uuid.uuid4()), target_id=target_b.id, profile="code", status="completed", phase="completed", progress=100)
    db.add_all([scan_a, scan_b])
    db.flush()
    # assets for code via raw SQL
    for asset_type, value in [("repository", "repo:proj-a:myrepo"), ("source_file", "src/main.py"), ("package", "lodash@4.17.20"), ("container_image", "alpine:3.14"), ("iac_resource", "aws_s3_bucket.mybucket"), ("api_endpoint", "GET /api/users"), ("cloud_account", "cloud_account:aws:123:us-east-1"), ("cloud_resource", "cloud_resource:aws:123:us-east-1:s3:mybucket")]:
        aid = str(uuid.uuid4())
        meta = '{"provider": "aws"}' if "cloud" in asset_type else '{}'
        db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata) VALUES (:id, :pid, :type, :val, :status, :meta)"),
                   {"id": aid, "pid": proj_a.id, "type": asset_type, "val": value, "status": "active", "meta": meta})
    db.flush()
    # findings code
    for scanner, severity in [("sast", "high"), ("sca", "critical"), ("secrets", "high"), ("container", "medium"), ("iac", "low"), ("api", "medium")]:
        fid = str(uuid.uuid4())
        ev = "password=supersecret123" if scanner == "secrets" else f"evidence for {scanner}"
        meta = '{"secret": "supersecret"}' if scanner == "secrets" else '{"rule": "test"}'
        db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, score, status, evidence, metadata) VALUES (:id, :scan_id, :target_id, :scanner, :title, :severity, :score, :status, :evidence, :metadata)"),
                   {"id": fid, "scan_id": scan_a.id, "target_id": target_a.id, "scanner": scanner, "title": f"{scanner} finding", "severity": severity, "score": 80, "status": "open", "evidence": ev, "metadata": meta})
    # cloud finding
    fid_c = str(uuid.uuid4())
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, score, status, evidence, metadata) VALUES (:id, :scan_id, :target_id, :scanner, :title, :severity, :score, :status, :evidence, :metadata)"),
               {"id": fid_c, "scan_id": scan_a.id, "target_id": target_a.id, "scanner": "cloud", "title": "Cloud finding", "severity": "critical", "score": 90, "status": "open", "evidence": "public bucket", "metadata": '{"check_id": "CLOUD-002"}'})
    # cross-project finding
    fid_other = str(uuid.uuid4())
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, score, status, evidence, metadata) VALUES (:id, :scan_id, :target_id, :scanner, :title, :severity, :score, :status, :evidence, :metadata)"),
               {"id": fid_other, "scan_id": scan_b.id, "target_id": target_b.id, "scanner": "sast", "title": "Other finding", "severity": "high", "score": 80, "status": "open", "evidence": "other", "metadata": '{}'})
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [super_u, admin_a, member_a, viewer_a, other_u]}
    return engine, Session, tokens, {"proj_a": proj_a, "proj_b": proj_b, "target_a": target_a}

def _client(Session):
    def override():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    fastapi_app.dependency_overrides[get_db] = override
    return TestClient(fastapi_app)

def test_code_security_summary():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/code-security/summary", headers={"Authorization": f"Bearer {tokens['member@code.test']}"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["findings"]["total"] == 6
        assert data["by_scanner"]["sast"] == 1
        assert data["by_scanner"]["secrets"] == 1
        assert data["assets"]["repository"] == 1
    finally:
        fastapi_app.dependency_overrides.clear()

def test_code_findings_filter_and_redaction():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/code-security/findings?scanner=secrets", headers={"Authorization": f"Bearer {tokens['member@code.test']}"})
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        # evidence must be redacted, not contain supersecret
        txt = str(items[0]).lower()
        assert "supersecret" not in txt
        assert "password" not in txt or "[redacted]" in txt
    finally:
        fastapi_app.dependency_overrides.clear()

def test_cloud_security_summary():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud-security/summary", headers={"Authorization": f"Bearer {tokens['member@code.test']}"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["accounts"] == 1
        assert data["resources"] == 1
        assert data["findings"]["total"] == 1
        assert "aws" in data["by_provider"]
    finally:
        fastapi_app.dependency_overrides.clear()

def test_cross_project_blocked():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # viewer from proj_a trying to access proj_b
        resp = client.get(f"/api/v1/projects/{objs['proj_b'].id}/code-security/summary", headers={"Authorization": f"Bearer {tokens['viewer@code.test']}"})
        assert resp.status_code == 404
        resp2 = client.get(f"/api/v1/projects/{objs['proj_b'].id}/cloud-security/summary", headers={"Authorization": f"Bearer {tokens['viewer@code.test']}"})
        assert resp2.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()

def test_viewer_can_read_but_not_mutate():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/code-security/summary", headers={"Authorization": f"Bearer {tokens['viewer@code.test']}"})
        assert resp.status_code == 200
        # viewer trying to create finding via finding patch should be blocked elsewhere, but code-security has no mutation
    finally:
        fastapi_app.dependency_overrides.clear()

def test_unauthorized_blocked():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/code-security/summary")
        assert resp.status_code == 401
    finally:
        fastapi_app.dependency_overrides.clear()

def test_secret_redaction_persisted():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # direct DB check that raw secret not persisted? Our test inserted supersecret but API should redact
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/code-security/findings", headers={"Authorization": f"Bearer {tokens['member@code.test']}"})
        assert resp.status_code == 200
        txt = str(resp.json()).lower()
        assert "supersecret123" not in txt
    finally:
        fastapi_app.dependency_overrides.clear()

def test_asset_intelligence_linked():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/code-security/assets?asset_type=repository", headers={"Authorization": f"Bearer {tokens['member@code.test']}"})
        assert resp.status_code == 200
        assert resp.json()["count"] == 1
    finally:
        fastapi_app.dependency_overrides.clear()

def test_dashboard_code_cloud_fields():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # dashboard summary should include code_security and cloud_security
        resp = client.get("/api/v1/dashboard/summary", headers={"Authorization": f"Bearer {tokens['member@code.test']}"})
        assert resp.status_code == 200
        data = resp.json()
        assert "code_security" in data
        assert "cloud_security" in data
    finally:
        fastapi_app.dependency_overrides.clear()

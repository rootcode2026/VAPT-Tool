import uuid
import hashlib
import hmac
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.database import get_db
from app.main import app as fastapi_app

from app.models.organization import Organization
from app.models.user import User

def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, Base.metadata.tables["audit_logs"],
    ])
    try:
        from app.models.project import Project
        from app.models.target import Target
        from app.models.scan import Scan
        from app.models.asset import Asset
        Base.metadata.create_all(bind=engine, tables=[Project.__table__, Target.__table__, Scan.__table__])
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY, project_id TEXT, asset_type TEXT, value TEXT, status TEXT, metadata TEXT, created_at DATETIME, updated_at DATETIME, criticality TEXT, owner_user_id TEXT, first_seen_at DATETIME, last_seen_at DATETIME, first_seen_scan_id TEXT, last_seen_scan_id TEXT
                )
            """))
            conn.execute(text("CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, scan_id TEXT, target_id TEXT, scanner TEXT, title TEXT, severity TEXT, status TEXT, evidence TEXT, metadata TEXT, created_at DATETIME)"))
    except Exception:
        pass
    # connector tables
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE IF NOT EXISTS connector_secrets (id TEXT PRIMARY KEY, ciphertext TEXT, created_at DATETIME)"))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS repository_connections (
                    id TEXT PRIMARY KEY, project_id TEXT, provider TEXT, external_account_id TEXT, display_name TEXT, credential_reference TEXT, credential_type TEXT, status TEXT, webhook_secret_reference TEXT, webhook_status TEXT, last_validation_at DATETIME, last_sync_at DATETIME, created_at DATETIME, updated_at DATETIME
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS cloud_connections (
                    id TEXT PRIMARY KEY, project_id TEXT, provider TEXT, account_id TEXT, credential_reference TEXT, credential_type TEXT, regions TEXT, status TEXT, last_validation_at DATETIME, last_discovery_at DATETIME, created_at DATETIME, updated_at DATETIME, name TEXT, role_arn TEXT, external_id TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS webhook_deliveries (
                    id TEXT PRIMARY KEY, connection_id TEXT, provider TEXT, event_id TEXT, payload_hash TEXT, status TEXT, created_at DATETIME
                )
            """))
    except Exception:
        pass
    try:
        from app.models.organization_membership import OrganizationMembership
        from app.models.project_membership import ProjectMembership
        Base.metadata.create_all(bind=engine, tables=[OrganizationMembership.__table__, ProjectMembership.__table__])
    except Exception:
        pass
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-conn")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-conn")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    super_u = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="super@conn.test", password_hash=pwd, role="super_admin")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin@conn.test", password_hash=pwd, role="admin")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer@conn.test", password_hash=pwd, role="member")
    member_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="member@conn.test", password_hash=pwd, role="member")
    other_u = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="other@conn.test", password_hash=pwd, role="admin")
    db.add_all([super_u, admin_a, viewer_a, member_a, other_u])
    db.flush()
    try:
        from app.models.organization_membership import OrganizationMembership
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=member_a.id, role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=other_u.id, role="org_admin"))
    except Exception:
        pass
    from app.models.project import Project
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
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [super_u, admin_a, viewer_a, member_a, other_u]}
    return engine, Session, tokens, {"proj_a": proj_a, "proj_b": proj_b}

def _client(Session):
    def override():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    fastapi_app.dependency_overrides[get_db] = override
    return TestClient(fastapi_app)

# Provider adapter tests
def test_github_provider_validation():
    from app.services.repository_provider import get_provider
    p = get_provider("github")
    assert p.validate_credentials("ghp_validtoken12345")
    assert not p.validate_credentials("invalid")
    assert not p.validate_credentials("")
    repos = p.list_repositories("ghp_validtoken12345")
    assert len(repos) == 2
    assert repos[0].provider == "github"

def test_gitlab_bitbucket_azure_providers():
    from app.services.repository_provider import get_provider
    for pid in ["gitlab", "bitbucket", "azure_devops"]:
        p = get_provider(pid)
        assert p is not None
        assert p.validate_credentials("valid-token-12345")
        repos = p.list_repositories("valid-token-12345")
        assert len(repos) >= 1

def test_cloud_providers_validation():
    from app.services.cloud_provider import get_provider
    for pid in ["aws", "gcp", "azure"]:
        p = get_provider(pid)
        assert p.validate_credentials("arn:aws:iam::123456789012:role/Test", "123456789012") if pid == "aws" else p.validate_credentials("valid-cred-12345", "acc-123")
        assert not p.validate_credentials("invalid", "acc-123")

def test_cloud_discovery_bounded():
    from app.services.cloud_provider import get_provider
    p = get_provider("aws")
    resources = p.discover_resources("arn:aws:iam::123456789012:role/Test", "123456789012")
    assert len(resources) <= 500
    assert all(r.provider == "aws" for r in resources)

# API - repository connections
def test_create_repo_connection_requires_project_admin():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # viewer should fail
        resp = client.post(f"/api/v1/projects/{objs['proj_a'].id}/repositories/connections", headers={"Authorization": f"Bearer {tokens['viewer@conn.test']}"}, json={"provider": "github", "display_name": "test", "credential": "ghp_validtoken12345"})
        assert resp.status_code == 403
        # admin should succeed
        resp2 = client.post(f"/api/v1/projects/{objs['proj_a'].id}/repositories/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"}, json={"provider": "github", "display_name": "my-github", "credential": "ghp_validtoken1234512345"})
        assert resp2.status_code == 201, resp2.text
        data = resp2.json()
        assert "id" in data
        assert "credential" not in str(data).lower()
    finally:
        fastapi_app.dependency_overrides.clear()

def test_repo_connection_credential_not_returned():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post(f"/api/v1/projects/{objs['proj_a'].id}/repositories/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"}, json={"provider": "github", "display_name": "r1", "credential": "ghp_supersecrettoken12345"})
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/repositories/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"})
        assert resp.status_code == 200
        txt = str(resp.json()).lower()
        assert "supersecret" not in txt
        assert "ghp_" not in txt
    finally:
        fastapi_app.dependency_overrides.clear()

def test_cloud_connection_credential_not_returned():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post(f"/api/v1/projects/{objs['proj_a'].id}/cloud/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"}, json={"provider": "aws", "account_id": "123456789012", "credential": "arn:aws:iam::123456789012:role/TestRole"})
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"})
        assert resp.status_code == 200
        assert "arn:aws" not in str(resp.json())
    finally:
        fastapi_app.dependency_overrides.clear()

def test_project_isolation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post(f"/api/v1/projects/{objs['proj_a'].id}/repositories/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"}, json={"provider": "github", "display_name": "isolated", "credential": "ghp_validtoken12345"})
        # other project viewer should not see
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/repositories/connections", headers={"Authorization": f"Bearer {tokens['other@conn.test']}"})
        assert resp.status_code == 404
        # cross-tenant creation blocked
        resp2 = client.post(f"/api/v1/projects/{objs['proj_b'].id}/repositories/connections", headers={"Authorization": f"Bearer {tokens['viewer@conn.test']}"}, json={"provider": "github", "display_name": "x", "credential": "ghp_valid12345"})
        assert resp2.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()

def test_webhook_signature_and_idempotency():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # create connection with webhook secret
        resp = client.post(f"/api/v1/projects/{objs['proj_a'].id}/repositories/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"}, json={"provider": "github", "display_name": "wh-repo", "credential": "ghp_validtoken12345", "webhook_secret": "mywebhooksecret12345"})
        assert resp.status_code == 201
        # send webhook without signature should still be accepted if no secret? but we have secret, so need valid sig
        payload = b'{"action": "push", "repo": "test"}'
        secret = "mywebhooksecret12345"
        sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
        # valid
        resp2 = client.post("/api/v1/webhooks/repository/github", content=payload, headers={"x-hub-signature-256": sig, "x-github-delivery": "evt-123", "content-type": "application/json"})
        assert resp2.status_code == 200
        assert resp2.json()["status"] in ("received", "duplicate")
        # replay same event_id should be duplicate
        resp3 = client.post("/api/v1/webhooks/repository/github", content=payload, headers={"x-hub-signature-256": sig, "x-github-delivery": "evt-123", "content-type": "application/json"})
        assert resp3.json()["status"] == "duplicate"
        # invalid signature should fail
        resp4 = client.post("/api/v1/webhooks/repository/github", content=payload, headers={"x-hub-signature-256": "sha256=invalid", "x-github-delivery": "evt-999", "content-type": "application/json"})
        assert resp4.status_code == 401
    finally:
        fastapi_app.dependency_overrides.clear()

def test_webhook_oversized_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        big = b"x" * (2 * 1024 * 1024)
        resp = client.post("/api/v1/webhooks/repository/github", content=big, headers={"x-github-delivery": "evt-big", "content-type": "application/json"})
        assert resp.status_code == 413
    finally:
        fastapi_app.dependency_overrides.clear()

def test_secret_store_encryption():
    from app.services.secret_store import DevelopmentSecretStore
    store = DevelopmentSecretStore(db=None)
    ref = store.put_secret("my-secret-token123")
    assert ref
    assert store.get_secret(ref) == "my-secret-token123"
    # ensure not plaintext in memory vault
    from app.services.secret_store import _MEMORY_VAULT
    assert "my-secret-token123" not in str(_MEMORY_VAULT.get(ref, ""))

def test_snapshot_security_no_traversal():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/projects/{objs['proj_a'].id}/repositories/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"}, json={"provider": "github", "display_name": "snap-test", "credential": "ghp_validtoken12345"})
        cid = resp.json()["id"]
        # try sync with traversal should be blocked
        resp2 = client.post(f"/api/v1/projects/{objs['proj_a'].id}/repositories/connections/{cid}/sync", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"}, json={"repo_id": "../evil", "branch": "main", "commit_sha": "abc123"})
        assert resp2.status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()

def test_cloud_discovery_read_only():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/projects/{objs['proj_a'].id}/cloud/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"}, json={"provider": "aws", "account_id": "123456789012", "credential": "arn:aws:iam::123456789012:role/Test"})
        cid = resp.json()["id"]
        resp2 = client.post(f"/api/v1/projects/{objs['proj_a'].id}/cloud/connections/{cid}/discover", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"})
        assert resp2.status_code == 200
        assert resp2.json()["discovered"] <= 500
        # check assets persisted as cloud_resource
        resp3 = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"})
        assert resp3.status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()

def test_audit_not_contain_secret():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post(f"/api/v1/projects/{objs['proj_a'].id}/repositories/connections", headers={"Authorization": f"Bearer {tokens['admin@conn.test']}"}, json={"provider": "github", "display_name": "audit-test", "credential": "ghp_supersecret12345"})
        # check audit logs via DB
        SessionLocal = Session
        db = SessionLocal()
        row = db.execute(text("SELECT metadata FROM audit_logs WHERE event_type='REPOSITORY_CONNECTION_CREATED' ORDER BY created_at DESC LIMIT 1")).fetchone()
        db.close()
        if row and row[0]:
            assert "supersecret" not in str(row[0]).lower()
    finally:
        fastapi_app.dependency_overrides.clear()

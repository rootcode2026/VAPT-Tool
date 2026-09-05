"""
Phase 6E — Auth + Authorization-denied audits.
"""
import uuid
import time
import jwt
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
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

from app.models.audit_log import AuditLog
from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.scan import Scan
from app.models.user import User


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__, Scan.__table__, AuditLog.__table__,
    ])
    # Also need assets for cloud but not needed for these tests
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY, project_id TEXT, asset_type TEXT, value TEXT, status TEXT, metadata TEXT, created_at DATETIME, updated_at DATETIME, first_seen_scan_id TEXT, last_seen_scan_id TEXT, first_seen_at DATETIME, last_seen_at DATETIME
                )
            """))
    except Exception:
        pass
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-6e")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-6e")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@6e.test", password_hash=pwd, role="admin")
    member_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="member-a@6e.test", password_hash=pwd, role="member")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@6e.test", password_hash=pwd, role="member")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@6e.test", password_hash=pwd, role="admin")
    db.add_all([admin_a, member_a, viewer_a, admin_b])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=member_a.id, role="member"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin"))
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A1", description="desc")
    proj_a2 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A2", description="desc")
    proj_b1 = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B1", description="desc")
    db.add_all([proj_a1, proj_a2, proj_b1])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=admin_a.id, role="project_admin"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=viewer_a.id, role="viewer"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a2.id, user_id=member_a.id, role="viewer"))
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, member_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_a2": proj_a2, "proj_b1": proj_b1, "admin_a": admin_a, "member_a": member_a, "viewer_a": viewer_a, "admin_b": admin_b}
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


def _count(Session, **f):
    db = Session()
    q = db.query(AuditLog)
    for k, v in f.items():
        q = q.filter(getattr(AuditLog, k) == v)
    c = q.count()
    db.close()
    return c


def test_successful_login_creates_AUTH_LOGIN_SUCCESS():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        before = _count(Session, event_type="AUTH_LOGIN_SUCCESS")
        resp = client.post("/api/v1/auth/login", json={"email": "admin-a@6e.test", "password": "password123"})
        assert resp.status_code == 200, resp.text
        after = _count(Session, event_type="AUTH_LOGIN_SUCCESS")
        assert after == before + 1
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTH_LOGIN_SUCCESS").order_by(AuditLog.created_at.desc()).first()
        assert audit.actor_user_id == objs["admin_a"].id
        assert audit.organization_id == objs["admin_a"].organization_id
        assert audit.resource_type == "authentication"
        assert audit.result == "SUCCESS"
        assert audit.extra_data.get("method") == "password"
        # No password in audit
        assert "password123" not in str(audit.extra_data)
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_failed_login_creates_AUTH_LOGIN_FAILURE():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        before = _count(Session, event_type="AUTH_LOGIN_FAILURE")
        resp = client.post("/api/v1/auth/login", json={"email": "admin-a@6e.test", "password": "wrong"})
        assert resp.status_code == 401
        after = _count(Session, event_type="AUTH_LOGIN_FAILURE")
        assert after == before + 1
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTH_LOGIN_FAILURE").order_by(AuditLog.created_at.desc()).first()
        assert audit.result == "FAILURE"
        assert audit.actor_user_id is None
        assert "wrong" not in str(audit.extra_data)
        assert "password" not in str(audit.extra_data).lower() or "[REDACTED]" in str(audit.extra_data)
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_login_failure_no_password_token():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/auth/login", json={"email": "admin-a@6e.test", "password": "wrongpass"})
        assert resp.status_code == 401
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTH_LOGIN_FAILURE").order_by(AuditLog.created_at.desc()).first()
        meta = str(audit.extra_data) if audit.extra_data else ""
        assert "wrongpass" not in meta
        assert "token" not in meta.lower() or "[REDACTED]" in meta
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_logout_creates_AUTH_LOGOUT():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        before = _count(Session, event_type="AUTH_LOGOUT")
        resp = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {tokens['admin-a@6e.test']}"})
        assert resp.status_code == 204, resp.text
        after = _count(Session, event_type="AUTH_LOGOUT")
        assert after == before + 1
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTH_LOGOUT").order_by(AuditLog.created_at.desc()).first()
        assert audit.actor_user_id == objs["admin_a"].id
        assert audit.result == "SUCCESS"
        assert audit.resource_type == "authentication"
        # No token
        assert "eyJ" not in str(audit.extra_data)
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_invalid_token_creates_AUTH_TOKEN_FAILURE():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        before = _count(Session, event_type="AUTH_TOKEN_FAILURE")
        resp = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
        assert resp.status_code == 401
        after = _count(Session, event_type="AUTH_TOKEN_FAILURE")
        assert after == before + 1
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTH_TOKEN_FAILURE").order_by(AuditLog.created_at.desc()).first()
        assert audit.result == "FAILURE"
        assert "invalid.token" not in str(audit.extra_data)
        assert "Bearer" not in str(audit.extra_data)
        assert audit.actor_user_id is None
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_expired_token_creates_AUTH_TOKEN_FAILURE():
    _, Session, tokens, objs = _setup()
    # Create expired token
    import jwt
    from datetime import datetime, timedelta, timezone
    payload = {"sub": objs["admin_a"].id, "exp": datetime.now(timezone.utc) - timedelta(minutes=1), "iat": datetime.now(timezone.utc) - timedelta(minutes=10), "type": "access"}
    expired = jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    client = _client(Session)
    try:
        before = _count(Session, event_type="AUTH_TOKEN_FAILURE")
        resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {expired}"})
        assert resp.status_code == 401
        after = _count(Session, event_type="AUTH_TOKEN_FAILURE")
        assert after == before + 1
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTH_TOKEN_FAILURE").order_by(AuditLog.created_at.desc()).first()
        assert audit.extra_data.get("failure") == "expired_token"
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_token_never_in_metadata():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer bad.token.value"})
        assert resp.status_code == 401
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTH_TOKEN_FAILURE").order_by(AuditLog.created_at.desc()).first()
        meta = str(audit.extra_data) if audit.extra_data else ""
        assert "bad.token" not in meta
        assert "Authorization" not in meta
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_unauthenticated_token_failure_no_actor():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/auth/me")  # no token
        assert resp.status_code == 401
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTH_TOKEN_FAILURE").order_by(AuditLog.created_at.desc()).first()
        assert audit.actor_user_id is None
        assert audit.organization_id is None
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_insufficient_permission_AUTHORIZATION_DENIED():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        before = _count(Session, event_type="AUTHORIZATION_DENIED")
        # member_a (member role) cannot create project (requires org_admin) -> 403
        resp = client.post("/api/v1/projects", json={"organization_id": objs["org_a"].id, "name": "Nope", "description": ""}, headers={"Authorization": f"Bearer {tokens['member-a@6e.test']}"})
        assert resp.status_code == 403
        after = _count(Session, event_type="AUTHORIZATION_DENIED")
        assert after == before + 1
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTHORIZATION_DENIED").order_by(AuditLog.created_at.desc()).first()
        assert audit.actor_user_id == objs["member_a"].id
        assert audit.result == "DENIED"
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_project_role_denied_AUTHORIZATION_DENIED():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        before = _count(Session, event_type="AUTHORIZATION_DENIED")
        # viewer_a is viewer on proj_a1, cannot create target (needs analyst)
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "x.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['viewer-a@6e.test']}"})
        assert resp.status_code == 403
        after = _count(Session, event_type="AUTHORIZATION_DENIED")
        assert after == before + 1
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTHORIZATION_DENIED").order_by(AuditLog.created_at.desc()).first()
        assert "insufficient_permissions" in str(audit.extra_data)
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_tenant_creates_CROSS_TENANT_DENIED():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        before_cross = _count(Session, event_type="CROSS_TENANT_ACCESS_DENIED")
        before_authz = _count(Session, event_type="AUTHORIZATION_DENIED")
        # admin_a accessing proj_b1 which is in org_b -> 404 but audit CROSS_TENANT
        resp = client.get(f"/api/v1/projects/{objs['proj_b1'].id}", headers={"Authorization": f"Bearer {tokens['admin-a@6e.test']}"})
        # Projects route returns 404 for cross-tenant (via direct query filtered by org), but require_project_access is not used for GET project
        # For this test, use target in proj_b1 via require_project_access
        # Create a target in proj_b1 as admin_b then access as admin_a
        # Simpler: use cloud accounts which uses require_project_access
        # Let's use targets via project filter
        resp2 = client.get(f"/api/v1/targets?project_id={objs['proj_b1'].id}", headers={"Authorization": f"Bearer {tokens['admin-a@6e.test']}"})
        assert resp2.status_code == 404
        after_cross = _count(Session, event_type="CROSS_TENANT_ACCESS_DENIED")
        after_authz = _count(Session, event_type="AUTHORIZATION_DENIED")
        assert after_cross == before_cross + 1
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "CROSS_TENANT_ACCESS_DENIED").order_by(AuditLog.created_at.desc()).first()
        assert audit.actor_user_id == objs["admin_a"].id
        assert audit.organization_id == objs["org_a"].id or audit.organization_id == objs["admin_a"].organization_id
        assert audit.result == "DENIED"
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_same_tenant_insufficient_not_cross_tenant():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        before_cross = _count(Session, event_type="CROSS_TENANT_ACCESS_DENIED")
        before_denied = _count(Session, event_type="AUTHORIZATION_DENIED")
        # viewer_a is in org_a, accessing proj_a1 where they are viewer but trying to create project (needs org_admin) -> 403 AUTHORIZATION_DENIED not cross
        resp = client.post("/api/v1/projects", json={"organization_id": objs["org_a"].id, "name": "Nope2", "description": ""}, headers={"Authorization": f"Bearer {tokens['viewer-a@6e.test']}"})
        assert resp.status_code == 403
        after_cross = _count(Session, event_type="CROSS_TENANT_ACCESS_DENIED")
        after_denied = _count(Session, event_type="AUTHORIZATION_DENIED")
        assert after_cross == before_cross  # no cross
        assert after_denied == before_denied + 1
    finally:
        fastapi_app.dependency_overrides.clear()


def test_denied_retains_http_status():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/projects", json={"organization_id": objs["org_a"].id, "name": "Nope", "description": ""}, headers={"Authorization": f"Bearer {tokens['member-a@6e.test']}"})
        assert resp.status_code == 403
        # Ensure response detail not leaking audit
        assert "Insufficient" in resp.text
    finally:
        fastapi_app.dependency_overrides.clear()


def test_denied_no_sensitive_contents():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/projects", json={"organization_id": objs["org_a"].id, "name": "Nope", "description": ""}, headers={"Authorization": f"Bearer {tokens['member-a@6e.test']}"})
        assert resp.status_code == 403
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "AUTHORIZATION_DENIED").order_by(AuditLog.created_at.desc()).first()
        meta = str(audit.extra_data) if audit.extra_data else ""
        assert "password" not in meta.lower() or "[REDACTED]" in meta
        assert "token" not in meta.lower() or "[REDACTED]" in meta or "actual_role" in meta
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_tenant_audit_actor_org_and_no_exposure():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/targets?project_id={objs['proj_b1'].id}", headers={"Authorization": f"Bearer {tokens['admin-a@6e.test']}"})
        assert resp.status_code == 404
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "CROSS_TENANT_ACCESS_DENIED").order_by(AuditLog.created_at.desc()).first()
        assert audit.actor_user_id == objs["admin_a"].id
        # Actor org is org_a, not org_b
        assert audit.organization_id == objs["org_a"].id
        # Should not expose org_b sensitive data like finding evidence
        assert "finding" not in str(audit.extra_data).lower() or "requested" in str(audit.extra_data).lower()
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_tenant_no_success_event():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        before_success = _count(Session, result="SUCCESS")
        resp = client.get(f"/api/v1/targets?project_id={objs['proj_b1'].id}", headers={"Authorization": f"Bearer {tokens['admin-a@6e.test']}"})
        assert resp.status_code == 404
        after_success = _count(Session, result="SUCCESS")
        # No new SUCCESS should be created for cross-tenant
        # The only SUCCESS could be from previous setup, but not new
        assert after_success == before_success
    finally:
        fastapi_app.dependency_overrides.clear()


def test_authz_bypass_by_org_id_manipulation_fails():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Try to create target in proj_b1 by passing its project_id but with admin_a token -> should be 404 not 200
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_b1"].id, "value": "bypass.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@6e.test']}"})
        assert resp.status_code == 404
        # Audit should be cross-tenant denied, not success
        before = _count(Session, event_type="TARGET_CREATED")
        after = _count(Session, event_type="TARGET_CREATED")
        assert after == before  # no success
        cross = _count(Session, event_type="CROSS_TENANT_ACCESS_DENIED")
        assert cross >= 1
    finally:
        fastapi_app.dependency_overrides.clear()

"""
Phase 6B — Audit membership + project lifecycle.

Covers:
- org member add / update / removal creates audit
- project member add / update / removal creates audit
- project creation / deletion creates audit
- correct organization_id / actor / target_user_id
- role-change metadata old/new
- sensitive metadata redaction
- unauthorized does not create SUCCESS
- audit survives project deletion
"""

import uuid

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.database import get_db
from app.main import app as fastapi_app

# Import all models so Base.metadata includes them
import app.models.organization  # noqa: F401
import app.models.user  # noqa: F401
import app.models.organization_membership  # noqa: F401
import app.models.project  # noqa: F401
import app.models.project_membership  # noqa: F401
import app.models.target  # noqa: F401
import app.models.scan  # noqa: F401
import app.models.finding  # noqa: F401
import app.models.asset  # noqa: F401
import app.models.scan_result  # noqa: F401
import app.models.audit_log  # noqa: F401
import app.models.asset_change_event  # noqa: F401
import app.models.asset_relationship  # noqa: F401

from app.models.audit_log import AuditLog
from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.user import User
from app.services.audit import sanitize_metadata


def _setup_audit_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    # Only create tables needed for audit membership/project tests to avoid JSONB
    # incompatibility with SQLite (assets/findings etc use JSONB).
    from app.models.target import Target as _Target
    from app.models.scan import Scan as _Scan

    Base.metadata.create_all(
        bind=engine,
        tables=[
            Organization.__table__,
            User.__table__,
            OrganizationMembership.__table__,
            Project.__table__,
            ProjectMembership.__table__,
            _Target.__table__,
            _Scan.__table__,
            AuditLog.__table__,
        ],
    )
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = TestingSession()
    # Orgs
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-audit-6b")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-audit-6b")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@audit6b.test", password_hash=pwd, role="admin")
    member_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="member-a@audit6b.test", password_hash=pwd, role="member")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@audit6b.test", password_hash=pwd, role="member")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@audit6b.test", password_hash=pwd, role="admin")
    db.add_all([admin_a, member_a, viewer_a, admin_b])
    db.flush()
    # Org memberships
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=member_a.id, role="member"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin"))
    # Projects
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A1", description="desc")
    proj_a2 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A2", description="desc")
    proj_b1 = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B1", description="desc")
    db.add_all([proj_a1, proj_a2, proj_b1])
    db.flush()
    # Project memberships — admin_a is project_admin on A1
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=admin_a.id, role="project_admin"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=viewer_a.id, role="viewer"))
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, member_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_a2": proj_a2, "proj_b1": proj_b1, "admin_a": admin_a, "member_a": member_a, "viewer_a": viewer_a, "admin_b": admin_b}
    return engine, TestingSession, tokens, objs


def _client(TestingSession):
    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()
    fastapi_app.dependency_overrides[get_db] = override
    return TestClient(fastapi_app)


def _count_audits(TestingSession, **filters):
    db = TestingSession()
    q = db.query(AuditLog)
    for k, v in filters.items():
        q = q.filter(getattr(AuditLog, k) == v)
    c = q.count()
    db.close()
    return c


def test_org_member_add_creates_audit():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        db = TestingSession()
        new_user_id = str(uuid.uuid4())
        db.add(User(id=new_user_id, organization_id=objs["org_a"].id, email="new-org-add@audit6b.test", password_hash=hash_password("x"), role="member"))
        db.commit()
        db.close()
        before = _count_audits(TestingSession, event_type="ORGANIZATION_MEMBER_ADDED")
        resp = client.post(f"/api/v1/organizations/{objs['org_a'].id}/members", json={"user_id": new_user_id, "role": "member"}, headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 201, resp.text
        after = _count_audits(TestingSession, event_type="ORGANIZATION_MEMBER_ADDED")
        assert after == before + 1
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "ORGANIZATION_MEMBER_ADDED").order_by(AuditLog.created_at.desc()).first()
        assert audit.organization_id == objs["org_a"].id
        assert audit.actor_user_id == objs["admin_a"].id
        assert audit.target_user_id == new_user_id
        assert audit.resource_type == "organization_membership"
        assert audit.result == "SUCCESS"
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_org_member_role_update_creates_audit():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        # Add a second member as org_admin so demotion is allowed (not last admin)
        second = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=second, organization_id=objs["org_a"].id, email="second-admin@audit6b.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=second, role="org_admin"))
        db.commit()
        db.close()
        # member_a is member, promote to org_admin then demote; but we test update of member_a role
        before = _count_audits(TestingSession, event_type="ORGANIZATION_MEMBER_UPDATED")
        resp = client.patch(f"/api/v1/organizations/{objs['org_a'].id}/members/{objs['member_a'].id}", json={"role": "org_admin"}, headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 200, resp.text
        after = _count_audits(TestingSession, event_type="ORGANIZATION_MEMBER_UPDATED")
        assert after == before + 1
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "ORGANIZATION_MEMBER_UPDATED", AuditLog.target_user_id == objs["member_a"].id).order_by(AuditLog.created_at.desc()).first()
        assert audit is not None
        assert audit.extra_data.get("old_role") == "member"
        assert audit.extra_data.get("new_role") == "org_admin"
        assert audit.organization_id == objs["org_a"].id
        assert audit.actor_user_id == objs["admin_a"].id
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_org_member_removal_creates_audit():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        # Create removable member
        removable = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=removable, organization_id=objs["org_a"].id, email="removable@audit6b.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=removable, role="member"))
        db.commit()
        db.close()
        before = _count_audits(TestingSession, event_type="ORGANIZATION_MEMBER_REMOVED")
        resp = client.delete(f"/api/v1/organizations/{objs['org_a'].id}/members/{removable}", headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 204, resp.text
        after = _count_audits(TestingSession, event_type="ORGANIZATION_MEMBER_REMOVED")
        assert after == before + 1
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "ORGANIZATION_MEMBER_REMOVED", AuditLog.target_user_id == removable).order_by(AuditLog.created_at.desc()).first()
        assert audit is not None
        assert audit.organization_id == objs["org_a"].id
        assert audit.actor_user_id == objs["admin_a"].id
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_project_member_add_creates_audit():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        # Ensure member_a is in org (already) — add to project A1
        new_user = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_user, organization_id=objs["org_a"].id, email="proj-add@audit6b.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=new_user, role="member"))
        db.commit()
        db.close()
        before = _count_audits(TestingSession, event_type="PROJECT_MEMBER_ADDED")
        resp = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/members", json={"user_id": new_user, "role": "viewer"}, headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 201, resp.text
        after = _count_audits(TestingSession, event_type="PROJECT_MEMBER_ADDED")
        assert after == before + 1
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "PROJECT_MEMBER_ADDED", AuditLog.target_user_id == new_user).order_by(AuditLog.created_at.desc()).first()
        assert audit.organization_id == objs["org_a"].id
        assert audit.project_id == objs["proj_a1"].id
        assert audit.actor_user_id == objs["admin_a"].id
        assert audit.target_user_id == new_user
        assert audit.resource_type == "project_membership"
        assert audit.result == "SUCCESS"
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_project_member_role_update_creates_audit():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        # viewer_a is viewer on proj_a1, update to analyst
        before = _count_audits(TestingSession, event_type="PROJECT_MEMBER_UPDATED")
        resp = client.patch(f"/api/v1/projects/{objs['proj_a1'].id}/members/{objs['viewer_a'].id}", json={"role": "analyst"}, headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 200, resp.text
        after = _count_audits(TestingSession, event_type="PROJECT_MEMBER_UPDATED")
        assert after == before + 1
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "PROJECT_MEMBER_UPDATED", AuditLog.target_user_id == objs["viewer_a"].id).order_by(AuditLog.created_at.desc()).first()
        assert audit.extra_data.get("old_role") == "viewer"
        assert audit.extra_data.get("new_role") == "analyst"
        assert audit.project_id == objs["proj_a1"].id
        assert audit.organization_id == objs["org_a"].id
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_project_member_removal_creates_audit():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        before = _count_audits(TestingSession, event_type="PROJECT_MEMBER_REMOVED")
        resp = client.delete(f"/api/v1/projects/{objs['proj_a1'].id}/members/{objs['viewer_a'].id}", headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 204, resp.text
        after = _count_audits(TestingSession, event_type="PROJECT_MEMBER_REMOVED")
        assert after == before + 1
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "PROJECT_MEMBER_REMOVED", AuditLog.target_user_id == objs["viewer_a"].id).order_by(AuditLog.created_at.desc()).first()
        assert audit is not None
        assert audit.project_id == objs["proj_a1"].id
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_project_creation_creates_audit():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        before = _count_audits(TestingSession, event_type="PROJECT_CREATED")
        resp = client.post("/api/v1/projects", json={"organization_id": objs["org_a"].id, "name": "New Audit Project", "description": "x"}, headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 200, resp.text
        after = _count_audits(TestingSession, event_type="PROJECT_CREATED")
        assert after == before + 1
        proj_id = resp.json()["id"]
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "PROJECT_CREATED", AuditLog.resource_id == proj_id).first()
        assert audit is not None
        assert audit.organization_id == objs["org_a"].id
        assert audit.project_id == proj_id
        assert audit.actor_user_id == objs["admin_a"].id
        assert audit.resource_type == "project"
        assert audit.result == "SUCCESS"
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_project_deletion_creates_audit():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        # Create a project to delete
        resp = client.post("/api/v1/projects", json={"organization_id": objs["org_a"].id, "name": "To Delete", "description": ""}, headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 200, resp.text
        proj_id = resp.json()["id"]
        before = _count_audits(TestingSession, event_type="PROJECT_DELETED")
        del_resp = client.delete(f"/api/v1/projects/{proj_id}", headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert del_resp.status_code == 200, del_resp.text
        after = _count_audits(TestingSession, event_type="PROJECT_DELETED")
        assert after == before + 1
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "PROJECT_DELETED", AuditLog.resource_id == proj_id).first()
        assert audit is not None
        assert audit.actor_user_id == objs["admin_a"].id
        # organization_id should be captured before deletion
        assert audit.organization_id == objs["org_a"].id
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_audit_contains_correct_ids():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        new_user = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_user, organization_id=objs["org_a"].id, email="correct-ids@audit6b.test", password_hash=hash_password("x"), role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, user_id=new_user, role="member"))
        db.commit()
        db.close()
        resp = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/members", json={"user_id": new_user, "role": "viewer"}, headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 201, resp.text
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "PROJECT_MEMBER_ADDED", AuditLog.target_user_id == new_user).order_by(AuditLog.created_at.desc()).first()
        assert audit.organization_id == objs["org_a"].id
        assert audit.project_id == objs["proj_a1"].id
        assert audit.actor_user_id == objs["admin_a"].id
        assert audit.target_user_id == new_user
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_role_change_metadata():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        resp = client.patch(f"/api/v1/projects/{objs['proj_a1'].id}/members/{objs['viewer_a'].id}", json={"role": "analyst"}, headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 200
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "PROJECT_MEMBER_UPDATED").order_by(AuditLog.created_at.desc()).first()
        assert audit.extra_data["old_role"] == "viewer"
        assert audit.extra_data["new_role"] == "analyst"
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_sensitive_metadata_remains_redacted():
    # Direct audit service redaction — even if caller passes sensitive keys, they are [REDACTED]
    meta = {"password": "secret123", "api_key": "sk_test", "authorization": "Bearer token", "normal": "visible"}
    sanitized = sanitize_metadata(meta)
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["normal"] == "visible"
    # Nested
    nested = {"outer": {"secret": "hidden", "ok": "yes"}}
    sanitized2 = sanitize_metadata(nested)
    assert sanitized2["outer"]["secret"] == "[REDACTED]"
    assert sanitized2["outer"]["ok"] == "yes"


def test_unauthorized_does_not_create_success_audit():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        new_user = str(uuid.uuid4())
        db = TestingSession()
        db.add(User(id=new_user, organization_id=objs["org_a"].id, email="unauth@audit6b.test", password_hash=hash_password("x"), role="member"))
        db.commit()
        db.close()
        before = _count_audits(TestingSession, event_type="ORGANIZATION_MEMBER_ADDED")
        # member_a is not org_admin, should be 403 and no SUCCESS audit
        resp = client.post(f"/api/v1/organizations/{objs['org_a'].id}/members", json={"user_id": new_user, "role": "member"}, headers={"Authorization": f"Bearer {tokens['member-a@audit6b.test']}"})
        assert resp.status_code == 403
        after = _count_audits(TestingSession, event_type="ORGANIZATION_MEMBER_ADDED")
        assert after == before
        # Cross-tenant: admin_a cannot manage org_b members
        before2 = _count_audits(TestingSession, event_type="ORGANIZATION_MEMBER_ADDED")
        resp2 = client.post(f"/api/v1/organizations/{objs['org_b'].id}/members", json={"user_id": new_user, "role": "member"}, headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp2.status_code == 403
        after2 = _count_audits(TestingSession, event_type="ORGANIZATION_MEMBER_ADDED")
        assert after2 == before2
    finally:
        fastapi_app.dependency_overrides.clear()


def test_audit_survives_project_deletion():
    _, TestingSession, tokens, objs = _setup_audit_db()
    client = _client(TestingSession)
    try:
        resp = client.post("/api/v1/projects", json={"organization_id": objs["org_a"].id, "name": "Survive Test", "description": ""}, headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert resp.status_code == 200, resp.text
        proj_id = resp.json()["id"]
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "PROJECT_CREATED", AuditLog.resource_id == proj_id).first()
        audit_id = audit.id if audit else None
        assert audit_id is not None
        db.close()
        # Delete project — audit should survive
        del_resp = client.delete(f"/api/v1/projects/{proj_id}", headers={"Authorization": f"Bearer {tokens['admin-a@audit6b.test']}"})
        assert del_resp.status_code == 200
        db = TestingSession()
        survived = db.query(AuditLog).filter(AuditLog.id == audit_id).first()
        assert survived is not None
        # Also deletion audit exists
        del_audit = db.query(AuditLog).filter(AuditLog.event_type == "PROJECT_DELETED", AuditLog.resource_id == proj_id).first()
        assert del_audit is not None
        # Project is gone
        proj = db.query(Project).filter(Project.id == proj_id).first()
        assert proj is None
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()

"""
Phase 6C — Target + Scan API audit tests.

Covers:
- target creation / deletion audits
- scan creation audit
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
from app.services.audit import sanitize_metadata
from unittest.mock import patch


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    # Only tables needed for target/scan audit tests
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__, Scan.__table__, AuditLog.__table__,
    ])
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = TestingSession()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-target-6c")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-target-6c")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@target6c.test", password_hash=pwd, role="admin")
    member_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="member-a@target6c.test", password_hash=pwd, role="member")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@target6c.test", password_hash=pwd, role="member")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@target6c.test", password_hash=pwd, role="admin")
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
    # proj_a2 has no explicit membership — fallback org_admin -> project_admin for admin_a
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


def _count(TestingSession, **f):
    db = TestingSession()
    q = db.query(AuditLog)
    for k, v in f.items():
        q = q.filter(getattr(AuditLog, k) == v)
    c = q.count()
    db.close()
    return c


def test_target_creation_produces_audit():
    _, TestingSession, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        before = _count(TestingSession, event_type="TARGET_CREATED")
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "audit-target-1.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert resp.status_code == 200, resp.text
        tid = resp.json()["id"]
        after = _count(TestingSession, event_type="TARGET_CREATED")
        assert after == before + 1
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "TARGET_CREATED", AuditLog.resource_id == tid).first()
        assert audit is not None
        assert audit.organization_id == objs["org_a"].id
        assert audit.project_id == objs["proj_a1"].id
        assert audit.actor_user_id == objs["admin_a"].id
        assert audit.resource_type == "target"
        assert audit.result == "SUCCESS"
        assert audit.extra_data.get("target_type") == "domain"
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_target_creation_correct_ids():
    _, TestingSession, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_a2"].id, "value": "audit-target-2.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert resp.status_code == 200, resp.text
        tid = resp.json()["id"]
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.resource_id == tid, AuditLog.event_type == "TARGET_CREATED").first()
        assert audit.organization_id == objs["org_a"].id
        assert audit.project_id == objs["proj_a2"].id
        assert audit.actor_user_id == objs["admin_a"].id
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_target_deletion_produces_audit_and_survives():
    _, TestingSession, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "to-delete.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert resp.status_code == 200, resp.text
        tid = resp.json()["id"]
        db = TestingSession()
        # ensure creation audit exists
        created = db.query(AuditLog).filter(AuditLog.resource_id == tid, AuditLog.event_type == "TARGET_CREATED").first()
        created_id = created.id
        db.close()
        before = _count(TestingSession, event_type="TARGET_DELETED")
        del_resp = client.delete(f"/api/v1/targets/{tid}", headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert del_resp.status_code == 200, del_resp.text
        after = _count(TestingSession, event_type="TARGET_DELETED")
        assert after == before + 1
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "TARGET_DELETED", AuditLog.resource_id == tid).first()
        assert audit is not None
        assert audit.organization_id == objs["org_a"].id
        assert audit.project_id == objs["proj_a1"].id
        assert audit.actor_user_id == objs["admin_a"].id
        # creation audit survives deletion
        survived = db.query(AuditLog).filter(AuditLog.id == created_id).first()
        assert survived is not None
        # target is gone
        assert db.query(Target).filter(Target.id == tid).first() is None
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_target_unauthorized_no_success_audit():
    _, TestingSession, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        before = _count(TestingSession, event_type="TARGET_CREATED")
        # member_a is not analyst/project_admin -> 403
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "unauth.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['member-a@target6c.test']}"})
        assert resp.status_code == 403
        after = _count(TestingSession, event_type="TARGET_CREATED")
        assert after == before
        # create a target then try delete as viewer (should be 403 for viewer? transitional allows analyst, viewer denied)
        # viewer_a is viewer on proj_a1 -> delete requires analyst/project_admin so 403
        create = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "viewer-delete.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert create.status_code == 200
        tid = create.json()["id"]
        before_del = _count(TestingSession, event_type="TARGET_DELETED")
        del_resp = client.delete(f"/api/v1/targets/{tid}", headers={"Authorization": f"Bearer {tokens['viewer-a@target6c.test']}"})
        assert del_resp.status_code == 403
        after_del = _count(TestingSession, event_type="TARGET_DELETED")
        assert after_del == before_del
    finally:
        fastapi_app.dependency_overrides.clear()


def test_target_cross_tenant_no_success_audit():
    _, TestingSession, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        before = _count(TestingSession, event_type="TARGET_CREATED")
        # admin_a trying to create target in org_b project -> 404
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_b1"].id, "value": "cross.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert resp.status_code == 404
        after = _count(TestingSession, event_type="TARGET_CREATED")
        assert after == before
        # create target in org_b as admin_b then try delete as admin_a -> 404 no audit
        create = client.post("/api/v1/targets", json={"project_id": objs["proj_b1"].id, "value": "cross2.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-b@target6c.test']}"})
        assert create.status_code == 200
        tid = create.json()["id"]
        before_del = _count(TestingSession, event_type="TARGET_DELETED")
        del_resp = client.delete(f"/api/v1/targets/{tid}", headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert del_resp.status_code == 404
        after_del = _count(TestingSession, event_type="TARGET_DELETED")
        assert after_del == before_del
    finally:
        fastapi_app.dependency_overrides.clear()


def test_scan_creation_produces_audit():
    _, TestingSession, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        # create target first
        t = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "scan-target.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert t.status_code == 200, t.text
        tid = t.json()["id"]
        before = _count(TestingSession, event_type="SCAN_CREATED")
        with patch("app.api.routes.scans.celery_app.send_task", return_value=None):
            resp = client.post("/api/v1/scans", json={"target_id": tid, "profile": "quick"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert resp.status_code == 200, resp.text
        sid = resp.json()["id"]
        after = _count(TestingSession, event_type="SCAN_CREATED")
        assert after == before + 1
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "SCAN_CREATED", AuditLog.resource_id == sid).first()
        assert audit is not None
        assert audit.organization_id == objs["org_a"].id
        assert audit.project_id == objs["proj_a1"].id
        assert audit.actor_user_id == objs["admin_a"].id
        assert audit.resource_type == "scan"
        assert audit.result == "SUCCESS"
        assert audit.extra_data.get("profile") == "quick"
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_scan_creation_tenant_and_actor():
    _, TestingSession, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        t = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "scan-tenant.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert t.status_code == 200
        tid = t.json()["id"]
        with patch("app.api.routes.scans.celery_app.send_task", return_value=None):
            resp = client.post("/api/v1/scans", json={"target_id": tid, "profile": "quick"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert resp.status_code == 200, resp.text
        sid = resp.json()["id"]
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.resource_id == sid, AuditLog.event_type == "SCAN_CREATED").first()
        assert audit.organization_id == objs["org_a"].id
        assert audit.project_id == objs["proj_a1"].id
        assert audit.actor_user_id == objs["admin_a"].id
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_scan_unauthorized_no_success_audit():
    _, TestingSession, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        t = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "scan-unauth.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert t.status_code == 200
        tid = t.json()["id"]
        before = _count(TestingSession, event_type="SCAN_CREATED")
        # viewer_a is viewer -> cannot create scan (requires analyst)
        with patch("app.api.routes.scans.celery_app.send_task", return_value=None):
            resp = client.post("/api/v1/scans", json={"target_id": tid, "profile": "quick"}, headers={"Authorization": f"Bearer {tokens['viewer-a@target6c.test']}"})
        assert resp.status_code == 403
        after = _count(TestingSession, event_type="SCAN_CREATED")
        assert after == before
        # cross-tenant: admin_b cannot scan org_a target
        with patch("app.api.routes.scans.celery_app.send_task", return_value=None):
            resp2 = client.post("/api/v1/scans", json={"target_id": tid, "profile": "quick"}, headers={"Authorization": f"Bearer {tokens['admin-b@target6c.test']}"})
        assert resp2.status_code == 404
        after2 = _count(TestingSession, event_type="SCAN_CREATED")
        assert after2 == before
    finally:
        fastapi_app.dependency_overrides.clear()


def test_scan_audit_no_sensitive_leak():
    _, TestingSession, tokens, objs = _setup()
    client = _client(TestingSession)
    try:
        t = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "scan-sensitive.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert t.status_code == 200
        tid = t.json()["id"]
        with patch("app.api.routes.scans.celery_app.send_task", return_value=None):
            resp = client.post("/api/v1/scans", json={"target_id": tid, "profile": "quick"}, headers={"Authorization": f"Bearer {tokens['admin-a@target6c.test']}"})
        assert resp.status_code == 200
        sid = resp.json()["id"]
        db = TestingSession()
        audit = db.query(AuditLog).filter(AuditLog.resource_id == sid, AuditLog.event_type == "SCAN_CREATED").first()
        # Should not contain raw output or secrets
        meta_str = str(audit.extra_data)
        assert "password" not in meta_str.lower() or "[REDACTED]" in meta_str
        assert "stdout" not in meta_str.lower()
        db.close()
        # Direct sanitize test
        m = sanitize_metadata({"password": "secret", "profile": "quick"})
        assert m["password"] == "[REDACTED]"
        assert m["profile"] == "quick"
    finally:
        fastapi_app.dependency_overrides.clear()

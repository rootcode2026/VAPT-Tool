"""
Phase 6F — Request context + tenant-isolated audit read API.
"""
import uuid
import time
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

from app.models.audit_log import AuditLog
from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.scan import Scan
from app.models.user import User
from app.services.audit import AuditService
from app.core.request_id import REQUEST_ID_HEADER, CORRELATION_ID_HEADER


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__, Scan.__table__, AuditLog.__table__,
    ])
    # Assets for cloud but not needed
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE TABLE IF NOT EXISTS assets (id TEXT PRIMARY KEY, project_id TEXT, asset_type TEXT, value TEXT, status TEXT, metadata TEXT, created_at DATETIME, updated_at DATETIME, first_seen_scan_id TEXT, last_seen_scan_id TEXT, first_seen_at DATETIME, last_seen_at DATETIME)"))
    except Exception:
        pass
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-6f")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-6f")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@6f.test", password_hash=pwd, role="admin")
    member_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="member-a@6f.test", password_hash=pwd, role="member")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@6f.test", password_hash=pwd, role="member")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@6f.test", password_hash=pwd, role="admin")
    super_u = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="super@6f.test", password_hash=pwd, role="super_admin")
    db.add_all([admin_a, member_a, viewer_a, admin_b, super_u])
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
    # Create some audit logs for org_a and org_b
    for i in range(5):
        db.add(AuditLog(id=str(uuid.uuid4()), organization_id=org_a.id, project_id=proj_a1.id, actor_user_id=admin_a.id, event_type="TARGET_CREATED", action="TARGET_CREATED", resource_type="target", resource_id=str(uuid.uuid4()), result="SUCCESS", created_at=None))
    for i in range(3):
        db.add(AuditLog(id=str(uuid.uuid4()), organization_id=org_b.id, project_id=proj_b1.id, actor_user_id=admin_b.id, event_type="TARGET_CREATED", action="TARGET_CREATED", resource_type="target", resource_id=str(uuid.uuid4()), result="SUCCESS", created_at=None))
    # One with actor filter
    db.add(AuditLog(id=str(uuid.uuid4()), organization_id=org_a.id, project_id=proj_a1.id, actor_user_id=viewer_a.id, event_type="SCAN_CREATED", action="SCAN_CREATED", resource_type="scan", resource_id=str(uuid.uuid4()), result="SUCCESS", created_at=None))
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, member_a, viewer_a, admin_b, super_u]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_a2": proj_a2, "proj_b1": proj_b1, "admin_a": admin_a, "member_a": member_a, "viewer_a": viewer_a, "admin_b": admin_b, "super_u": super_u}
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


# ---- Request context tests ----
def test_generated_request_id_returned():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        assert REQUEST_ID_HEADER in resp.headers
        assert CORRELATION_ID_HEADER in resp.headers
        rid = resp.headers[REQUEST_ID_HEADER]
        cid = resp.headers[CORRELATION_ID_HEADER]
        assert 10 <= len(rid) <= 64
        assert 10 <= len(cid) <= 64
    finally:
        fastapi_app.dependency_overrides.clear()


def test_valid_incoming_ids_propagated():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        want_req = "req-abc123.def-456"
        want_corr = "corr-xyz789"
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}", REQUEST_ID_HEADER: want_req, CORRELATION_ID_HEADER: want_corr})
        assert resp.status_code == 200
        assert resp.headers[REQUEST_ID_HEADER] == want_req
        assert resp.headers[CORRELATION_ID_HEADER] == want_corr
    finally:
        fastapi_app.dependency_overrides.clear()


def test_oversized_malformed_ids_replaced():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        bad = "x" * 200
        evil = "bad/../evil$#@!"
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}", REQUEST_ID_HEADER: bad, CORRELATION_ID_HEADER: evil})
        assert resp.status_code == 200
        rid = resp.headers[REQUEST_ID_HEADER]
        cid = resp.headers[CORRELATION_ID_HEADER]
        assert rid != bad
        assert cid != evil
        assert len(rid) <= 64
        assert len(cid) <= 64
        assert ".." not in rid
        assert "$" not in cid
    finally:
        fastapi_app.dependency_overrides.clear()


def test_audit_record_receives_request_ids():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        want_req = "audit-req-123"
        want_corr = "audit-corr-456"
        # Create a target to generate audit
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "audit-req.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}", REQUEST_ID_HEADER: want_req, CORRELATION_ID_HEADER: want_corr})
        assert resp.status_code == 200, resp.text
        tid = resp.json()["id"]
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.resource_id == tid, AuditLog.event_type == "TARGET_CREATED").first()
        assert audit.request_id == want_req
        assert audit.correlation_id == want_corr
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_ip_captured_safely():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "ip-test.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        tid = resp.json()["id"]
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.resource_id == tid).first()
        # TestClient IP is testclient
        assert audit.ip_address is not None
        # Should not be spoofed X-Forwarded-For
        db.close()
        # Try spoofed X-Forwarded-For should not be stored
        resp2 = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "ip-spoof.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}", "X-Forwarded-For": "1.2.3.4, 5.6.7.8"})
        assert resp2.status_code == 200
        tid2 = resp2.json()["id"]
        db = Session()
        audit2 = db.query(AuditLog).filter(AuditLog.resource_id == tid2).first()
        assert audit2.ip_address != "1.2.3.4"
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_user_agent_captured_and_bounded():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        long_ua = "A" * 1000
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "ua-test.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}", "User-Agent": long_ua})
        assert resp.status_code == 200
        tid = resp.json()["id"]
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.resource_id == tid).first()
        assert audit.user_agent is not None
        assert len(audit.user_agent) <= 500
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_authorization_not_persisted():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/targets", json={"project_id": objs["proj_a1"].id, "value": "noauth.example.com", "target_type": "domain"}, headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}", "Cookie": "session=abc", REQUEST_ID_HEADER: "req1", CORRELATION_ID_HEADER: "corr1"})
        assert resp.status_code == 200, resp.text
        tid = resp.json()["id"]
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.resource_id == tid).first()
        meta = str(audit.extra_data) if audit.extra_data else ""
        assert "Bearer" not in meta
        assert "Cookie" not in meta
        # Also check that audit's user_agent is not Authorization
        assert audit.user_agent is None or "Bearer" not in audit.user_agent
        assert audit.user_agent is None or "Cookie" not in audit.user_agent
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


# ---- Audit read API tenant isolation ----
def test_org_a_can_read_own():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 5
        for item in data["items"]:
            assert item["organization_id"] == objs["org_a"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_org_a_cannot_read_org_b():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert item["organization_id"] != objs["org_b"].id
        # Ensure org_b logs not leaked via direct filter
        resp2 = client.get(f"/api/v1/audit_logs?actor_user_id={objs['admin_b'].id}", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp2.status_code == 200
        assert resp2.json()["total"] == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_project_filter_cannot_escape_org():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # admin_a trying to read proj_b1 (org_b) via project_id
        resp = client.get(f"/api/v1/audit_logs?project_id={objs['proj_b1'].id}", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        # Should be 404 due to require_project_access, not 200 with data
        assert resp.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_project_user_cannot_read_unauthorized_project():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # viewer_a is viewer on proj_a1 but not proj_a2; audit read requires org_admin so viewer will get 403 anyway
        resp = client.get(f"/api/v1/audit_logs?project_id={objs['proj_a2'].id}", headers={"Authorization": f"Bearer {tokens['viewer-a@6f.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_super_admin_platform_access():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['super@6f.test']}"})
        assert resp.status_code == 200
        # Super admin sees both orgs
        org_ids = {i["organization_id"] for i in resp.json()["items"]}
        assert objs["org_a"].id in org_ids
        assert objs["org_b"].id in org_ids
    finally:
        fastapi_app.dependency_overrides.clear()


def test_missing_audit_read_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['member-a@6f.test']}"})
        assert resp.status_code == 403
        resp2 = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['viewer-a@6f.test']}"})
        assert resp2.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_unknown_project_cannot_bypass():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        fake = str(uuid.uuid4())
        resp = client.get(f"/api/v1/audit_logs?project_id={fake}", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_actor_filter_cannot_bypass_tenant():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/audit_logs?actor_user_id={objs['admin_b'].id}", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 0
        for item in resp.json()["items"]:
            assert item["actor_user_id"] != objs["admin_b"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_resource_id_filter_cannot_bypass():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Get a resource_id from org_b
        db = Session()
        org_b_audit = db.query(AuditLog).filter(AuditLog.organization_id == objs["org_b"].id).first()
        rid = org_b_audit.resource_id
        db.close()
        resp = client.get(f"/api/v1/audit_logs?resource_id={rid}", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 0
    finally:
        fastapi_app.dependency_overrides.clear()


# ---- Pagination ----
def test_default_page_size_bounded():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["page_size"] == 50
        assert len(data["items"]) <= 50
    finally:
        fastapi_app.dependency_overrides.clear()


def test_page_size_over_100_rejected_or_bounded():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs?page_size=200", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        # FastAPI validation: le=100 -> 422
        assert resp.status_code == 422
    finally:
        fastapi_app.dependency_overrides.clear()


def test_page_zero_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs?page=0", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 422
    finally:
        fastapi_app.dependency_overrides.clear()


def test_total_respects_tenant():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp_a = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp_a.status_code == 200
        total_a = resp_a.json()["total"]
        # admin_a sees only org_a (5 + 1 =6)
        assert total_a == 6
        resp_b = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-b@6f.test']}"})
        assert resp_b.status_code == 200
        assert resp_b.json()["total"] == 3
    finally:
        fastapi_app.dependency_overrides.clear()


def test_ordering_desc():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Create a new audit to ensure latest
        db = Session()
        latest_id = str(uuid.uuid4())
        db.add(AuditLog(id=latest_id, organization_id=objs["org_a"].id, event_type="TEST", action="TEST", result="SUCCESS", created_at=None))
        db.commit()
        db.close()
        resp = client.get("/api/v1/audit_logs?page_size=10", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        items = resp.json()["items"]
        # First item should be most recent (latest_id)
        assert items[0]["id"] == latest_id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_filters_combine():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/audit_logs?event_type=SCAN_CREATED&actor_user_id={objs['viewer_a'].id}", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert item["event_type"] == "SCAN_CREATED"
            assert item["actor_user_id"] == objs["viewer_a"].id
    finally:
        fastapi_app.dependency_overrides.clear()


# ---- Response redaction ----
def test_response_safe_metadata():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Create audit with sensitive keys via direct insert (should be redacted on write, but test response)
        db = Session()
        fid = str(uuid.uuid4())
        AuditService.record(db, event_type="TEST", action="TEST", result="SUCCESS", organization_id=objs["org_a"].id, project_id=objs["proj_a1"].id, actor_user_id=objs["admin_a"].id, resource_type="test", resource_id=fid, metadata={"password": "secret", "profile": "quick"})
        db.commit()
        db.close()
        resp = client.get(f"/api/v1/audit_logs?resource_id={fid}", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 1
        meta = resp.json()["items"][0]["metadata"]
        assert meta["password"] == "[REDACTED]"
        assert meta["profile"] == "quick"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_response_no_passwords_tokens():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            meta_str = str(item["metadata"]) if item["metadata"] else ""
            assert "password" not in meta_str.lower() or "[REDACTED]" in meta_str
    finally:
        fastapi_app.dependency_overrides.clear()


def test_tenant_b_not_in_tenant_a_response():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        org_b_ids = [i["id"] for i in resp.json()["items"] if i["organization_id"] == objs["org_b"].id]
        assert org_b_ids == []
    finally:
        fastapi_app.dependency_overrides.clear()


def test_raw_body_never_exposed():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/audit_logs", headers={"Authorization": f"Bearer {tokens['admin-a@6f.test']}"})
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert "raw_body" not in str(item["metadata"]).lower()
            assert "Authorization" not in str(item)
    finally:
        fastapi_app.dependency_overrides.clear()

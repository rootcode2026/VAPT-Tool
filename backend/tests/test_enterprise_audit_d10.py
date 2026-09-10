"""D10 enterprise audit tests — quality, taxonomy, RBAC, IDOR, filters, bounds,
secrets, integrity, immutability, export, access auditing.

AuditService.record is the single creation path under test; worker direct-SQL
inserts are out of scope (documented as unchained, never failures).
"""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import JSON as _JSON
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
import app.models.audit_log  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.user import User
from app.models.audit_log import AuditLog
from app.services.audit import (
    EVENT_PROJECT_UPDATED,
    EVENT_REPORT_CREATED,
    EVENT_REPORT_GENERATION_COMPLETED,
    EVENT_SCANNER_CANARY_REQUESTED,
    GENESIS_PREV_HASH,
    RESULT_SUCCESS,
    AuditService,
    compute_event_hash,
    canonical_audit_payload,
    verify_audit_chain,
    verify_record_integrity,
)


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for _tbl in list(Base.metadata.tables.values()):
        for _col in _tbl.columns:
            if _col.type.__class__.__name__ == "JSONB":
                _col.type = _JSON()
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, AuditLog.__table__,
    ])
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-d10", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-d10", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@d10.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@d10.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@d10.test", password_hash=pwd, role="member", status="active")
    dev_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="dev-a@d10.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@d10.test", password_hash=pwd, role="admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, dev_a, admin_b])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=dev_a.id, role="developer", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin", status="active"))
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A1", description="d")
    proj_b1 = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B1", description="d")
    db.add_all([proj_a1, proj_b1])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=admin_a.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=analyst_a.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=viewer_a.id, role="viewer", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=dev_a.id, role="developer", status="active"))
    db.commit()
    # Seeded audit history via the single canonical path.
    AuditService.record(db, event_type="TEST_ACTION_ONE", action="TEST_ACTION_ONE", result=RESULT_SUCCESS, actor_user_id=analyst_a.id, organization_id=org_a.id, project_id=proj_a1.id, resource_type="finding", resource_id="finding-1", correlation_id="corr-1", metadata={"k": "v"})
    AuditService.record(db, event_type="TEST_ACTION_TWO", action="TEST_ACTION_TWO", result="FAILURE", actor_user_id=admin_a.id, organization_id=org_a.id, project_id=proj_a1.id, resource_type="project", resource_id=proj_a1.id, correlation_id="corr-2")
    AuditService.record(db, event_type="TEST_OTHER_TENANT", action="TEST_OTHER_TENANT", result=RESULT_SUCCESS, actor_user_id=admin_b.id, organization_id=org_b.id, project_id=proj_b1.id, resource_type="project", resource_id=proj_b1.id)
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, dev_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_b1": proj_b1,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a, "dev_a": dev_a, "admin_b": admin_b}
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


def _auth(tokens, email):
    return {"Authorization": f"Bearer {tokens[email]}"}


# --- creation quality ---
def test_d10_creation_quality_and_chain_link():
    _, Session, tokens, objs = _setup()
    s = Session()
    try:
        rows = s.query(AuditLog).filter(AuditLog.project_id == objs["proj_a1"].id).order_by(AuditLog.created_at).all()
        assert len(rows) == 2
        first, second = rows
        assert first.actor_user_id == objs["analyst_a"].id
        assert first.organization_id == objs["org_a"].id
        assert first.resource_type == "finding" and first.resource_id == "finding-1"
        assert first.result == "SUCCESS"
        assert first.correlation_id == "corr-1"
        assert first.prev_hash == GENESIS_PREV_HASH
        assert first.event_hash == compute_event_hash(canonical_audit_payload(first), GENESIS_PREV_HASH)
        assert second.prev_hash == first.event_hash
        assert verify_record_integrity(s, first) == "verified"
        assert verify_record_integrity(s, second) == "verified"
    finally:
        s.close()


def test_d10_taxonomy_compatible_no_duplicates():
    assert EVENT_REPORT_CREATED == "REPORT_CREATED"
    assert EVENT_REPORT_GENERATION_COMPLETED == "REPORT_GENERATION_COMPLETED"
    assert EVENT_SCANNER_CANARY_REQUESTED == "SCANNER_CANARY_REQUESTED"
    assert EVENT_PROJECT_UPDATED == "PROJECT_UPDATED"
    _, Session, tokens, objs = _setup()
    s = Session()
    try:
        n = s.query(AuditLog).filter(AuditLog.event_type == "TEST_ACTION_ONE").count()
        assert n == 1
    finally:
        s.close()


# --- RBAC ---
def test_d10_read_rbac():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        assert client.get(f"/api/v1/projects/{pid}/audit", headers=_auth(tokens, "viewer-a@d10.test")).status_code == 200
        assert client.get(f"/api/v1/projects/{pid}/audit", headers=_auth(tokens, "analyst-a@d10.test")).status_code == 200
        assert client.get(f"/api/v1/projects/{pid}/audit", headers=_auth(tokens, "admin-a@d10.test")).status_code == 200
        # developer lacks audit.read
        assert client.get(f"/api/v1/projects/{pid}/audit", headers=_auth(tokens, "dev-a@d10.test")).status_code == 403
        assert client.get(f"/api/v1/projects/{pid}/audit").status_code in (401, 403)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d10_manage_rbac():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        assert client.get(f"/api/v1/projects/{pid}/audit/export?format=json", headers=_auth(tokens, "admin-a@d10.test")).status_code == 200
        assert client.post(f"/api/v1/projects/{pid}/audit/verify-integrity", json={}, headers=_auth(tokens, "admin-a@d10.test")).status_code == 200
        assert client.get(f"/api/v1/projects/{pid}/audit/export?format=json", headers=_auth(tokens, "analyst-a@d10.test")).status_code == 403
        assert client.post(f"/api/v1/projects/{pid}/audit/verify-integrity", json={}, headers=_auth(tokens, "viewer-a@d10.test")).status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


# --- IDOR / tenant isolation ---
def test_d10_cross_project_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert client.get(f"/api/v1/projects/{objs['proj_b1'].id}/audit", headers=_auth(tokens, "analyst-a@d10.test")).status_code == 404
        s = Session()
        try:
            own = s.query(AuditLog).filter(AuditLog.project_id == objs["proj_a1"].id).first()
            own_id = own.id
        finally:
            s.close()
        assert client.get(f"/api/v1/projects/{objs['proj_b1'].id}/audit/{own_id}", headers=_auth(tokens, "admin-b@d10.test")).status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d10_cross_tenant_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert client.get(f"/api/v1/projects/{objs['proj_a1'].id}/audit", headers=_auth(tokens, "admin-b@d10.test")).status_code == 404
        assert client.get(f"/api/v1/projects/{objs['proj_a1'].id}/audit/export?format=json", headers=_auth(tokens, "admin-b@d10.test")).status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d10_resource_filter_cannot_escape_scope():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        # resource_id belonging to the other tenant yields nothing in this scope.
        r = client.get(f"/api/v1/projects/{pid}/audit?resource_id={objs['proj_b1'].id}", headers=_auth(tokens, "analyst-a@d10.test")).json()
        assert r["items"] == []
    finally:
        fastapi_app.dependency_overrides.clear()


# --- filtering ---
def test_d10_filters():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d10.test")
    pid = objs["proj_a1"].id
    try:
        assert len(client.get(f"/api/v1/projects/{pid}/audit?event_type=TEST_ACTION_ONE", headers=H).json()["items"]) == 1
        assert len(client.get(f"/api/v1/projects/{pid}/audit?actor_user_id={objs['admin_a'].id}", headers=H).json()["items"]) == 1
        assert len(client.get(f"/api/v1/projects/{pid}/audit?resource_type=finding", headers=H).json()["items"]) == 1
        assert len(client.get(f"/api/v1/projects/{pid}/audit?resource_id=finding-1", headers=H).json()["items"]) == 1
        assert len(client.get(f"/api/v1/projects/{pid}/audit?result=FAILURE", headers=H).json()["items"]) == 1
        assert len(client.get(f"/api/v1/projects/{pid}/audit?correlation_id=corr-1", headers=H).json()["items"]) == 1
        assert len(client.get(f"/api/v1/projects/{pid}/audit?action=TEST_ACTION_TWO", headers=H).json()["items"]) == 1
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d10_result_validation_and_date_bounds():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d10.test")
    pid = objs["proj_a1"].id
    try:
        assert client.get(f"/api/v1/projects/{pid}/audit?result=BOGUS", headers=H).status_code == 400
        assert client.get(f"/api/v1/projects/{pid}/audit?limit=1000", headers=H).status_code == 422
        assert client.get(f"/api/v1/projects/{pid}/audit?since=not-a-date", headers=H).status_code == 400
        assert client.get(f"/api/v1/projects/{pid}/audit/export?format=json&since=2020-01-01T00:00:00Z&until=2025-01-01T00:00:00Z", headers=_auth(tokens, "admin-a@d10.test")).status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


# --- secrets / bounds ---
def test_d10_secrets_redacted_and_bounded():
    _, Session, tokens, objs = _setup()
    s = Session()
    try:
        AuditService.record(s, event_type="TEST_SECRET", action="TEST_SECRET", result=RESULT_SUCCESS, actor_user_id=objs["analyst_a"].id, organization_id=objs["org_a"].id, project_id=objs["proj_a1"].id, metadata={"password": "hunter2", "api_key": "sk-123", "note": "x" * 9000})
        s.commit()
        row = s.query(AuditLog).filter(AuditLog.event_type == "TEST_SECRET").first()
        import json as _json
        blob = _json.dumps(row.extra_data or {})
        assert "hunter2" not in blob and "sk-123" not in blob
        assert len(blob.encode()) <= 4096 + 256
    finally:
        s.close()


# --- integrity ---
def test_d10_chain_verifies_and_detects_tamper():
    _, Session, tokens, objs = _setup()
    s = Session()
    try:
        ok = verify_audit_chain(s, objs["org_a"].id, limit=100)
        assert ok["valid"] is True and ok["checked"] == 2 and ok["failures"] == []
        victim = s.query(AuditLog).filter(AuditLog.project_id == objs["proj_a1"].id).order_by(AuditLog.created_at).first()
        victim_id = victim.id
        victim.action = "TAMPERED_ACTION"
        s.commit()
        assert verify_record_integrity(s, s.query(AuditLog).filter(AuditLog.id == victim_id).first()) == "mismatch"
        bad = verify_audit_chain(s, objs["org_a"].id, limit=100)
        assert bad["valid"] is False and victim_id in bad["failures"]
    finally:
        s.close()


def test_d10_broken_link_and_hash_tamper_detected():
    _, Session, tokens, objs = _setup()
    s = Session()
    try:
        rows = s.query(AuditLog).filter(AuditLog.project_id == objs["proj_a1"].id).order_by(AuditLog.created_at).all()
        first, second = rows
        # Attacker deletes the parent: child recomputes fine but its prev link is gone.
        s.delete(first)
        s.commit()
        assert verify_record_integrity(s, s.query(AuditLog).filter(AuditLog.id == second.id).first()) == "broken_link"
        bad = verify_audit_chain(s, objs["org_a"].id, limit=100)
        assert bad["valid"] is False and second.id in bad["failures"]
        # Attacker rewrites the stored hash: recomputation mismatches.
        second.event_hash = "f" * 64
        s.commit()
        assert verify_record_integrity(s, s.query(AuditLog).filter(AuditLog.id == second.id).first()) == "mismatch"
    finally:
        s.close()


def test_d10_unchained_rows_skipped_not_failed():
    _, Session, tokens, objs = _setup()
    s = Session()
    try:
        s.execute(text("INSERT INTO audit_logs (id, organization_id, project_id, event_type, action, result, created_at) VALUES (:id, :org, :proj, 'LEGACY', 'LEGACY', 'SUCCESS', :now)"),
                  {"id": str(uuid.uuid4()), "org": objs["org_a"].id, "proj": objs["proj_a1"].id, "now": datetime.now(timezone.utc).replace(tzinfo=None)})
        s.commit()
        result = verify_audit_chain(s, objs["org_a"].id, limit=100)
        assert result["valid"] is True
        assert result["unchained"] == 1
    finally:
        s.close()


def test_d10_detail_integrity_status():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        H = _auth(tokens, "analyst-a@d10.test")
        first_id = client.get(f"/api/v1/projects/{pid}/audit?limit=10", headers=H).json()["items"][-1]["id"]
        detail = client.get(f"/api/v1/projects/{pid}/audit/{first_id}", headers=H).json()
        assert detail["integrity"] == "verified"
        assert detail["event_hash"] and detail["prev_hash"]
    finally:
        fastapi_app.dependency_overrides.clear()


# --- immutability ---
def test_d10_no_update_or_delete_api():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        H = _auth(tokens, "admin-a@d10.test")
        assert client.put(f"/api/v1/projects/{pid}/audit", json={}, headers=H).status_code in (404, 405)
        assert client.delete(f"/api/v1/projects/{pid}/audit", headers=H).status_code in (404, 405)
    finally:
        fastapi_app.dependency_overrides.clear()


# --- export ---
def test_d10_export_authorized_bounded_clean():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H_admin = _auth(tokens, "admin-a@d10.test")
    try:
        pid = objs["proj_a1"].id
        r = client.get(f"/api/v1/projects/{pid}/audit/export?format=json", headers=H_admin)
        assert r.status_code == 200
        body = r.json()
        assert body["project_id"] == pid and body["truncated"] is False
        assert all(i["project_id"] == pid for i in body["items"])
        import json as _json
        assert "hunter2" not in _json.dumps(body)
        c = client.get(f"/api/v1/projects/{pid}/audit/export?format=csv", headers=H_admin)
        assert c.status_code == 200 and "text/csv" in c.headers["content-type"]
        assert c.text.splitlines()[0].startswith("id,created_at,")
        assert client.get(f"/api/v1/projects/{pid}/audit/export?format=xml", headers=H_admin).status_code == 400
        assert client.get(f"/api/v1/projects/{pid}/audit/export?format=json", headers=_auth(tokens, "analyst-a@d10.test")).status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


# --- access auditing ---
def test_d10_export_and_verify_audited_list_not():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H_admin = _auth(tokens, "admin-a@d10.test")
    try:
        pid = objs["proj_a1"].id
        s = Session()
        try:
            before = s.query(AuditLog).filter(AuditLog.project_id == pid).count()
        finally:
            s.close()
        client.get(f"/api/v1/projects/{pid}/audit?limit=10", headers=H_admin)
        client.get(f"/api/v1/projects/{pid}/audit/export?format=json", headers=H_admin)
        client.post(f"/api/v1/projects/{pid}/audit/verify-integrity", json={"limit": 50}, headers=H_admin)
        s = Session()
        try:
            types = {r.event_type for r in s.query(AuditLog).filter(AuditLog.project_id == pid).all()}
            assert "AUDIT_EXPORTED" in types
            assert "AUDIT_INTEGRITY_VERIFIED" in types
            # list added nothing; export+verify added exactly 2.
            assert s.query(AuditLog).filter(AuditLog.project_id == pid).count() == before + 2
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d10_verify_endpoint_result_shape():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        r = client.post(f"/api/v1/projects/{pid}/audit/verify-integrity", json={"limit": 50}, headers=_auth(tokens, "admin-a@d10.test")).json()
        assert r["valid"] is True and r["checked"] >= 2 and r["scope"] == objs["org_a"].id
        assert client.post(f"/api/v1/projects/{pid}/audit/verify-integrity", json={"limit": 99999}, headers=_auth(tokens, "admin-a@d10.test")).json()["checked"] <= 1000
    finally:
        fastapi_app.dependency_overrides.clear()

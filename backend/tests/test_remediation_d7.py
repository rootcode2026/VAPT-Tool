"""D7 remediation workflow tests — deterministic, tenant-scoped, bounded.

Covers: creation, owner validation, blocked lifecycle, SLA reuse,
evidence references, RBAC/IDOR isolation, audit, idempotency,
bounded listing, and verification boundary (completed != verified).
"""

import uuid
from datetime import datetime, timedelta, timezone

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


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    # SQLite compat shim (test-only): JSONB is Postgres-only; use generic JSON.
    # Pre-existing repo issue: JSONB/SQLite fixture drift breaks SQLite suites.
    from sqlalchemy import JSON as _JSON
    for _tbl in list(Base.metadata.tables.values()):
        for _col in _tbl.columns:
            if _col.type.__class__.__name__ == "JSONB":
                _col.type = _JSON()
            try:
                _sd = _col.server_default
                if _sd is not None and "jsonb" in str(getattr(_sd, "arg", "")):
                    _col.server_default = None
            except Exception:
                pass
    from app.models.finding import (
        FindingComment, FindingHistory, FindingTag, FindingRemediation,
        FindingRetest, FindingRiskAcceptance, FindingSLA, SLAPolicy,
    )
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__, Scan.__table__,
        AuditLog.__table__, FindingComment.__table__, FindingHistory.__table__, FindingTag.__table__,
        FindingSLA.__table__, FindingRiskAcceptance.__table__, FindingRemediation.__table__,
        FindingRetest.__table__, SLAPolicy.__table__,
    ])
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT, target_id TEXT, asset_id TEXT, scanner TEXT, title TEXT, description TEXT,
                severity TEXT, score INTEGER, status TEXT, evidence TEXT, remediation TEXT, cve TEXT, cwe TEXT,
                assigned_to TEXT, assigned_at DATETIME, assigned_by TEXT,
                owner_user_id TEXT, owner_team_id TEXT, severity_override TEXT,
                workflow_status TEXT, closed_at DATETIME, closed_by TEXT,
                remediation_claimed_at DATETIME, remediation_claimed_by TEXT,
                ready_for_retest_at DATETIME,
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
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-d7", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-d7", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@d7.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@d7.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@d7.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@d7.test", password_hash=pwd, role="admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, admin_b])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin", status="active"))
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A1", description="d")
    proj_b1 = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B1", description="d")
    db.add_all([proj_a1, proj_b1])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=admin_a.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=analyst_a.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=viewer_a.id, role="viewer", status="active"))
    target_a1 = Target(id=str(uuid.uuid4()), project_id=proj_a1.id, value="a1.example.com", target_type="domain", is_active=True)
    target_b1 = Target(id=str(uuid.uuid4()), project_id=proj_b1.id, value="b1.example.com", target_type="domain", is_active=True)
    db.add_all([target_a1, target_b1])
    db.flush()
    scan_a1 = Scan(id=str(uuid.uuid4()), target_id=target_a1.id, profile="quick", status="completed", phase="completed", progress=100)
    scan_b1 = Scan(id=str(uuid.uuid4()), target_id=target_b1.id, profile="quick", status="completed", phase="completed", progress=100)
    db.add_all([scan_a1, scan_b1])
    db.flush()
    fid_a1 = str(uuid.uuid4())
    fid_b1 = str(uuid.uuid4())
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan, :target, :scanner, :title, :sev, :status, :ev, :meta)"),
               {"id": fid_a1, "scan": scan_a1.id, "target": target_a1.id, "scanner": "nmap", "title": "F A", "sev": "high", "status": "triaged", "ev": "ev", "meta": "{}"})
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan, :target, :scanner, :title, :sev, :status, :ev, :meta)"),
               {"id": fid_b1, "scan": scan_b1.id, "target": target_b1.id, "scanner": "nmap", "title": "F B", "sev": "medium", "status": "open", "ev": "ev", "meta": "{}"})
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_b1": proj_b1,
            "fid_a1": fid_a1, "fid_b1": fid_b1,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a, "admin_b": admin_b}
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


def _create(client, tokens, objs, **kw):
    body = {"title": "fix vuln"}
    body.update(kw)
    return client.post(f"/api/v1/findings/{objs['fid_a1']}/remediations", json=body, headers=_auth(tokens, "analyst-a@d7.test"))


# --- creation ---
def test_d7_create_remediation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = _create(client, tokens, objs, assigned_to=objs["analyst_a"].id)
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["status"] == "open"
        assert data["assigned_to"] == objs["analyst_a"].id
        assert data["verified"] is False
        assert data["verification_required"] is False
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_duplicate_active_409():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert _create(client, tokens, objs).status_code == 201
        assert _create(client, tokens, objs).status_code == 409
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_cross_project_finding_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_b1']}/remediations", json={"title": "x"}, headers=_auth(tokens, "analyst-a@d7.test"))
        assert r.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_auth_required():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert client.post(f"/api/v1/findings/{objs['fid_a1']}/remediations", json={"title": "x"}).status_code in (401, 403)
        assert client.get(f"/api/v1/projects/{objs['proj_a1'].id}/remediations").status_code in (401, 403)
    finally:
        fastapi_app.dependency_overrides.clear()


# --- owner ---
def test_d7_cross_tenant_owner_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = _create(client, tokens, objs, assigned_to=objs["admin_b"].id)
        assert r.status_code in (403, 404), r.text
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_viewer_cannot_write():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/findings/{objs['fid_a1']}/remediations", json={"title": "x"}, headers=_auth(tokens, "viewer-a@d7.test"))
        assert r.status_code == 403
        # viewer can read project queue
        rem = _create(client, tokens, objs)
        assert rem.status_code == 201
        g = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/remediations", headers=_auth(tokens, "viewer-a@d7.test"))
        assert g.status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_owner_change_audited_with_history():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        rem = _create(client, tokens, objs).json()
        u = client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rem['id']}", json={"assigned_to": objs["admin_a"].id}, headers=_auth(tokens, "analyst-a@d7.test"))
        assert u.status_code == 200, u.text
        assert u.json()["assigned_to"] == objs["admin_a"].id
        h = client.get(f"/api/v1/findings/{objs['fid_a1']}/history", headers=_auth(tokens, "analyst-a@d7.test")).json()
        assert any(x["action"] == "remediation_assigned" for x in h["items"])
    finally:
        fastapi_app.dependency_overrides.clear()


# --- lifecycle ---
def test_d7_start_block_unblock_complete():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        rem = _create(client, tokens, objs).json()
        pid = objs["proj_a1"].id
        assert client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/start", headers=H).json()["status"] == "in_progress"
        b = client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/block", json={"blocked_reason": "waiting for deploy"}, headers=H)
        assert b.status_code == 200, b.text
        assert b.json()["status"] == "blocked"
        assert client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/unblock", headers=H).json()["status"] == "in_progress"
        # submitted via PATCH then complete via action
        assert client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rem['id']}", json={"status": "submitted"}, headers=H).status_code == 200
        c = client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/complete", json={"completion_notes": "patched"}, headers=H)
        assert c.status_code == 200, c.text
        body = c.json()
        assert body["status"] == "completed"
        assert body["verification_required"] is True
        assert body["verified"] is False
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_block_requires_reason():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        rem = _create(client, tokens, objs).json()
        pid = objs["proj_a1"].id
        client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/start", headers=H)
        assert client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/block", json={}, headers=H).status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_invalid_transition_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        rem = _create(client, tokens, objs).json()
        r = client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rem['id']}", json={"status": "completed"}, headers=H)
        assert r.status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_repeat_transition_idempotent():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        rem = _create(client, tokens, objs).json()
        pid = objs["proj_a1"].id
        assert client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/start", headers=H).status_code == 200
        # second start is idempotent no-op
        assert client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/start", headers=H).status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_completion_does_not_resolve_finding():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        rem = _create(client, tokens, objs).json()
        pid = objs["proj_a1"].id
        client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/start", headers=H)
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rem['id']}", json={"status": "submitted"}, headers=H)
        client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/complete", json={}, headers=H)
        f = client.get(f"/api/v1/findings/{objs['fid_a1']}", headers=H).json()
        assert f["status"] != "resolved"
        assert f["status"] != "verified"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_duplicate_completion_stable():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        rem = _create(client, tokens, objs).json()
        pid = objs["proj_a1"].id
        client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/start", headers=H)
        client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rem['id']}", json={"status": "submitted"}, headers=H)
        assert client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/complete", json={}, headers=H).status_code == 200
        # second complete: idempotent no-op, still completed
        r2 = client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/complete", json={}, headers=H)
        assert r2.status_code == 200
        assert r2.json()["status"] == "completed"
    finally:
        fastapi_app.dependency_overrides.clear()


# --- SLA reuse ---
def test_d7_due_defaults_from_sla():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        assert client.post(f"/api/v1/findings/{objs['fid_a1']}/sla/start", headers=H).status_code == 201
        rem = _create(client, tokens, objs).json()
        assert rem["due_at"] is not None
        assert rem["due_source"] == "sla"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_no_duplicate_sla_engine():
    from app.services import finding_lifecycle as lc
    # Remediation must reuse SLA policy calculation, not define its own.
    assert lc.get_sla_target_hours is not None
    import inspect
    src = inspect.getsource(lc)
    assert src.count("target_hours") < 12  # single SLA engine, not duplicated


# --- evidence ---
def test_d7_evidence_ref_attached_bounded():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        rem = _create(client, tokens, objs, evidence_ref="retest:run-123").json()
        assert rem["evidence_ref"] == "retest:run-123"
        u = client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rem['id']}", json={"evidence_ref": "scan:abc"}, headers=H)
        assert u.status_code == 200
        assert u.json()["evidence_ref"] == "scan:abc"
        # oversized truncated to 2000
        big = "x" * 5000
        u2 = client.patch(f"/api/v1/findings/{objs['fid_a1']}/remediations/{rem['id']}", json={"evidence_ref": big}, headers=H)
        assert len(u2.json()["evidence_ref"]) == 2000
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_secret_evidence_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = _create(client, tokens, objs, evidence_ref="-----BEGIN PRIVATE KEY----- abc")
        assert r.status_code == 400, r.text
    finally:
        fastapi_app.dependency_overrides.clear()


# --- security / isolation ---
def test_d7_cross_project_queue_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        _create(client, tokens, objs)
        # other tenant cannot read project A queue
        r = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/remediations", headers=_auth(tokens, "admin-b@d7.test"))
        assert r.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_idor_remediation_id_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        rem = _create(client, tokens, objs).json()
        # project B context must not resolve project A remediation
        r = client.get(f"/api/v1/projects/{objs['proj_b1'].id}/remediations/{rem['id']}", headers=_auth(tokens, "admin-b@d7.test"))
        assert r.status_code == 404
        # cross-project action denied
        r2 = client.post(f"/api/v1/projects/{objs['proj_b1'].id}/remediations/{rem['id']}/start", headers=_auth(tokens, "admin-b@d7.test"))
        assert r2.status_code in (403, 404)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d7_viewer_cannot_transition():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        rem = _create(client, tokens, objs).json()
        pid = objs["proj_a1"].id
        r = client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/start", headers=_auth(tokens, "viewer-a@d7.test"))
        assert r.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


# --- audit ---
def test_d7_audit_events_no_secrets():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        rem = _create(client, tokens, objs).json()
        pid = objs["proj_a1"].id
        client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/start", headers=H)
        client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/block", json={"blocked_reason": "waiting"}, headers=H)
        client.post(f"/api/v1/projects/{pid}/remediations/{rem['id']}/unblock", headers=H)
        s = Session()
        try:
            rows = s.query(AuditLog).filter(AuditLog.project_id == pid).all()
            types = {r.event_type for r in rows}
            assert "REMEDIATION_CREATED" in types
            assert "REMEDIATION_BLOCKED" in types
            assert "REMEDIATION_UNBLOCKED" in types
            import json as _json
            for r in rows:
                blob = _json.dumps(getattr(r, "extra_data", None) or {})
                assert "BEGIN PRIVATE" not in blob
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


# --- listing bounds ---
def test_d7_list_bounded_and_filtered():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        rem = _create(client, tokens, objs).json()
        q = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/remediations?status=open&limit=10", headers=H).json()
        assert q["total"] >= 1
        assert len(q["items"]) <= 10
        q2 = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/remediations?status=completed&limit=10", headers=H).json()
        assert all(i["status"] == "completed" for i in q2["items"])
        assert client.get(f"/api/v1/projects/{objs['proj_a1'].id}/remediations/{rem['id']}", headers=H).status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()


# --- regression: finding + SLA intact ---
def test_d7_regression_finding_sla_intact():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@d7.test")
    try:
        assert client.post(f"/api/v1/findings/{objs['fid_a1']}/sla/start", headers=H).status_code == 201
        s = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/sla/summary", headers=H)
        assert s.status_code == 200
        f = client.get(f"/api/v1/findings/{objs['fid_a1']}", headers=H)
        assert f.status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()

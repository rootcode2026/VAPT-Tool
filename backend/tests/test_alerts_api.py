"""D3 alert API tests: lifecycle, RBAC, tenant/project isolation, policy."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
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
import app.models.audit_log  # noqa
import app.models.alert  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.alert import Alert, AlertPolicy


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__,
        AuditLog.__table__, Alert.__table__, AlertPolicy.__table__,
    ])
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-d3", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-d3", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@d3.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@d3.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@d3.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@d3.test", password_hash=pwd, role="admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, admin_b])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin", status="active"))
    proj_a = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A", description="d")
    proj_b = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B", description="d")
    db.add_all([proj_a, proj_b])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=admin_a.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=analyst_a.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=viewer_a.id, role="viewer", status="active"))
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    a_open = Alert(
        id=str(uuid.uuid4()), organization_id=org_a.id, project_id=proj_a.id,
        monitoring_config_id="cfg-1", alert_type="NEW_CRITICAL_FINDING", severity="critical",
        status="open", title="Critical vulnerability detected: TLS weak cipher",
        description="Critical vulnerability detected on scan scan-1 (monitoring run run-1).",
        source_change_event_id="ev-1", source_finding_id="f-1", finding_fingerprint="fp1",
        monitoring_run_id="run-1", first_seen_at=now, last_seen_at=now,
        event_count=2, dedup_key="dk-" + str(uuid.uuid4()), extra_data={"monitoring_run_id": "run-1"},
    )
    a_ack = Alert(
        id=str(uuid.uuid4()), organization_id=org_a.id, project_id=proj_a.id,
        alert_type="HIGH_ASSET_EXPOSURE", severity="high", status="acknowledged",
        title="New externally visible asset detected: example.com",
        first_seen_at=now, last_seen_at=now, acknowledged_at=now, acknowledged_by=analyst_a.id,
        event_count=1, dedup_key="dk-" + str(uuid.uuid4()), extra_data={},
    )
    a_res = Alert(
        id=str(uuid.uuid4()), organization_id=org_a.id, project_id=proj_a.id,
        alert_type="NEW_HIGH_FINDING", severity="high", status="resolved",
        title="High severity finding detected: Old",
        first_seen_at=now - timedelta(days=2), last_seen_at=now,
        resolved_at=now - timedelta(days=1), resolved_by=admin_a.id,
        event_count=1, dedup_key="dk-" + str(uuid.uuid4()), extra_data={},
    )
    db.add_all([a_open, a_ack, a_res])
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a": proj_a, "proj_b": proj_b,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a, "admin_b": admin_b,
            "a_open": a_open, "a_ack": a_ack, "a_res": a_res}
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


def _url(objs, suffix=""):
    return f"/api/v1/projects/{objs['proj_a'].id}/alerts{suffix}"


def test_list_shape_and_pagination():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.get(_url(objs), headers=_auth(tokens, "admin-a@d3.test"))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 3 and body["page"] == 1 and "total_pages" in body
        item = [i for i in body["items"] if i["id"] == objs["a_open"].id][0]
        assert item["severity"] == "critical" and item["event_count"] == 2
        assert item["monitoring_run_id"] == "run-1"
        assert item["finding_fingerprint"] == "fp1"
        r = client.get(_url(objs), params={"page": 1, "page_size": 2}, headers=_auth(tokens, "admin-a@d3.test"))
        assert len(r.json()["items"]) == 2 and r.json()["total_pages"] == 2
    finally:
        fastapi_app.dependency_overrides.clear()


def test_status_severity_type_filters():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d3.test")
        assert client.get(_url(objs), params={"status": "open"}, headers=h).json()["total"] == 1
        assert client.get(_url(objs), params={"status": "resolved"}, headers=h).json()["total"] == 1
        assert client.get(_url(objs), params={"severity": "critical"}, headers=h).json()["total"] == 1
        assert client.get(_url(objs), params={"alert_type": "HIGH_ASSET_EXPOSURE"}, headers=h).json()["total"] == 1
        assert client.get(_url(objs), params={"monitoring_run_id": "run-1"}, headers=h).json()["total"] == 1
        assert client.get(_url(objs), params={"monitoring_run_id": "run-nope"}, headers=h).json()["total"] == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_date_filters_and_invalid():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d3.test")
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        assert client.get(_url(objs), params={"since": future}, headers=h).json()["total"] == 0
        assert client.get(_url(objs), params={"since": past}, headers=h).json()["total"] == 3
        assert client.get(_url(objs), params={"since": "junk"}, headers=h).status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_detail_and_unknown_404():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "viewer-a@d3.test")
        r = client.get(_url(objs, f"/{objs['a_open'].id}"), headers=h)
        assert r.status_code == 200 and r.json()["title"].startswith("Critical vulnerability")
        assert client.get(_url(objs, "/nope"), headers=h).status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_read_only():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "viewer-a@d3.test")
        assert client.get(_url(objs), headers=h).status_code == 200
        assert client.post(_url(objs, f"/{objs['a_open'].id}/acknowledge"), headers=h).status_code == 403
        assert client.post(_url(objs, f"/{objs['a_open'].id}/resolve"), headers=h).status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_analyst_ack_idempotent_and_audited():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d3.test")
        r1 = client.post(_url(objs, f"/{objs['a_open'].id}/acknowledge"), headers=h)
        assert r1.status_code == 200, r1.text
        assert r1.json()["status"] == "acknowledged"
        assert r1.json()["acknowledged_by"] == objs["analyst_a"].id
        r2 = client.post(_url(objs, f"/{objs['a_open'].id}/acknowledge"), headers=h)
        assert r2.status_code == 200
        assert r2.json()["acknowledged_at"] == r1.json()["acknowledged_at"]
        db = Session()
        events = {a.event_type for a in db.query(AuditLog).filter(AuditLog.resource_id == objs["a_open"].id).all()}
        assert "ALERT_ACKNOWLEDGED" in events
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_resolve_from_open_and_idempotent():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "admin-a@d3.test")
        r = client.post(_url(objs, f"/{objs['a_open'].id}/resolve"), headers=h)
        assert r.status_code == 200 and r.json()["status"] == "resolved"
        r2 = client.post(_url(objs, f"/{objs['a_open'].id}/resolve"), headers=h)
        assert r2.status_code == 200 and r2.json()["status"] == "resolved"
        db = Session()
        events = {a.event_type for a in db.query(AuditLog).filter(AuditLog.resource_id == objs["a_open"].id).all()}
        assert "ALERT_RESOLVED" in events
        for a in db.query(AuditLog).all():
            s = str(a.extra_data).lower() if a.extra_data else ""
            for bad in ("password", "api_key", "cookie", "secret"):
                assert bad not in s or "[redacted]" in s
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_project_idor_and_cross_tenant():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # alert from proj A addressed under proj B path
        other = f"/api/v1/projects/{objs['proj_b'].id}/alerts/{objs['a_open'].id}"
        assert client.get(other, headers=_auth(tokens, "admin-b@d3.test")).status_code == 404
        assert client.post(other + "/acknowledge", headers=_auth(tokens, "admin-b@d3.test")).status_code == 404
        assert client.post(other + "/resolve", headers=_auth(tokens, "admin-b@d3.test")).status_code == 404
        # cross-tenant admin on proj A paths
        assert client.get(_url(objs), headers=_auth(tokens, "admin-b@d3.test")).status_code in (403, 404)
        assert client.post(_url(objs, f"/{objs['a_open'].id}/acknowledge"), headers=_auth(tokens, "admin-b@d3.test")).status_code in (403, 404)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_unauthenticated_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert client.get(_url(objs)).status_code == 401
        assert client.post(_url(objs, f"/{objs['a_open'].id}/acknowledge")).status_code == 401
    finally:
        fastapi_app.dependency_overrides.clear()


def test_policy_defaults_and_update():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h_admin = _auth(tokens, "admin-a@d3.test")
        url = f"/api/v1/projects/{objs['proj_a'].id}/alert-policy"
        d = client.get(url, headers=h_admin).json()
        assert d["enabled"] is True and d["min_severity"] == "high"
        assert d["alert_relationships"] is False and d["alert_metadata_changes"] is False
        r = client.put(url, json={"alert_relationships": True, "min_severity": "medium", "bogus": 1}, headers=h_admin)
        assert r.status_code == 200, r.text
        assert r.json()["alert_relationships"] is True and r.json()["min_severity"] == "medium"
        assert client.put(url, json={"min_severity": "everything"}, headers=h_admin).status_code == 400
        assert client.put(url, json={"enabled": False}, headers=_auth(tokens, "viewer-a@d3.test")).status_code == 403
        assert client.put(url, json={"enabled": False}, headers=_auth(tokens, "analyst-a@d3.test")).status_code == 403
        db = Session()
        events = {a.event_type for a in db.query(AuditLog).filter(AuditLog.resource_id == objs["proj_a"].id).all()}
        assert "ALERT_POLICY_UPDATED" in events
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()

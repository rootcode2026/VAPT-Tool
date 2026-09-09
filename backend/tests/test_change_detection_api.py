"""D2 change-detection API tests: read endpoint, RBAC, tenant/project isolation."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
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
import app.models.monitoring  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.user import User
from app.models.scan import Scan
from app.models.monitoring import (
    MonitoringChangeEvent,
    MonitoringConfig,
    MonitoringObservationBaseline,
    MonitoringRun,
)


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__,
        Scan.__table__,
        MonitoringConfig.__table__, MonitoringRun.__table__,
        MonitoringChangeEvent.__table__, MonitoringObservationBaseline.__table__,
    ])
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY, project_id TEXT, first_seen_scan_id TEXT,
                last_seen_scan_id TEXT, asset_type TEXT, value TEXT, status TEXT,
                first_seen_at DATETIME, last_seen_at DATETIME,
                created_at DATETIME, updated_at DATETIME
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS asset_change_events (
                id TEXT PRIMARY KEY, project_id TEXT, asset_id TEXT, scan_id TEXT,
                change_type TEXT, previous_state TEXT, current_state TEXT,
                detected_at DATETIME, metadata TEXT
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, scan_id TEXT, target_id TEXT, asset_id TEXT,
                scanner TEXT, title TEXT, severity TEXT, status TEXT,
                metadata TEXT, created_at DATETIME, updated_at DATETIME
            )
        """))
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-d2", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-d2", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@d2.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@d2.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@d2.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@d2.test", password_hash=pwd, role="admin", status="active")
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
    target_a = Target(id=str(uuid.uuid4()), project_id=proj_a.id, value="example.com", target_type="domain", is_active=True)
    db.add(target_a)
    db.flush()
    scan = Scan(id=str(uuid.uuid4()), target_id=target_a.id, profile="quick", status="completed")
    db.add(scan)
    db.flush()
    cfg = MonitoringConfig(id=str(uuid.uuid4()), organization_id=org_a.id, project_id=proj_a.id,
                           name="M", enabled=True, frequency="daily", profile="quick",
                           target_scope="all", created_by=admin_a.id, baseline_established=True)
    db.add(cfg)
    db.flush()
    run1 = MonitoringRun(id=str(uuid.uuid4()), monitoring_config_id=cfg.id, organization_id=org_a.id,
                         project_id=proj_a.id, status="completed", scan_ids=[scan.id],
                         correlation_id="mr:aaa", change_status="completed", change_events_count=1)
    run2 = MonitoringRun(id=str(uuid.uuid4()), monitoring_config_id=cfg.id, organization_id=org_a.id,
                         project_id=proj_a.id, status="completed", scan_ids=[scan.id],
                         correlation_id="mr:bbb", change_status="completed", change_events_count=2)
    db.add_all([run1, run2])
    db.flush()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ev1 = MonitoringChangeEvent(
        id=str(uuid.uuid4()), project_id=proj_a.id, monitoring_config_id=cfg.id,
        prev_run_id=run1.id, curr_run_id=run2.id, change_type="ASSET_CREATED",
        asset_id="asset-1", scan_id=scan.id,
        previous_state=None, current_state={"asset_type": "ip", "value": "10.0.0.2", "status": "active"},
        scanners=["nmap"], scan_ids=[scan.id], completeness="complete",
        event_key="k-" + str(uuid.uuid4()), detected_at=now,
        extra_data={"monitoring_config_id": cfg.id},
    )
    ev2 = MonitoringChangeEvent(
        id=str(uuid.uuid4()), project_id=proj_a.id, monitoring_config_id=cfg.id,
        prev_run_id=run1.id, curr_run_id=run2.id, change_type="FINDING_RESOLVED",
        finding_id="finding-9",
        previous_state={"fingerprint": "fp9", "status": "open"},
        current_state={"fingerprint": "fp9", "status": "resolved"},
        scanners=["nuclei"], scan_ids=[scan.id], completeness="complete",
        event_key="k-" + str(uuid.uuid4()), detected_at=now,
        extra_data={"monitoring_config_id": cfg.id},
    )
    db.add_all([ev1, ev2])
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a": proj_a, "proj_b": proj_b,
            "target_a": target_a, "scan": scan, "cfg": cfg, "run1": run1, "run2": run2,
            "ev1": ev1, "ev2": ev2,
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


@pytest.fixture(autouse=True)
def _fast_celery_dispatch(monkeypatch):
    def _fake_send(*args, **kwargs):
        class _Async:
            id = "fake-task-id"
        return _Async()
    import app.core.celery as celery_mod
    monkeypatch.setattr(celery_mod.celery_app, "send_task", _fake_send)


def _auth(tokens, email):
    return {"Authorization": f"Bearer {tokens[email]}"}


def _url(objs):
    return f"/api/v1/projects/{objs['proj_a'].id}/monitoring/changes"


def test_list_returns_events_with_shape():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.get(_url(objs), headers=_auth(tokens, "admin-a@d2.test"))
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 2 and len(body["items"]) == 2
        item = [i for i in body["items"] if i["change_type"] == "ASSET_CREATED"][0]
        assert item["curr_run_id"] == objs["run2"].id
        assert item["prev_run_id"] == objs["run1"].id
        assert item["current_state"]["value"] == "10.0.0.2"
        assert item["scanners"] == ["nmap"] and item["completeness"] == "complete"
        assert "detected_at" in item and "extra_data" in item
    finally:
        fastapi_app.dependency_overrides.clear()


def test_run_filter_and_linkage():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d2.test")
        r = client.get(_url(objs), params={"monitoring_run_id": objs["run2"].id}, headers=h)
        assert r.status_code == 200 and r.json()["total"] == 2
        r = client.get(_url(objs), params={"monitoring_run_id": objs["run1"].id}, headers=h)
        assert r.status_code == 200 and r.json()["total"] == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_type_asset_finding_filters():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d2.test")
        assert client.get(_url(objs), params={"change_type": "ASSET_CREATED"}, headers=h).json()["total"] == 1
        assert client.get(_url(objs), params={"asset_id": "asset-1"}, headers=h).json()["total"] == 1
        assert client.get(_url(objs), params={"finding_id": "finding-9"}, headers=h).json()["total"] == 1
        assert client.get(_url(objs), params={"change_type": "NOPE"}, headers=h).json()["total"] == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_time_filters():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d2.test")
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        assert client.get(_url(objs), params={"since": future}, headers=h).json()["total"] == 0
        assert client.get(_url(objs), params={"until": past}, headers=h).json()["total"] == 0
        assert client.get(_url(objs), params={"since": past}, headers=h).json()["total"] == 2
        assert client.get(_url(objs), params={"since": "not-a-date"}, headers=h).status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_and_analyst_can_read():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert client.get(_url(objs), headers=_auth(tokens, "viewer-a@d2.test")).status_code == 200
        assert client.get(_url(objs), headers=_auth(tokens, "analyst-a@d2.test")).status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()


def test_unauthenticated_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert client.get(_url(objs)).status_code == 401
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_tenant_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.get(_url(objs), headers=_auth(tokens, "admin-b@d2.test"))
        assert r.status_code in (403, 404)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_project_run_rejected_and_unknown_run():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "admin-a@d2.test")
        # run_id that belongs to no project here
        assert client.get(_url(objs), params={"monitoring_run_id": "run-nope"}, headers=h).status_code == 404
        # other project's listing must not leak this project's events
        other = f"/api/v1/projects/{objs['proj_b'].id}/monitoring/changes"
        r = client.get(other, headers=_auth(tokens, "admin-b@d2.test"))
        assert r.status_code in (200, 403, 404)
        if r.status_code == 200:
            assert r.json()["total"] == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_run_payload_exposes_change_status():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "admin-a@d2.test")
        r = client.get(f"/api/v1/monitoring/{objs['cfg'].id}/runs/{objs['run2'].id}", headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["change_status"] == "completed"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_manual_run_marks_change_pending():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/monitoring/{objs['cfg'].id}/run",
                        headers=_auth(tokens, "analyst-a@d2.test"))
        assert r.status_code == 201, r.text
        assert r.json()["change_status"] == "pending"
    finally:
        fastapi_app.dependency_overrides.clear()

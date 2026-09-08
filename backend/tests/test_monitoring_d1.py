"""D1 continuous monitoring backend tests: service helpers, API, RBAC, isolation."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.permissions import (
    PERM_MONITORING_MANAGE,
    PERM_MONITORING_READ,
    permissions_for_org_role,
    permissions_for_project_role,
)
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
from app.models.audit_log import AuditLog
from app.models.monitoring import MonitoringConfig, MonitoringRun
from app.services.monitoring_service import (
    compute_next_run,
    finalize_run,
    frequency_interval_seconds,
    shift_run_window,
)


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__,
        app.models.scan.Scan.__table__, AuditLog.__table__,
        MonitoringConfig.__table__, MonitoringRun.__table__,
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
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-d1", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-d1", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@d1.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@d1.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@d1.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@d1.test", password_hash=pwd, role="admin", status="active")
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
    target_b = Target(id=str(uuid.uuid4()), project_id=proj_b.id, value="other.com", target_type="domain", is_active=True)
    db.add_all([target_a, target_b])
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a": proj_a, "proj_b": proj_b,
            "target_a": target_a, "target_b": target_b,
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
    """Avoid real broker connection retries (tens of seconds per send_task with
    no RabbitMQ in tests). The endpoint treats dispatch errors as data, so a
    recording fake preserves the execution-path contract deterministically."""
    calls = []

    def _fake_send(*args, **kwargs):
        calls.append((args, kwargs))

        class _Async:
            id = "fake-task-id"

        return _Async()

    import app.core.celery as celery_mod

    monkeypatch.setattr(celery_mod.celery_app, "send_task", _fake_send)
    return calls


def _auth(tokens, email):
    return {"Authorization": f"Bearer {tokens[email]}"}


def _mk_config(client, Session, tokens, objs, **kw):
    body = {"name": "M", "frequency": "daily", "profile": "quick"}
    body.update(kw)
    r = client.post(f"/api/v1/projects/{objs['proj_a'].id}/monitoring", json=body,
                    headers=_auth(tokens, "admin-a@d1.test"))
    assert r.status_code == 201, r.text
    return r.json()


# --- service helpers ---------------------------------------------------------

def test_compute_next_run_intervals():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    assert compute_next_run(None, "hourly", now) == now + timedelta(hours=1)
    assert compute_next_run(None, "six_hourly", now) == now + timedelta(hours=6)
    assert compute_next_run(None, "daily", now) == now + timedelta(days=1)
    assert compute_next_run(None, "weekly", now) == now + timedelta(weeks=1)
    assert frequency_interval_seconds("six_hourly") == 21600


def test_compute_next_run_preserves_future_never_past():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    future = now + timedelta(hours=10)
    assert compute_next_run(future, "hourly", now) == future
    past = now - timedelta(hours=5)
    assert compute_next_run(past, "hourly", now) == now + timedelta(hours=1)
    assert compute_next_run(now, "bogus", now) == now + timedelta(days=1)


def test_compute_next_run_mixed_naive_aware():
    """Postgres returns TIMESTAMPTZ as aware datetimes while the code works
    in naive UTC (live 500-class bug: aware <= naive raises TypeError)."""
    naive_now = datetime.now(timezone.utc).replace(tzinfo=None)
    aware_now = datetime.now(timezone.utc)
    aware_future = aware_now + timedelta(hours=10)
    aware_past = aware_now - timedelta(hours=5)
    # Aware DB value in the future is preserved (same instant, naive form).
    kept = compute_next_run(aware_future, "hourly", naive_now)
    assert kept.tzinfo is None
    assert kept == aware_future.astimezone(timezone.utc).replace(tzinfo=None)
    # Aware past recomputes from now; aware `now` is accepted too.
    assert compute_next_run(aware_past, "hourly", naive_now) == naive_now + timedelta(hours=1)
    assert compute_next_run(None, "hourly", aware_now) == aware_now.replace(tzinfo=None) + timedelta(hours=1)


def test_finalize_run_helper():
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    out = finalize_run("partial", now, scan_ids=["a"], scanner_count=3,
                       successful_scanners=2, failed_scanners=1, error="x" * 900)
    assert out["status"] == "partial" and out["scanner_count"] == 3
    assert len(out["error"]) <= 500
    bad = finalize_run("weird", now)
    assert bad["status"] == "failed"
    w = shift_run_window(now, "daily")
    assert w == now - timedelta(days=1)


def test_monitoring_permissions_matrix():
    assert PERM_MONITORING_MANAGE in permissions_for_org_role("organization_admin")
    assert PERM_MONITORING_MANAGE in permissions_for_org_role("security_analyst")
    assert PERM_MONITORING_READ in permissions_for_org_role("viewer")
    assert PERM_MONITORING_MANAGE not in permissions_for_org_role("viewer")
    assert PERM_MONITORING_MANAGE in permissions_for_project_role("project_admin")
    assert PERM_MONITORING_MANAGE in permissions_for_project_role("security_analyst")
    assert PERM_MONITORING_MANAGE not in permissions_for_project_role("developer")
    assert PERM_MONITORING_READ in permissions_for_project_role("auditor")


# --- API ---------------------------------------------------------------------

def test_create_config_with_target_and_next_run():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _mk_config(client, Session, tokens, objs, target_id=objs["target_a"].id, frequency="six_hourly")
        assert body["target_id"] == objs["target_a"].id
        assert body["frequency"] == "six_hourly"
        assert body["next_run_at"] is not None
        assert body["consecutive_failures"] == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_create_rejects_bad_frequency_profile_scope_target():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "admin-a@d1.test")
        url = f"/api/v1/projects/{objs['proj_a'].id}/monitoring"
        assert client.post(url, json={"name": "x", "frequency": "minutely"}, headers=h).status_code == 400
        assert client.post(url, json={"name": "x", "profile": "everything"}, headers=h).status_code == 400
        assert client.post(url, json={"name": "x", "target_scope": "org"}, headers=h).status_code == 400
        # target from another project
        r = client.post(url, json={"name": "x", "target_id": objs["target_b"].id}, headers=h)
        assert r.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_update_frequency_recomputes_schedule():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "admin-a@d1.test")
        body = _mk_config(client, Session, tokens, objs)
        # A future next_run is preserved (no drift)...
        u = client.patch(f"/api/v1/monitoring/{body['id']}", json={"profile": "web"}, headers=h)
        assert u.status_code == 200 and u.json()["next_run_at"] == body["next_run_at"]
        # ...while a past next_run is recomputed from the new frequency.
        db = Session()
        past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)
        db.execute(text("UPDATE monitoring_configs SET next_run_at = :p WHERE id = :c"),
                   {"p": past, "c": body["id"]})
        db.commit()
        db.close()
        u2 = client.patch(f"/api/v1/monitoring/{body['id']}", json={"frequency": "hourly"}, headers=h)
        assert u2.status_code == 200, u2.text
        assert u2.json()["frequency"] == "hourly"
        nxt = datetime.fromisoformat(u2.json()["next_run_at"])
        assert nxt > datetime.now(timezone.utc).replace(tzinfo=None)
        bad = client.patch(f"/api/v1/monitoring/{body['id']}", json={"frequency": "minutely"}, headers=h)
        assert bad.status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_pause_and_resume():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "admin-a@d1.test")
        body = _mk_config(client, Session, tokens, objs)
        cid = body["id"]
        p = client.post(f"/api/v1/monitoring/{cid}/pause", json={"reason": "maintenance"}, headers=h)
        assert p.status_code == 200, p.text
        assert p.json()["paused_at"] is not None
        assert p.json()["pause_reason"] == "maintenance"
        assert p.json()["next_run_at"] is None
        # idempotent
        p2 = client.post(f"/api/v1/monitoring/{cid}/pause", json={}, headers=h)
        assert p2.status_code == 200
        r = client.post(f"/api/v1/monitoring/{cid}/resume", headers=h)
        assert r.status_code == 200, r.text
        assert r.json()["paused_at"] is None
        assert r.json()["next_run_at"] is not None
        # resume again: no duplicate, same-ish schedule preserved
        r2 = client.post(f"/api/v1/monitoring/{cid}/resume", headers=h)
        assert r2.status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()


def test_resume_disabled_conflict():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "admin-a@d1.test")
        body = _mk_config(client, Session, tokens, objs)
        cid = body["id"]
        client.post(f"/api/v1/monitoring/{cid}/pause", json={}, headers=h)
        client.patch(f"/api/v1/monitoring/{cid}", json={"enabled": False}, headers=h)
        r = client.post(f"/api/v1/monitoring/{cid}/resume", headers=h)
        assert r.status_code == 409
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_cannot_pause_but_analyst_can_run():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _mk_config(client, Session, tokens, objs)
        cid = body["id"]
        v = client.post(f"/api/v1/monitoring/{cid}/pause", json={}, headers=_auth(tokens, "viewer-a@d1.test"))
        assert v.status_code == 403
        run = client.post(f"/api/v1/monitoring/{cid}/run", headers=_auth(tokens, "analyst-a@d1.test"))
        assert run.status_code == 201, run.text
    finally:
        fastapi_app.dependency_overrides.clear()


def test_per_config_runs_list_detail_and_idor():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h_admin = _auth(tokens, "admin-a@d1.test")
        h_analyst = _auth(tokens, "analyst-a@d1.test")
        c1 = _mk_config(client, Session, tokens, objs, **{"name": "one"})
        c2 = _mk_config(client, Session, tokens, objs, **{"name": "two"})
        run = client.post(f"/api/v1/monitoring/{c1['id']}/run", headers=h_analyst)
        rid = run.json()["id"]
        lst = client.get(f"/api/v1/monitoring/{c1['id']}/runs", headers=h_admin)
        assert lst.status_code == 200 and lst.json()["total"] == 1
        one = client.get(f"/api/v1/monitoring/{c1['id']}/runs/{rid}", headers=h_admin)
        assert one.status_code == 200 and one.json()["id"] == rid
        # run of c1 not visible under c2
        cross = client.get(f"/api/v1/monitoring/{c2['id']}/runs/{rid}", headers=h_admin)
        assert cross.status_code == 404
        # other org admin cannot reach
        other = client.get(f"/api/v1/monitoring/{c1['id']}/runs", headers=_auth(tokens, "admin-b@d1.test"))
        assert other.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_manual_run_links_scans_and_updates_config():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _mk_config(client, Session, tokens, objs, **{"profile": "web"})
        run = client.post(f"/api/v1/monitoring/{body['id']}/run", headers=_auth(tokens, "analyst-a@d1.test"))
        assert run.status_code == 201, run.text
        payload = run.json()
        assert payload["status"] == "completed"
        assert payload["correlation_id"].startswith("mr:")
        assert len(payload["scan_ids"]) == 1
        assert payload["scanner_count"] == 8
        db = Session()
        from app.models.scan import Scan
        scan = db.query(Scan).filter(Scan.id == payload["scan_ids"][0]).first()
        assert scan is not None
        assert (scan.scan_metadata or {}).get("monitoring_run_id") == payload["id"]
        cfg = db.query(MonitoringConfig).filter(MonitoringConfig.id == body["id"]).first()
        assert cfg.last_scan_id == scan.id and cfg.last_status == "completed"
        assert cfg.last_run_at is not None and cfg.next_run_at is not None
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_dispatch_failure_is_partial_not_failed(monkeypatch):
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        import app.core.celery as celery_mod

        def _boom(*args, **kwargs):
            raise ConnectionError("no broker")

        monkeypatch.setattr(celery_mod.celery_app, "send_task", _boom)
        body = _mk_config(client, Session, tokens, objs)
        run = client.post(f"/api/v1/monitoring/{body['id']}/run", headers=_auth(tokens, "analyst-a@d1.test"))
        assert run.status_code == 201, run.text
        payload = run.json()
        # Canonical terminal vocabulary (same "partial" the scheduler finalize
        # path persists): scans were created but no dispatch reached the broker.
        assert payload["status"] == "partial"
        assert "dispatch" in (payload["error"] or "")
        db = Session()
        events = {a.event_type for a in db.query(AuditLog).filter(AuditLog.resource_id == payload["id"]).all()}
        assert "MONITORING_RUN_PARTIAL" in events
        cfg = db.query(MonitoringConfig).filter(MonitoringConfig.id == body["id"]).first()
        assert cfg.last_status == "partial" and cfg.consecutive_failures == 1
        # The created (undispatched) scans are still persisted, not lost.
        from app.models.scan import Scan as _Scan
        assert db.query(_Scan).filter(_Scan.id.in_(payload["scan_ids"])).count() == len(payload["scan_ids"]) == 1
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_change_observation_linked_to_run():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d1.test")
        body = _mk_config(client, Session, tokens, objs)
        first = client.post(f"/api/v1/monitoring/{body['id']}/run", headers=h)
        assert first.json()["assets_discovered"] == 0  # baseline, no fake changes
        db = Session()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, first_seen_at, last_seen_at, created_at) VALUES (:id, :pid, 'domain', 'new.example.com', 'active', :n, :n, :n)"),
                   {"id": str(uuid.uuid4()), "pid": objs["proj_a"].id, "n": now})
        db.execute(text("INSERT INTO asset_change_events (id, project_id, asset_id, scan_id, change_type, detected_at, metadata) VALUES (:id, :pid, 'a1', 's1', 'discovered', :n, '{}')"),
                   {"id": str(uuid.uuid4()), "pid": objs["proj_a"].id, "n": now})
        db.commit()
        db.close()
        second = client.post(f"/api/v1/monitoring/{body['id']}/run", headers=h)
        assert second.status_code == 201
        assert second.json()["assets_discovered"] >= 1
        assert second.json()["assets_changed"] >= 1
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cross_tenant_and_unauthenticated_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _mk_config(client, Session, tokens, objs)
        # cross-tenant modify
        r = client.patch(f"/api/v1/monitoring/{body['id']}", json={"name": "hijack"}, headers=_auth(tokens, "admin-b@d1.test"))
        assert r.status_code in (403, 404)
        run = client.post(f"/api/v1/monitoring/{body['id']}/run", headers=_auth(tokens, "admin-b@d1.test"))
        assert run.status_code in (403, 404)
        # unauthenticated
        u = client.get(f"/api/v1/projects/{objs['proj_a'].id}/monitoring")
        assert u.status_code == 401
    finally:
        fastapi_app.dependency_overrides.clear()


def test_pause_resume_audited_and_redacted():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "admin-a@d1.test")
        body = _mk_config(client, Session, tokens, objs)
        cid = body["id"]
        client.post(f"/api/v1/monitoring/{cid}/pause", json={"reason": "window"}, headers=h)
        client.post(f"/api/v1/monitoring/{cid}/resume", headers=h)
        db = Session()
        events = {a.event_type for a in db.query(AuditLog).filter(AuditLog.resource_id == cid).all()}
        assert "MONITORING_CONFIG_PAUSED" in events
        assert "MONITORING_CONFIG_RESUMED" in events
        for a in db.query(AuditLog).all():
            s = str(a.extra_data).lower() if a.extra_data else ""
            for bad in ("password", "jwt", "api_key", "cookie", "secret"):
                assert bad not in s or "[redacted]" in s
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_list_configs_expose_scheduling_state():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        body = _mk_config(client, Session, tokens, objs)
        lst = client.get(f"/api/v1/projects/{objs['proj_a'].id}/monitoring", headers=_auth(tokens, "analyst-a@d1.test"))
        assert lst.status_code == 200
        item = [c for c in lst.json()["items"] if c["id"] == body["id"]][0]
        assert item["next_run_at"] is not None
        assert "last_status" in item and "consecutive_failures" in item and "paused_at" in item
    finally:
        fastapi_app.dependency_overrides.clear()


def test_change_detection_failure_persists_failed_run():
    """Rollback-path survival: a counting-query failure must mark the run
    failed WITHOUT losing the run row, its scans, or config bookkeeping
    (a full-transaction rollback would discard them and the refresh raise)."""
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d1.test")
        body = _mk_config(client, Session, tokens, objs)
        first = client.post(f"/api/v1/monitoring/{body['id']}/run", headers=h)
        assert first.status_code == 201 and first.json()["status"] == "completed"
        # Break the change-observation source so the second run's counting
        # SELECT raises inside the savepoint.
        db = Session()
        db.execute(text("DROP TABLE assets"))
        db.commit()
        db.close()
        second = client.post(f"/api/v1/monitoring/{body['id']}/run", headers=h)
        assert second.status_code == 201, second.text
        payload = second.json()
        assert payload["status"] == "failed"
        assert payload["error"]
        db2 = Session()
        row = db2.query(MonitoringRun).filter(MonitoringRun.id == payload["id"]).first()
        assert row is not None and row.status == "failed"
        from app.models.scan import Scan as _Scan
        scans = db2.query(_Scan).filter(_Scan.id.in_(payload["scan_ids"])).all()
        assert len(scans) == len(payload["scan_ids"]) == 1
        cfg = db2.query(MonitoringConfig).filter(MonitoringConfig.id == body["id"]).first()
        assert cfg.last_status == "failed" and cfg.consecutive_failures == 1
        events = {a.event_type for a in db2.query(AuditLog).filter(AuditLog.resource_id == payload["id"]).all()}
        assert "MONITORING_RUN_FAILED" in events
        db2.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_dispatch_happens_after_commit(monkeypatch):
    """Commit/dispatch ordering: no send_task may be issued before the run's
    creating transaction commits (same invariant as scans.py), so a worker
    can never observe an uncommitted Scan row."""
    from sqlalchemy import event as sa_event

    _, Session, tokens, objs = _setup()
    commits: list = []

    def _on_commit(session):
        commits.append(True)

    sa_event.listen(Session, "after_commit", _on_commit)
    try:
        client = _client(Session)
        try:
            import app.core.celery as celery_mod

            seen: list = []

            def _recording(*args, **kwargs):
                seen.append(len(commits) > 0)

                class _Async:
                    id = "fake-task-id"

                return _Async()

            monkeypatch.setattr(celery_mod.celery_app, "send_task", _recording)
            body = _mk_config(client, Session, tokens, objs)
            commits.clear()  # ignore the config-creation commit
            run = client.post(f"/api/v1/monitoring/{body['id']}/run",
                              headers=_auth(tokens, "analyst-a@d1.test"))
            assert run.status_code == 201, run.text
            assert seen, "expected at least one dispatch"
            assert all(seen), "dispatch issued before commit"
        finally:
            fastapi_app.dependency_overrides.clear()
    finally:
        sa_event.remove(Session, "after_commit", _on_commit)

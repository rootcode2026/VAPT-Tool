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
import app.models.monitoring  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.scan import Scan
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.monitoring import MonitoringConfig, MonitoringRun
from app.services.attack_surface import classify_exposure, compute_asset_state


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__, Scan.__table__,
        AuditLog.__table__, MonitoringConfig.__table__, MonitoringRun.__table__,
    ])
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                project_id TEXT, first_seen_scan_id TEXT, last_seen_scan_id TEXT,
                asset_type TEXT, value TEXT, status TEXT,
                criticality TEXT DEFAULT 'unknown', owner_user_id TEXT,
                metadata TEXT, first_seen_at DATETIME, last_seen_at DATETIME,
                created_at DATETIME, updated_at DATETIME
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS asset_relationships (
                id TEXT PRIMARY KEY,
                project_id TEXT, source_asset_id TEXT, target_asset_id TEXT,
                relationship_type TEXT, last_seen_scan_id TEXT,
                metadata TEXT, created_at DATETIME, updated_at DATETIME
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS asset_change_events (
                id TEXT PRIMARY KEY,
                project_id TEXT, asset_id TEXT, scan_id TEXT, change_type TEXT,
                previous_state TEXT, current_state TEXT, detected_at DATETIME, metadata TEXT
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT, target_id TEXT, asset_id TEXT, scanner TEXT, title TEXT, description TEXT,
                severity TEXT, score INTEGER, status TEXT, evidence TEXT, remediation TEXT, cve TEXT, cwe TEXT,
                assigned_to TEXT, owner_user_id TEXT, severity_override TEXT,
                metadata TEXT, created_at DATETIME, updated_at DATETIME
            )
        """))
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-attsurf", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-attsurf", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@attsurf.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@attsurf.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@attsurf.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@attsurf.test", password_hash=pwd, role="admin", status="active")
    super_u = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="super@attsurf.test", password_hash=pwd, role="super_admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, admin_b, super_u])
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
    db.flush()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    # Assets in proj_a
    aid_ip = str(uuid.uuid4())
    aid_domain = str(uuid.uuid4())
    aid_port = str(uuid.uuid4())
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, criticality, metadata, last_seen_at, created_at) VALUES (:id, :pid, :t, :v, :s, :c, :m, :ls, :now)"),
               {"id": aid_ip, "pid": proj_a.id, "t": "ip", "v": "93.184.216.34", "s": "active", "c": "unknown", "m": "{}", "ls": now, "now": now})
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, criticality, metadata, last_seen_at, created_at) VALUES (:id, :pid, :t, :v, :s, :c, :m, :ls, :now)"),
               {"id": aid_domain, "pid": proj_a.id, "t": "domain", "v": "example.com", "s": "active", "c": "unknown", "m": "{}", "ls": now, "now": now})
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, criticality, metadata, last_seen_at, created_at) VALUES (:id, :pid, :t, :v, :s, :c, :m, :ls, :now)"),
               {"id": aid_port, "pid": proj_a.id, "t": "port", "v": "80", "s": "active", "c": "unknown", "m": "{}", "ls": now, "now": now})
    # Asset in proj_b
    aid_b = str(uuid.uuid4())
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, criticality, metadata, last_seen_at, created_at) VALUES (:id, :pid, :t, :v, :s, :c, :m, :ls, :now)"),
               {"id": aid_b, "pid": proj_b.id, "t": "domain", "v": "other.com", "s": "active", "c": "unknown", "m": "{}", "ls": now, "now": now})
    # Relationship domain -> ip
    rel_id = str(uuid.uuid4())
    db.execute(text("INSERT INTO asset_relationships (id, project_id, source_asset_id, target_asset_id, relationship_type, metadata) VALUES (:id, :pid, :s, :t, :r, :m)"),
               {"id": rel_id, "pid": proj_a.id, "s": aid_domain, "t": aid_ip, "r": "resolves_to", "m": "{}"})
    # Change event
    db.execute(text("INSERT INTO asset_change_events (id, project_id, asset_id, scan_id, change_type, detected_at, metadata) VALUES (:id, :pid, :aid, :scan, :ct, :now, :m)"),
               {"id": str(uuid.uuid4()), "pid": proj_a.id, "aid": aid_ip, "scan": "scan-1", "ct": "discovered", "now": now, "m": '{"scanner": "nmap"}'})
    # Finding on asset
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, asset_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan, :target, :asset, :scanner, :title, :sev, :status, :ev, :meta)"),
               {"id": str(uuid.uuid4()), "scan": "scan-1", "target": target_a.id, "asset": aid_ip, "scanner": "nmap", "title": "Open Port", "sev": "high", "status": "open", "ev": "port", "meta": "{}"})
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b, super_u]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a": proj_a, "proj_b": proj_b,
            "target_a": target_a, "target_b": target_b,
            "aid_ip": aid_ip, "aid_domain": aid_domain, "aid_port": aid_port, "aid_b": aid_b,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a,
            "admin_b": admin_b, "super_u": super_u}
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


# Exposure unit tests (no HTTP)
def test_exposure_public_ip():
    assert classify_exposure("ip", "8.8.8.8", {}) == "INTERNET_EXPOSED"


def test_exposure_private_ip():
    assert classify_exposure("ip", "10.0.0.5", {}) == "INTERNAL"


def test_exposure_url_external():
    assert classify_exposure("url", "https://example.com/app", {}) == "EXTERNALLY_REACHABLE"


def test_exposure_no_inference_port():
    assert classify_exposure("port", "443", {}) == "UNKNOWN"


def test_exposure_explicit_metadata():
    assert classify_exposure("port", "443", {"internet_facing": True}) == "INTERNET_EXPOSED"


def test_state_thresholds():
    now = datetime.now(timezone.utc)
    assert compute_asset_state(now, now) == "active"
    assert compute_asset_state(now - timedelta(days=10), now) == "stale"
    assert compute_asset_state(now - timedelta(days=40), now) == "inactive"
    assert compute_asset_state(None, now) == "unknown"


# Attack surface APIs
def test_summary_isolation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/attack-surface/summary", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["total_assets"] == 3
        # Cross-project denied
        resp2 = client.get(f"/api/v1/projects/{objs['proj_b'].id}/attack-surface/summary", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp2.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_asset_list_isolation_pagination():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/attack-surface/assets?page=1&page_size=2", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 3
        assert len(resp.json()["items"]) == 2
        for item in resp.json()["items"]:
            assert item["project_id"] == objs["proj_a"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_asset_filter_exposure():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/attack-surface/assets?exposure=INTERNET_EXPOSED", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1
        for item in resp.json()["items"]:
            assert item["exposure"] == "INTERNET_EXPOSED"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_changes_isolation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/attack-surface/changes", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1
        resp2 = client.get(f"/api/v1/projects/{objs['proj_b'].id}/attack-surface/changes", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp2.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_relationships_isolation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/attack-surface/relationships", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 1
    finally:
        fastapi_app.dependency_overrides.clear()


def test_graph_isolation_limits():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/attack-surface/graph", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp.status_code == 200
        assert len(resp.json()["nodes"]) <= 500
        assert len(resp.json()["edges"]) <= 1000
        for n in resp.json()["nodes"]:
            assert "exposure" in n and "finding_count" in n
        # Cross-project denied
        resp2 = client.get(f"/api/v1/projects/{objs['proj_b'].id}/attack-surface/graph", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp2.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_asset_finding_association():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/attack-surface/assets?has_findings=true", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp.status_code == 200
        assert resp.json()["total"] >= 1
        item = resp.json()["items"][0]
        assert item["finding_count"] >= 1
    finally:
        fastapi_app.dependency_overrides.clear()


def test_owner_assignment_same_org():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/assets/{objs['aid_ip']}", json={"owner_user_id": objs["analyst_a"].id}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["owner_user_id"] == objs["analyst_a"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_owner_cross_org_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/assets/{objs['aid_ip']}", json={"owner_user_id": objs["admin_b"].id}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_cannot_modify_asset():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/assets/{objs['aid_ip']}", json={"criticality": "high"}, headers={"Authorization": f"Bearer {tokens['viewer-a@attsurf.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_criticality_audited():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.patch(f"/api/v1/assets/{objs['aid_ip']}", json={"criticality": "critical"}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        assert resp.status_code == 200
        db = Session()
        audit = db.query(AuditLog).filter(AuditLog.event_type == "ASSET_CRITICALITY_CHANGED").order_by(AuditLog.created_at.desc()).first()
        assert audit is not None
        assert audit.resource_id == objs["aid_ip"]
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


# Monitoring
def test_create_config():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/projects/{objs['proj_a'].id}/monitoring", json={"name": "Daily", "frequency": "daily", "profile": "quick"}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        assert resp.status_code == 201, resp.text
        assert resp.json()["frequency"] == "daily"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_update_config():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/projects/{objs['proj_a'].id}/monitoring", json={"name": "M", "frequency": "daily", "profile": "quick"}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        cid = r.json()["id"]
        u = client.patch(f"/api/v1/monitoring/{cid}", json={"enabled": False}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        assert u.status_code == 200
        assert u.json()["enabled"] is False
    finally:
        fastapi_app.dependency_overrides.clear()


def test_delete_config():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/projects/{objs['proj_a'].id}/monitoring", json={"name": "M", "frequency": "daily", "profile": "quick"}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        cid = r.json()["id"]
        d = client.delete(f"/api/v1/monitoring/{cid}", headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        assert d.status_code == 204
    finally:
        fastapi_app.dependency_overrides.clear()


def test_manual_run():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/projects/{objs['proj_a'].id}/monitoring", json={"name": "M", "frequency": "daily", "profile": "quick"}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        cid = r.json()["id"]
        run = client.post(f"/api/v1/monitoring/{cid}/run", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert run.status_code == 201, run.text
        # Canonical run vocabulary: completed when all dispatches reach the
        # broker, partial when some fail (no broker in this test env).
        assert run.json()["status"] in ("completed", "partial")
    finally:
        fastapi_app.dependency_overrides.clear()


def test_duplicate_run_protection():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/projects/{objs['proj_a'].id}/monitoring", json={"name": "M", "frequency": "daily", "profile": "quick"}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        cid = r.json()["id"]
        # Insert a fake running run
        db = Session()
        db.execute(text("INSERT INTO monitoring_runs (id, monitoring_config_id, organization_id, project_id, status, assets_discovered, assets_changed, assets_stale, findings_created) VALUES (:id, :cid, :oid, :pid, 'running', 0, 0, 0, 0)"),
                   {"id": str(uuid.uuid4()), "cid": cid, "oid": objs["org_a"].id, "pid": objs["proj_a"].id})
        db.commit()
        db.close()
        run = client.post(f"/api/v1/monitoring/{cid}/run", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert run.status_code == 409
    finally:
        fastapi_app.dependency_overrides.clear()


def test_monitoring_rbac():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post(f"/api/v1/projects/{objs['proj_a'].id}/monitoring", json={"name": "M"}, headers={"Authorization": f"Bearer {tokens['viewer-a@attsurf.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_monitoring_project_isolation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_b'].id}/monitoring", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_unauthenticated_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/attack-surface/summary")
        assert resp.status_code == 401
    finally:
        fastapi_app.dependency_overrides.clear()


def test_client_cannot_override_tenant():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # No organization_id param is accepted; project scoping is server-side
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/attack-surface/assets?project_id={objs['proj_b'].id}", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp.status_code == 200
        for item in resp.json()["items"]:
            assert item["project_id"] == objs["proj_a"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_suspended_owner_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        db = Session()
        db.execute(text("UPDATE users SET status='suspended' WHERE id=:id"), {"id": objs["viewer_a"].id})
        db.commit()
        db.close()
        resp = client.patch(f"/api/v1/assets/{objs['aid_ip']}", json={"owner_user_id": objs["viewer_a"].id}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        assert resp.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()


def test_graph_no_leak():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/attack-surface/graph", headers={"Authorization": f"Bearer {tokens['analyst-a@attsurf.test']}"})
        assert resp.status_code == 200
        # Ensure no proj_b asset id appears
        ids = {n["id"] for n in resp.json()["nodes"]}
        assert objs["aid_b"] not in ids
    finally:
        fastapi_app.dependency_overrides.clear()


def test_audit_redacted():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post(f"/api/v1/projects/{objs['proj_a'].id}/monitoring", json={"name": "M"}, headers={"Authorization": f"Bearer {tokens['admin-a@attsurf.test']}"})
        db = Session()
        for a in db.query(AuditLog).all():
            s = str(a.extra_data).lower() if a.extra_data else ""
            for bad in ["password", "jwt", "api_key", "cookie", "secret"]:
                assert bad not in s or "[redacted]" in s
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()

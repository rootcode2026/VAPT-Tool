"""D9 notification tests — policy, evaluation, recipients, delivery, security.

D3 remains authoritative for alerts; D9 only delivers. Local/test provider
never touches the network; email/webhooks are deferred (SSRF section N/A).
"""

import os
import sys
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
import app.models.target  # noqa
import app.models.scan  # noqa
import app.models.audit_log  # noqa
import app.models.finding  # noqa
import app.models.alert  # noqa
import app.models.notification  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.scan import Scan
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.alert import Alert
from app.models.notification import (
    Notification,
    NotificationDelivery,
    NotificationOutbox,
    NotificationPolicy,
)


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    # SQLite compat shim (test-only; pre-existing JSONB/fixture drift).
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
    from app.models.finding import FindingComment, FindingHistory, FindingTag
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__, Scan.__table__,
        AuditLog.__table__, FindingComment.__table__, FindingHistory.__table__, FindingTag.__table__,
        Alert.__table__,
        NotificationPolicy.__table__, NotificationDelivery.__table__,
        Notification.__table__, NotificationOutbox.__table__,
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
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-d9", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-d9", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@d9.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@d9.test", password_hash=pwd, role="member", status="active")
    analyst_a2 = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a2@d9.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@d9.test", password_hash=pwd, role="member", status="active")
    inactive_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="inactive-a@d9.test", password_hash=pwd, role="member", status="suspended")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@d9.test", password_hash=pwd, role="admin", status="active")
    db.add_all([admin_a, analyst_a, analyst_a2, viewer_a, inactive_a, admin_b])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a2.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin", status="active"))
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A1", description="d")
    proj_b1 = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B1", description="d")
    db.add_all([proj_a1, proj_b1])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=admin_a.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=analyst_a.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=analyst_a2.id, role="analyst", status="active"))
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
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata, assigned_to) VALUES (:id, :scan, :target, :scanner, :title, :sev, :status, :ev, :meta, :owner)"),
               {"id": fid_a1, "scan": scan_a1.id, "target": target_a1.id, "scanner": "nmap", "title": "F A", "sev": "critical", "status": "open", "ev": "ev", "meta": "{}", "owner": analyst_a.id})
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan, :target, :scanner, :title, :sev, :status, :ev, :meta)"),
               {"id": fid_b1, "scan": scan_b1.id, "target": target_b1.id, "scanner": "nmap", "title": "F B", "sev": "medium", "status": "open", "ev": "ev", "meta": "{}"})
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    alert_a1 = Alert(id=str(uuid.uuid4()), organization_id=org_a.id, project_id=proj_a1.id, alert_type="NEW_CRITICAL_FINDING", severity="critical", status="open", title="Critical finding on a1", description="synthetic", source_finding_id=fid_a1, first_seen_at=now, last_seen_at=now, event_count=1, dedup_key="d9-a1")
    alert_b1 = Alert(id=str(uuid.uuid4()), organization_id=org_b.id, project_id=proj_b1.id, alert_type="NEW_HIGH_FINDING", severity="high", status="open", title="High finding on b1", description="synthetic", source_finding_id=fid_b1, first_seen_at=now, last_seen_at=now, event_count=1, dedup_key="d9-b1")
    db.add_all([alert_a1, alert_b1])
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, analyst_a2, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_b1": proj_b1,
            "fid_a1": fid_a1, "fid_b1": fid_b1, "alert_a1": alert_a1, "alert_b1": alert_b1,
            "admin_a": admin_a, "analyst_a": analyst_a, "analyst_a2": analyst_a2,
            "viewer_a": viewer_a, "inactive_a": inactive_a, "admin_b": admin_b}
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


def _notify(client, tokens, objs, alert_id=None):
    return client.post(f"/api/v1/projects/{objs['proj_a1'].id}/alerts/{alert_id or objs['alert_a1'].id}/notify", headers=_auth(tokens, "analyst-a@d9.test"))


# --- policy ---
def test_d9_policy_defaults_and_update():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H_admin = _auth(tokens, "admin-a@d9.test")
    try:
        g = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/notification-policies", headers=H_admin)
        assert g.status_code == 200
        assert g.json()["channel"] == "in_app" and g.json()["enabled"] is True
        u = client.put(f"/api/v1/projects/{objs['proj_a1'].id}/notification-policies", json={"channel": "local", "recipient_mode": "project_analysts"}, headers=H_admin)
        assert u.status_code == 200, u.text
        assert u.json()["channel"] == "local"
        assert u.json()["recipient_mode"] == "project_analysts"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_policy_validation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H_admin = _auth(tokens, "admin-a@d9.test")
    try:
        assert client.put(f"/api/v1/projects/{objs['proj_a1'].id}/notification-policies", json={"channel": "sms"}, headers=H_admin).status_code == 400
        assert client.put(f"/api/v1/projects/{objs['proj_a1'].id}/notification-policies", json={"min_severity": "extreme"}, headers=H_admin).status_code == 400
        assert client.put(f"/api/v1/projects/{objs['proj_a1'].id}/notification-policies", json={"recipient_mode": "everyone"}, headers=H_admin).status_code == 400
        assert client.put(f"/api/v1/projects/{objs['proj_a1'].id}/notification-policies", json={"cooldown_seconds": 5}, headers=H_admin).status_code == 400
        # No webhook/URL config surface: rejected.
        assert client.put(f"/api/v1/projects/{objs['proj_a1'].id}/notification-policies", json={"provider_config": {"callback_url": "https://x.example/hook"}}, headers=H_admin).status_code == 400
        # No secrets accepted.
        assert client.put(f"/api/v1/projects/{objs['proj_a1'].id}/notification-policies", json={"provider_config": {"api_key": "sk-123"}}, headers=H_admin).status_code == 400
        assert client.put(f"/api/v1/projects/{objs['proj_a1'].id}/notification-policies", json={"provider_config": {"fail_mode": "sometimes"}}, headers=H_admin).status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_policy_rbac_and_isolation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        assert client.put(f"/api/v1/projects/{pid}/notification-policies", json={"enabled": False}, headers=_auth(tokens, "viewer-a@d9.test")).status_code == 403
        assert client.put(f"/api/v1/projects/{pid}/notification-policies", json={"enabled": False}, headers=_auth(tokens, "analyst-a@d9.test")).status_code == 403
        assert client.get(f"/api/v1/projects/{objs['proj_b1'].id}/notification-policies", headers=_auth(tokens, "admin-a@d9.test")).status_code == 404
        assert client.put(f"/api/v1/projects/{pid}/notification-policies", json={"enabled": False}).status_code in (401, 403)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_explicit_recipients_validated():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H_admin = _auth(tokens, "admin-a@d9.test")
    try:
        pid = objs["proj_a1"].id
        ok = client.put(f"/api/v1/projects/{pid}/notification-policies", json={"recipient_mode": "explicit_users", "explicit_user_ids": [objs["analyst_a"].id]}, headers=H_admin)
        assert ok.status_code == 200, ok.text
        # Cross-tenant user rejected.
        bad = client.put(f"/api/v1/projects/{pid}/notification-policies", json={"recipient_mode": "explicit_users", "explicit_user_ids": [objs["admin_b"].id]}, headers=H_admin)
        assert bad.status_code == 400
        # Inactive user rejected.
        bad2 = client.put(f"/api/v1/projects/{pid}/notification-policies", json={"recipient_mode": "explicit_users", "explicit_user_ids": [objs["inactive_a"].id]}, headers=H_admin)
        assert bad2.status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


# --- alert -> notification ---
def test_d9_critical_alert_notifies_owner():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = _notify(client, tokens, objs)
        assert r.status_code == 201, r.text
        items = r.json()["items"]
        assert len(items) == 1
        assert items[0]["status"] == "sent"
        assert items[0]["recipient_user_id"] == objs["analyst_a"].id
        assert items[0]["channel"] == "in_app"
        # Inbox created for the owner.
        q = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/notifications", headers=_auth(tokens, "analyst-a@d9.test"))
        assert q.status_code == 200
        assert q.json()["unread_count"] == 1
        assert q.json()["items"][0]["alert_id"] == objs["alert_a1"].id
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_duplicate_evaluation_no_duplicate():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r1 = _notify(client, tokens, objs).json()
        r2 = _notify(client, tokens, objs).json()
        assert r1["items"][0]["id"] == r2["items"][0]["id"]
        s = Session()
        try:
            n = s.query(NotificationDelivery).filter(NotificationDelivery.alert_id == objs["alert_a1"].id).count()
            assert n == 1
            assert s.query(Notification).filter(Notification.alert_id == objs["alert_a1"].id).count() == 1
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_gates_severity_type_disabled():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H_admin = _auth(tokens, "admin-a@d9.test")
    try:
        pid = objs["proj_a1"].id
        # Below-threshold severity: craft a medium alert.
        s = Session()
        try:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            s.add(Alert(id=str(uuid.uuid4()), organization_id=objs["org_a"].id, project_id=pid, alert_type="NEW_HIGH_FINDING", severity="medium", status="open", title="med", first_seen_at=now, last_seen_at=now, event_count=1, dedup_key="d9-med"))
            s.commit()
            med_id = s.query(Alert).filter(Alert.dedup_key == "d9-med").first().id
        finally:
            s.close()
        r = client.post(f"/api/v1/projects/{pid}/alerts/{med_id}/notify", headers=_auth(tokens, "analyst-a@d9.test"))
        assert r.json()["items"] == []
        # Disabled policy.
        client.put(f"/api/v1/projects/{pid}/notification-policies", json={"enabled": False}, headers=H_admin)
        assert _notify(client, tokens, objs).json()["items"] == []
        # Excluded type.
        client.put(f"/api/v1/projects/{pid}/notification-policies", json={"enabled": True, "alert_types": ["NEW_HIGH_FINDING"]}, headers=H_admin)
        assert _notify(client, tokens, objs).json()["items"] == []
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_redetection_opt_in_with_cooldown():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H_admin = _auth(tokens, "admin-a@d9.test")
    try:
        pid = objs["proj_a1"].id
        _notify(client, tokens, objs)
        # Bump occurrence; default policy ignores redetection.
        s = Session()
        try:
            a = s.query(Alert).filter(Alert.id == objs["alert_a1"].id).first()
            a.event_count = 2
            s.commit()
        finally:
            s.close()
        assert len(_notify(client, tokens, objs).json()["items"]) == 1  # same delivery reused
        s = Session()
        try:
            assert s.query(NotificationDelivery).filter(NotificationDelivery.alert_id == objs["alert_a1"].id).count() == 1
        finally:
            s.close()
        # Opt in with short cooldown, backdate last delivery, bump again -> new occurrence.
        client.put(f"/api/v1/projects/{pid}/notification-policies", json={"notify_on_redetection": True, "cooldown_seconds": 60}, headers=H_admin)
        s = Session()
        try:
            a = s.query(Alert).filter(Alert.id == objs["alert_a1"].id).first()
            a.event_count = 3
            d = s.query(NotificationDelivery).filter(NotificationDelivery.alert_id == objs["alert_a1"].id).first()
            d.created_at = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=2)
            s.commit()
        finally:
            s.close()
        items = _notify(client, tokens, objs).json()["items"]
        assert len(items) == 1 and items[0]["occurrence"] == 3
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_recipient_modes():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H_admin = _auth(tokens, "admin-a@d9.test")
    try:
        pid = objs["proj_a1"].id
        client.put(f"/api/v1/projects/{pid}/notification-policies", json={"recipient_mode": "project_analysts"}, headers=H_admin)
        items = _notify(client, tokens, objs).json()["items"]
        got = sorted(i["recipient_user_id"] for i in items)
        # admin (project_admin) + 2 analysts; viewer/inactive excluded.
        assert got == sorted([objs["admin_a"].id, objs["analyst_a"].id, objs["analyst_a2"].id]), got
        client.put(f"/api/v1/projects/{pid}/notification-policies", json={"recipient_mode": "explicit_users", "explicit_user_ids": [objs["analyst_a2"].id]}, headers=H_admin)
        # New recipient mode -> new delivery for the new recipient (old rows remain).
        items2 = _notify(client, tokens, objs).json()["items"]
        assert [i["recipient_user_id"] for i in items2] == [objs["analyst_a2"].id]
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_no_owner_no_delivery():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        s = Session()
        try:
            s.execute(text("UPDATE findings SET assigned_to=NULL, owner_user_id=NULL WHERE id=:id"), {"id": objs["fid_a1"]})
            s.commit()
        finally:
            s.close()
        assert _notify(client, tokens, objs).json()["items"] == []
    finally:
        fastapi_app.dependency_overrides.clear()


# --- security ---
def test_d9_cross_project_tenant_denied():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # Finding from another project cannot be notified here.
        r = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/alerts/{objs['alert_b1'].id}/notify", headers=_auth(tokens, "analyst-a@d9.test"))
        assert r.status_code == 404
        # Cross-tenant inbox/queue access denied.
        assert client.get(f"/api/v1/projects/{objs['proj_a1'].id}/notifications", headers=_auth(tokens, "admin-b@d9.test")).status_code == 404
        assert client.get(f"/api/v1/projects/{objs['proj_a1'].id}/notification-deliveries", headers=_auth(tokens, "admin-b@d9.test")).status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_viewer_cannot_notify_or_manage():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        assert client.post(f"/api/v1/projects/{pid}/alerts/{objs['alert_a1'].id}/notify", headers=_auth(tokens, "viewer-a@d9.test")).status_code == 403
        # Viewer reads own inbox fine.
        _notify(client, tokens, objs)
        assert client.get(f"/api/v1/projects/{pid}/notifications", headers=_auth(tokens, "viewer-a@d9.test")).status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_content_bounded_redacted_no_secrets():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        s = Session()
        try:
            a = s.query(Alert).filter(Alert.id == objs["alert_a1"].id).first()
            a.title = "T" * 500
            a.description = "db password=hunter2-secret and -----BEGIN PRIVATE KEY----- abc"
            s.commit()
        finally:
            s.close()
        items = _notify(client, tokens, objs).json()["items"]
        assert len(items[0]["subject"]) <= 255
        q = client.get(f"/api/v1/projects/{objs['proj_a1'].id}/notifications", headers=_auth(tokens, "analyst-a@d9.test")).json()
        summary = q["items"][0]["summary"] or ""
        assert "hunter2" not in summary and "BEGIN PRIVATE" not in summary
        assert "[REDACTED]" in summary
        s = Session()
        try:
            rows = s.query(AuditLog).filter(AuditLog.project_id == objs["proj_a1"].id).all()
            import json as _json
            for r in rows:
                blob = _json.dumps(getattr(r, "extra_data", None) or {})
                assert "hunter2" not in blob and "BEGIN PRIVATE" not in blob
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_inbox_read_and_bounds():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        _notify(client, tokens, objs)
        H = _auth(tokens, "analyst-a@d9.test")
        nid = client.get(f"/api/v1/projects/{pid}/notifications", headers=H).json()["items"][0]["id"]
        assert client.post(f"/api/v1/projects/{pid}/notifications/{nid}/read", headers=H).json()["read"] is True
        assert client.get(f"/api/v1/projects/{pid}/notifications?unread=true", headers=H).json()["unread_count"] == 0
        # Another user cannot read it (404, no leakage).
        assert client.post(f"/api/v1/projects/{pid}/notifications/{nid}/read", headers=_auth(tokens, "analyst-a2@d9.test")).status_code == 404
        # Bounded deliveries list.
        d = client.get(f"/api/v1/projects/{pid}/notification-deliveries?limit=10", headers=H).json()
        assert len(d["items"]) <= 10
    finally:
        fastapi_app.dependency_overrides.clear()


def test_d9_alert_reads_still_work():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        H = _auth(tokens, "analyst-a@d9.test")
        assert client.get(f"/api/v1/projects/{pid}/alerts", headers=H).status_code == 200
        assert client.get(f"/api/v1/projects/{pid}/alerts/{objs['alert_a1'].id}", headers=H).status_code == 200
        # Lazy evaluation created the owner notification as a side effect.
        assert client.get(f"/api/v1/projects/{pid}/notifications", headers=_auth(tokens, "analyst-a@d9.test")).json()["unread_count"] == 1
    finally:
        fastapi_app.dependency_overrides.clear()

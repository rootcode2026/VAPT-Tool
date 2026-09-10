"""D9 local-channel delivery worker tests (no network, no broker needed).

The worker task is driven directly with a patched SessionLocal; Celery Retry
is caught to simulate bounded redelivery.
"""

import os
import sys
import uuid
from datetime import datetime, timezone

import pytest
from celery.exceptions import Retry
from sqlalchemy import JSON as _JSON
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _load_worker_notifications():
    saved_modules = dict(sys.modules)
    saved_path = list(sys.path)
    for mod in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
        del sys.modules[mod]
    sys.path.insert(0, os.path.join(REPO_ROOT, "worker"))
    try:
        import app.notifications as wnotify  # type: ignore
        return wnotify
    finally:
        for mod in [m for m in list(sys.modules) if m == "app" or m.startswith("app.")]:
            del sys.modules[mod]
        sys.modules.update(saved_modules)
        sys.path[:] = saved_path


wn = _load_worker_notifications()

import app.models.organization  # noqa
import app.models.user  # noqa
import app.models.organization_membership  # noqa
import app.models.project  # noqa
import app.models.target  # noqa
import app.models.audit_log  # noqa
import app.models.alert  # noqa
import app.models.notification  # noqa

from app.models.organization import Organization
from app.models.project import Project
from app.models.target import Target
from app.models.user import User
from app.models.alert import Alert
from app.models.notification import NotificationDelivery, NotificationOutbox, NotificationPolicy


def _setup(fail_mode="none"):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for _tbl in list(Base.metadata.tables.values()):
        for _col in _tbl.columns:
            if _col.type.__class__.__name__ == "JSONB":
                _col.type = _JSON()
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, Project.__table__, Target.__table__,
        Alert.__table__, NotificationPolicy.__table__, NotificationDelivery.__table__,
        NotificationOutbox.__table__,
    ])
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE IF NOT EXISTS audit_logs (id TEXT PRIMARY KEY, organization_id TEXT, project_id TEXT, actor_user_id TEXT, event_type TEXT, action TEXT, resource_type TEXT, resource_id TEXT, result TEXT, metadata TEXT, created_at DATETIME)"))
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org = Organization(id=str(uuid.uuid4()), name="O", slug="o-d9w", status="active")
    db.add(org)
    db.flush()
    user = User(id=str(uuid.uuid4()), organization_id=org.id, email="u@d9w.test", password_hash="x", role="member", status="active")
    db.add(user)
    db.flush()
    proj = Project(id=str(uuid.uuid4()), organization_id=org.id, name="P", description="d")
    db.add(proj)
    db.flush()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    alert = Alert(id=str(uuid.uuid4()), organization_id=org.id, project_id=proj.id, alert_type="NEW_CRITICAL_FINDING", severity="critical", status="open", title="T", first_seen_at=now, last_seen_at=now, event_count=1, dedup_key="d9w-1")
    db.add(alert)
    db.flush()
    db.add(NotificationPolicy(project_id=proj.id, enabled=True, channel="local", min_severity="high", recipient_mode="finding_owner", provider_config={"fail_mode": fail_mode} if fail_mode else None))
    delivery = NotificationDelivery(id=str(uuid.uuid4()), organization_id=org.id, project_id=proj.id, alert_id=alert.id, recipient_user_id=user.id, channel="local", notification_type="NEW_CRITICAL_FINDING", occurrence=1, status="pending", subject="s", body="b")
    db.add(delivery)
    db.commit()
    ids = {"delivery": delivery.id, "alert": alert.id, "proj": proj.id, "org": org.id, "user": user.id}
    db.close()
    wn.SessionLocal = Session
    return Session, ids


def _row(Session, delivery_id):
    s = Session()
    try:
        return s.query(NotificationDelivery).filter(NotificationDelivery.id == delivery_id).first()
    finally:
        s.close()


def test_d9w_success_marks_sent_with_outbox():
    Session, ids = _setup()
    out = wn.deliver_notification(ids["delivery"])
    assert out["status"] == "sent"
    assert _row(Session, ids["delivery"]).status == "sent"
    s = Session()
    try:
        assert s.query(NotificationOutbox).filter(NotificationOutbox.delivery_id == ids["delivery"]).count() == 1
    finally:
        s.close()


def test_d9w_terminal_stable_no_duplicate():
    Session, ids = _setup()
    wn.deliver_notification(ids["delivery"])
    out = wn.deliver_notification(ids["delivery"])
    assert out["status"] == "sent" and out["reason"] == "terminal_stable"
    s = Session()
    try:
        assert s.query(NotificationOutbox).filter(NotificationOutbox.delivery_id == ids["delivery"]).count() == 1
    finally:
        s.close()


def test_d9w_temporary_retries_then_fails_bounded():
    Session, ids = _setup(fail_mode="temporary")
    outcomes = []
    for _ in range(6):
        try:
            outcomes.append(wn.deliver_notification(ids["delivery"])["status"])
            break
        except (Retry, wn.TransientDeliveryError):
            # Celery re-raises the original exc after scheduling the retry.
            outcomes.append("retry")
    assert "retry" in outcomes
    assert _row(Session, ids["delivery"]).status == "failed"
    assert outcomes[-1] == "failed"
    s = Session()
    try:
        assert s.query(NotificationOutbox).filter(NotificationOutbox.delivery_id == ids["delivery"]).count() == 0
    finally:
        s.close()


def test_d9w_permanent_fails_without_retry():
    Session, ids = _setup(fail_mode="permanent")
    out = wn.deliver_notification(ids["delivery"])
    assert out["status"] == "failed"
    assert _row(Session, ids["delivery"]).last_error.startswith("permanent_provider_failure")


def test_d9w_concurrent_claim_lost_no_double_send():
    Session, ids = _setup()
    s = Session()
    try:
        d = s.query(NotificationDelivery).filter(NotificationDelivery.id == ids["delivery"]).first()
        d.status = "sending"
        s.commit()
    finally:
        s.close()
    out = wn.deliver_notification(ids["delivery"])
    assert out["reason"] == "claim_lost"
    s = Session()
    try:
        assert s.query(NotificationOutbox).filter(NotificationOutbox.delivery_id == ids["delivery"]).count() == 0
    finally:
        s.close()


def test_d9w_tenant_mismatch_fails():
    Session, ids = _setup()
    s = Session()
    try:
        a = s.query(Alert).filter(Alert.id == ids["alert"]).first()
        a.project_id = "other-project"
        s.commit()
    finally:
        s.close()
    out = wn.deliver_notification(ids["delivery"])
    assert out["status"] == "failed" and out["reason"] == "tenant_validation_failure"

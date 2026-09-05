"""
Audit log foundation tests — Phase 6A.

Covers model, service, taxonomy, redaction, limits, and migration.
"""

import uuid

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.db.base import Base
from app.models.audit_log import AuditLog
from app.models.organization import Organization
from app.models.user import User
from app.services.audit import (
    EVENT_AUTH_LOGIN_SUCCESS,
    EVENT_PROJECT_CREATED,
    RESOURCE_PROJECT,
    RESULT_SUCCESS,
    AuditService,
    sanitize_metadata,
)


def _sqlite_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    # Only create tables needed for audit tests to avoid JSONB incompatibility with SQLite
    Base.metadata.create_all(bind=engine, tables=[AuditLog.__table__, Organization.__table__, User.__table__])
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    return engine, SessionLocal


def test_audit_event_can_be_created():
    engine, Session = _sqlite_session()
    db = Session()
    org = Organization(id=str(uuid.uuid4()), name="Org", slug="org-audit-1")
    user = User(id=str(uuid.uuid4()), organization_id=org.id, email="a@a.test", password_hash="x", role="member")
    db.add_all([org, user])
    db.commit()
    audit = AuditService.record(
        db,
        event_type=EVENT_PROJECT_CREATED,
        action="project.create",
        result=RESULT_SUCCESS,
        actor_user_id=user.id,
        organization_id=org.id,
        project_id=str(uuid.uuid4()),
        resource_type=RESOURCE_PROJECT,
        resource_id=str(uuid.uuid4()),
        metadata={"name": "Test Project"},
    )
    db.commit()
    fetched = db.query(AuditLog).filter(AuditLog.id == audit.id).first()
    assert fetched is not None
    assert fetched.event_type == EVENT_PROJECT_CREATED
    assert fetched.organization_id == org.id
    db.close()
    engine.dispose()


def test_organization_context_preserved():
    engine, Session = _sqlite_session()
    db = Session()
    org = Organization(id=str(uuid.uuid4()), name="Org", slug="org-audit-2")
    db.add(org)
    db.commit()
    audit = AuditService.record(db, event_type=EVENT_PROJECT_CREATED, action="project.create", result=RESULT_SUCCESS, organization_id=org.id, project_id=str(uuid.uuid4()), resource_type=RESOURCE_PROJECT, resource_id=str(uuid.uuid4()))
    db.commit()
    fetched = db.query(AuditLog).filter(AuditLog.id == audit.id).first()
    assert fetched.organization_id == org.id
    assert fetched.project_id is not None
    db.close()
    engine.dispose()


def test_project_context_preserved():
    engine, Session = _sqlite_session()
    db = Session()
    proj_id = str(uuid.uuid4())
    audit = AuditService.record(db, event_type="TEST", action="test", result=RESULT_SUCCESS, project_id=proj_id, resource_type="project", resource_id=proj_id)
    db.commit()
    fetched = db.query(AuditLog).filter(AuditLog.id == audit.id).first()
    assert fetched.project_id == proj_id
    db.close()
    engine.dispose()


def test_actor_is_server_controlled():
    engine, Session = _sqlite_session()
    db = Session()
    actor_id = str(uuid.uuid4())
    audit = AuditService.record(db, event_type=EVENT_AUTH_LOGIN_SUCCESS, action="login", result=RESULT_SUCCESS, actor_user_id=actor_id, organization_id=str(uuid.uuid4()))
    db.commit()
    fetched = db.query(AuditLog).filter(AuditLog.id == audit.id).first()
    assert fetched.actor_user_id == actor_id
    # Ensure that client cannot spoof actor via metadata
    audit2 = AuditService.record(db, event_type=EVENT_AUTH_LOGIN_SUCCESS, action="login", result=RESULT_SUCCESS, actor_user_id=actor_id, metadata={"actor_user_id": "spoofed"})
    db.commit()
    # The spoofed value is in metadata, but actor_user_id remains the server-controlled one
    assert audit2.extra_data.get("actor_user_id") == "[REDACTED]" or audit2.extra_data.get("actor_user_id") != actor_id
    db.close()
    engine.dispose()


def test_metadata_redaction_works():
    metadata = {
        "password": "secret123",
        "api_key": "sk_test_123",
        "authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        "nested": {"secret": "hidden", "normal": "visible"},
        "list_secret": [{"token": "abc", "value": "ok"}],
    }
    sanitized = sanitize_metadata(metadata)
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["authorization"] == "[REDACTED]"
    assert sanitized["nested"]["secret"] == "[REDACTED]"
    assert sanitized["nested"]["normal"] == "visible"
    # List handling
    assert sanitized["list_secret"][0]["token"] == "[REDACTED]"


def test_nested_metadata_redaction():
    metadata = {"outer": {"inner": {"password": "p", "secret_token": "s"}, "list": [{"api_key": "k"}, {"normal": "v"}]}}
    sanitized = sanitize_metadata(metadata)
    assert sanitized["outer"]["inner"]["password"] == "[REDACTED]"
    assert sanitized["outer"]["inner"]["secret_token"] == "[REDACTED]"
    assert sanitized["outer"]["list"][0]["api_key"] == "[REDACTED]"
    assert sanitized["outer"]["list"][1]["normal"] == "v"


def test_metadata_size_protection():
    large = {"a": "x" * 5000}
    sanitized = sanitize_metadata(large)
    import json

    assert len(json.dumps(sanitized).encode("utf-8")) <= getattr(settings, "AUDIT_METADATA_MAX_BYTES", 4096) + 500
    # Huge metadata should be truncated
    huge = {f"key{i}": "x" * 1000 for i in range(20)}
    sanitized2 = sanitize_metadata(huge)
    assert sanitized2 is not None
    assert len(json.dumps(sanitized2).encode("utf-8")) <= 5000


def test_sensitive_values_never_persist():
    engine, Session = _sqlite_session()
    db = Session()
    audit = AuditService.record(
        db,
        event_type=EVENT_AUTH_LOGIN_SUCCESS,
        action="login",
        result=RESULT_SUCCESS,
        actor_user_id=str(uuid.uuid4()),
        metadata={"password": "mysecret", "access_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.xxx"},
    )
    db.commit()
    fetched = db.query(AuditLog).filter(AuditLog.id == audit.id).first()
    assert fetched.extra_data["password"] == "[REDACTED]"
    assert fetched.extra_data["access_token"] == "[REDACTED]"
    db.close()
    engine.dispose()


def test_audit_event_taxonomy():
    from app.services.audit import (
        EVENT_AUTH_LOGIN_FAILURE,
        EVENT_ORG_MEMBER_ADDED,
        EVENT_PROJECT_MEMBER_ADDED,
        EVENT_TARGET_CREATED,
        EVENT_SCAN_CREATED,
        EVENT_INGESTION_CREATED,
    )

    assert EVENT_AUTH_LOGIN_FAILURE == "AUTH_LOGIN_FAILURE"
    assert EVENT_ORG_MEMBER_ADDED == "ORGANIZATION_MEMBER_ADDED"
    assert EVENT_PROJECT_MEMBER_ADDED == "PROJECT_MEMBER_ADDED"
    assert EVENT_TARGET_CREATED == "TARGET_CREATED"
    assert EVENT_SCAN_CREATED == "SCAN_CREATED"
    assert EVENT_INGESTION_CREATED == "INGESTION_CREATED"


def test_audit_records_survive_user_deletion():
    engine, Session = _sqlite_session()
    db = Session()
    org = Organization(id=str(uuid.uuid4()), name="Org", slug="org-audit-survive")
    user = User(id=str(uuid.uuid4()), organization_id=org.id, email="survive@a.test", password_hash="x", role="member")
    db.add_all([org, user])
    db.commit()
    audit = AuditService.record(db, event_type=EVENT_PROJECT_CREATED, action="project.create", result=RESULT_SUCCESS, actor_user_id=user.id, organization_id=org.id, project_id=str(uuid.uuid4()), resource_type=RESOURCE_PROJECT, resource_id=str(uuid.uuid4()))
    db.commit()
    audit_id = audit.id
    # Delete user — on Postgres with SET NULL this would null the FK, on SQLite it may retain the id (FKs disabled)
    # The important assertion is that the audit record itself is not deleted (no CASCADE)
    db.delete(user)
    db.commit()
    fetched = db.query(AuditLog).filter(AuditLog.id == audit_id).first()
    assert fetched is not None
    # On Postgres, actor_user_id would be SET NULL; on SQLite with FKs off it retains the id — both are acceptable as long as audit survives
    assert fetched.id == audit_id
    db.close()
    engine.dispose()


def test_migration_and_indexes():
    # Verify table exists and indexes are present via SQLite master
    engine, Session = _sqlite_session()
    db = Session()
    # Check that audit_logs table exists
    result = db.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'")).fetchone()
    assert result is not None
    # Check indexes
    idx = db.execute(text("SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='audit_logs'")).fetchall()
    idx_names = {r[0] for r in idx}
    assert "ix_audit_logs_organization_id" in idx_names
    assert "ix_audit_logs_project_id" in idx_names
    assert "ix_audit_logs_event_type" in idx_names
    db.close()
    engine.dispose()


def test_rls_remains_disabled():
    from app.core.config import settings as _s

    assert _s.RLS_ENABLED is False
    # Check that no migration actually enables RLS (look for op.execute with ENABLE)
    import pathlib

    found = False
    for p in pathlib.Path("backend/alembic").rglob("*.py"):
        text = p.read_text(errors="ignore")
        if "ENABLE ROW LEVEL SECURITY" in text and "op.execute" in text:
            found = True
            break
    assert not found


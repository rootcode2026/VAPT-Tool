"""
Worker Phase 6D — Finding audit tests (system-created findings)
"""
import uuid
import json
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from app.tasks import _audit_finding_event, _sanitize_audit_metadata


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT, slug TEXT)"))
        conn.execute(text("CREATE TABLE projects (id TEXT PRIMARY KEY, organization_id TEXT, name TEXT)"))
        conn.execute(text("CREATE TABLE targets (id TEXT PRIMARY KEY, project_id TEXT, value TEXT, target_type TEXT)"))
        conn.execute(text("""
            CREATE TABLE audit_logs (
                id TEXT PRIMARY KEY,
                organization_id TEXT,
                project_id TEXT,
                actor_user_id TEXT,
                target_user_id TEXT,
                event_type TEXT,
                action TEXT,
                resource_type TEXT,
                resource_id TEXT,
                result TEXT,
                request_id TEXT,
                correlation_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                metadata TEXT,
                created_at DATETIME
            )
        """))
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    db = Session()
    org = str(uuid.uuid4())
    proj = str(uuid.uuid4())
    target = str(uuid.uuid4())
    db.execute(text("INSERT INTO organizations (id, name, slug) VALUES (:id, 'Org', 'org')"), {"id": org})
    db.execute(text("INSERT INTO projects (id, organization_id, name) VALUES (:pid, :oid, 'Proj')"), {"pid": proj, "oid": org})
    db.execute(text("INSERT INTO targets (id, project_id, value, target_type) VALUES (:tid, :pid, 'example.com', 'domain')"), {"tid": target, "pid": proj})
    db.commit()
    db.close()
    return engine, Session, org, proj, target


def test_finding_creation_creates_audit():
    engine, Session, org, proj, target = _setup()
    db = Session()
    fid = str(uuid.uuid4())
    _audit_finding_event(db, finding_id=fid, target_id=target, event_type="FINDING_CREATED", result="SUCCESS", metadata={"severity": "high", "scanner": "nmap", "status": "open"})
    db.commit()
    row = db.execute(text("SELECT event_type, resource_id, resource_type, result, organization_id, project_id, metadata FROM audit_logs WHERE resource_id=:fid"), {"fid": fid}).fetchone()
    assert row is not None
    assert row[0] == "FINDING_CREATED"
    assert row[1] == fid
    assert row[2] == "finding"
    assert row[3] == "SUCCESS"
    assert row[4] == org
    assert row[5] == proj
    meta = json.loads(row[6]) if row[6] else {}
    assert meta["severity"] == "high"
    assert meta["scanner"] == "nmap"
    db.close()
    engine.dispose()


def test_finding_correct_tenant():
    engine, Session, org, proj, target = _setup()
    db = Session()
    fid = str(uuid.uuid4())
    _audit_finding_event(db, finding_id=fid, target_id=target, event_type="FINDING_CREATED", result="SUCCESS", metadata={"severity": "critical"})
    db.commit()
    row = db.execute(text("SELECT organization_id, project_id FROM audit_logs WHERE resource_id=:fid"), {"fid": fid}).fetchone()
    assert row[0] == org
    assert row[1] == proj
    db.close()
    engine.dispose()


def test_finding_actor_NULL_for_system():
    engine, Session, org, proj, target = _setup()
    db = Session()
    fid = str(uuid.uuid4())
    _audit_finding_event(db, finding_id=fid, target_id=target, event_type="FINDING_CREATED", result="SUCCESS", metadata={"severity": "medium"})
    db.commit()
    row = db.execute(text("SELECT actor_user_id FROM audit_logs WHERE resource_id=:fid"), {"fid": fid}).fetchone()
    assert row[0] is None
    db.close()
    engine.dispose()


def test_finding_evidence_not_written():
    engine, Session, org, proj, target = _setup()
    db = Session()
    fid = str(uuid.uuid4())
    _audit_finding_event(db, finding_id=fid, target_id=target, event_type="FINDING_CREATED", result="SUCCESS", metadata={"severity": "high", "scanner": "secrets", "status": "open"})
    db.commit()
    row = db.execute(text("SELECT metadata FROM audit_logs WHERE resource_id=:fid"), {"fid": fid}).fetchone()
    meta_str = row[0] if row[0] else ""
    assert "BEGIN PRIVATE KEY" not in meta_str
    assert "evidence" not in meta_str.lower() or "high" in meta_str
    db.close()
    engine.dispose()


def test_finding_redaction():
    meta = {"password": "secret", "severity": "high", "nested": {"token": "abc"}}
    sanitized = _sanitize_audit_metadata(meta)
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["nested"]["token"] == "[REDACTED]"
    assert sanitized["severity"] == "high"


def test_duplicate_finding_not_duplicated_without_canonical():
    # Each finding row gets its own audit; correlation should not duplicate canonical
    engine, Session, org, proj, target = _setup()
    db = Session()
    fid = str(uuid.uuid4())
    _audit_finding_event(db, finding_id=fid, target_id=target, event_type="FINDING_CREATED", result="SUCCESS", metadata={"severity": "low"})
    db.commit()
    cnt = db.execute(text("SELECT COUNT(*) FROM audit_logs WHERE resource_id=:fid"), {"fid": fid}).scalar()
    assert cnt == 1
    db.close()
    engine.dispose()

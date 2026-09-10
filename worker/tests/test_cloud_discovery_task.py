"""E1 discovery task — sqlite-backed run lifecycle, idempotency, partial failure.

boto3 never imported: aws_discovery functions are monkeypatched with fakes and
the task SessionLocal is patched to sqlite.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, func, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

import app.cloud_discovery as taskmod
import app.aws_discovery as engine_


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(36))


class CloudConnection(Base):
    __tablename__ = "cloud_connections"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    provider: Mapped[str] = mapped_column(String(20))
    account_id: Mapped[str] = mapped_column(String(255))
    role_arn: Mapped[str | None] = mapped_column(String(512), nullable=True)
    external_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    regions: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="active")
    last_validation_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_discovery_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class CloudDiscovery(Base):
    __tablename__ = "cloud_discoveries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(36))
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    connection_id: Mapped[str] = mapped_column(String(36), ForeignKey("cloud_connections.id"))
    provider: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="queued")
    regions_attempted: Mapped[int] = mapped_column(Integer, default=0)
    regions_succeeded: Mapped[int] = mapped_column(Integer, default=0)
    regions_failed: Mapped[int] = mapped_column(Integer, default=0)
    assets_discovered: Mapped[int] = mapped_column(Integer, default=0)
    relationships_discovered: Mapped[int] = mapped_column(Integer, default=0)
    region_results: Mapped[list | None] = mapped_column(JSON, nullable=True)
    resource_counts: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    warnings: Mapped[list | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("project_id", "asset_type", "value", name="uq_assets_project_type_value"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    first_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    last_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(50))
    value: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(20), default="active")
    extra_data: Mapped[str] = mapped_column("metadata", Text, default="{}")
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AssetRelationship(Base):
    __tablename__ = "asset_relationships"
    __table_args__ = (UniqueConstraint("project_id", "source_asset_id", "target_asset_id", "relationship_type", name="uq_asset_relationships_identity"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    source_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"))
    target_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"))
    relationship_type: Mapped[str] = mapped_column(String(50))
    last_seen_scan_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    extra_data: Mapped[str] = mapped_column("metadata", Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    project_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    actor_user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100))
    action: Mapped[str] = mapped_column(String(100))
    resource_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    result: Mapped[str] = mapped_column(String(20))
    extra_data: Mapped[str | None] = mapped_column("metadata", Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


FAKE_RESOURCES = [
    {"service": "ec2", "resource_type": "aws_vpc", "resource_id": "vpc-1",
     "region": "us-east-1", "account_id": "123456789012", "name": "main", "tags": {}, "extra": {}},
    {"service": "ec2", "resource_type": "aws_ec2_instance", "resource_id": "i-1",
     "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1", "region": "us-east-1",
     "account_id": "123456789012", "tags": {}, "extra": {"vpc_id": "vpc-1"}},
]


def _setup(monkeypatch):
    from sqlalchemy.pool import StaticPool
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    proj = Project(id=str(uuid.uuid4()), organization_id="org-1")
    db.add(proj)
    db.flush()
    conn = CloudConnection(id=str(uuid.uuid4()), project_id=proj.id, provider="aws",
                           account_id="123456789012",
                           role_arn="arn:aws:iam::123456789012:role/VAPT", external_id="ext",
                           status="active")
    db.add(conn)
    db.flush()
    run = CloudDiscovery(id=str(uuid.uuid4()), organization_id="org-1", project_id=proj.id,
                         connection_id=conn.id, provider="aws", status="queued")
    db.add(run)
    db.commit()
    ids = {"proj": proj.id, "conn": conn.id, "run": run.id}
    db.close()
    monkeypatch.setattr(taskmod, "SessionLocal", Session)
    monkeypatch.setattr(engine_, "assume_role_session", lambda *a, **k: object())
    monkeypatch.setattr(engine_, "get_caller_account", lambda *a, **k: "123456789012")
    monkeypatch.setattr(engine_, "list_enabled_regions", lambda *a, **k: ["us-east-1"])
    return Session, ids


def _outcome(resources=None, status="completed"):
    resources = FAKE_RESOURCES if resources is None else resources
    return {"status": status, "regions_attempted": 1, "regions_succeeded": 1,
            "regions_failed": 0, "resources": [dict(r) for r in resources],
            "region_results": [{"region": "us-east-1", "status": "ok", "resources": len(resources)}],
            "warnings": [], "resource_counts": {"aws_vpc": 1, "aws_ec2_instance": 1}}


def test_task_completed_persists_assets_and_relationships(monkeypatch):
    Session, ids = _setup(monkeypatch)
    monkeypatch.setattr(engine_, "discover_account", lambda *a, **k: _outcome())
    out = taskmod.discover_cloud(ids["conn"], ids["proj"], ids["run"])
    assert out["status"] == "completed"
    s = Session()
    try:
        assert s.query(Asset).filter(Asset.project_id == ids["proj"]).count() == 3  # account + vpc + ec2
        assert s.query(AssetRelationship).filter(AssetRelationship.project_id == ids["proj"]).count() >= 2
        run = s.query(CloudDiscovery).filter(CloudDiscovery.id == ids["run"]).first()
        assert run.status == "completed" and run.assets_discovered == 3
        assert s.query(AuditLog).filter(AuditLog.event_type == "CLOUD_DISCOVERY_COMPLETED").count() == 1
    finally:
        s.close()


def test_task_idempotent_no_duplicates(monkeypatch):
    Session, ids = _setup(monkeypatch)
    monkeypatch.setattr(engine_, "discover_account", lambda *a, **k: _outcome())
    taskmod.discover_cloud(ids["conn"], ids["proj"], ids["run"])
    s = Session()
    try:
        n_assets = s.query(Asset).filter(Asset.project_id == ids["proj"]).count()
        n_rels = s.query(AssetRelationship).filter(AssetRelationship.project_id == ids["proj"]).count()
        first_seen = {a.value: a.first_seen_at for a in s.query(Asset).filter(Asset.project_id == ids["proj"]).all()}
        # Second run (new run row, same resources): update, don't duplicate.
        run2 = CloudDiscovery(id=str(uuid.uuid4()), organization_id="org-1", project_id=ids["proj"],
                              connection_id=ids["conn"], provider="aws", status="queued")
        s.add(run2)
        s.commit()
        run2_id = run2.id
    finally:
        s.close()
    out = taskmod.discover_cloud(ids["conn"], ids["proj"], run2_id)
    assert out["status"] == "completed"
    s = Session()
    try:
        assert s.query(Asset).filter(Asset.project_id == ids["proj"]).count() == n_assets
        assert s.query(AssetRelationship).filter(AssetRelationship.project_id == ids["proj"]).count() == n_rels
        for a in s.query(Asset).filter(Asset.project_id == ids["proj"]).all():
            assert a.first_seen_at == first_seen[a.value]  # first_seen preserved
            assert a.last_seen_at >= a.first_seen_at  # last_seen advanced
    finally:
        s.close()


def test_task_partial_on_region_warnings(monkeypatch):
    Session, ids = _setup(monkeypatch)
    outcome = _outcome(status="partial")
    outcome["regions_failed"] = 1
    outcome["warnings"] = [{"service": "rds", "reason": "permission_denied", "detail": "denied"}]
    monkeypatch.setattr(engine_, "discover_account", lambda *a, **k: outcome)
    out = taskmod.discover_cloud(ids["conn"], ids["proj"], ids["run"])
    assert out["status"] == "partial"
    s = Session()
    try:
        run = s.query(CloudDiscovery).filter(CloudDiscovery.id == ids["run"]).first()
        assert run.status == "partial" and run.regions_failed == 1
        assert s.query(AuditLog).filter(AuditLog.event_type == "CLOUD_DISCOVERY_PARTIAL").count() == 1
    finally:
        s.close()


def test_task_account_mismatch_fails(monkeypatch):
    Session, ids = _setup(monkeypatch)
    monkeypatch.setattr(engine_, "get_caller_account", lambda *a, **k: "999988887777")
    out = taskmod.discover_cloud(ids["conn"], ids["proj"], ids["run"])
    assert out["status"] == "failed" and out["reason"] == "account_mismatch"


def test_task_disabled_and_missing_role_rejected(monkeypatch):
    Session, ids = _setup(monkeypatch)
    s = Session()
    try:
        conn = s.query(CloudConnection).filter(CloudConnection.id == ids["conn"]).first()
        conn.status = "inactive"
        s.commit()
    finally:
        s.close()
    assert taskmod.discover_cloud(ids["conn"], ids["proj"], ids["run"])["reason"] == "connection_disabled"
    s = Session()
    try:
        conn = s.query(CloudConnection).filter(CloudConnection.id == ids["conn"]).first()
        conn.status = "active"
        conn.role_arn = None
        s.commit()
    finally:
        s.close()
    assert taskmod.discover_cloud(ids["conn"], ids["proj"], ids["run"])["reason"] == "role_arn_required"


def test_task_terminal_stable_no_rerun(monkeypatch):
    Session, ids = _setup(monkeypatch)
    monkeypatch.setattr(engine_, "discover_account", lambda *a, **k: _outcome())
    taskmod.discover_cloud(ids["conn"], ids["proj"], ids["run"])
    out = taskmod.discover_cloud(ids["conn"], ids["proj"], ids["run"])
    assert out["reason"] == "terminal_stable"

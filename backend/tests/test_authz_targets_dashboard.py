"""
Regression tests for IDOR / cross-tenant authorization fixes.

Covers the 6 critical endpoints fixed in the API inventory audit:
- POST /api/v1/targets (cross-org create)
- GET /api/v1/targets (enumeration)
- GET /api/v1/targets/{id} (IDOR read)
- DELETE /api/v1/targets/{id} (IDOR delete)
- GET /api/v1/dashboard/summary (cross-tenant aggregate)
- GET /api/v1/assets/summary without project_id (cross-tenant aggregate)
"""

import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.database import get_db
from app.main import app


class Base(DeclarativeBase):
    pass


class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(255), unique=True)


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    value: Mapped[str] = mapped_column(String(255))
    target_type: Mapped[str] = mapped_column(String(50))
    is_active: Mapped[bool] = mapped_column(default=True)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))
    profile: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50), default="queued")
    phase: Mapped[str] = mapped_column(String(50), default="queued")
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_grade: Mapped[str | None] = mapped_column(String(1), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(30), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    progress: Mapped[int] = mapped_column(Integer, default=0)


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
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
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
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"))
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))
    scanner: Mapped[str] = mapped_column(String(50))
    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="info")
    score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(30), default="open")
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve: Mapped[str | None] = mapped_column(String(50), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(50), nullable=True)
    asset_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="member")


class ScanResult(Base):
    __tablename__ = "scan_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"))
    scanner: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50), default="pending")
    raw_output: Mapped[str] = mapped_column(Text, nullable=False, default="")
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    max_attempts: Mapped[int] = mapped_column(Integer, default=2)
    error_type: Mapped[str | None] = mapped_column(String(50), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_phase: Mapped[str | None] = mapped_column(String(50), nullable=True)
    retryable: Mapped[bool | None] = mapped_column(JSON, nullable=True)
    findings_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    assets_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


class AssetChangeEvent(Base):
    __tablename__ = "asset_change_events"
    __table_args__ = (UniqueConstraint("scan_id", "asset_id", "change_type", name="uq3"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36))
    asset_id: Mapped[str] = mapped_column(String(36))
    scan_id: Mapped[str] = mapped_column(String(36))
    change_type: Mapped[str] = mapped_column(String(50))
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)


def _setup_isolated_db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)

    db = TestingSession()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b")
    db.add_all([org_a, org_b])
    db.flush()

    user_a = User(
        id=str(uuid.uuid4()),
        organization_id=org_a.id,
        email="alice@org-a.test",
        password_hash=hash_password("password123"),
        role="member",
    )
    user_b = User(
        id=str(uuid.uuid4()),
        organization_id=org_b.id,
        email="bob@org-b.test",
        password_hash=hash_password("password123"),
        role="member",
    )
    db.add_all([user_a, user_b])
    db.flush()

    proj_a = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Project A")
    proj_b = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Project B")
    db.add_all([proj_a, proj_b])
    db.flush()

    target_a = Target(id=str(uuid.uuid4()), project_id=proj_a.id, value="target-a.example.com", target_type="domain", is_active=True)
    target_b = Target(id=str(uuid.uuid4()), project_id=proj_b.id, value="target-b.example.com", target_type="domain", is_active=True)
    db.add_all([target_a, target_b])
    db.flush()

    scan_a = Scan(id=str(uuid.uuid4()), target_id=target_a.id, profile="quick", status="completed", phase="completed", risk_score=75, created_at=datetime.now(timezone.utc))
    scan_b = Scan(id=str(uuid.uuid4()), target_id=target_b.id, profile="quick", status="failed", phase="failed", risk_score=20, created_at=datetime.now(timezone.utc))
    db.add_all([scan_a, scan_b])
    db.flush()

    finding_a = Finding(
        id=str(uuid.uuid4()), scan_id=scan_a.id, target_id=target_a.id, asset_id=None,
        scanner="nmap", title="Finding A", description="desc", severity="critical", score=90, status="detected",
        created_at=datetime.now(timezone.utc),
    )
    finding_b = Finding(
        id=str(uuid.uuid4()), scan_id=scan_b.id, target_id=target_b.id, asset_id=None,
        scanner="nmap", title="Finding B", description="desc", severity="high", score=75, status="detected",
        created_at=datetime.now(timezone.utc),
    )
    db.add_all([finding_a, finding_b])
    db.flush()

    asset_a = Asset(id=str(uuid.uuid4()), project_id=proj_a.id, asset_type="domain", value="target-a.example.com", status="active", created_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    asset_b = Asset(id=str(uuid.uuid4()), project_id=proj_b.id, asset_type="domain", value="target-b.example.com", status="active", created_at=datetime.now(timezone.utc), last_seen_at=datetime.now(timezone.utc))
    db.add_all([asset_a, asset_b])

    db.commit()
    db.close()

    token_a = create_access_token(user_a.id)
    token_b = create_access_token(user_b.id)

    return engine, TestingSession, app, token_a, token_b, proj_a, proj_b, target_a, target_b, scan_a, scan_b


def test_create_target_cross_org_rejected():
    _, TestingSession, test_app, token_a, token_b, proj_a, proj_b, target_a, target_b, *_ = _setup_isolated_db()

    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()

    test_app.dependency_overrides[get_db] = override
    client = TestClient(test_app)
    try:
        resp = client.post(
            "/api/v1/targets",
            json={"project_id": proj_a.id, "value": "evil.example.com", "target_type": "domain"},
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert resp.status_code == 404, resp.text

        resp2 = client.post(
            "/api/v1/targets",
            json={"project_id": proj_a.id, "value": "allowed.example.com", "target_type": "domain"},
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert resp2.status_code == 200, resp2.text
    finally:
        test_app.dependency_overrides.clear()


def test_list_targets_isolated():
    _, TestingSession, test_app, token_a, token_b, proj_a, proj_b, target_a, target_b, *_ = _setup_isolated_db()

    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()

    test_app.dependency_overrides[get_db] = override
    client = TestClient(test_app)
    try:
        resp_a = client.get("/api/v1/targets", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_a.status_code == 200
        ids_a = {t["id"] for t in resp_a.json()}
        assert target_a.id in ids_a
        assert target_b.id not in ids_a

        resp_b = client.get("/api/v1/targets", headers={"Authorization": f"Bearer {token_b}"})
        assert resp_b.status_code == 200
        ids_b = {t["id"] for t in resp_b.json()}
        assert target_b.id in ids_b
        assert target_a.id not in ids_b

        resp_a_proj = client.get(f"/api/v1/targets?project_id={proj_a.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_a_proj.status_code == 200
        assert all(t["project_id"] == proj_a.id for t in resp_a_proj.json())

        resp_cross = client.get(f"/api/v1/targets?project_id={proj_b.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_cross.status_code == 404
    finally:
        test_app.dependency_overrides.clear()


def test_get_target_cross_org_404():
    _, TestingSession, test_app, token_a, token_b, proj_a, proj_b, target_a, target_b, *_ = _setup_isolated_db()

    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()

    test_app.dependency_overrides[get_db] = override
    client = TestClient(test_app)
    try:
        resp = client.get(f"/api/v1/targets/{target_a.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert resp.status_code == 200
        resp2 = client.get(f"/api/v1/targets/{target_a.id}", headers={"Authorization": f"Bearer {token_b}"})
        assert resp2.status_code == 404
    finally:
        test_app.dependency_overrides.clear()


def test_delete_target_cross_org_404():
    _, TestingSession, test_app, token_a, token_b, proj_a, proj_b, target_a, target_b, *_ = _setup_isolated_db()

    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()

    test_app.dependency_overrides[get_db] = override
    client = TestClient(test_app)
    try:
        resp = client.delete(f"/api/v1/targets/{target_a.id}", headers={"Authorization": f"Bearer {token_b}"})
        assert resp.status_code == 404
        resp2 = client.get(f"/api/v1/targets/{target_a.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert resp2.status_code == 200
        resp3 = client.delete(f"/api/v1/targets/{target_a.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert resp3.status_code == 200
        resp4 = client.get(f"/api/v1/targets/{target_a.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert resp4.status_code == 404
    finally:
        test_app.dependency_overrides.clear()


def test_dashboard_summary_isolated():
    _, TestingSession, test_app, token_a, token_b, proj_a, proj_b, target_a, target_b, scan_a, scan_b = _setup_isolated_db()

    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()

    test_app.dependency_overrides[get_db] = override
    client = TestClient(test_app)
    try:
        resp_a = client.get("/api/v1/dashboard/summary", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_a.status_code == 200
        data_a = resp_a.json()
        assert data_a["scans"]["total"] == 1
        assert data_a["findings"]["total"] == 1
        assert data_a["findings"]["critical"] == 1
        assert data_a["findings"]["high"] == 0

        resp_b = client.get("/api/v1/dashboard/summary", headers={"Authorization": f"Bearer {token_b}"})
        assert resp_b.status_code == 200
        data_b = resp_b.json()
        assert data_b["scans"]["total"] == 1
        assert data_b["findings"]["total"] == 1
        assert data_b["findings"]["critical"] == 0
        assert data_b["findings"]["high"] == 1
    finally:
        test_app.dependency_overrides.clear()


def test_dashboard_requires_auth():
    _, TestingSession, test_app, token_a, token_b, *_ = _setup_isolated_db()

    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()

    test_app.dependency_overrides[get_db] = override
    client = TestClient(test_app)
    try:
        resp = client.get("/api/v1/dashboard/summary")
        assert resp.status_code == 401
    finally:
        test_app.dependency_overrides.clear()


def test_assets_summary_without_project_isolated():
    _, TestingSession, test_app, token_a, token_b, proj_a, proj_b, target_a, target_b, *_ = _setup_isolated_db()

    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()

    test_app.dependency_overrides[get_db] = override
    client = TestClient(test_app)
    try:
        resp_a = client.get("/api/v1/assets/summary", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_a.status_code == 200
        data_a = resp_a.json()
        assert data_a["total_assets"] == 1

        resp_b = client.get("/api/v1/assets/summary", headers={"Authorization": f"Bearer {token_b}"})
        assert resp_b.status_code == 200
        data_b = resp_b.json()
        assert data_b["total_assets"] == 1

        resp_a_proj = client.get(f"/api/v1/assets/summary?project_id={proj_a.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_a_proj.status_code == 200
        assert resp_a_proj.json()["total_assets"] == 1

        resp_cross = client.get(f"/api/v1/assets/summary?project_id={proj_b.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert resp_cross.status_code == 404
    finally:
        test_app.dependency_overrides.clear()


def test_assets_summary_requires_auth():
    _, TestingSession, test_app, token_a, token_b, *_ = _setup_isolated_db()

    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()

    test_app.dependency_overrides[get_db] = override
    client = TestClient(test_app)
    try:
        resp = client.get("/api/v1/assets/summary")
        assert resp.status_code == 401
    finally:
        test_app.dependency_overrides.clear()

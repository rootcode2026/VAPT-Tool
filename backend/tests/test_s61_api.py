import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import JSON, String, DateTime, Integer, Text, ForeignKey, UniqueConstraint, create_engine
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


# Additional tables required by app services (scan_results, asset_change_events, etc.)
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
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)

    # Org A — primary analyst
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b")
    user_a = User(
        id=str(uuid.uuid4()),
        organization_id=org_a.id,
        email="alice@org-a.test",
        password_hash=hash_password("password"),
        role="admin",
    )
    user_b = User(
        id=str(uuid.uuid4()),
        organization_id=org_b.id,
        email="bob@org-b.test",
        password_hash=hash_password("password"),
        role="admin",
    )
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A1")
    proj_a2 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A2")
    proj_b = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B")
    tgt_a1 = Target(id=str(uuid.uuid4()), project_id=proj_a1.id, value="example.com", target_type="domain")
    tgt_b = Target(id=str(uuid.uuid4()), project_id=proj_b.id, value="other.com", target_type="domain")

    scan_a1 = Scan(id=str(uuid.uuid4()), target_id=tgt_a1.id, profile="web", status="completed", phase="done", risk_score=75, risk_level="high", risk_grade="B")
    scan_b = Scan(id=str(uuid.uuid4()), target_id=tgt_b.id, profile="web", status="completed", phase="done")

    asset_a1 = Asset(id=str(uuid.uuid4()), project_id=proj_a1.id, asset_type="domain", value="example.com", status="active")
    asset_a2 = Asset(id=str(uuid.uuid4()), project_id=proj_a1.id, asset_type="ip", value="8.8.8.8", status="active")
    asset_b = Asset(id=str(uuid.uuid4()), project_id=proj_b.id, asset_type="domain", value="other.com", status="active")

    rel_a = AssetRelationship(id=str(uuid.uuid4()), project_id=proj_a1.id, source_asset_id=asset_a1.id, target_asset_id=asset_a2.id, relationship_type="resolves_to")

    finding_a = Finding(id=str(uuid.uuid4()), scan_id=scan_a1.id, target_id=tgt_a1.id, asset_id=asset_a1.id, scanner="nuclei", title="Critical Vuln", severity="critical", score=90, status="open")
    finding_b = Finding(id=str(uuid.uuid4()), scan_id=scan_b.id, target_id=tgt_b.id, asset_id=asset_b.id, scanner="nuclei", title="Other Vuln", severity="high", score=75, status="open")

    db = Session()
    db.add_all([org_a, org_b, user_a, user_b, proj_a1, proj_a2, proj_b, tgt_a1, tgt_b, scan_a1, scan_b, asset_a1, asset_a2, asset_b, rel_a, finding_a, finding_b])
    db.commit()

    token_a = create_access_token(user_a.id)
    token_b = create_access_token(user_b.id)

    return {
        "engine": engine,
        "Session": Session,
        "org_a": org_a,
        "org_b": org_b,
        "user_a": user_a,
        "user_b": user_b,
        "proj_a1": proj_a1,
        "proj_a2": proj_a2,
        "proj_b": proj_b,
        "tgt_a1": tgt_a1,
        "scan_a1": scan_a1,
        "scan_b": scan_b,
        "asset_a1": asset_a1,
        "asset_a2": asset_a2,
        "asset_b": asset_b,
        "finding_a": finding_a,
        "finding_b": finding_b,
        "token_a": token_a,
        "token_b": token_b,
        "rel_a": rel_a,
    }


def _client_for(session_factory):
    def override():
        s = session_factory()
        try:
            yield s
        finally:
            s.close()

    app.dependency_overrides[get_db] = override
    return TestClient(app)


def test_projects_authenticated_and_isolated():
    ctx = _setup_isolated_db()
    client = _client_for(ctx["Session"])
    try:
        # No auth -> 401
        assert client.get("/api/v1/projects").status_code == 401

        # Authenticated A sees only own 2 projects
        r = client.get("/api/v1/projects", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r.status_code == 200
        ids = {p["id"] for p in r.json()}
        assert ctx["proj_a1"].id in ids and ctx["proj_a2"].id in ids
        assert ctx["proj_b"].id not in ids

        # Valid project detail
        assert client.get(f"/api/v1/projects/{ctx['proj_a1'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 200

        # Invalid project -> 404
        assert client.get(f"/api/v1/projects/{uuid.uuid4()}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # Cross-org project -> 404 (not 200)
        assert client.get(f"/api/v1/projects/{ctx['proj_b'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # Malformed ID -> 404
        assert client.get("/api/v1/projects/not-a-uuid", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_scans_project_isolation_and_pagination():
    ctx = _setup_isolated_db()
    client = _client_for(ctx["Session"])
    try:
        # Create extra scans for pagination: need targets in same project
        # Already have 1 scan in proj_a1
        # List via query param project_id
        r = client.get(f"/api/v1/scans?project_id={ctx['proj_a1'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r.status_code == 200
        body = r.json()
        assert "items" in body and "total" in body
        assert body["total"] == 1
        assert all(item["id"] == ctx["scan_a1"].id for item in body["items"])

        # Project alias route
        r2 = client.get(f"/api/v1/projects/{ctx['proj_a1'].id}/scans?page=1&page_size=1", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r2.status_code == 200
        assert r2.json()["total"] == 1

        # Empty collection for proj_a2 (no scans)
        r3 = client.get(f"/api/v1/projects/{ctx['proj_a2'].id}/scans", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r3.json()["total"] == 0
        assert r3.json()["items"] == []

        # Cross-org -> 404
        assert client.get(f"/api/v1/projects/{ctx['proj_b'].id}/scans", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404
        assert client.get(f"/api/v1/scans?project_id={ctx['proj_b'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # No auth -> 401 (scans protected via main dependencies)
        assert client.get("/api/v1/scans").status_code == 401

        # Scan detail isolation
        assert client.get(f"/api/v1/scans/{ctx['scan_a1'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 200
        assert client.get(f"/api/v1/scans/{ctx['scan_b'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404
        assert client.get(f"/api/v1/scans/{uuid.uuid4()}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # Progress
        assert client.get(f"/api/v1/scans/{ctx['scan_a1'].id}/progress", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 200
        assert client.get(f"/api/v1/scans/{ctx['scan_b'].id}/progress", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # Details
        assert client.get(f"/api/v1/scans/{ctx['scan_a1'].id}/details", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 200
    finally:
        app.dependency_overrides.clear()


def test_assets_isolation_filtering_pagination_search():
    ctx = _setup_isolated_db()
    client = _client_for(ctx["Session"])
    try:
        # List via query param — isolation
        r = client.get(f"/api/v1/assets?project_id={ctx['proj_a1'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r.status_code == 200
        # Backward compat list
        vals = [a["value"] for a in r.json()] if isinstance(r.json(), list) else [a["value"] for a in r.json()["items"]]
        assert "example.com" in vals
        assert "other.com" not in vals

        # Filter asset_type
        r2 = client.get(f"/api/v1/assets?project_id={ctx['proj_a1'].id}&asset_type=domain", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        j2 = r2.json()
        lst2 = j2 if isinstance(j2, list) else j2["items"]
        assert all(a["asset_type"] == "domain" for a in lst2)

        # Search
        r3 = client.get(f"/api/v1/assets?project_id={ctx['proj_a1'].id}&search=example", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        j3 = r3.json()
        lst3 = j3 if isinstance(j3, list) else j3["items"]
        assert any("example.com" == a["value"] for a in lst3)

        # Pagination mode
        r4 = client.get(f"/api/v1/assets?project_id={ctx['proj_a1'].id}&page=1&page_size=1", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r4.status_code == 200
        body = r4.json()
        assert "items" in body and "total" in body and "page" in body
        assert body["total"] == 2
        assert len(body["items"]) == 1

        # Alias via project route
        r5 = client.get(f"/api/v1/projects/{ctx['proj_a1'].id}/assets?page=1&page_size=10", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r5.status_code == 200
        assert r5.json()["total"] == 2

        # Cross-project -> 404 or filtered empty (for query param it should be 404 because we validate)
        assert client.get(f"/api/v1/assets?project_id={ctx['proj_b'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # No auth -> 401
        assert client.get("/api/v1/assets").status_code == 401

        # Asset detail isolation
        assert client.get(f"/api/v1/assets/{ctx['asset_a1'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 200
        assert client.get(f"/api/v1/assets/{ctx['asset_b'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404
        assert client.get(f"/api/v1/assets/{uuid.uuid4()}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # Relationships per asset
        r6 = client.get(f"/api/v1/assets/{ctx['asset_a1'].id}/relationships", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r6.status_code == 200
        assert any(rel["relationship_type"] == "resolves_to" for rel in r6.json())

        # Cross-org relationships -> 404 via asset check
        assert client.get(f"/api/v1/assets/{ctx['asset_b'].id}/relationships", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # Project relationships list
        r7 = client.get(f"/api/v1/assets/relationships?project_id={ctx['proj_a1'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r7.status_code == 200
        assert len(r7.json()) == 1
    finally:
        app.dependency_overrides.clear()


def test_findings_isolation_filtering_pagination():
    ctx = _setup_isolated_db()
    client = _client_for(ctx["Session"])
    try:
        # List with project filter
        r = client.get(f"/api/v1/findings?project_id={ctx['proj_a1'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r.status_code == 200
        lst = r.json() if isinstance(r.json(), list) else r.json()["items"]
        assert any(f["severity"] == "critical" for f in lst)
        assert all(f["id"] != ctx["finding_b"].id for f in lst)

        # Filter severity
        r2 = client.get(f"/api/v1/findings?project_id={ctx['proj_a1'].id}&severity=critical", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        lst2 = r2.json() if isinstance(r2.json(), list) else r2.json()["items"]
        assert all(f["severity"] == "critical" for f in lst2)

        # Filter scanner
        r3 = client.get(f"/api/v1/findings?project_id={ctx['proj_a1'].id}&scanner=nuclei", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        lst3 = r3.json() if isinstance(r3.json(), list) else r3.json()["items"]
        assert len(lst3) >= 1

        # Search
        r4 = client.get(f"/api/v1/findings?project_id={ctx['proj_a1'].id}&search=Critical", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        lst4 = r4.json() if isinstance(r4.json(), list) else r4.json()["items"]
        assert any("Critical" in f["title"] for f in lst4)

        # Pagination
        r5 = client.get(f"/api/v1/findings?project_id={ctx['proj_a1'].id}&page=1&page_size=1", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r5.status_code == 200
        body = r5.json()
        assert body["total"] == 1 and len(body["items"]) == 1

        # Alias via project
        r6 = client.get(f"/api/v1/projects/{ctx['proj_a1'].id}/findings?page=1&page_size=10", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r6.status_code == 200
        assert r6.json()["total"] == 1

        # Cross-project -> 404
        assert client.get(f"/api/v1/findings?project_id={ctx['proj_b'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # No auth -> 401
        assert client.get("/api/v1/findings").status_code == 401

        # Detail isolation
        assert client.get(f"/api/v1/findings/{ctx['finding_a'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 200
        assert client.get(f"/api/v1/findings/{ctx['finding_b'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404
        assert client.get(f"/api/v1/findings/{uuid.uuid4()}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_attack_paths_and_risk_isolation():
    ctx = _setup_isolated_db()
    client = _client_for(ctx["Session"])
    try:
        # Attack paths via query param
        r = client.get(f"/api/v1/assets/attack-paths?project_id={ctx['proj_a1'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r.status_code == 200
        body = r.json()
        assert "paths" in body and "total" in body

        # Alias via project
        r2 = client.get(f"/api/v1/projects/{ctx['proj_a1'].id}/attack-paths", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r2.status_code == 200
        assert r2.json()["total"] == body["total"]

        # Cross-project -> 404
        assert client.get(f"/api/v1/assets/attack-paths?project_id={ctx['proj_b'].id}", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404
        assert client.get(f"/api/v1/projects/{ctx['proj_b'].id}/attack-paths", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # Risk / security summary
        r3 = client.get(f"/api/v1/projects/{ctx['proj_a1'].id}/security-summary", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r3.status_code == 200
        assert "total_assets" in r3.json()

        r4 = client.get(f"/api/v1/projects/{ctx['proj_a1'].id}/risk-summary", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r4.status_code == 200
        assert r4.json()["total_assets"] == r3.json()["total_assets"]

        # Cross-project risk -> 404
        assert client.get(f"/api/v1/projects/{ctx['proj_b'].id}/security-summary", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404

        # No auth
        assert client.get(f"/api/v1/projects/{ctx['proj_a1'].id}/attack-paths").status_code == 401
        assert client.get(f"/api/v1/projects/{ctx['proj_a1'].id}/security-summary").status_code == 401

        # Malformed ID
        assert client.get("/api/v1/projects/not-a-uuid/attack-paths", headers={"Authorization": f"Bearer {ctx['token_a']}"}).status_code == 404
    finally:
        app.dependency_overrides.clear()


def test_empty_collections():
    ctx = _setup_isolated_db()
    client = _client_for(ctx["Session"])
    try:
        # Proj_a2 has no assets/findings/scans
        r_assets = client.get(f"/api/v1/projects/{ctx['proj_a2'].id}/assets", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r_assets.status_code == 200
        # Our alias returns paginated dict with total 0 when page param supplied, else list
        body = r_assets.json()
        if isinstance(body, dict):
            assert body["total"] == 0
        else:
            assert body == []

        r_find = client.get(f"/api/v1/projects/{ctx['proj_a2'].id}/findings", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        b2 = r_find.json()
        if isinstance(b2, dict):
            assert b2["total"] == 0
        else:
            assert b2 == []

        r_scans = client.get(f"/api/v1/projects/{ctx['proj_a2'].id}/scans", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r_scans.json()["total"] == 0

        r_sum = client.get(f"/api/v1/projects/{ctx['proj_a2'].id}/security-summary", headers={"Authorization": f"Bearer {ctx['token_a']}"})
        assert r_sum.json()["total_assets"] == 0
    finally:
        app.dependency_overrides.clear()

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.schemas.finding import FindingResponse


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
    organization_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("organizations.id"),
    )
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id"),
    )
    value: Mapped[str] = mapped_column(String(255))
    target_type: Mapped[str] = mapped_column(String(50))
    is_active: Mapped[bool] = mapped_column(default=True)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("targets.id"),
    )
    profile: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(50), default="queued")
    phase: Mapped[str] = mapped_column(String(50), default="queued")


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "asset_type",
            "value",
            name="uq_assets_project_type_value",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id"),
    )
    first_seen_scan_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("scans.id"),
        nullable=True,
    )
    last_seen_scan_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("scans.id"),
        nullable=True,
    )
    asset_type: Mapped[str] = mapped_column(String(50))
    value: Mapped[str] = mapped_column(String(1024))
    extra_data: Mapped[dict] = mapped_column(
        "metadata",
        JSON,
        default=dict,
    )
    first_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime,
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )


class AssetRelationship(Base):
    __tablename__ = "asset_relationships"
    __table_args__ = (
        UniqueConstraint(
            "project_id",
            "source_asset_id",
            "target_asset_id",
            "relationship_type",
            name="uq_asset_relationships_identity",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("projects.id"),
    )
    source_asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id"),
    )
    target_asset_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("assets.id"),
    )
    relationship_type: Mapped[str] = mapped_column(String(50))
    extra_data: Mapped[dict] = mapped_column(
        "metadata",
        JSON,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id"),
    )
    target_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("targets.id"),
    )
    asset_id: Mapped[str | None] = mapped_column(
        String(36),
        ForeignKey("assets.id"),
        nullable=True,
    )
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
    extra_data: Mapped[dict] = mapped_column(
        "metadata",
        JSON,
        default=dict,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
    )


def _session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    org_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())

    db.add(Organization(id=org_id, name="Org", slug="org"))
    db.add(
        Project(
            id=project_id,
            organization_id=org_id,
            name="Project",
        )
    )
    db.add(
        Target(
            id=target_id,
            project_id=project_id,
            value="internal.test",
            target_type="domain",
        )
    )
    db.add(
        Scan(
            id=scan_id,
            target_id=target_id,
            profile="web",
            status="running",
            phase="analyzing",
        )
    )
    db.commit()

    db.info["ids"] = {
        "project_id": project_id,
        "target_id": target_id,
        "scan_id": scan_id,
    }
    return db


def test_finding_persists_metadata_and_round_trips():
    db = _session()
    ids = db.info["ids"]
    finding_id = str(uuid.uuid4())

    db.add(
        Finding(
            id=finding_id,
            scan_id=ids["scan_id"],
            target_id=ids["target_id"],
            scanner="zap",
            title="CSP Header Not Set",
            severity="medium",
            extra_data={
                "plugin_id": "10038",
                "uri": "https://internal.test/",
                "method": "GET",
            },
        )
    )
    db.commit()

    stored = db.get(Finding, finding_id)
    assert stored.extra_data["plugin_id"] == "10038"
    assert stored.extra_data["uri"] == "https://internal.test/"

    payload = FindingResponse.model_validate(stored).model_dump()
    assert payload["metadata"]["plugin_id"] == "10038"
    assert "extra_data" not in payload
    db.close()


def test_finding_without_metadata_defaults_to_empty_object():
    db = _session()
    ids = db.info["ids"]
    finding_id = str(uuid.uuid4())

    db.add(
        Finding(
            id=finding_id,
            scan_id=ids["scan_id"],
            target_id=ids["target_id"],
            scanner="nmap",
            title="HTTP service exposed",
            severity="low",
            extra_data={},
        )
    )
    db.commit()

    stored = db.get(Finding, finding_id)
    stored.extra_data = stored.extra_data or {}
    db.commit()

    payload = FindingResponse.model_validate(
        db.get(Finding, finding_id)
    ).model_dump()
    assert payload["metadata"] == {}
    db.close()


def test_asset_persists_and_repeated_observation_does_not_duplicate():
    db = _session()
    ids = db.info["ids"]
    first_id = str(uuid.uuid4())

    db.add(
        Asset(
            id=first_id,
            project_id=ids["project_id"],
            first_seen_scan_id=ids["scan_id"],
            last_seen_scan_id=ids["scan_id"],
            asset_type="web_site",
            value="https://internal.test",
            extra_data={"port": 443, "ssl": True},
        )
    )
    db.commit()

    existing = (
        db.query(Asset)
        .filter_by(
            project_id=ids["project_id"],
            asset_type="web_site",
            value="https://internal.test",
        )
        .one()
    )

    existing.last_seen_scan_id = str(uuid.uuid4())
    existing.extra_data = {"port": 443, "ssl": True, "host": "internal.test"}
    db.commit()

    rows = (
        db.query(Asset)
        .filter_by(
            project_id=ids["project_id"],
            asset_type="web_site",
            value="https://internal.test",
        )
        .all()
    )

    assert len(rows) == 1
    assert rows[0].id == first_id
    assert rows[0].extra_data["host"] == "internal.test"
    db.close()


def test_dns_and_subdomain_assets_persist_without_duplicates():
    db = _session()
    ids = db.info["ids"]
    first_id = str(uuid.uuid4())

    db.add(
        Asset(
            id=first_id,
            project_id=ids["project_id"],
            first_seen_scan_id=ids["scan_id"],
            last_seen_scan_id=ids["scan_id"],
            asset_type="subdomain",
            value="api.internal.test",
            extra_data={"parent": "internal.test", "source": "cname"},
        )
    )
    db.commit()

    existing = (
        db.query(Asset)
        .filter_by(
            project_id=ids["project_id"],
            asset_type="subdomain",
            value="api.internal.test",
        )
        .one()
    )
    existing.extra_data = {
        "source": "crtsh",
        "resolved_ip": "10.0.0.9",
    }
    db.commit()

    rows = (
        db.query(Asset)
        .filter_by(
            project_id=ids["project_id"],
            asset_type="subdomain",
            value="api.internal.test",
        )
        .all()
    )

    assert len(rows) == 1
    assert rows[0].id == first_id
    assert rows[0].extra_data["source"] == "crtsh"
    assert rows[0].extra_data["resolved_ip"] == "10.0.0.9"
    db.close()


def test_asset_first_seen_preserved_and_last_seen_updates():
    db = _session()
    ids = db.info["ids"]
    first_id = str(uuid.uuid4())
    first_seen = datetime(2026, 9, 1, 12, 0, 0)
    second_seen = datetime(2026, 9, 3, 12, 0, 0)

    db.add(
        Asset(
            id=first_id,
            project_id=ids["project_id"],
            first_seen_scan_id=ids["scan_id"],
            last_seen_scan_id=ids["scan_id"],
            asset_type="domain",
            value="internal.test",
            extra_data={"sources": ["dns"]},
            first_seen_at=first_seen,
            last_seen_at=first_seen,
        )
    )
    db.commit()

    stored = db.get(Asset, first_id)
    stored.last_seen_scan_id = str(uuid.uuid4())
    stored.last_seen_at = second_seen
    stored.extra_data = {
        "sources": ["dns", "subdomain"],
        "resolver": "10.0.0.53:53",
    }
    db.commit()

    stored = db.get(Asset, first_id)
    assert stored.first_seen_at == first_seen
    assert stored.last_seen_at == second_seen
    assert stored.extra_data["sources"] == ["dns", "subdomain"]
    db.close()


def test_asset_relationship_round_trip_and_dedup_identity():
    db = _session()
    ids = db.info["ids"]
    domain_id = str(uuid.uuid4())
    sub_id = str(uuid.uuid4())
    rel_id = str(uuid.uuid4())

    db.add(
        Asset(
            id=domain_id,
            project_id=ids["project_id"],
            asset_type="domain",
            value="internal.test",
            extra_data={"sources": ["subdomain"]},
        )
    )
    db.add(
        Asset(
            id=sub_id,
            project_id=ids["project_id"],
            asset_type="subdomain",
            value="api.internal.test",
            extra_data={"sources": ["subdomain"]},
        )
    )
    db.add(
        AssetRelationship(
            id=rel_id,
            project_id=ids["project_id"],
            source_asset_id=domain_id,
            target_asset_id=sub_id,
            relationship_type="contains",
            extra_data={"scanner": "subdomain"},
        )
    )
    db.commit()

    stored = (
        db.query(AssetRelationship)
        .filter_by(
            project_id=ids["project_id"],
            source_asset_id=domain_id,
            target_asset_id=sub_id,
            relationship_type="contains",
        )
        .one()
    )
    stored.extra_data = {"scanner": "subdomain", "input": "internal.test"}
    db.commit()

    rows = (
        db.query(AssetRelationship)
        .filter_by(
            project_id=ids["project_id"],
            source_asset_id=domain_id,
            target_asset_id=sub_id,
            relationship_type="contains",
        )
        .all()
    )
    assert len(rows) == 1
    assert rows[0].id == rel_id
    assert rows[0].extra_data["input"] == "internal.test"
    db.close()


def test_relationship_created_at_stable_and_metadata_merges():
    db = _session()
    ids = db.info["ids"]
    domain_id = str(uuid.uuid4())
    ip_id = str(uuid.uuid4())
    rel_id = str(uuid.uuid4())
    first_seen = datetime(2026, 9, 1, 12, 0, 0)

    db.add(
        Asset(
            id=domain_id,
            project_id=ids["project_id"],
            asset_type="domain",
            value="internal.test",
            extra_data={},
        )
    )
    db.add(
        Asset(
            id=ip_id,
            project_id=ids["project_id"],
            asset_type="ip",
            value="10.0.0.8",
            extra_data={},
        )
    )
    db.add(
        AssetRelationship(
            id=rel_id,
            project_id=ids["project_id"],
            source_asset_id=domain_id,
            target_asset_id=ip_id,
            relationship_type="resolves_to",
            extra_data={
                "sources": ["dns"],
                "confidence": "high",
                "evidence": {"record_type": "A"},
            },
            created_at=first_seen,
            updated_at=first_seen,
        )
    )
    db.commit()

    stored = db.get(AssetRelationship, rel_id)
    created = stored.created_at
    stored.extra_data = {
        "sources": ["dns", "subdomain"],
        "confidence": "high",
        "evidence": {"record_type": "A", "kind": "resolved_ip"},
    }
    stored.updated_at = datetime(2026, 9, 3, 12, 0, 0)
    db.commit()

    stored = db.get(AssetRelationship, rel_id)
    assert stored.created_at == created
    assert stored.updated_at != created
    assert stored.extra_data["sources"] == ["dns", "subdomain"]
    db.close()

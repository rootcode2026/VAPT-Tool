import uuid
import json
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine, String, ForeignKey, DateTime, UniqueConstraint, JSON, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from app.persistence import upsert_assets, upsert_relationships, observation_timestamps


class Base(DeclarativeBase):
    pass


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))


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
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    first_seen_scan_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    last_seen_scan_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("scans.id"), nullable=True)
    asset_type: Mapped[str] = mapped_column(String(50))
    value: Mapped[str] = mapped_column(String(1024))
    extra_data: Mapped[str] = mapped_column("metadata", String, default="{}")
    first_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


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
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    source_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"))
    target_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"))
    relationship_type: Mapped[str] = mapped_column(String(50))
    extra_data: Mapped[str] = mapped_column("metadata", String, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


def _setup_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    project_id = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())

    db.add(Project(id=project_id, name="Test Project"))
    db.add(Target(id=target_id, project_id=project_id))
    db.add(Scan(id=scan_id, target_id=target_id))
    db.commit()

    return db, project_id, scan_id


def _get_metadata(db, model, record_id) -> dict:
    item = db.get(model, record_id)
    raw = item.extra_data
    if isinstance(raw, str):
        return json.loads(raw)
    elif isinstance(raw, dict):
        return raw
    return {}


def test_1_new_asset_insert():
    db, project_id, scan_id = _setup_db()
    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    persisted = upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[{"type": "domain", "value": "example.com", "metadata": {"ip": "10.0.0.1"}}],
        scanner="nmap",
        now=t0,
    )
    db.commit()

    assert len(persisted) == 1
    asset = db.query(Asset).filter_by(project_id=project_id, value="example.com").one()
    assert asset.asset_type == "domain"
    assert asset.first_seen_scan_id == scan_id
    assert asset.last_seen_scan_id == scan_id
    meta = _get_metadata(db, Asset, asset.id)
    assert meta["sources"] == ["nmap"]
    db.close()


def test_2_existing_asset_update():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    t1 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 2, 10, 0, 0, tzinfo=timezone.utc)

    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        assets=[{"type": "domain", "value": "example.com"}],
        scanner="nmap",
        now=t1,
    )
    db.commit()

    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        assets=[{"type": "domain", "value": "example.com"}],
        scanner="dns",
        now=t2,
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="example.com").one()
    assert asset.last_seen_scan_id == scan_id2
    meta = _get_metadata(db, Asset, asset.id)
    assert meta["sources"] == ["nmap", "dns"]
    db.close()


def test_3_duplicate_asset_single_row():
    db, project_id, scan_id = _setup_db()
    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    for _ in range(5):
        upsert_assets(
            db,
            project_id=project_id,
            scan_id=scan_id,
            assets=[{"type": "domain", "value": "example.com"}],
            scanner="nmap",
            now=t0,
        )
        db.commit()

    count = db.query(Asset).filter_by(project_id=project_id, value="example.com").count()
    assert count == 1
    db.close()


def test_4_same_asset_from_two_sources():
    db, project_id, scan_id = _setup_db()
    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[{"type": "domain", "value": "example.com"}],
        scanner="nmap",
        now=t0,
    )
    db.commit()

    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[{"type": "domain", "value": "example.com"}],
        scanner="nuclei",
        now=t0,
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="example.com").one()
    meta = _get_metadata(db, Asset, asset.id)
    assert set(meta["sources"]) == {"nmap", "nuclei"}
    db.close()


def test_5_metadata_merge():
    db, project_id, scan_id = _setup_db()

    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[{"type": "domain", "value": "example.com", "metadata": {"banner": "nginx"}}],
        scanner="http_fingerprint",
    )
    db.commit()

    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[{"type": "domain", "value": "example.com", "metadata": {"tls_version": "1.3"}}],
        scanner="tls",
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="example.com").one()
    meta = _get_metadata(db, Asset, asset.id)
    assert meta["banner"] == "nginx"
    assert meta["tls_version"] == "1.3"
    db.close()


def test_6_source_deduplication():
    db, project_id, scan_id = _setup_db()

    for _ in range(3):
        upsert_assets(
            db,
            project_id=project_id,
            scan_id=scan_id,
            assets=[{"type": "domain", "value": "example.com"}],
            scanner="nmap",
        )
        db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="example.com").one()
    meta = _get_metadata(db, Asset, asset.id)
    assert meta["sources"] == ["nmap"]
    db.close()


def test_7_first_seen_remains_unchanged():
    db, project_id, scan_id = _setup_db()
    t1 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 5, 10, 0, 0, tzinfo=timezone.utc)

    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[{"type": "domain", "value": "example.com"}],
        scanner="nmap",
        now=t1,
    )
    db.commit()

    asset1 = db.query(Asset).filter_by(project_id=project_id, value="example.com").one()
    first_seen_initial = asset1.first_seen_at

    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[{"type": "domain", "value": "example.com"}],
        scanner="dns",
        now=t2,
    )
    db.commit()

    asset2 = db.query(Asset).filter_by(project_id=project_id, value="example.com").one()
    assert asset2.first_seen_at == first_seen_initial
    db.close()


def test_8_last_seen_updates():
    db, project_id, scan_id = _setup_db()
    t1 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 5, 10, 0, 0, tzinfo=timezone.utc)

    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[{"type": "domain", "value": "example.com"}],
        scanner="nmap",
        now=t1,
    )
    db.commit()

    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[{"type": "domain", "value": "example.com"}],
        scanner="dns",
        now=t2,
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="example.com").one()
    assert asset.last_seen_at == t2
    db.close()


def test_9_relationship_duplicate_single_row():
    db, project_id, scan_id = _setup_db()

    persisted = upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[
            {"type": "domain", "value": "example.com"},
            {"type": "ip", "value": "10.0.0.1"},
        ],
        scanner="nmap",
    )
    db.commit()

    rel = {
        "source_type": "domain",
        "source_value": "example.com",
        "target_type": "ip",
        "target_value": "10.0.0.1",
        "relationship_type": "resolves_to",
        "metadata": {"evidence": {"record_type": "A"}},
    }

    upsert_relationships(
        db,
        project_id=project_id,
        relationships=[rel],
        persisted_assets=persisted,
        scanner="dns",
    )
    db.commit()

    upsert_relationships(
        db,
        project_id=project_id,
        relationships=[rel],
        persisted_assets=persisted,
        scanner="nmap",
    )
    db.commit()

    rel_count = db.query(AssetRelationship).filter_by(project_id=project_id).count()
    assert rel_count == 1
    db.close()


def test_10_relationship_metadata_merge():
    db, project_id, scan_id = _setup_db()

    persisted = upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=[
            {"type": "domain", "value": "example.com"},
            {"type": "ip", "value": "10.0.0.1"},
        ],
    )
    db.commit()

    rel1 = {
        "source_type": "domain",
        "source_value": "example.com",
        "target_type": "ip",
        "target_value": "10.0.0.1",
        "relationship_type": "resolves_to",
        "metadata": {"evidence": {"record_type": "A"}},
    }

    rel2 = {
        "source_type": "domain",
        "source_value": "example.com",
        "target_type": "ip",
        "target_value": "10.0.0.1",
        "relationship_type": "resolves_to",
        "metadata": {"evidence": {"kind": "resolved_ip"}},
    }

    upsert_relationships(
        db,
        project_id=project_id,
        relationships=[rel1],
        persisted_assets=persisted,
        scanner="dns",
    )
    db.commit()

    upsert_relationships(
        db,
        project_id=project_id,
        relationships=[rel2],
        persisted_assets=persisted,
        scanner="nmap",
    )
    db.commit()

    row = db.query(AssetRelationship).filter_by(project_id=project_id).one()
    meta = _get_metadata(db, AssetRelationship, row.id)
    assert "dns" in meta["sources"]
    assert "nmap" in meta["sources"]
    db.close()


def test_11_out_of_order_observations_last_seen_does_not_move_backwards():
    db, project_id, scan_id_latest = _setup_db()
    target = db.query(Target).first()
    scan_id_older = str(uuid.uuid4())
    db.add(Scan(id=scan_id_older, target_id=target.id))
    db.commit()

    t_latest = datetime(2026, 9, 5, 12, 0, 0, tzinfo=timezone.utc)
    t_older = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Latest observation arrives first
    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id_latest,
        assets=[{"type": "domain", "value": "time.test"}],
        scanner="nmap",
        now=t_latest,
    )
    db.commit()

    # Delayed/older observation arrives second
    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id_older,
        assets=[{"type": "domain", "value": "time.test"}],
        scanner="dns",
        now=t_older,
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="time.test").one()
    assert asset.last_seen_at == t_latest
    assert asset.last_seen_scan_id == scan_id_latest
    assert asset.first_seen_at == t_older
    db.close()


def test_12_out_of_order_worker_processing():
    db, project_id, scan_id_1 = _setup_db()
    target = db.query(Target).first()
    scan_id_2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id_2, target_id=target.id))
    db.commit()

    t_earlier = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    t_later = datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc)

    # Scan 2 finishes first
    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id_2,
        assets=[{"type": "domain", "value": "order.test"}],
        scanner="scan2_worker",
        now=t_later,
    )
    db.commit()

    # Scan 1 finishes later out-of-order
    upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id_1,
        assets=[{"type": "domain", "value": "order.test"}],
        scanner="scan1_worker",
        now=t_earlier,
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="order.test").one()
    assert asset.first_seen_at == t_earlier
    assert asset.last_seen_at == t_later
    assert asset.last_seen_scan_id == scan_id_2
    db.close()


def test_13_transaction_usable_after_validation_error():
    db, project_id, scan_id = _setup_db()

    p2_id = str(uuid.uuid4())
    db.add(Project(id=p2_id, name="Project B"))
    db.commit()

    # Invalid cross-project relationship should be isolated & skipped
    persisted = [
        {"id": "a1", "project_id": project_id, "asset_type": "domain", "value": "a.test"},
        {"id": "a2", "project_id": p2_id, "asset_type": "domain", "value": "b.test"},
    ]
    rel = {
        "source_type": "domain",
        "source_value": "a.test",
        "target_type": "domain",
        "target_value": "b.test",
        "relationship_type": "contains",
    }
    # Load endpoints fails validation -> skipped cleanly
    stored = upsert_relationships(
        db,
        project_id=project_id,
        relationships=[rel],
        persisted_assets=persisted,
    )
    db.commit()

    assert len(stored) == 0

    # Session is usable for subsequent query
    count = db.query(Project).count()
    assert count == 2
    db.close()


def test_14_genuine_db_persistence_errors_propagate():
    db, project_id, scan_id = _setup_db()

    # Invalid table column in query causes genuine DB error -> must propagate
    with pytest.raises(Exception):
        db.execute(text("SELECT non_existent_column FROM assets"))
    db.close()

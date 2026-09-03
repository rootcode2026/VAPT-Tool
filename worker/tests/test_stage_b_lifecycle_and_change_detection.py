import uuid
import json
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine, String, ForeignKey, DateTime, UniqueConstraint, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from app.persistence import persist_parsed_bundle, upsert_assets
from app.asset_intel.change_detection import (
    compute_asset_lifecycle_status,
    detect_asset_changes,
    persist_change_events,
)


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
    status: Mapped[str] = mapped_column(String(20), default="active")
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


class AssetChangeEvent(Base):
    __tablename__ = "asset_change_events"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "asset_id",
            "change_type",
            name="uq_asset_change_events_idempotency",
        ),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"))
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id"))
    change_type: Mapped[str] = mapped_column(String(50))
    previous_state: Mapped[str | None] = mapped_column(String, nullable=True)
    current_state: Mapped[str | None] = mapped_column(String, nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    extra_data: Mapped[str] = mapped_column("metadata", String, default="{}")


def _setup_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    db = SessionLocal()

    project_id = str(uuid.uuid4())
    target_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())

    db.add(Project(id=project_id, name="Stage B Project"))
    db.add(Target(id=target_id, project_id=project_id))
    db.add(Scan(id=scan_id, target_id=target_id))
    db.commit()

    return db, project_id, scan_id


# ---------------------------------------------------------
# Lifecycle Tests (1-7)
# ---------------------------------------------------------

def test_1_newly_observed_asset_becomes_active():
    db, project_id, scan_id = _setup_db()
    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner="nmap",
        assets=[{"type": "domain", "value": "active.test"}],
        findings=[],
        now=t0,
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="active.test").one()
    assert asset.status == "active"
    db.close()


def test_2_recently_observed_asset_remains_active():
    db, project_id, scan_id = _setup_db()
    t1 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 4, 10, 0, 0, tzinfo=timezone.utc)

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner="nmap",
        assets=[{"type": "domain", "value": "active.test"}],
        findings=[],
        now=t1,
    )
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner="nmap",
        assets=[{"type": "domain", "value": "active.test"}],
        findings=[],
        now=t2,
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="active.test").one()
    assert asset.status == "active"
    db.close()


def test_3_stale_threshold_transition():
    t_last = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_ref = datetime(2026, 9, 9, 10, 0, 0, tzinfo=timezone.utc)  # 8 days later

    status = compute_asset_lifecycle_status(t_last, reference_time=t_ref, stale_days=7, inactive_days=30)
    assert status == "stale"


def test_4_inactive_threshold_transition():
    t_last = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_ref = datetime(2026, 9, 5, 10, 0, 0, tzinfo=timezone.utc)  # 35 days later

    status = compute_asset_lifecycle_status(t_last, reference_time=t_ref, stale_days=7, inactive_days=30)
    assert status == "inactive"


def test_5_inactive_asset_remains_persisted():
    db, project_id, scan_id = _setup_db()
    t1 = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_eval = datetime(2026, 9, 5, 10, 0, 0, tzinfo=timezone.utc)

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner="nmap",
        assets=[{"type": "domain", "value": "persisted.test"}],
        findings=[],
        now=t1,
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="persisted.test").one()
    # Derived status at t_eval is inactive
    computed = compute_asset_lifecycle_status(asset.last_seen_at, reference_time=t_eval)
    assert computed == "inactive"
    assert asset.id is not None  # Physically persisted
    db.close()


def test_6_inactive_asset_reappears():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    t1 = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="nmap",
        assets=[{"type": "domain", "value": "reappear.test"}],
        findings=[],
        now=t1,
    )
    db.commit()

    # Manually set status to inactive simulating passage of time
    asset = db.query(Asset).filter_by(project_id=project_id, value="reappear.test").one()
    asset.status = "inactive"
    db.commit()

    # Re-observed at t2
    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="nmap",
        assets=[{"type": "domain", "value": "reappear.test"}],
        findings=[],
        now=t2,
    )
    db.commit()

    asset_updated = db.query(Asset).filter_by(project_id=project_id, value="reappear.test").one()
    assert asset_updated.status == "active"
    db.close()


def test_7_out_of_order_observation_does_not_corrupt_lifecycle():
    db, project_id, scan_id_latest = _setup_db()
    target = db.query(Target).first()
    scan_id_older = str(uuid.uuid4())
    db.add(Scan(id=scan_id_older, target_id=target.id))
    db.commit()

    t_latest = datetime(2026, 9, 5, 10, 0, 0, tzinfo=timezone.utc)
    t_older = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id_latest,
        scanner="nmap",
        assets=[{"type": "domain", "value": "order.test"}],
        findings=[],
        now=t_latest,
    )
    db.commit()

    # Delayed older scan arrives
    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id_older,
        scanner="nmap",
        assets=[{"type": "domain", "value": "order.test"}],
        findings=[],
        now=t_older,
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="order.test").one()
    assert asset.status == "active"
    assert asset.last_seen_at == t_latest
    db.close()


# ---------------------------------------------------------
# Change Detection Tests (8-20)
# ---------------------------------------------------------

def test_8_new_asset_produces_new_asset_event():
    db, project_id, scan_id = _setup_db()
    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner="nmap",
        assets=[{"type": "domain", "value": "new.test"}],
        findings=[],
        now=t0,
    )
    db.commit()

    events = db.query(AssetChangeEvent).filter_by(project_id=project_id, change_type="new_asset").all()
    assert len(events) == 1
    db.close()


def test_9_identical_observation_produces_no_change_event():
    db, project_id, scan_id = _setup_db()
    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner="nmap",
        assets=[{"type": "domain", "value": "same.test"}],
        findings=[],
        now=t0,
    )
    db.commit()

    count_before = db.query(AssetChangeEvent).count()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner="nmap",
        assets=[{"type": "domain", "value": "same.test"}],
        findings=[],
        now=t0,
    )
    db.commit()

    count_after = db.query(AssetChangeEvent).count()
    assert count_after == count_before
    db.close()


def test_10_ip_change_detected():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="nmap",
        assets=[{"type": "domain", "value": "ipchange.test", "metadata": {"ip": "1.1.1.1"}}],
        findings=[],
    )
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="nmap",
        assets=[{"type": "domain", "value": "ipchange.test", "metadata": {"ip": "2.2.2.2"}}],
        findings=[],
    )
    db.commit()

    event = db.query(AssetChangeEvent).filter_by(project_id=project_id, change_type="ip_changed").one()
    assert event is not None
    db.close()


def test_11_url_change_detected():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="http_fingerprint",
        assets=[{"type": "domain", "value": "urlchange.test", "metadata": {"url": "http://urlchange.test"}}],
        findings=[],
    )
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="http_fingerprint",
        assets=[{"type": "domain", "value": "urlchange.test", "metadata": {"url": "https://urlchange.test"}}],
        findings=[],
    )
    db.commit()

    event = db.query(AssetChangeEvent).filter_by(project_id=project_id, change_type="url_changed").one()
    assert event is not None
    db.close()


def test_12_technology_addition_removal_detected():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="http_fingerprint",
        assets=[{"type": "domain", "value": "tech.test", "metadata": {"technologies": ["nginx"]}}],
        findings=[],
    )
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="http_fingerprint",
        assets=[{"type": "domain", "value": "tech.test", "metadata": {"technologies": ["nginx", "react"]}}],
        findings=[],
    )
    db.commit()

    event = db.query(AssetChangeEvent).filter_by(project_id=project_id, change_type="technology_changed").one()
    assert event is not None
    db.close()


def test_13_port_addition_removal_detected():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="nmap",
        assets=[{"type": "ip", "value": "10.0.0.1", "metadata": {"ports": [80]}}],
        findings=[],
    )
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="nmap",
        assets=[{"type": "ip", "value": "10.0.0.1", "metadata": {"ports": [80, 443]}}],
        findings=[],
    )
    db.commit()

    event = db.query(AssetChangeEvent).filter_by(project_id=project_id, change_type="port_changed").one()
    assert event is not None
    db.close()


def test_14_service_change_detected():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="nmap",
        assets=[{"type": "ip", "value": "10.0.0.2", "metadata": {"service": "http"}}],
        findings=[],
    )
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="nmap",
        assets=[{"type": "ip", "value": "10.0.0.2", "metadata": {"service": "https"}}],
        findings=[],
    )
    db.commit()

    event = db.query(AssetChangeEvent).filter_by(project_id=project_id, change_type="metadata_changed").one()
    assert event is not None
    db.close()


def test_15_dns_relationship_change_detected():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="dns",
        assets=[{"type": "domain", "value": "cname.test", "metadata": {"cname": "target1.test"}}],
        findings=[],
    )
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="dns",
        assets=[{"type": "domain", "value": "cname.test", "metadata": {"cname": "target2.test"}}],
        findings=[],
    )
    db.commit()

    event = db.query(AssetChangeEvent).filter_by(project_id=project_id, change_type="metadata_changed").one()
    assert event is not None
    db.close()


def test_16_meaningful_metadata_change_detected():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="nmap",
        assets=[{"type": "domain", "value": "meta.test", "metadata": {"os": "Linux"}}],
        findings=[],
    )
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="nmap",
        assets=[{"type": "domain", "value": "meta.test", "metadata": {"os": "Ubuntu"}}],
        findings=[],
    )
    db.commit()

    event = db.query(AssetChangeEvent).filter_by(project_id=project_id, change_type="metadata_changed").one()
    assert event is not None
    db.close()


def test_17_ignored_volatile_metadata_does_not_produce_change():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="nmap",
        assets=[{"type": "domain", "value": "volatile.test", "metadata": {"sources": ["nmap"]}}],
        findings=[],
    )
    db.commit()

    count_before = db.query(AssetChangeEvent).count()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="nmap",
        assets=[{"type": "domain", "value": "volatile.test", "metadata": {"sources": ["nmap", "dns"]}}],
        findings=[],
    )
    db.commit()

    count_after = db.query(AssetChangeEvent).count()
    assert count_after == count_before
    db.close()


def test_18_asset_disappearance_detected_only_within_valid_authoritative_scope():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    # Pre-populate existing assets in previous_map
    prev_map = {
        ("domain", "absent.test"): {
            "id": str(uuid.uuid4()),
            "asset_type": "domain",
            "value": "absent.test",
            "metadata": {},
            "status": "active",
        }
    }

    # Nmap scan missing absent.test -> Nmap is not authoritative for domain -> NO disappearance
    events_nmap = detect_asset_changes(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="nmap",
        current_assets=[{"type": "ip", "value": "10.0.0.1"}],
        current_relationships=[],
        previous_assets_map=prev_map,
    )
    disappeared_nmap = [e for e in events_nmap if e["change_type"] == "asset_disappeared"]
    assert len(disappeared_nmap) == 0

    # DNS scan missing absent.test -> DNS is authoritative for domain -> Emits disappearance
    events_dns = detect_asset_changes(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="dns",
        current_assets=[{"type": "domain", "value": "present.test"}],
        current_relationships=[],
        previous_assets_map=prev_map,
    )
    disappeared_dns = [e for e in events_dns if e["change_type"] == "asset_disappeared"]
    assert len(disappeared_dns) == 1
    db.close()


def test_19_reappearance_detected_correctly():
    db, project_id, scan_id = _setup_db()
    prev_id = str(uuid.uuid4())

    prev_map = {
        ("domain", "reappeared.test"): {
            "id": prev_id,
            "asset_type": "domain",
            "value": "reappeared.test",
            "metadata": {},
            "status": "stale",
        }
    }

    events = detect_asset_changes(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner="dns",
        current_assets=[{"type": "domain", "value": "reappeared.test"}],
        current_relationships=[],
        previous_assets_map=prev_map,
    )

    reappeared = [e for e in events if e["change_type"] == "asset_reappeared"]
    assert len(reappeared) == 1
    assert reappeared[0]["asset_id"] == prev_id
    db.close()


def test_20_duplicate_processing_is_idempotent():
    db, project_id, scan_id = _setup_db()
    asset_id = str(uuid.uuid4())

    event = {
        "id": str(uuid.uuid4()),
        "project_id": project_id,
        "asset_id": asset_id,
        "scan_id": scan_id,
        "change_type": "new_asset",
        "previous_state": None,
        "current_state": {"status": "active"},
        "detected_at": datetime.now(timezone.utc),
        "metadata": {},
    }

    persist_change_events(db, [event])
    db.commit()
    persist_change_events(db, [event])
    db.commit()

    count = db.query(AssetChangeEvent).filter_by(scan_id=scan_id, asset_id=asset_id, change_type="new_asset").count()
    assert count == 1
    db.close()


# ---------------------------------------------------------
# Isolation & Integrity Tests (21-24)
# ---------------------------------------------------------

def test_21_project_isolation_for_change_events():
    db, p1_id, scan_id1 = _setup_db()
    p2_id = str(uuid.uuid4())
    db.add(Project(id=p2_id, name="Project 2"))
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=p1_id,
        scan_id=scan_id1,
        scanner="nmap",
        assets=[{"type": "domain", "value": "p1.test"}],
        findings=[],
    )
    db.commit()

    events_p1 = db.query(AssetChangeEvent).filter_by(project_id=p1_id).all()
    events_p2 = db.query(AssetChangeEvent).filter_by(project_id=p2_id).all()

    assert len(events_p1) >= 1
    assert len(events_p2) == 0
    db.close()


def test_22_change_event_references_correct_entities():
    db, project_id, scan_id = _setup_db()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner="nmap",
        assets=[{"type": "domain", "value": "ref.test"}],
        findings=[],
    )
    db.commit()

    asset = db.query(Asset).filter_by(project_id=project_id, value="ref.test").one()
    event = db.query(AssetChangeEvent).filter_by(project_id=project_id, asset_id=asset.id).one()

    assert event.project_id == project_id
    assert event.scan_id == scan_id
    assert event.asset_id == asset.id
    db.close()


def test_23_previous_and_current_state_preserved_in_jsonb():
    db, project_id, scan_id1 = _setup_db()
    scan_id2 = str(uuid.uuid4())
    db.add(Scan(id=scan_id2, target_id=db.query(Target).first().id))
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id1,
        scanner="nmap",
        assets=[{"type": "ip", "value": "10.0.0.99", "metadata": {"ports": [80]}}],
        findings=[],
    )
    db.commit()

    persist_parsed_bundle(
        db,
        project_id=project_id,
        scan_id=scan_id2,
        scanner="nmap",
        assets=[{"type": "ip", "value": "10.0.0.99", "metadata": {"ports": [80, 443]}}],
        findings=[],
    )
    db.commit()

    event = db.query(AssetChangeEvent).filter_by(project_id=project_id, change_type="port_changed").one()
    prev_st = json.loads(event.previous_state) if isinstance(event.previous_state, str) else event.previous_state
    curr_st = json.loads(event.current_state) if isinstance(event.current_state, str) else event.current_state

    assert prev_st["ports"] == [80]
    assert curr_st["ports"] == [80, 443]
    db.close()


def test_24_repeated_processing_does_not_create_duplicate_events():
    db, project_id, scan_id = _setup_db()

    for _ in range(3):
        persist_parsed_bundle(
            db,
            project_id=project_id,
            scan_id=scan_id,
            scanner="nmap",
            assets=[{"type": "domain", "value": "repeat.test"}],
            findings=[],
        )
        db.commit()

    events = db.query(AssetChangeEvent).filter_by(project_id=project_id, change_type="new_asset").all()
    assert len(events) == 1
    db.close()

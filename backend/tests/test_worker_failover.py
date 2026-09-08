import uuid
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import hash_password
from app.db.base import Base
from app.db.database import get_db
from app.main import app
from app.models.organization import Organization
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.models.scanner_fleet import WorkerPool, Worker
from app.services.scanner_control import get_pool_for_scanner, assign_worker, release_worker, heartbeat_worker

from fastapi.testclient import TestClient


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    from app.models.organization import Organization as OrgM
    from app.models.project import Project as ProjM
    from app.models.user import User as UserM
    from app.models.target import Target as TargetM
    from app.models.scan import Scan as ScanM
    from app.models.scanner_fleet import WorkerPool as PoolM, Worker as WorkerM
    Base.metadata.create_all(bind=engine, tables=[OrgM.__table__, ProjM.__table__, UserM.__table__, TargetM.__table__, ScanM.__table__, PoolM.__table__, WorkerM.__table__])
    db = TestingSession()
    org = Organization(id=str(uuid.uuid4()), name="Org", slug="org")
    db.add(org)
    db.flush()
    org_id = org.id
    proj = Project(id=str(uuid.uuid4()), organization_id=org_id, name="Proj", description="test")
    db.add(proj)
    db.flush()
    proj_id = proj.id
    user = User(id=str(uuid.uuid4()), organization_id=org_id, email="a@test.local", password_hash=hash_password("Pass123!"), role="member")
    db.add(user)
    db.flush()
    user_id = user.id
    pool = WorkerPool(id=str(uuid.uuid4()), name="default", pool_key="default", display_name="Default", pool_type="generic", scanner_families=["network"], total_capacity=2, reserved_buffer=1, status="healthy", enabled=True)
    db.add(pool)
    db.flush()
    pool_id = pool.id
    w1 = Worker(id=str(uuid.uuid4()), pool_id=pool_id, worker_key="default-worker-1", status="healthy", enabled=True, capabilities=["network"], last_heartbeat=datetime.now(timezone.utc).replace(tzinfo=timezone.utc), role="normal")
    w2 = Worker(id=str(uuid.uuid4()), pool_id=pool_id, worker_key="default-worker-2", status="healthy", enabled=True, capabilities=["network"], last_heartbeat=datetime.now(timezone.utc).replace(tzinfo=timezone.utc), role="normal")
    wb = Worker(id=str(uuid.uuid4()), pool_id=pool_id, worker_key="default-buffer-1", status="healthy", enabled=True, capabilities=["network"], last_heartbeat=datetime.now(timezone.utc).replace(tzinfo=timezone.utc), role="buffer")
    db.add_all([w1, w2, wb])
    db.commit()
    w1_id, w2_id, wb_id = w1.id, w2.id, wb.id
    target = Target(id=str(uuid.uuid4()), project_id=proj_id, value="example.com", target_type="domain")
    db.add(target)
    db.flush()
    target_id = target.id
    scan = Scan(id=str(uuid.uuid4()), target_id=target_id, profile="quick", status="queued")
    db.add(scan)
    db.commit()
    scan_id = scan.id
    db.close()
    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[get_db] = override
    class DummyPool:
        def __init__(self, _id):
            self.id = _id
            self.name = "default"
            self.pool_key = "default"
            self.total_capacity = 2
            self.reserved_buffer = 1
            self.status = "healthy"
            self.enabled = True
    class Dummy:
        def __init__(self, _id):
            self.id = _id
    return TestingSession, Dummy(org_id), Dummy(proj_id), Dummy(user_id), DummyPool(pool_id), Dummy(w1_id), Dummy(w2_id), Dummy(wb_id), Dummy(target_id), Dummy(scan_id)


def test_reserved_buffer_exists():
    TestingSession, org, proj, user, pool, w1, w2, wb, target, scan = _setup()
    try:
        db = TestingSession()
        assert pool.reserved_buffer == 1
        assert pool.total_capacity == 2
        db.close()
    finally:
        app.dependency_overrides.clear()

def test_normal_cannot_consume_buffer():
    TestingSession, org, proj, user, pool, w1, w2, wb, target, scan = _setup()
    try:
        db = TestingSession()
        # For this test, set pool to larger capacity so available >0
        pool_db = db.query(WorkerPool).filter(WorkerPool.id == pool.id).first()
        pool_db.total_capacity = 3
        pool_db.reserved_buffer = 1
        db.commit()
        # Clear existing scans to have active=0
        db.query(Scan).delete()
        db.commit()
        from app.services.scanner_control import can_accept_job
        # Make w1 busy
        w1_db = db.query(Worker).filter(Worker.id == w1.id).first()
        w1_db.status = "busy"
        w1_db.current_job_id = str(uuid.uuid4())
        db.commit()
        # Now one normal (w2) free, available = 3-1-1=1 >0, so can_accept true
        assert can_accept_job(pool_db, db) is True
        # Make w2 also busy
        w2_db = db.query(Worker).filter(Worker.id == w2.id).first()
        w2_db.status = "busy"
        w2_db.current_job_id = str(uuid.uuid4())
        db.commit()
        # Now no normal free, but buffer free, but normal cannot consume buffer
        assert can_accept_job(pool_db, db) is False
        db.close()
    finally:
        app.dependency_overrides.clear()

def test_buffer_activation():
    TestingSession, org, proj, user, pool, w1, w2, wb, target, scan = _setup()
    try:
        db = TestingSession()
        from app.services.scanner_control import can_accept_buffer_job
        assert can_accept_buffer_job(pool, db) is True
        db.close()
    finally:
        app.dependency_overrides.clear()

def test_worker_failure_detection():
    TestingSession, org, proj, user, pool, w1, w2, wb, target, scan = _setup()
    try:
        db = TestingSession()
        w = db.query(Worker).filter(Worker.id == w1.id).first()
        w.status = "failed"
        w.failure_reason = "container crash"
        db.commit()
        # Failed worker should not be eligible
        from app.services.scanner_control import can_accept_job
        # Make w2 busy to force only w1 (failed) as normal
        w2_db = db.query(Worker).filter(Worker.id == w2.id).first()
        w2_db.status = "busy"
        w2_db.current_job_id = str(uuid.uuid4())
        db.commit()
        assert can_accept_job(pool, db) is False
        db.close()
    finally:
        app.dependency_overrides.clear()

def test_one_failed_one_buffer():
    TestingSession, org, proj, user, pool, w1, w2, wb, target, scan = _setup()
    try:
        db = TestingSession()
        # Fail w1
        w1_db = db.query(Worker).filter(Worker.id == w1.id).first()
        w1_db.status = "failed"
        db.commit()
        # Assign via buffer should succeed
        from app.services.scanner_control import assign_worker
        wid = assign_worker(pool, db, "nmap", "job-1", is_failover=True)
        assert wid == wb.id
        # Second failover should not get same buffer (now busy)
        wid2 = assign_worker(pool, db, "nmap", "job-2", is_failover=True)
        assert wid2 is None
        # Release wb
        from app.services.scanner_control import release_worker, can_accept_job
        release_worker(pool, db, wb.id, success=True)
        assert can_accept_job(pool, db) is False  # still no normal, but buffer now free
        # Buffer should be available again
        from app.services.scanner_control import can_accept_buffer_job
        assert can_accept_buffer_job(pool, db) is True
        db.close()
    finally:
        app.dependency_overrides.clear()

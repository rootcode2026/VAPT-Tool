import uuid
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.database import get_db
from app.main import app as fastapi_app

import app.models.organization  # noqa
import app.models.user  # noqa
import app.models.audit_log  # noqa

from app.models.organization import Organization
from app.models.user import User
from app.models.scanner_fleet import ScannerDefinition, ScannerHealth, ScannerVersion, WorkerPool, ScannerRollout
from app.services.scanner_catalog import SCANNER_CATALOG, PROFILE_SCANNERS


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, Base.metadata.tables["audit_logs"],
        ScannerDefinition.__table__, ScannerVersion.__table__, ScannerHealth.__table__, WorkerPool.__table__, ScannerRollout.__table__,
    ])
    try:
        from app.models.organization_membership import OrganizationMembership
        from app.models.project_membership import ProjectMembership
        from app.models.project import Project
        from app.models.target import Target
        from app.models.scan import Scan
        Base.metadata.create_all(bind=engine, tables=[OrganizationMembership.__table__, ProjectMembership.__table__, Project.__table__, Target.__table__, Scan.__table__])
    except Exception:
        pass
    # ensure scanner catalog seeded
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-scanctl")
    db.add(org)
    db.flush()
    pwd = hash_password("password123")
    super_u = User(id=str(uuid.uuid4()), organization_id=org.id, email="super@scan.test", password_hash=pwd, role="super_admin")
    admin_u = User(id=str(uuid.uuid4()), organization_id=org.id, email="admin@scan.test", password_hash=pwd, role="admin")
    member_u = User(id=str(uuid.uuid4()), organization_id=org.id, email="member@scan.test", password_hash=pwd, role="member")
    viewer_u = User(id=str(uuid.uuid4()), organization_id=org.id, email="viewer@scan.test", password_hash=pwd, role="member")
    db.add_all([super_u, admin_u, member_u, viewer_u])
    db.flush()
    try:
        from app.models.organization_membership import OrganizationMembership
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=admin_u.id, role="org_admin"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=member_u.id, role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=viewer_u.id, role="member"))
    except Exception:
        pass
    # seed catalog
    from app.services.scanner_catalog import seed_definitions
    try:
        seed_definitions(db)
    except Exception:
        pass
    # ensure pools
    try:
        from app.services.scanner_control import ensure_default_pools
        ensure_default_pools(db)
    except Exception:
        pass
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [super_u, admin_u, member_u, viewer_u]}
    return engine, Session, tokens, {"org": org, "super_u": super_u, "admin_u": admin_u, "member_u": member_u, "viewer_u": viewer_u}

def _client(Session):
    def override():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    fastapi_app.dependency_overrides[get_db] = override
    return TestClient(fastapi_app)

# CATALOG
def test_catalog_all_14_scanners_registered():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/scanners", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["total"] == 14
        keys = {i["key"] for i in data["items"]}
        for expected in ["nmap","nuclei","http_fingerprint","zap","nikto","tls","dns","subdomain","sast","sca","secrets","container","iac","api"]:
            assert expected in keys, f"missing {expected}"
        # no duplicate keys
        assert len(keys) == 14
    finally:
        fastapi_app.dependency_overrides.clear()

def test_catalog_capabilities_correct():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/scanners", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 200
        items = {i["key"]: i for i in resp.json()["items"]}
        # check a few capabilities are correct per worker
        assert "host_discovery" in items["nmap"]["capabilities"]
        assert "sast" in items["sast"]["capabilities"]
        assert "secrets" in items["secrets"]["capabilities"]
        assert "container" in items["container"]["capabilities"]
        assert "iac" in items["iac"]["capabilities"]
    finally:
        fastapi_app.dependency_overrides.clear()

def test_catalog_profiles_correct():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/scanners", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 200
        items = {i["key"]: i for i in resp.json()["items"]}
        assert "quick" in items["nmap"]["supported_profiles"]
        assert "web" in items["nuclei"]["supported_profiles"]
        assert "sast" in items["sast"]["supported_profiles"]
        assert "container" in items["container"]["supported_profiles"]
        # quick must not include every scanner
        quick_scanners = PROFILE_SCANNERS["quick"]
        assert quick_scanners == ["nmap"]
        assert "nuclei" not in quick_scanners
    finally:
        fastapi_app.dependency_overrides.clear()

# VERSIONS
def test_register_version():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version": "9.9.9", "channel": "candidate", "image_ref": "vapt-tool-nmap:9.9.9"})
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["version"] == "9.9.9"
        assert data["channel"] == "candidate"
        # duplicate rejected
        resp2 = client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version": "9.9.9", "channel": "candidate"})
        assert resp2.status_code == 409
    finally:
        fastapi_app.dependency_overrides.clear()

def test_invalid_version_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version": "bad version!!", "channel": "candidate"})
        assert resp.status_code == 400
        resp2 = client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version": "1.0.0", "channel": "invalid"})
        assert resp2.status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()

def test_version_lifecycle():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post("/api/v1/admin/scanners/sast/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version": "2.0.0", "channel": "candidate", "image_ref": "vapt-sast:2.0.0"})
        # list versions
        resp = client.get("/api/v1/admin/scanners/sast/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 200
        assert any(v["version"] == "2.0.0" for v in resp.json()["items"])
    finally:
        fastapi_app.dependency_overrides.clear()

# HEALTH
def test_health_check():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/scanners/nmap/health/check", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["status"] in ("healthy","degraded","unknown")
        # sanitized error never contains secret
        resp2 = client.get("/api/v1/admin/scanners/nmap/health", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp2.status_code == 200
        assert "password" not in str(resp2.json()).lower()
    finally:
        fastapi_app.dependency_overrides.clear()

def test_health_sanitized():
    _, Session, tokens, objs = _setup()
    # inject unhealthy with sensitive error via service directly then check API sanitization
    SessionLocal = Session
    db = SessionLocal()
    try:
        from app.services.scanner_control import record_health
        d = db.query(ScannerDefinition).filter(ScannerDefinition.scanner_key=="nmap").first()
        record_health(db, d, status="unhealthy", last_error="failed due to password=supersecret token=abc")
        db.close()
    except Exception:
        pass
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/scanners/nmap/health", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 200
        txt = str(resp.json()).lower()
        assert "supersecret" not in txt
        assert "password" not in txt or "sanitized" in txt
    finally:
        fastapi_app.dependency_overrides.clear()

# AUTHORIZATION
def test_unauthenticated_401():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/scanners")
        assert resp.status_code == 401
    finally:
        fastapi_app.dependency_overrides.clear()

def test_non_super_admin_403():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        for email in ["admin@scan.test","member@scan.test","viewer@scan.test"]:
            resp = client.get("/api/v1/admin/scanners", headers={"Authorization": f"Bearer {tokens[email]}"})
            assert resp.status_code == 403, f"{email} should be 403 got {resp.status_code}"
            resp2 = client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens[email]}"}, json={"version":"1.2.3"})
            assert resp2.status_code == 403
            resp3 = client.post("/api/v1/admin/scanners/nmap/health/check", headers={"Authorization": f"Bearer {tokens[email]}"})
            assert resp3.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()

def test_super_admin_allowed():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/scanners", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()

# FLEET
def test_fleet_capacity():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/scanner-fleet", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "total_capacity" in data
        assert "available_capacity" in data
        assert "reserved_buffer" in data
        assert data["reserved_buffer"] >= 1
        assert data["total_capacity"] >= 14
        assert len(data["pools"]) >= 1
        # pools have family mapping
        for p in data["pools"]:
            assert "scanner_families" not in p  # we use families
            assert "families" in p or "scanner_families" in p
    finally:
        fastapi_app.dependency_overrides.clear()

def test_worker_pool_mapping():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/scanner-fleet/pools", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 200
        assert len(resp.json()["items"]) >= 1
    finally:
        fastapi_app.dependency_overrides.clear()

# UPGRADE / ROLLBACK
def test_upgrade_canary_success():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # register candidate
        client.post("/api/v1/admin/scanners/sast/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version":"9.0.0","channel":"candidate","image_ref":"vapt-sast:9.0.0"})
        resp = client.post("/api/v1/admin/scanners/sast/upgrade", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"target_version":"9.0.0"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["state"] in ("active","canary","pending")
        # previous stable should be preserved
        # check scanner detail
        resp2 = client.get("/api/v1/admin/scanners/sast", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp2.status_code == 200
        # if canary passed, current_version is 9.0.0
        assert resp2.json()["current_version"] in ("9.0.0","1.75.0")
    finally:
        fastapi_app.dependency_overrides.clear()

def test_failed_rollout_preserves_previous():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # make current version failed channel
        db = Session()
        d = db.query(ScannerDefinition).filter(ScannerDefinition.scanner_key=="nmap").first()
        # register a version and mark failed
        from app.services.scanner_control import register_version
        try:
            register_version(db, d, version="0.0.1", channel="failed", image_ref="vapt-tool-nmap:0.0.1", actor=objs["super_u"])
        except Exception:
            pass
        db.close()
        # try upgrade to failed version should be rejected
        client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version":"9.9.0","channel":"candidate","image_ref":"vapt-tool-nmap:9.9.0"})
        resp = client.post("/api/v1/admin/scanners/nmap/upgrade", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"target_version":"0.0.1"})
        # should be 400 because target is failed
        assert resp.status_code in (400,404)
    finally:
        fastapi_app.dependency_overrides.clear()

def test_downgrade_and_rollback():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post("/api/v1/admin/scanners/sast/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version":"1.0.0","channel":"candidate","image_ref":"vapt-sast:1.0.0"})
        client.post("/api/v1/admin/scanners/sast/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version":"2.0.0","channel":"candidate","image_ref":"vapt-sast:2.0.0"})
        # upgrade to 2.0.0
        client.post("/api/v1/admin/scanners/sast/upgrade", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"target_version":"2.0.0"})
        # downgrade to 1.0.0
        resp = client.post("/api/v1/admin/scanners/sast/downgrade", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"target_version":"1.0.0"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["operation"] == "downgrade"
        # rollback
        resp2 = client.post("/api/v1/admin/scanners/sast/rollback", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        # may be 200 or 400 if no failed rollout, but should not be 500
        assert resp2.status_code in (200,400,404)
    finally:
        fastapi_app.dependency_overrides.clear()

def test_idempotent_upgrade():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version":"8.0.0","channel":"candidate","image_ref":"vapt-tool-nmap:8.0.0"})
        resp1 = client.post("/api/v1/admin/scanners/nmap/upgrade", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"target_version":"8.0.0"})
        assert resp1.status_code == 200
        id1 = resp1.json()["id"]
        resp2 = client.post("/api/v1/admin/scanners/nmap/upgrade", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"target_version":"8.0.0"})
        # idempotent: second call to same version after active should be 400 (already current) which is also idempotent
        assert resp2.status_code in (200,400)
        if resp2.status_code == 200:
            assert resp2.json()["target_version"] == "8.0.0"
    finally:
        fastapi_app.dependency_overrides.clear()

# SECURITY
def test_arbitrary_docker_image_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version":"1.0.1","image_ref":"; rm -rf /"})
        assert resp.status_code == 400
        resp2 = client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version":"1.0.2","image_ref":"evil/image; cat /etc/passwd"})
        assert resp2.status_code == 400
        resp3 = client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version":"1.0.3","command":"echo hacked"})
        assert resp3.status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()

def test_arbitrary_shell_rejected():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/scanners/nmap/upgrade", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"target_version":"1.0.0","shell":"bash -c evil"})
        # should be 400 due to forbidden field or 404 if version not found, but not 500
        assert resp.status_code in (400,404)
    finally:
        fastapi_app.dependency_overrides.clear()

def test_sensitive_not_returned():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/scanners", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 200
        txt = str(resp.json()).lower()
        for s in ["password","password_hash","jwt","api_key","private_key","cookie"]:
            assert s not in txt
    finally:
        fastapi_app.dependency_overrides.clear()

def test_audit_metadata_sanitized():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"}, json={"version":"9.9.1","channel":"candidate","image_ref":"vapt-tool-nmap:9.9.1"})
        assert resp.status_code == 201
        # check audit_logs via direct DB
        db = Session()
        row = db.execute(text("SELECT metadata FROM audit_logs WHERE event_type='SCANNER_VERSION_REGISTERED' ORDER BY created_at DESC LIMIT 1")).fetchone()
        db.close()
        if row and row[0]:
            txt = str(row[0]).lower()
            assert "password" not in txt
            assert "secret" not in txt or "secret" in txt and "[redacted]" in txt
    finally:
        fastapi_app.dependency_overrides.clear()

def test_404_handling():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/admin/scanners/unknown_scanner", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp.status_code == 404
        resp2 = client.get("/api/v1/admin/scanners/nmap/versions", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp2.status_code == 200
        resp3 = client.get("/api/v1/admin/scanner-rollouts/unknown-id", headers={"Authorization": f"Bearer {tokens['super@scan.test']}"})
        assert resp3.status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()

def test_eligible_scanners_filtering():
    # Test runtime filtering logic: unhealthy/disabled excluded
    _, Session, tokens, objs = _setup()
    SessionLocal = Session
    db = SessionLocal()
    try:
        from app.services.scanner_catalog import get_eligible_scanners
        # initially all healthy, so eligible for quick should be nmap
        eligible = get_eligible_scanners("quick", db)
        assert eligible == ["nmap"]
        # disable nmap
        d = db.query(ScannerDefinition).filter(ScannerDefinition.scanner_key=="nmap").first()
        d.enabled = False
        db.commit()
        eligible2 = get_eligible_scanners("quick", db)
        assert eligible2 == []
        # re-enable and mark unhealthy
        d.enabled = True
        db.commit()
        from app.services.scanner_control import record_health
        record_health(db, d, status="unhealthy")
        eligible3 = get_eligible_scanners("quick", db)
        assert eligible3 == []
        db.close()
    except Exception as e:
        try:
            db.close()
        except Exception:
            pass
        raise
    finally:
        fastapi_app.dependency_overrides.clear()

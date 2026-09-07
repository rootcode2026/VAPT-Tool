import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.database import get_db
from app.main import app
from app.models.organization import Organization
from app.models.user import User
from app.services.scanner_catalog import SCANNER_CATALOG, get_catalog, get_scanner_entry, DOCUMENTED_STABLE_VERSIONS
from fastapi.testclient import TestClient
from sqlalchemy import text


def _client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine, tables=[Organization.__table__, User.__table__])
    db = TestingSession()
    org = Organization(id="org-1", name="Org", slug="org")
    db.add(org)
    db.flush()
    user = User(id="user-1", organization_id=org.id, email="a@test.local", password_hash=hash_password("Pass123!"), role="member")
    db.add(user)
    db.commit()
    user_id = user.id
    db.close()
    def override():
        s = TestingSession()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[get_db] = override
    class Dummy:
        def __init__(self, _id):
            self.id = _id
    return TestClient(app), Dummy(user_id)


def test_all_scanners_registered():
    catalog = get_catalog()
    assert len(catalog) == 15
    keys = {s["key"] for s in catalog}
    assert "nmap" in keys
    assert "nuclei" in keys
    assert "sast" in keys
    assert "sqlmap" in keys


def test_stable_ids():
    for entry in SCANNER_CATALOG:
        assert entry["key"] in ("nmap", "nuclei", "http_fingerprint", "zap", "nikto", "tls", "dns", "subdomain", "sast", "sca", "secrets", "container", "iac", "api", "sqlmap")


def test_metadata_available():
    for entry in SCANNER_CATALOG:
        assert "name" in entry
        assert "category" in entry
        assert "family" in entry
        assert "capabilities" in entry
        assert "profiles" in entry
        assert "requires_workspace" in entry


def test_duplicate_rejected():
    # Use catalog duplicate check via DB constraint
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app.db.base import Base
    from app.models.scanner_fleet import ScannerDefinition

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine, tables=[ScannerDefinition.__table__])
    db = TestingSession()
    db.add(ScannerDefinition(scanner_key="nmap", display_name="Nmap", category="recon", family="network", enabled=True, current_version="1.0", capabilities=[], supported_profiles=[], requires_workspace=False, execution_type="docker", timeout_seconds=300, default_image="nmap"))
    db.commit()
    # Duplicate should raise IntegrityError on commit
    db.add(ScannerDefinition(scanner_key="nmap", display_name="Nmap2", category="recon", family="network", enabled=True, current_version="1.0", capabilities=[], supported_profiles=[], requires_workspace=False, execution_type="docker", timeout_seconds=300, default_image="nmap"))
    with pytest.raises(Exception):
        db.commit()
    db.close()


def test_unknown_rejected():
    from app.services.scanner_catalog import get_scanner_entry
    assert get_scanner_entry("unknown_scanner_xyz") is None


def test_enabled_excluded():
    # Use DB-backed is_eligible
    from app.services.scanner_catalog import get_eligible_scanners
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app.db.base import Base
    from app.models.scanner_fleet import ScannerDefinition

    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    TestingSession = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine, tables=[ScannerDefinition.__table__])
    db = TestingSession()
    # Seed one disabled
    db.add(ScannerDefinition(scanner_key="nmap", display_name="Nmap", category="recon", family="network", enabled=False, current_version="7.95", capabilities=[], supported_profiles=["quick"], requires_workspace=False, execution_type="docker", timeout_seconds=300, default_image="vapt-tool-nmap"))
    db.commit()
    eligible = get_eligible_scanners("quick", db)
    # nmap should be excluded
    assert "nmap" not in (eligible or [])
    db.close()


def test_api_requires_auth():
    client, _ = _client()
    try:
        r = client.get("/api/v1/scanners")
        assert r.status_code == 401
    finally:
        app.dependency_overrides.clear()


def test_api_returns_scanners_when_authed():
    client, user = _client()
    try:
        token = create_access_token(user.id)
        r = client.get("/api/v1/scanners", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body, list)
        assert len(body) >= 14
        assert any(s["name"] == "nmap" for s in body)
    finally:
        app.dependency_overrides.clear()

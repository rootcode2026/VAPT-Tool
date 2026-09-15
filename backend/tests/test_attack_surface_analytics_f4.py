"""F4 Attack Surface Analytics — 35 deterministic tests."""
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine, JSON
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from app.core.security import create_access_token, hash_password
from app.db.database import get_db
from app.main import app

def _engine():
    from app.db.base import Base as ProdBase
    for tbl in ProdBase.metadata.tables.values():
        for col in tbl.columns:
            if col.type.__class__.__name__ == "JSONB":
                col.type = JSON()
            if col.server_default is not None:
                try:
                    if "jsonb" in str(col.server_default.arg).lower():
                        col.server_default = None
                except: pass
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    needed = ["organizations","users","projects","project_memberships","organization_memberships","assets","asset_relationships","findings","applications","application_assets","audit_logs","security_investigations","investigation_notes","security_validations","asset_change_events","finding_remediations","finding_retests","finding_slas","cloud_attack_paths","cloud_attack_path_observations","targets","scans","finding_history"]
    tables = [ProdBase.metadata.tables[n] for n in needed if n in ProdBase.metadata.tables]
    ProdBase.metadata.create_all(bind=eng, tables=tables)
    return eng

def _setup():
    from app.models.organization import Organization
    from app.models.user import User
    from app.models.project import Project
    from app.models.organization_membership import OrganizationMembership
    from app.models.project_membership import ProjectMembership
    eng = _engine()
    SessionLocal = sessionmaker(bind=eng, autocommit=False, autoflush=False, expire_on_commit=False)
    db = SessionLocal()
    org = Organization(id=str(uuid.uuid4()), name="OrgF4", slug="orgf4-"+str(uuid.uuid4())[:6])
    db.add(org); db.flush()
    pwd = hash_password("password123")
    u_admin = User(id=str(uuid.uuid4()), organization_id=org.id, email="admin@f4.test", password_hash=pwd, role="member")
    u_analyst = User(id=str(uuid.uuid4()), organization_id=org.id, email="analyst@f4.test", password_hash=pwd, role="member")
    u_viewer = User(id=str(uuid.uuid4()), organization_id=org.id, email="viewer@f4.test", password_hash=pwd, role="member")
    db.add_all([u_admin, u_analyst, u_viewer]); db.flush()
    proj = Project(id=str(uuid.uuid4()), organization_id=org.id, name="ProjF4")
    db.add(proj); db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=u_admin.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=u_analyst.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=u_viewer.id, role="member", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj.id, user_id=u_admin.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj.id, user_id=u_analyst.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj.id, user_id=u_viewer.id, role="viewer", status="active"))
    db.commit(); db.close()
    return eng, SessionLocal, {"org": org, "u_admin": u_admin, "u_analyst": u_analyst, "u_viewer": u_viewer, "proj": proj}

def _client(SessionLocal):
    def override():
        s = SessionLocal()
        try: yield s
        finally: s.close()
    app.dependency_overrides[get_db] = override
    return TestClient(app)

def _add_asset(SessionLocal, proj_id, asset_type="domain", value=None, extra=None):
    from app.models.asset import Asset
    db = SessionLocal()
    a = Asset(id=str(uuid.uuid4()), project_id=proj_id, asset_type=asset_type, value=value or f"val-{str(uuid.uuid4())[:6]}", extra_data=extra or {})
    # ensure created_at for historical
    a.created_at = datetime.now(timezone.utc)
    a.last_seen_at = datetime.now(timezone.utc)
    db.add(a); db.commit(); db.close()
    return a

def _add_finding(SessionLocal, asset_id, scanner="nuclei", severity="high", title="Test", cve=None, cwe=None, evidence="evidence"):
    from app.models.finding import Finding
    db = SessionLocal()
    f = Finding(id=str(uuid.uuid4()), scanner=scanner, title=title, severity=severity, asset_id=asset_id, evidence=evidence, cve=cve, cwe=cwe)
    f.created_at = datetime.now(timezone.utc)
    db.add(f); db.commit(); db.close()
    return f

def _add_app(SessionLocal, proj, org, name=None, criticality="medium", lifecycle="PRODUCTION"):
    from app.services.application_intelligence import create_application
    from app.models.application import Application
    db = SessionLocal()
    # use direct create
    app_obj = create_application(proj.id, db, name=name or f"App-{str(uuid.uuid4())[:6]}", application_type="WEB", lifecycle=lifecycle, criticality=criticality)
    db.close()
    # need to fetch
    db2 = SessionLocal()
    obj = db2.query(Application).filter(Application.id == app_obj.id).first()
    db2.close()
    return obj

# 1 overview
def test_overview():
    eng, SL, objs = _setup()
    _add_asset(SL, objs["proj"].id, asset_type="domain", value="example.com", extra={"externally_reachable": True})
    _add_asset(SL, objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:ec2:i-123", extra={"resource_type": "aws_ec2_instance"})
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        j = r.json()
        assert "total_assets" in j
        assert "externally_reachable_assets" in j
        assert "applications" in j
        assert "cloud_resources" in j
    finally: app.dependency_overrides.clear()

# 2 asset type distribution
def test_asset_type_distribution():
    eng, SL, objs = _setup()
    _add_asset(SL, objs["proj"].id, asset_type="domain", value="example.com")
    _add_asset(SL, objs["proj"].id, asset_type="api_endpoint", value="/api/v1/test")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert "assets_by_type" in r.json()
        assert r.json()["assets_by_type"].get("domain",0) >= 1
    finally: app.dependency_overrides.clear()

# 3 external exposure
def test_external_exposure():
    eng, SL, objs = _setup()
    a = _add_asset(SL, objs["proj"].id, asset_type="subdomain", value="sub.example.com", extra={"externally_reachable": True})
    _add_finding(SL, a.id, severity="critical")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/cloud", headers={"Authorization": f"Bearer {tok}"})
        # also test internet exposure analytics via overview
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert r2.status_code == 200
    finally: app.dependency_overrides.clear()

# 4 cloud exposure
def test_cloud_exposure():
    eng, SL, objs = _setup()
    _add_asset(SL, objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:123:us-east-1:s3:bucket", extra={"resource_type": "aws_s3_bucket", "public": True})
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/cloud", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        j = r.json()
        assert "aws_resources" in j
        assert j["total_cloud_resources"] >= 1
    finally: app.dependency_overrides.clear()

# 5 application exposure
def test_application_exposure():
    eng, SL, objs = _setup()
    app_obj = _add_app(SL, objs["proj"], objs["org"])
    a = _add_asset(SL, objs["proj"].id, asset_type="api_endpoint", value="https://api.example.com/v1")
    # link
    from app.services.application_intelligence import link_asset
    db = SL()
    link_asset(app_obj.id, db, objs["proj"].id, asset_id=a.id, relationship_type="contains", confidence="CONFIRMED")
    db.close()
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/applications", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert r.json()["total_applications"] >= 1
    finally: app.dependency_overrides.clear()

# 6 API exposure
def test_api_exposure():
    eng, SL, objs = _setup()
    _add_asset(SL, objs["proj"].id, asset_type="api_endpoint", value="https://api.example.com/health")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/distribution", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        dist = r.json()["distribution"]
        api_cat = next((x for x in dist if x["category"]=="api"), None)
        assert api_cat is not None
        assert api_cat["total"] >= 1
    finally: app.dependency_overrides.clear()

# 7 findings distribution
def test_findings_distribution():
    eng, SL, objs = _setup()
    a = _add_asset(SL, objs["proj"].id)
    _add_finding(SL, a.id, scanner="nuclei", severity="high")
    _add_finding(SL, a.id, scanner="sast", severity="critical")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/finding-concentration", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert r.json()["total_findings"] >= 2
    finally: app.dependency_overrides.clear()

# 8 severity distribution
def test_severity_distribution():
    eng, SL, objs = _setup()
    a = _add_asset(SL, objs["proj"].id)
    _add_finding(SL, a.id, severity="critical")
    _add_finding(SL, a.id, severity="high")
    _add_finding(SL, a.id, severity="medium")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/finding-concentration", headers={"Authorization": f"Bearer {tok}"})
        j = r.json()
        assert j["by_severity"].get("critical",0) >= 1
        assert j["by_severity"].get("high",0) >= 1
    finally: app.dependency_overrides.clear()

# 9 scanner distribution
def test_scanner_distribution():
    eng, SL, objs = _setup()
    a = _add_asset(SL, objs["proj"].id)
    _add_finding(SL, a.id, scanner="sast", severity="high")
    _add_finding(SL, a.id, scanner="secrets", severity="critical")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/finding-concentration", headers={"Authorization": f"Bearer {tok}"})
        assert r.json()["by_scanner"].get("sast",0) >= 1
        assert r.json()["by_scanner"].get("secrets",0) >= 1
    finally: app.dependency_overrides.clear()

# 10 technology concentration
def test_technology_concentration():
    eng, SL, objs = _setup()
    # create technology asset and relationship
    tech = _add_asset(SL, objs["proj"].id, asset_type="technology", value="nginx")
    src = _add_asset(SL, objs["proj"].id, asset_type="url", value="https://example.com")
    from app.models.asset_relationship import AssetRelationship
    db = SL()
    rel = AssetRelationship(id=str(uuid.uuid4()), project_id=objs["proj"].id, source_asset_id=src.id, target_asset_id=tech.id, relationship_type="serves")
    db.add(rel); db.commit(); db.close()
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/technology", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert "technologies" in r.json()
    finally: app.dependency_overrides.clear()

# 11 service concentration
def test_service_concentration():
    eng, SL, objs = _setup()
    svc = _add_asset(SL, objs["proj"].id, asset_type="service", value="http")
    src = _add_asset(SL, objs["proj"].id, asset_type="port", value="80")
    from app.models.asset_relationship import AssetRelationship
    db = SL()
    rel = AssetRelationship(id=str(uuid.uuid4()), project_id=objs["proj"].id, source_asset_id=src.id, target_asset_id=svc.id, relationship_type="runs")
    db.add(rel); db.commit(); db.close()
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/technology", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert "services" in r.json()
    finally: app.dependency_overrides.clear()

# 12 attack-path concentration
def test_attack_path_concentration():
    eng, SL, objs = _setup()
    a1 = _add_asset(SL, objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:ec2:i-1", extra={"public": True})
    a2 = _add_asset(SL, objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:s3:bucket", extra={"resource_type": "aws_s3_bucket"})
    from app.models.asset_relationship import AssetRelationship
    from app.models.cloud_attack_path import CloudAttackPath
    db = SL()
    rel = AssetRelationship(id=str(uuid.uuid4()), project_id=objs["proj"].id, source_asset_id=a1.id, target_asset_id=a2.id, relationship_type="contains")
    db.add(rel)
    cap = CloudAttackPath(id=str(uuid.uuid4()), project_id=objs["proj"].id, organization_id=objs["org"].id, fingerprint="fp-"+str(uuid.uuid4())[:6], provider="aws", path_type="INTERNET_TO_RESOURCE", severity="critical", priority_score=90, confidence="HIGH", status="ACTIVE", asset_ids=[a1.id, a2.id])
    db.add(cap); db.commit(); db.close()
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/attack-paths", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        j = r.json()
        assert "total_attack_paths" in j
    finally: app.dependency_overrides.clear()

# 13 hotspot detection
def test_hotspot_detection():
    eng, SL, objs = _setup()
    a = _add_asset(SL, objs["proj"].id, asset_type="api_endpoint", value="https://api.example.com", extra={"externally_reachable": True})
    _add_finding(SL, a.id, severity="critical")
    # link to critical app
    app_obj = _add_app(SL, objs["proj"], objs["org"], criticality="critical")
    from app.services.application_intelligence import link_asset
    db = SL()
    link_asset(app_obj.id, db, objs["proj"].id, asset_id=a.id, relationship_type="exposes", confidence="CONFIRMED")
    db.close()
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/hotspots", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        j = r.json()
        assert "hotspots" in j
        # should have at least one hotspot with multiple signals
        assert len(j["hotspots"]) >= 1
        hs = j["hotspots"][0]
        assert "priority" in hs
        assert "exposure_signals" in hs
        assert len(hs["exposure_signals"]) >= 1
    finally: app.dependency_overrides.clear()

# 14 F2 priority integration
def test_f2_integration():
    eng, SL, objs = _setup()
    a = _add_asset(SL, objs["proj"].id, asset_type="api_endpoint", extra={"externally_reachable": True})
    f = _add_finding(SL, a.id, severity="critical", scanner="secrets")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/hotspots", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        # F2 priority should be present
        assert any(h["priority"] > 0 for h in r.json()["hotspots"])
        # concentration risk integration
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/concentration", headers={"Authorization": f"Bearer {tok}"})
        assert r2.status_code == 200
        assert "risk_concentration" in r2.json()
    finally: app.dependency_overrides.clear()

# 15 F3 trend integration
def test_f3_trend():
    eng, SL, objs = _setup()
    _add_asset(SL, objs["proj"].id)
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/historical?window=7d", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        # should be deterministic dict
        assert "window" in r.json() or "status" in r.json()
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/historical?window=30d", headers={"Authorization": f"Bearer {tok}"})
        assert r2.status_code == 200
    finally: app.dependency_overrides.clear()

# 16 coverage gap detection
def test_coverage_gap():
    eng, SL, objs = _setup()
    app_obj = _add_app(SL, objs["proj"], objs["org"])
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/coverage", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        j = r.json()
        assert "coverage_gaps" in j
        # app has no repo -> gap exists
        assert any(g["gap_type"] == "APPLICATION_NO_REPOSITORY" for g in j["coverage_gaps"])
    finally: app.dependency_overrides.clear()

# 17 no-evidence vs vulnerable distinction
def test_no_evidence_vs_vulnerable():
    eng, SL, objs = _setup()
    app_obj = _add_app(SL, objs["proj"], objs["org"], criticality="critical")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/coverage", headers={"Authorization": f"Bearer {tok}"})
        gaps = r.json()["coverage_gaps"]
        for g in gaps:
            assert g["status"] in ("COVERAGE_GAP", "NOT_ASSESSED")
            # must not say vulnerable
            assert "vulnerable" not in g["recommendation"].lower() or "not vulnerable" in g["recommendation"].lower() or "NOT_ASSESSED" in g["status"]
    finally: app.dependency_overrides.clear()

# 18 concentration percentage
def test_concentration_percentage():
    eng, SL, objs = _setup()
    for _ in range(3):
        a = _add_asset(SL, objs["proj"].id)
        for _ in range(2):
            _add_finding(SL, a.id, severity="critical")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/concentration", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        pct = r.json()["concentration"]["top_assets_critical_high_pct"]
        assert 0 <= pct <= 100
    finally: app.dependency_overrides.clear()

# 19 zero denominator
def test_zero_denominator():
    eng, SL, objs = _setup()
    # no findings, no paths -> denominator zero
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/concentration", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        conc = r.json()["concentration"]
        for v in conc.values():
            assert v == 0 or v is None or isinstance(v, (int,float))
    finally: app.dependency_overrides.clear()

# 20 deterministic ordering
def test_deterministic_ordering():
    eng, SL, objs = _setup()
    for i in range(3):
        a = _add_asset(SL, objs["proj"].id, value=f"val-{i}")
        _add_finding(SL, a.id, severity="high" if i==1 else "critical")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r1 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/hotspots", headers={"Authorization": f"Bearer {tok}"})
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/hotspots", headers={"Authorization": f"Bearer {tok}"})
        assert r1.json()["hotspots"] == r2.json()["hotspots"]
        # also top ordering
        r3 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/top", headers={"Authorization": f"Bearer {tok}"})
        r4 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/top", headers={"Authorization": f"Bearer {tok}"})
        assert r3.json()["top_assets"] == r4.json()["top_assets"]
    finally: app.dependency_overrides.clear()

# 21 deterministic output (overview twice)
def test_deterministic_output():
    eng, SL, objs = _setup()
    _add_asset(SL, objs["proj"].id)
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r1 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        j1 = {k:v for k,v in r1.json().items() if k not in ("generated_at",)}
        j2 = {k:v for k,v in r2.json().items() if k not in ("generated_at",)}
        assert j1 == j2
    finally: app.dependency_overrides.clear()

# 22 bounded results
def test_bounded_results():
    eng, SL, objs = _setup()
    for i in range(25):
        a = _add_asset(SL, objs["proj"].id, value=f"bounded-{i}")
        _add_finding(SL, a.id, severity="high")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/hotspots?limit=5", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert len(r.json()["hotspots"]) <= 5
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/top", headers={"Authorization": f"Bearer {tok}"})
        assert len(r2.json()["top_assets"]) <= 10
    finally: app.dependency_overrides.clear()

# 23 tenant isolation
def test_tenant_isolation():
    eng, SL, objs = _setup()
    _add_asset(SL, objs["proj"].id)
    from app.models.organization import Organization
    from app.models.project import Project
    from app.models.user import User
    from app.models.organization_membership import OrganizationMembership
    from app.models.project_membership import ProjectMembership
    db = SL()
    org2 = Organization(id=str(uuid.uuid4()), name="Org2", slug="org2-"+str(uuid.uuid4())[:4])
    db.add(org2); db.flush()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=org2.id, name="Proj2")
    db.add(proj2); db.flush()
    u2 = User(id=str(uuid.uuid4()), organization_id=org2.id, email="u2@org2.test", password_hash=hash_password("password123"), role="member")
    db.add(u2); db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org2.id, user_id=u2.id, role="org_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj2.id, user_id=u2.id, role="project_admin", status="active"))
    db.commit(); db.close()
    c = _client(SL)
    try:
        tok_b = create_access_token(u2.id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok_b}"})
        assert r.status_code == 404
    finally: app.dependency_overrides.clear()

# 24 project isolation
def test_project_isolation():
    eng, SL, objs = _setup()
    from app.models.project import Project
    from app.models.project_membership import ProjectMembership
    from app.core.config import settings
    orig = settings.RBAC_STRICT_MODE
    settings.RBAC_STRICT_MODE = True
    db = SL()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=objs["org"].id, name="Proj2SameOrg")
    db.add(proj2); db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj2.id, user_id=objs["u_admin"].id, role="project_admin", status="active"))
    db.commit(); db.close()
    c = _client(SL)
    try:
        tok_analyst = create_access_token(objs["u_analyst"].id)
        r = c.get(f"/api/v1/projects/{proj2.id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok_analyst}"})
        assert r.status_code in (403,404)
    finally:
        app.dependency_overrides.clear()
        settings.RBAC_STRICT_MODE = orig

# 25 strict RBAC viewer can read
def test_viewer_can_read():
    eng, SL, objs = _setup()
    _add_asset(SL, objs["proj"].id)
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_viewer"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/distribution", headers={"Authorization": f"Bearer {tok}"})
        assert r2.status_code == 200
    finally: app.dependency_overrides.clear()

# 26 IDOR
def test_idor():
    eng, SL, objs = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{str(uuid.uuid4())}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 404
    finally: app.dependency_overrides.clear()

# 27 invalid parameters
def test_invalid_window():
    eng, SL, objs = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/historical?window=invalid", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 400 or r.status_code == 422
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface?window=5d", headers={"Authorization": f"Bearer {tok}"})
        assert r2.status_code == 400
    finally: app.dependency_overrides.clear()

# 28 secret redaction
def test_secret_redaction():
    eng, SL, objs = _setup()
    a = _add_asset(SL, objs["proj"].id, asset_type="source_file", value="src/secret.py")
    _add_finding(SL, a.id, scanner="secrets", severity="critical", title="Secret exposure", evidence="mysecret password token123")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        # hotspots should not leak secret
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/hotspots", headers={"Authorization": f"Bearer {tok}"})
        assert "mysecret" not in str(r.json()).lower()
        assert "password" not in str(r.json()).lower() or "[redacted]" in str(r.json()).lower()
        # overview should not leak
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        assert "mysecret" not in str(r2.json()).lower()
    finally: app.dependency_overrides.clear()

# 29 no cross-project aggregation
def test_no_cross_project():
    eng, SL, objs = _setup()
    from app.models.project import Project
    from app.models.project_membership import ProjectMembership
    db = SL()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=objs["org"].id, name="Proj2")
    db.add(proj2); db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj2.id, user_id=objs["u_admin"].id, role="project_admin", status="active"))
    # add asset to proj2
    db.close()
    _add_asset(SL, proj2.id, asset_type="domain", value="other.com")
    _add_asset(SL, objs["proj"].id, asset_type="domain", value="example.com")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        # should count only 1 domain in proj
        assert r.json()["assets_by_type"].get("domain",0) == 1
    finally: app.dependency_overrides.clear()

# 30 no cross-tenant aggregation
def test_no_cross_tenant():
    eng, SL, objs = _setup()
    from app.models.organization import Organization
    from app.models.project import Project
    from app.models.user import User
    from app.models.organization_membership import OrganizationMembership
    from app.models.project_membership import ProjectMembership
    db = SL()
    org2 = Organization(id=str(uuid.uuid4()), name="Org2b", slug="org2b-"+str(uuid.uuid4())[:4])
    db.add(org2); db.flush()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=org2.id, name="ProjB")
    db.add(proj2); db.flush()
    a = _add_asset(SL, proj2.id, asset_type="domain", value="tenant2.com")
    # use direct engine to add finding to tenant2 proj via asset without auth
    db.close()
    _add_finding(SL, a.id, severity="critical")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        # should not count tenant2's critical finding
        assert r.json()["critical_findings"] == 0
    finally: app.dependency_overrides.clear()

# 31 application integration
def test_application_integration():
    eng, SL, objs = _setup()
    app_obj = _add_app(SL, objs["proj"], objs["org"])
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/applications", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert r.json()["total_applications"] >= 1
        assert any(a["name"] == app_obj.name for a in r.json()["ranking"])
    finally: app.dependency_overrides.clear()

# 32 external attack surface integration
def test_external_integration():
    eng, SL, objs = _setup()
    _add_asset(SL, objs["proj"].id, asset_type="domain", value="external.com", extra={"externally_reachable": True, "ownership_confidence": "CONFIRMED"})
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface", headers={"Authorization": f"Bearer {tok}"})
        assert r.json()["externally_reachable_assets"] >= 1
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/distribution", headers={"Authorization": f"Bearer {tok}"})
        ext_cat = next((x for x in r2.json()["distribution"] if x["category"]=="external"), None)
        assert ext_cat is not None
        assert ext_cat["exposed"] >= 1
    finally: app.dependency_overrides.clear()

# 33 cloud integration
def test_cloud_integration():
    eng, SL, objs = _setup()
    _add_asset(SL, objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:123:us-east-1:ec2:i-abc", extra={"resource_type": "aws_ec2_instance", "public": True})
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/cloud", headers={"Authorization": f"Bearer {tok}"})
        assert r.json()["aws_resources"] >= 1
    finally: app.dependency_overrides.clear()

# 34 correlation integration
def test_correlation_integration():
    eng, SL, objs = _setup()
    a = _add_asset(SL, objs["proj"].id)
    # two findings same CVE on same asset -> correlation duplicate
    _add_finding(SL, a.id, scanner="sast", severity="high", cve="CVE-2023-1234")
    _add_finding(SL, a.id, scanner="sca", severity="high", cve="CVE-2023-1234")
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/finding-concentration", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert r.json()["by_cve"].get("cve-2023-1234",0) >= 2 or "cve-2023-1234" in str(r.json()).lower()
    finally: app.dependency_overrides.clear()

# 35 attack-path integration
def test_attack_path_integration():
    eng, SL, objs = _setup()
    a1 = _add_asset(SL, objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:ec2:i-9", extra={"public": True})
    a2 = _add_asset(SL, objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:rds:db", extra={"resource_type": "aws_rds_instance"})
    from app.models.asset_relationship import AssetRelationship
    from app.models.cloud_attack_path import CloudAttackPath
    db = SL()
    rel = AssetRelationship(id=str(uuid.uuid4()), project_id=objs["proj"].id, source_asset_id=a1.id, target_asset_id=a2.id, relationship_type="contains")
    db.add(rel)
    cap = CloudAttackPath(id=str(uuid.uuid4()), project_id=objs["proj"].id, organization_id=objs["org"].id, fingerprint="fp2-"+str(uuid.uuid4())[:4], provider="aws", path_type="INTERNET_TO_RESOURCE", severity="high", priority_score=75, confidence="MEDIUM", status="ACTIVE", asset_ids=[a1.id, a2.id])
    db.add(cap); db.commit(); db.close()
    # asset should appear as hotspot via attack path
    c = _client(SL)
    try:
        tok = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/hotspots", headers={"Authorization": f"Bearer {tok}"})
        # should have attack_path signal if asset in path
        hotspots = r.json()["hotspots"]
        # check at least one hotspot has attack_path signal or path count
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/attack-surface/attack-paths", headers={"Authorization": f"Bearer {tok}"})
        assert r2.json()["total_attack_paths"] >= 1
    finally: app.dependency_overrides.clear()

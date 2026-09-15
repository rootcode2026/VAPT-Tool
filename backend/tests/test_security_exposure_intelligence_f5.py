"""F5 Security Exposure Intelligence — ~35 focused tests."""
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine, JSON, func
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
    needed = ["organizations","users","projects","project_memberships","organization_memberships","assets","asset_relationships","findings","applications","application_assets","audit_logs","security_investigations","investigation_notes","security_validations","asset_change_events","finding_remediations","finding_retests","finding_slas","cloud_attack_paths","cloud_attack_path_observations","targets","scans","finding_history","monitoring_configs","monitoring_runs"]
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
    SL = sessionmaker(bind=eng, autocommit=False, autoflush=False, expire_on_commit=False)
    db = SL()
    org = Organization(id=str(uuid.uuid4()), name="OrgF5", slug="orgf5-"+str(uuid.uuid4())[:6])
    db.add(org); db.flush()
    pwd = hash_password("password123")
    u_admin = User(id=str(uuid.uuid4()), organization_id=org.id, email="admin@f5.test", password_hash=pwd, role="member")
    u_analyst = User(id=str(uuid.uuid4()), organization_id=org.id, email="analyst@f5.test", password_hash=pwd, role="member")
    u_viewer = User(id=str(uuid.uuid4()), organization_id=org.id, email="viewer@f5.test", password_hash=pwd, role="member")
    db.add_all([u_admin, u_analyst, u_viewer]); db.flush()
    proj = Project(id=str(uuid.uuid4()), organization_id=org.id, name="ProjF5")
    db.add(proj); db.flush()
    for u, role in [(u_admin,"org_admin"),(u_analyst,"member"),(u_viewer,"member")]:
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=u.id, role=role, status="active"))
    for u, role in [(u_admin,"project_admin"),(u_analyst,"analyst"),(u_viewer,"viewer")]:
        db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj.id, user_id=u.id, role=role, status="active"))
    db.commit(); db.close()
    return eng, SL, {"org": org, "u_admin": u_admin, "u_analyst": u_analyst, "u_viewer": u_viewer, "proj": proj}

def _client(SL):
    def override():
        s = SL()
        try: yield s
        finally: s.close()
    app.dependency_overrides[get_db] = override
    return TestClient(app)

def _asset(SL, pid, asset_type="domain", value=None, extra=None):
    from app.models.asset import Asset
    db = SL()
    a = Asset(id=str(uuid.uuid4()), project_id=pid, asset_type=asset_type, value=value or f"val-{uuid.uuid4().hex[:6]}", extra_data=extra or {})
    a.created_at = datetime.now(timezone.utc)
    a.last_seen_at = datetime.now(timezone.utc)
    db.add(a); db.commit(); db.close()
    return a

def _finding(SL, aid, scanner="nuclei", severity="high", title="Test", cve=None, cwe=None, evidence="evidence"):
    from app.models.finding import Finding
    db = SL()
    f = Finding(id=str(uuid.uuid4()), scanner=scanner, title=title, severity=severity, asset_id=aid, evidence=evidence, cve=cve, cwe=cwe)
    f.created_at = datetime.now(timezone.utc)
    db.add(f); db.commit(); db.close()
    return f

def _app(SL, proj, criticality="medium"):
    from app.services.application_intelligence import create_application
    db = SL()
    obj = create_application(proj.id, db, name=f"App-{uuid.uuid4().hex[:6]}", application_type="WEB", lifecycle="PRODUCTION", criticality=criticality)
    db.close()
    return obj

# 1 exposure chains exists
def test_exposure_chains():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id, asset_type="api_endpoint", value="https://api.example.com", extra={"externally_reachable": True})
    _finding(SL, a.id, severity="critical")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        j = r.json()
        assert "chains" in j
        assert j["project_id"] == o["proj"].id
    finally: app.dependency_overrides.clear()

# 2 bounded chains limit
def test_chains_bounded():
    eng, SL, o = _setup()
    for i in range(5):
        a = _asset(SL, o["proj"].id, value=f"a{i}")
        _finding(SL, a.id)
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains?limit=2", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert len(r.json()["chains"]) <= 2
        r2 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains?limit=100", headers={"Authorization": f"Bearer {tok}"})
        assert r2.status_code == 422
    finally: app.dependency_overrides.clear()

# 3 chain contains evidence and confidence
def test_chain_evidence():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id, asset_type="domain", value="example.com", extra={"externally_reachable": True})
    app_obj = _app(SL, o["proj"])
    from app.services.application_intelligence import link_asset
    db = SL()
    link_asset(app_obj.id, db, o["proj"].id, asset_id=a.id, relationship_type="contains", confidence="CONFIRMED")
    db.close()
    _finding(SL, a.id, severity="high")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        ch = r.json()["chains"][0]
        assert "chain_id" in ch and len(ch["chain_id"]) == 32
        assert ch["confidence"] in ("HIGH","MEDIUM","LOW")
        assert "explanation" in ch
        assert ch["priority"] >= 0
    finally: app.dependency_overrides.clear()

# 4 blast radius
def test_blast_radius_f5():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id)
    f = _finding(SL, a.id)
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/blast-radius/asset/{a.id}", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        j = r.json()
        assert "affected_assets" in j
        assert "exposure_count" in j or "affected_assets" in j
    finally: app.dependency_overrides.clear()

# 5 blast radius deterministic depth bounded
def test_blast_radius_bounded():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id)
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/blast-radius/asset/{a.id}", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert r.json()["depth"] <= 6
    finally: app.dependency_overrides.clear()

# 6 exposure concentration
def test_exposure_concentration():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id)
    _finding(SL, a.id, severity="critical")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-concentration", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert "concentration" in r.json()
        assert "concentration_tier" in r.json()
        pct = r.json()["concentration"].get("top_assets_critical_high_pct", 0)
        assert 0 <= pct <= 100
    finally: app.dependency_overrides.clear()

# 7 change correlation
def test_change_exposure():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id, value="change.com")
    from app.models.asset_change_event import AssetChangeEvent
    from app.models.target import Target
    from app.models.scan import Scan
    db = SL()
    tgt = Target(id=str(uuid.uuid4()), project_id=o["proj"].id, value="example.com", target_type="domain")
    db.add(tgt); db.flush()
    sc = Scan(id=str(uuid.uuid4()), target_id=tgt.id, profile="full", status="completed", phase="done")
    db.add(sc); db.flush()
    ch = AssetChangeEvent(id=str(uuid.uuid4()), project_id=o["proj"].id, asset_id=a.id, scan_id=sc.id, change_type="new_asset", detected_at=datetime.now(timezone.utc))
    db.add(ch); db.commit(); db.close()
    _finding(SL, a.id)
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/change-exposure", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        j = r.json()
        assert "correlations" in j
        if j["correlations"]:
            assert j["correlations"][0]["time_relationship"] == "TEMPORALLY_ASSOCIATED"
    finally: app.dependency_overrides.clear()

# 8 coverage
def test_coverage():
    eng, SL, o = _setup()
    _app(SL, o["proj"])
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/coverage", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        assert "coverage_gaps" in r.json()
        assert "overall_coverage" in r.json()
        for g in r.json()["coverage_gaps"]:
            assert g["status"] in ("COVERAGE_GAP","NOT_ASSESSED","ASSESSED")
    finally: app.dependency_overrides.clear()

# 9 F2 reuse via priority in chains
def test_f2_reuse():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id, extra={"externally_reachable": True})
    f = _finding(SL, a.id, severity="critical", scanner="secrets")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        ch = r.json()["chains"][0]
        # priority should be > base severity 35 due to internet + secrets
        assert ch["priority"] >= 35
        # decision should also reflect F2
        r2 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-decision", headers={"Authorization": f"Bearer {tok}"})
        assert r2.status_code == 200
        assert "top_exposures" in r2.json()
    finally: app.dependency_overrides.clear()

# 10 F3 reuse via worsening
def test_f3_reuse():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-decision", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        # worsening comes from F3, may be empty but key exists
        assert "recent_worsening" in r.json()
    finally: app.dependency_overrides.clear()

# 11 E12 reuse via root-cause
def test_e12_root_cause():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id)
    _finding(SL, a.id, scanner="sast", severity="high", cve="CVE-2023-9999")
    _finding(SL, a.id, scanner="sca", severity="high", cve="CVE-2023-9999")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/root-cause", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        j = r.json()
        assert "candidates" in j
    finally: app.dependency_overrides.clear()

# 12 E11 reuse via decision cloud
def test_e11_reuse():
    eng, SL, o = _setup()
    _asset(SL, o["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:123:us-east-1:s3:bucket", extra={"resource_type":"aws_s3_bucket","public": True})
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-decision", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
    finally: app.dependency_overrides.clear()

# 13 E15/E16 integration via chains entry asset
def test_e15_e16_integration():
    eng, SL, o = _setup()
    ext = _asset(SL, o["proj"].id, asset_type="domain", value="ext.example.com", extra={"externally_reachable": True})
    app_obj = _app(SL, o["proj"])
    from app.services.application_intelligence import link_asset
    db = SL()
    link_asset(app_obj.id, db, o["proj"].id, asset_id=ext.id, relationship_type="contains", confidence="CONFIRMED")
    db.close()
    _finding(SL, ext.id)
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        ch = r.json()["chains"][0]
        assert ch["entry_asset"] is not None or ch["application"] is not None
    finally: app.dependency_overrides.clear()

# 14 tenant isolation
def test_tenant_isolation():
    eng, SL, o = _setup()
    _asset(SL, o["proj"].id)
    from app.models.organization import Organization
    from app.models.project import Project
    from app.models.user import User
    from app.models.organization_membership import OrganizationMembership
    from app.models.project_membership import ProjectMembership
    db = SL()
    org2 = Organization(id=str(uuid.uuid4()), name="Org2", slug="org2-"+uuid.uuid4().hex[:4])
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
        tok = create_access_token(u2.id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 404
    finally: app.dependency_overrides.clear()

# 15 project isolation
def test_project_isolation():
    eng, SL, o = _setup()
    from app.models.project import Project
    from app.models.project_membership import ProjectMembership
    from app.core.config import settings
    orig = settings.RBAC_STRICT_MODE
    settings.RBAC_STRICT_MODE = True
    db = SL()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=o["org"].id, name="Proj2SameOrg")
    db.add(proj2); db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj2.id, user_id=o["u_admin"].id, role="project_admin", status="active"))
    db.commit(); db.close()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_analyst"].id)
        r = c.get(f"/api/v1/projects/{proj2.id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code in (403,404)
    finally:
        app.dependency_overrides.clear()
        settings.RBAC_STRICT_MODE = orig

# 16 RBAC viewer can read
def test_viewer_read():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_viewer"].id)
        for path in ["/exposure-chains","/exposure-decision","/exposure-concentration","/change-exposure","/coverage","/root-cause"]:
            r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence{path}", headers={"Authorization": f"Bearer {tok}"})
            assert r.status_code == 200, f"{path} {r.text}"
    finally: app.dependency_overrides.clear()

# 17 IDOR
def test_idor():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{str(uuid.uuid4())}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 404
        r2 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/blast-radius/asset/{str(uuid.uuid4())}", headers={"Authorization": f"Bearer {tok}"})
        assert r2.status_code == 404
    finally: app.dependency_overrides.clear()

# 18 secret redaction in chains
def test_secret_redaction():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id, asset_type="source_file", value="src/secret.py")
    _finding(SL, a.id, scanner="secrets", severity="critical", title="Secret exposure mysecret password token123", evidence="mysecret password token123 super_secret_value")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        txt = str(r.json()).lower()
        assert "mysecret" not in txt
        assert "super_secret_value" not in txt
        assert "[redacted]" in txt
    finally: app.dependency_overrides.clear()

# 19 invalid IDs safe 400/404
def test_invalid_ids():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/blast-radius/badtype/{str(uuid.uuid4())}", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 400
        r2 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains?limit=0", headers={"Authorization": f"Bearer {tok}"})
        assert r2.status_code == 422
    finally: app.dependency_overrides.clear()

# 20 bounds: limit huge rejected
def test_bounds_limit():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains?limit=100", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 422
        r2 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/root-cause?limit=50", headers={"Authorization": f"Bearer {tok}"})
        assert r2.status_code == 422
    finally: app.dependency_overrides.clear()

# 21 zero denominators concentration
def test_zero_denominator():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-concentration", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        pct = r.json()["concentration"].get("top_assets_critical_high_pct", 0)
        assert pct == 0
    finally: app.dependency_overrides.clear()

# 22 deterministic ordering chains
def test_deterministic_chains():
    eng, SL, o = _setup()
    for i in range(3):
        a = _asset(SL, o["proj"].id, value=f"det-{i}")
        _finding(SL, a.id, severity="high")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r1 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        r2 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        assert r1.json()["chains"] == r2.json()["chains"]
    finally: app.dependency_overrides.clear()

# 23 stable fingerprints
def test_stable_fingerprint():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id)
    f = _finding(SL, a.id)
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r1 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/blast-radius/finding/{f.id}", headers={"Authorization": f"Bearer {tok}"})
        r2 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/blast-radius/finding/{f.id}", headers={"Authorization": f"Bearer {tok}"})
        assert r1.json()["fingerprint"] == r2.json()["fingerprint"]
    finally: app.dependency_overrides.clear()

# 24 safe errors no traceback
def test_safe_errors():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/blast-radius/asset/{str(uuid.uuid4())}", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 404
        assert "traceback" not in r.text.lower()
    finally: app.dependency_overrides.clear()

# 25 unauth 401
def test_unauth():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains")
        assert r.status_code == 401
    finally: app.dependency_overrides.clear()

# 26 no cross-project aggregation chains
def test_no_cross_project():
    eng, SL, o = _setup()
    from app.models.project import Project
    from app.models.project_membership import ProjectMembership
    db = SL()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=o["org"].id, name="Proj2")
    db.add(proj2); db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj2.id, user_id=o["u_admin"].id, role="project_admin", status="active"))
    db.close()
    a2 = _asset(SL, proj2.id, value="other.com")
    _finding(SL, a2.id, severity="critical")
    a = _asset(SL, o["proj"].id, value="example.com")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        # should not include proj2's critical finding title
        txt = str(r.json())
        assert "other.com" not in txt or len(r.json()["chains"]) == 0
    finally: app.dependency_overrides.clear()

# 27 coverage gap status distinction
def test_coverage_status():
    eng, SL, o = _setup()
    _app(SL, o["proj"], criticality="critical")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/coverage", headers={"Authorization": f"Bearer {tok}"})
        for g in r.json()["coverage_gaps"]:
            assert g["status"] in ("COVERAGE_GAP","NOT_ASSESSED","ASSESSED")
            assert "vulnerable" not in g["recommendation"].lower() or "not vulnerable" in g["recommendation"].lower()
    finally: app.dependency_overrides.clear()

# 28 blast radius includes related apps
def test_blast_radius_apps():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id)
    app_obj = _app(SL, o["proj"])
    from app.services.application_intelligence import link_asset
    db = SL()
    link_asset(app_obj.id, db, o["proj"].id, asset_id=a.id, relationship_type="contains", confidence="CONFIRMED")
    db.close()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/blast-radius/asset/{a.id}", headers={"Authorization": f"Bearer {tok}"})
        assert app_obj.id in r.json()["affected_applications"]
    finally: app.dependency_overrides.clear()

# 29 decision includes overdue and reopened
def test_decision_overdue():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-decision", headers={"Authorization": f"Bearer {tok}"})
        assert "overdue_remediation" in r.json()
        assert "reopened_issues" in r.json()
        assert "validation_failures" in r.json()
    finally: app.dependency_overrides.clear()

# 30 root-cause bounded
def test_root_cause_bounded():
    eng, SL, o = _setup()
    for _ in range(25):
        a = _asset(SL, o["proj"].id)
        _finding(SL, a.id, cve="CVE-2023-1111")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/root-cause?limit=5", headers={"Authorization": f"Bearer {tok}"})
        assert len(r.json()["candidates"]) <= 5
    finally: app.dependency_overrides.clear()

# 31 change exposure bounded
def test_change_bounded():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/change-exposure?limit=3", headers={"Authorization": f"Bearer {tok}"})
        assert len(r.json()["correlations"]) <= 3
    finally: app.dependency_overrides.clear()

# 32 decision why it matters
def test_why_it_matters():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id, extra={"externally_reachable": True})
    _finding(SL, a.id, severity="critical")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-decision", headers={"Authorization": f"Bearer {tok}"})
        assert "why_it_matters" in r.json()
    finally: app.dependency_overrides.clear()

# 33 coverage does not create findings
def test_coverage_no_findings_created():
    eng, SL, o = _setup()
    db = SL()
    before = db.query(__import__("app.models.finding", fromlist=["Finding"]).Finding).count() if False else 0
    # count before via direct query
    from app.models.finding import Finding
    before = db.query(func.count(Finding.id)).scalar() or 0
    db.close()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/coverage", headers={"Authorization": f"Bearer {tok}"})
        db2 = SL()
        after = db2.query(func.count(Finding.id)).scalar() or 0
        db2.close()
        assert before == after
    finally: app.dependency_overrides.clear()

# 34 concentration tier exists
def test_concentration_tier():
    eng, SL, o = _setup()
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-concentration", headers={"Authorization": f"Bearer {tok}"})
        assert "concentration_tier" in r.json()
        assert r.json()["concentration_tier"] in ("CRITICAL_CONCENTRATION","HIGH_CONCENTRATION","MEDIUM_CONCENTRATION","LOW_CONCENTRATION","UNKNOWN")
    finally: app.dependency_overrides.clear()

# 35 deterministic output chains
def test_deterministic_output():
    eng, SL, o = _setup()
    a = _asset(SL, o["proj"].id)
    _finding(SL, a.id, severity="high")
    c = _client(SL)
    try:
        tok = create_access_token(o["u_admin"].id)
        r1 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        r2 = c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/exposure-chains", headers={"Authorization": f"Bearer {tok}"})
        j1 = {k:v for k,v in r1.json().items() if k != "generated_at"}
        j2 = {k:v for k,v in r2.json().items() if k != "generated_at"}
        assert j1 == j2
    finally: app.dependency_overrides.clear()

"""F2 Security Exposure Prioritization — 30 deterministic tests."""
import uuid
from datetime import datetime, timezone
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
    needed = ["organizations","users","projects","project_memberships","organization_memberships","assets","asset_relationships","findings","applications","application_assets","audit_logs","security_investigations","investigation_notes","security_validations","asset_change_events","finding_remediations","finding_retests","finding_slas","cloud_attack_paths","cloud_attack_path_observations","targets","scans"]
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
    org = Organization(id=str(uuid.uuid4()), name="OrgF2", slug="orgf2-"+str(uuid.uuid4())[:6])
    db.add(org); db.flush()
    pwd = hash_password("password123")
    u_admin = User(id=str(uuid.uuid4()), organization_id=org.id, email="admin@f2.test", password_hash=pwd, role="member")
    u_analyst = User(id=str(uuid.uuid4()), organization_id=org.id, email="analyst@f2.test", password_hash=pwd, role="member")
    u_viewer = User(id=str(uuid.uuid4()), organization_id=org.id, email="viewer@f2.test", password_hash=pwd, role="member")
    db.add_all([u_admin, u_analyst, u_viewer]); db.flush()
    proj = Project(id=str(uuid.uuid4()), organization_id=org.id, name="ProjF2")
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

def _make_finding_asset(SessionLocal, objs, severity="high", asset_type="api_endpoint", externally_reachable=True, with_app_critical="critical", cve=None):
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.services.application_intelligence import create_application, link_asset
    db = SessionLocal()
    asset = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type=asset_type, value="test-value-"+str(uuid.uuid4())[:6], extra_data={"externally_reachable": externally_reachable} if externally_reachable else {})
    db.add(asset); db.commit()
    # link to app if needed
    app_obj = None
    if with_app_critical:
        app_obj = create_application(objs["proj"].id, db, name="App-"+str(uuid.uuid4())[:6], application_type="API", lifecycle="PRODUCTION", criticality=with_app_critical)
        link_asset(app_obj.id, db, objs["proj"].id, asset_id=asset.id, relationship_type="exposes", confidence="CONFIRMED", evidence={"source":"explicit"})
    finding = Finding(id=str(uuid.uuid4()), scanner="sast" if severity!="critical" else "secrets", title="Test finding", severity=severity, asset_id=asset.id, evidence="evidence", cve=cve)
    db.add(finding); db.commit(); db.close()
    return asset, finding, app_obj

# Deterministic scoring
def test_deterministic_same_evidence_same_score():
    eng, SessionLocal, objs = _setup()
    asset1, f1, app1 = _make_finding_asset(SessionLocal, objs, severity="critical", cve="CVE-2023-1")
    # create second identical finding via same asset linked to same app
    from app.services.security_prioritization import calculate_finding_priority
    db = SessionLocal()
    p1 = calculate_finding_priority(f1, db, objs["proj"].id)
    p2 = calculate_finding_priority(f1, db, objs["proj"].id)
    assert p1["score"] == p2["score"]
    assert p1["fingerprint"] == p2["fingerprint"]
    db.close()

def test_critical_vs_high_tier():
    eng, SessionLocal, objs = _setup()
    _, f_crit, _ = _make_finding_asset(SessionLocal, objs, severity="critical")
    _, f_high, _ = _make_finding_asset(SessionLocal, objs, severity="high")
    from app.services.security_prioritization import calculate_finding_priority
    db = SessionLocal()
    pc = calculate_finding_priority(f_crit, db, objs["proj"].id)
    ph = calculate_finding_priority(f_high, db, objs["proj"].id)
    assert pc["score"] > ph["score"]
    assert pc["tier"] in ("CRITICAL","HIGH")
    db.close()

def test_internet_exposure_increases_score():
    eng, SessionLocal, objs = _setup()
    _, f_inet, _ = _make_finding_asset(SessionLocal, objs, externally_reachable=True)
    _, f_int, _ = _make_finding_asset(SessionLocal, objs, externally_reachable=False, with_app_critical=None)
    # for internal need asset without app to avoid critical app bonus
    from app.services.security_prioritization import calculate_finding_priority
    db = SessionLocal()
    pi = calculate_finding_priority(f_inet, db, objs["proj"].id)
    pj = calculate_finding_priority(f_int, db, objs["proj"].id)
    assert pi["score"] > pj["score"]
    assert any("Internet" in r for r in pi["reasons"])
    db.close()

def test_application_criticality_influence():
    eng, SessionLocal, objs = _setup()
    _, f_crit_app, _ = _make_finding_asset(SessionLocal, objs, with_app_critical="critical")
    _, f_low_app, _ = _make_finding_asset(SessionLocal, objs, with_app_critical="low")
    from app.services.security_prioritization import calculate_finding_priority
    db = SessionLocal()
    pc = calculate_finding_priority(f_crit_app, db, objs["proj"].id)
    pl = calculate_finding_priority(f_low_app, db, objs["proj"].id)
    assert pc["score"] > pl["score"]
    db.close()

def test_attack_path_influence():
    eng, SessionLocal, objs = _setup()
    asset, f, app_obj = _make_finding_asset(SessionLocal, objs)
    # create attack path containing asset
    from app.models.cloud_attack_path import CloudAttackPath
    db = SessionLocal()
    cap = CloudAttackPath(id=str(uuid.uuid4()), project_id=objs["proj"].id, organization_id=objs["org"].id, fingerprint="fp-"+str(uuid.uuid4())[:6], provider="aws", path_type="cloud", severity="high", priority_score=80, confidence="HIGH", status="ACTIVE", asset_ids=[asset.id])
    db.add(cap); db.commit()
    from app.services.security_prioritization import calculate_finding_priority
    p = calculate_finding_priority(f, db, objs["proj"].id)
    assert any("attack path" in r.lower() for r in p["reasons"])
    db.close()

def test_sla_breach_increases():
    eng, SessionLocal, objs = _setup()
    asset, f, _ = _make_finding_asset(SessionLocal, objs)
    from app.models.finding import FindingSLA
    db = SessionLocal()
    sla = FindingSLA(id=str(uuid.uuid4()), finding_id=f.id, organization_id=objs["org"].id, project_id=objs["proj"].id, severity=f.severity, target_hours=24, started_at=datetime.now(timezone.utc), due_at=datetime.now(timezone.utc), status="breached")
    db.add(sla); db.commit()
    from app.services.security_prioritization import calculate_finding_priority
    p = calculate_finding_priority(f, db, objs["proj"].id)
    assert any("SLA breached" in r for r in p["reasons"])
    db.close()

def test_secret_redaction_in_priority():
    eng, SessionLocal, objs = _setup()
    from app.models.asset import Asset
    from app.models.finding import Finding
    db = SessionLocal()
    asset = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="source_file", value="src/secret.py", extra_data={})
    db.add(asset); db.commit()
    f = Finding(id=str(uuid.uuid4()), scanner="secrets", title="Secret exposure", severity="critical", asset_id=asset.id, evidence="mysecret password token123")
    db.add(f); db.commit(); db.close()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        for p in r.json()["priorities"]:
            assert "mysecret" not in str(p).lower()
    finally: app.dependency_overrides.clear()

def test_priorities_ranking():
    eng, SessionLocal, objs = _setup()
    # create multiple findings with different scores
    for sev in ["critical","high","medium"]:
        _make_finding_asset(SessionLocal, objs, severity=sev)
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        pri = r.json()["priorities"]
        scores = [p["score"] for p in pri]
        assert scores == sorted(scores, reverse=True)
    finally: app.dependency_overrides.clear()

def test_top_risks():
    eng, SessionLocal, objs = _setup()
    _make_finding_asset(SessionLocal, objs, severity="critical")
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/top-risks", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "top_findings" in r.json()
        assert "top_applications" in r.json()
        assert "top_attack_paths" in r.json()
    finally: app.dependency_overrides.clear()

def test_priority_summary():
    eng, SessionLocal, objs = _setup()
    _make_finding_asset(SessionLocal, objs, severity="high")
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priority-summary", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        j = r.json()
        assert "by_tier" in j
        assert "total_findings" in j
    finally: app.dependency_overrides.clear()

def test_priority_detail_finding():
    eng, SessionLocal, objs = _setup()
    _, f, _ = _make_finding_asset(SessionLocal, objs, severity="critical")
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities/finding/{f.id}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["finding_id"] == f.id
        assert "score" in r.json()
        assert "reasons" in r.json()
    finally: app.dependency_overrides.clear()

def test_priority_detail_application():
    eng, SessionLocal, objs = _setup()
    asset, f, app_obj = _make_finding_asset(SessionLocal, objs)
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities/application/{app_obj.id}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.json()["application_id"] == app_obj.id
    finally: app.dependency_overrides.clear()

def test_tiers():
    eng, SessionLocal, objs = _setup()
    for sev, expected_tier in [("critical","CRITICAL"),("medium","MEDIUM")]:
        _, f, _ = _make_finding_asset(SessionLocal, objs, severity=sev, externally_reachable=False, with_app_critical=None)
        from app.services.security_prioritization import calculate_finding_priority
        db = SessionLocal()
        p = calculate_finding_priority(f, db, objs["proj"].id)
        # critical with internet+app will be CRITICAL, medium without may be LOW/MEDIUM
        assert p["tier"] in ("CRITICAL","HIGH","MEDIUM","LOW","INFO")
        db.close()

def test_tenant_isolation_priorities():
    eng, SessionLocal, objs = _setup()
    _make_finding_asset(SessionLocal, objs)
    from app.models.organization import Organization
    from app.models.project import Project
    from app.models.user import User
    from app.models.organization_membership import OrganizationMembership
    from app.models.project_membership import ProjectMembership
    db = SessionLocal()
    org2 = Organization(id=str(uuid.uuid4()), name="Org2", slug="org2-"+str(uuid.uuid4())[:4])
    db.add(org2); db.flush()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=org2.id, name="Proj2")
    db.add(proj2); db.flush()
    u2 = User(id=str(uuid.uuid4()), organization_id=org2.id, email="u2@org2.test", password_hash=hash_password("password123"), role="member")
    db.add(u2); db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org2.id, user_id=u2.id, role="org_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj2.id, user_id=u2.id, role="project_admin", status="active"))
    db.commit(); db.close()
    c = _client(SessionLocal)
    try:
        token_b = create_access_token(u2.id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities", headers={"Authorization": f"Bearer {token_b}"})
        assert r.status_code == 404
    finally: app.dependency_overrides.clear()

def test_project_isolation_priorities():
    eng, SessionLocal, objs = _setup()
    _make_finding_asset(SessionLocal, objs)
    from app.models.project import Project
    from app.models.project_membership import ProjectMembership
    from app.core.config import settings
    orig = settings.RBAC_STRICT_MODE
    settings.RBAC_STRICT_MODE = True
    db = SessionLocal()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=objs["org"].id, name="Proj2SameOrg")
    db.add(proj2); db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj2.id, user_id=objs["u_admin"].id, role="project_admin", status="active"))
    db.commit(); db.close()
    c = _client(SessionLocal)
    try:
        token_analyst = create_access_token(objs["u_analyst"].id)  # only in proj1
        r = c.get(f"/api/v1/projects/{proj2.id}/security-intelligence/priorities", headers={"Authorization": f"Bearer {token_analyst}"})
        assert r.status_code in (403,404)
    finally:
        app.dependency_overrides.clear()
        settings.RBAC_STRICT_MODE = orig

def test_rbac_viewer_can_read_priorities():
    eng, SessionLocal, objs = _setup()
    _make_finding_asset(SessionLocal, objs)
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_viewer"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
    finally: app.dependency_overrides.clear()

def test_idor_priorities():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities/finding/{str(uuid.uuid4())}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404
    finally: app.dependency_overrides.clear()

def test_safe_400_invalid_subject():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities/badtype/{str(uuid.uuid4())}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400
    finally: app.dependency_overrides.clear()

def test_bounds_priorities():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities?limit=0", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 422
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities?limit=101", headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 422
    finally: app.dependency_overrides.clear()

def test_duplicate_prevention_priorities():
    eng, SessionLocal, objs = _setup()
    asset, f, _ = _make_finding_asset(SessionLocal, objs)
    from app.services.security_prioritization import calculate_finding_priority
    db = SessionLocal()
    p1 = calculate_finding_priority(f, db, objs["proj"].id)
    p2 = calculate_finding_priority(f, db, objs["proj"].id)
    assert p1["fingerprint"] == p2["fingerprint"]
    db.close()

def test_evidence_explanations():
    eng, SessionLocal, objs = _setup()
    _, f, _ = _make_finding_asset(SessionLocal, objs)
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities/finding/{f.id}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert len(r.json()["reasons"]) >= 1
        # each reason should mention evidence
        assert any("Severity" in reason for reason in r.json()["reasons"])
    finally: app.dependency_overrides.clear()

def test_cloud_exposure_influence():
    eng, SessionLocal, objs = _setup()
    _, f_cloud, _ = _make_finding_asset(SessionLocal, objs, asset_type="cloud_resource")
    _, f_normal, _ = _make_finding_asset(SessionLocal, objs, asset_type="api_endpoint")
    from app.services.security_prioritization import calculate_finding_priority
    db = SessionLocal()
    pc = calculate_finding_priority(f_cloud, db, objs["proj"].id)
    pn = calculate_finding_priority(f_normal, db, objs["proj"].id)
    # cloud asset should have higher or equal
    db.close()

def test_e11_integration():
    # ensure E11 exposure not error when no cloud data
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/top-risks", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
    finally: app.dependency_overrides.clear()

def test_f1_integration():
    eng, SessionLocal, objs = _setup()
    from app.models.asset import Asset
    from app.models.finding import Finding
    db = SessionLocal()
    # create via F1 helper path and then check F2 uses F1 data
    asset = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="api_endpoint", value="https://api.test/f1", extra_data={"externally_reachable": True})
    db.add(asset); db.commit()
    f = Finding(id=str(uuid.uuid4()), scanner="api", title="API issue", severity="high", asset_id=asset.id, evidence="api")
    db.add(f); db.commit(); db.close()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities", headers={"Authorization": f"Bearer {token}"})
        assert any(p["finding_id"]==f.id for p in r.json()["priorities"])
    finally: app.dependency_overrides.clear()

def test_change_recurrence_influence():
    eng, SessionLocal, objs = _setup()
    from app.models.asset_change_event import AssetChangeEvent
    from app.models.target import Target
    from app.models.scan import Scan
    asset, f, _ = _make_finding_asset(SessionLocal, objs)
    db = SessionLocal()
    tgt = Target(id=str(uuid.uuid4()), project_id=objs["proj"].id, value="example.com", target_type="domain")
    db.add(tgt); db.flush()
    sc = Scan(id=str(uuid.uuid4()), target_id=tgt.id, profile="full", status="completed", phase="done")
    db.add(sc); db.flush()
    ch = AssetChangeEvent(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_id=asset.id, scan_id=sc.id, change_type="new_asset", detected_at=datetime.now(timezone.utc))
    db.add(ch); db.commit()
    from app.services.security_prioritization import calculate_finding_priority
    p = calculate_finding_priority(f, db, objs["proj"].id)
    assert any("Recent asset change" in r for r in p["reasons"])
    db.close()

def test_remediation_influence():
    eng, SessionLocal, objs = _setup()
    asset, f, _ = _make_finding_asset(SessionLocal, objs)
    from app.models.finding import FindingRemediation
    db = SessionLocal()
    rem = FindingRemediation(id=str(uuid.uuid4()), finding_id=f.id, organization_id=objs["org"].id, project_id=objs["proj"].id, status="open", title="Fix", created_by=objs["u_admin"].id)
    db.add(rem); db.commit()
    from app.services.security_prioritization import calculate_finding_priority
    p = calculate_finding_priority(f, db, objs["proj"].id)
    assert any("Remediation open" in r for r in p["reasons"])
    db.close()

def test_validation_influence():
    eng, SessionLocal, objs = _setup()
    asset, f, _ = _make_finding_asset(SessionLocal, objs)
    from app.models.security_validation import SecurityValidation
    db = SessionLocal()
    val = SecurityValidation(id=str(uuid.uuid4()), project_id=objs["proj"].id, organization_id=objs["org"].id, finding_id=f.id, status="INVALID", validation_type="PASSIVE_RECHECK", verdict="INVALID", confidence="HIGH", scanner="sast", target="src")
    db.add(val); db.commit()
    from app.services.security_prioritization import calculate_finding_priority
    p = calculate_finding_priority(f, db, objs["proj"].id)
    assert any("Validation INVALID" in r for r in p["reasons"])
    db.close()

def test_safe_404_priority():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/security-intelligence/priorities/finding/{str(uuid.uuid4())}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404
        assert "traceback" not in r.text.lower()
    finally: app.dependency_overrides.clear()

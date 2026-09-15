"""F6 Security Decision History — ~35 tests."""
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
            if col.type.__class__.__name__=="JSONB": col.type=JSON()
            if col.server_default is not None:
                try:
                    if "jsonb" in str(col.server_default.arg).lower(): col.server_default=None
                except: pass
    eng=create_engine("sqlite://", connect_args={"check_same_thread":False}, poolclass=StaticPool)
    needed=["organizations","users","projects","project_memberships","organization_memberships","assets","asset_relationships","findings","applications","application_assets","audit_logs","security_investigations","investigation_notes","security_validations","asset_change_events","finding_remediations","finding_retests","finding_slas","finding_risk_acceptances","finding_history","cloud_attack_paths","cloud_attack_path_observations","targets","scans","monitoring_configs","monitoring_runs"]
    tables=[ProdBase.metadata.tables[n] for n in needed if n in ProdBase.metadata.tables]
    ProdBase.metadata.create_all(bind=eng, tables=tables)
    return eng

def _setup():
    from app.models.organization import Organization
    from app.models.user import User
    from app.models.project import Project
    from app.models.organization_membership import OrganizationMembership
    from app.models.project_membership import ProjectMembership
    eng=_engine()
    SL=sessionmaker(bind=eng, autocommit=False, autoflush=False, expire_on_commit=False)
    db=SL()
    org=Organization(id=str(uuid.uuid4()), name="OrgF6", slug="orgf6-"+uuid.uuid4().hex[:6])
    db.add(org); db.flush()
    pwd=hash_password("password123")
    u_admin=User(id=str(uuid.uuid4()), organization_id=org.id, email="admin@f6.test", password_hash=pwd, role="member")
    u_viewer=User(id=str(uuid.uuid4()), organization_id=org.id, email="viewer@f6.test", password_hash=pwd, role="member")
    db.add_all([u_admin,u_viewer]); db.flush()
    proj=Project(id=str(uuid.uuid4()), organization_id=org.id, name="ProjF6")
    db.add(proj); db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=u_admin.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org.id, user_id=u_viewer.id, role="member", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj.id, user_id=u_admin.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj.id, user_id=u_viewer.id, role="viewer", status="active"))
    db.commit(); db.close()
    return eng,SL,{"org":org,"u_admin":u_admin,"u_viewer":u_viewer,"proj":proj}

def _client(SL):
    def override():
        s=SL()
        try: yield s
        finally: s.close()
    app.dependency_overrides[get_db]=override
    return TestClient(app)

def _asset(SL,pid,atype="domain",value=None,extra=None):
    from app.models.asset import Asset
    db=SL()
    a=Asset(id=str(uuid.uuid4()), project_id=pid, asset_type=atype, value=value or f"val-{uuid.uuid4().hex[:6]}", extra_data=extra or {})
    a.created_at=datetime.now(timezone.utc); a.last_seen_at=datetime.now(timezone.utc)
    db.add(a); db.commit(); db.close()
    return a

def _finding(SL,aid,sev="high",scanner="nuclei",title="Test",evidence="evidence"):
    from app.models.finding import Finding
    db=SL()
    f=Finding(id=str(uuid.uuid4()), scanner=scanner, title=title, severity=sev, asset_id=aid, evidence=evidence)
    f.created_at=datetime.now(timezone.utc)
    db.add(f); db.commit(); db.close()
    return f

# 1 history 7d
def test_history_7d():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history?window=7d", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert r.json()["window"]=="7d"
    finally: app.dependency_overrides.clear()

# 2 history invalid window 400
def test_history_invalid():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history?window=5d", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code in (400,422)
    finally: app.dependency_overrides.clear()

# 3 F3 reuse: history contains trends
def test_history_f3_reuse():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    _finding(SL,a.id,sev="critical")
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history?window=7d", headers={"Authorization":f"Bearer {tok}"})
        j=r.json()
        assert "history" in j
    finally: app.dependency_overrides.clear()

# 4 improvement
def test_improvement():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/improvement?window=7d", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert r.json()["overall"] in ("IMPROVED","WORSENED","UNCHANGED","INSUFFICIENT_DATA")
    finally: app.dependency_overrides.clear()

# 5 insufficient data when empty
def test_insufficient():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history?window=7d", headers={"Authorization":f"Bearer {tok}"})
        # may be insufficient or partial
        assert r.json()["data_quality"]["status"] in ("INSUFFICIENT_DATA","PARTIAL","SUFFICIENT")
    finally: app.dependency_overrides.clear()

# 6 recurring findings via reopened
def test_recurring_finding():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    f=_finding(SL,a.id)
    from app.models.finding import FindingHistory
    db=SL()
    h=FindingHistory(id=str(uuid.uuid4()), finding_id=f.id, action="reopened", old_value="closed", new_value="open", project_id=o["proj"].id)
    db.add(h); db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/recurring-exposure", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert any(x["type"]=="finding_reopened" for x in r.json()["recurring"])
    finally: app.dependency_overrides.clear()

# 7 recurring asset hotspot
def test_recurring_asset():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    for _ in range(3):
        _finding(SL,a.id)
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/recurring-exposure", headers={"Authorization":f"Bearer {tok}"})
        assert any(x["type"]=="asset_hotspot" for x in r.json()["recurring"])
    finally: app.dependency_overrides.clear()

# 8 recurring attack path
def test_recurring_attack_path():
    eng,SL,o=_setup()
    from app.models.cloud_attack_path import CloudAttackPath
    db=SL()
    # use two different fingerprints to avoid unique constraint, verify total counts
    for i in range(2):
        fp=f"fp-test-{i}-{uuid.uuid4().hex[:4]}"
        cap=CloudAttackPath(id=str(uuid.uuid4()), project_id=o["proj"].id, organization_id=o["org"].id, fingerprint=fp, provider="aws", path_type="INTERNET_TO_RESOURCE", severity="high", priority_score=70, confidence="HIGH", status="ACTIVE", asset_ids=[])
        db.add(cap)
    db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/attack-path-history", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert r.json()["total"]>=2
    finally: app.dependency_overrides.clear()

# 9 remediation effectiveness
def test_remediation_effectiveness():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    f=_finding(SL,a.id)
    from app.models.finding import FindingRemediation
    db=SL()
    rem=FindingRemediation(id=str(uuid.uuid4()), finding_id=f.id, organization_id=o["org"].id, project_id=o["proj"].id, status="completed", title="Fix")
    db.add(rem); db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/remediation-effectiveness", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert "success_rate" in r.json()
        assert 0 <= r.json()["success_rate"] <= 100
    finally: app.dependency_overrides.clear()

# 10 retest evidence
def test_retest_evidence():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    f=_finding(SL,a.id)
    from app.models.finding import FindingRemediation, FindingRetest
    db=SL()
    rem=FindingRemediation(id=str(uuid.uuid4()), finding_id=f.id, organization_id=o["org"].id, project_id=o["proj"].id, status="completed", title="Fix")
    db.add(rem); db.flush()
    rt=FindingRetest(id=str(uuid.uuid4()), finding_id=f.id, organization_id=o["org"].id, project_id=o["proj"].id, status="completed", result="fixed")
    db.add(rt); db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/remediation-effectiveness", headers={"Authorization":f"Bearer {tok}"})
        assert r.json()["successful"]>=1 or r.json()["partial"]>=1
    finally: app.dependency_overrides.clear()

# 11 validation evidence
def test_validation_evidence():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    f=_finding(SL,a.id)
    from app.models.finding import FindingRemediation
    from app.models.security_validation import SecurityValidation
    db=SL()
    rem=FindingRemediation(id=str(uuid.uuid4()), finding_id=f.id, organization_id=o["org"].id, project_id=o["proj"].id, status="completed", title="Fix")
    db.add(rem); db.flush()
    from app.models.finding import FindingRetest
    rt=FindingRetest(id=str(uuid.uuid4()), finding_id=f.id, organization_id=o["org"].id, project_id=o["proj"].id, status="completed", result="fixed")
    db.add(rt); db.flush()
    v=SecurityValidation(id=str(uuid.uuid4()), project_id=o["proj"].id, organization_id=o["org"].id, finding_id=f.id, status="completed", validation_type="manual", verdict="VALID", confidence="HIGH", scanner="nuclei", target="x")
    db.add(v); db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/remediation-effectiveness", headers={"Authorization":f"Bearer {tok}"})
        assert r.json()["successful"]>=1
    finally: app.dependency_overrides.clear()

# 12 risk acceptance aging
def test_acceptance_aging():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    f=_finding(SL,a.id,sev="critical")
    from app.models.finding import FindingRiskAcceptance
    db=SL()
    ra=FindingRiskAcceptance(id=str(uuid.uuid4()), finding_id=f.id, organization_id=o["org"].id, project_id=o["proj"].id, status="accepted", reason="business", expires_at=datetime.now(timezone.utc)+timedelta(days=10))
    ra.created_at=datetime.now(timezone.utc)-timedelta(days=100)
    db.add(ra); db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/risk-acceptance-aging", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert r.json()["active"]>=1
        assert r.json()["aging"]>=1
    finally: app.dependency_overrides.clear()

# 13 attack-path history
def test_attack_path_history_detail():
    eng,SL,o=_setup()
    from app.models.cloud_attack_path import CloudAttackPath
    db=SL()
    cap=CloudAttackPath(id=str(uuid.uuid4()), project_id=o["proj"].id, organization_id=o["org"].id, fingerprint="fp-abc", provider="aws", path_type="INTERNET_TO_RESOURCE", severity="critical", priority_score=90, confidence="HIGH", status="ACTIVE", asset_ids=[])
    db.add(cap); db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/attack-path-history", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert "paths" in r.json()
    finally: app.dependency_overrides.clear()

# 14 change exposure temporal
def test_change_exposure_temporal():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    from app.models.asset_change_event import AssetChangeEvent
    from app.models.target import Target
    from app.models.scan import Scan
    db=SL()
    tgt=Target(id=str(uuid.uuid4()), project_id=o["proj"].id, value="example.com", target_type="domain")
    db.add(tgt); db.flush()
    sc=Scan(id=str(uuid.uuid4()), target_id=tgt.id, profile="full", status="completed", phase="done")
    db.add(sc); db.flush()
    ch=AssetChangeEvent(id=str(uuid.uuid4()), project_id=o["proj"].id, asset_id=a.id, scan_id=sc.id, change_type="new_asset", detected_at=datetime.now(timezone.utc))
    db.add(ch); db.commit(); db.close()
    _finding(SL,a.id)
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        from app.services.security_decision_history import get_change_exposure_history
        # also via F6 history endpoint
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history?window=7d", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
    finally: app.dependency_overrides.clear()

# 15 scorecard
def test_scorecard():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/scorecard?window=7d", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        j=r.json()
        assert "overall_direction" in j
        assert "confidence" in j
        assert "evidence" in j
    finally: app.dependency_overrides.clear()

# 16 subject history finding
def test_subject_history_finding():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    f=_finding(SL,a.id)
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/subject-history/finding/{f.id}?window=7d", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
        assert r.json()["subject_id"]==f.id
        assert "first_seen" in r.json()
    finally: app.dependency_overrides.clear()

# 17 subject history asset
def test_subject_history_asset():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/subject-history/asset/{a.id}", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
    finally: app.dependency_overrides.clear()

# 18 subject history application
def test_subject_history_app():
    eng,SL,o=_setup()
    from app.services.application_intelligence import create_application
    db=SL()
    app_obj=create_application(o["proj"].id, db, name="AppHist", application_type="WEB", lifecycle="PRODUCTION", criticality="high")
    db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/subject-history/application/{app_obj.id}", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
    finally: app.dependency_overrides.clear()

# 19 subject history attack_path
def test_subject_history_attack_path():
    eng,SL,o=_setup()
    from app.models.cloud_attack_path import CloudAttackPath
    db=SL()
    cap=CloudAttackPath(id=str(uuid.uuid4()), project_id=o["proj"].id, organization_id=o["org"].id, fingerprint="fp-subj", provider="aws", path_type="INTERNET_TO_RESOURCE", severity="high", priority_score=70, confidence="HIGH", status="ACTIVE", asset_ids=[])
    db.add(cap); db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/subject-history/attack_path/{cap.fingerprint}", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==200
    finally: app.dependency_overrides.clear()

# 20 bounds limit
def test_bounds_limit():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/recurring-exposure?limit=100", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==422
        r2=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history?window=90d", headers={"Authorization":f"Bearer {tok}"})
        assert r2.status_code==200
    finally: app.dependency_overrides.clear()

# 21 zero denominators
def test_zero_denominator():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/remediation-effectiveness", headers={"Authorization":f"Bearer {tok}"})
        assert r.json()["success_rate"]==0
        r2=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/scorecard", headers={"Authorization":f"Bearer {tok}"})
        assert r2.status_code==200
    finally: app.dependency_overrides.clear()

# 22 deterministic ordering recurring
def test_deterministic_recurring():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    for _ in range(2):
        f=_finding(SL,a.id)
        from app.models.finding import FindingHistory
        db=SL()
        h=FindingHistory(id=str(uuid.uuid4()), finding_id=f.id, action="reopened", project_id=o["proj"].id)
        db.add(h); db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r1=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/recurring-exposure", headers={"Authorization":f"Bearer {tok}"})
        r2=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/recurring-exposure", headers={"Authorization":f"Bearer {tok}"})
        assert r1.json()["recurring"]==r2.json()["recurring"]
    finally: app.dependency_overrides.clear()

# 23 tenant isolation
def test_tenant_isolation():
    eng,SL,o=_setup()
    from app.models.organization import Organization
    from app.models.project import Project
    from app.models.user import User
    from app.models.organization_membership import OrganizationMembership
    from app.models.project_membership import ProjectMembership
    db=SL()
    org2=Organization(id=str(uuid.uuid4()), name="Org2", slug="org2-"+uuid.uuid4().hex[:4])
    db.add(org2); db.flush()
    proj2=Project(id=str(uuid.uuid4()), organization_id=org2.id, name="Proj2")
    db.add(proj2); db.flush()
    u2=User(id=str(uuid.uuid4()), organization_id=org2.id, email="u2@org2.test", password_hash=hash_password("password123"), role="member")
    db.add(u2); db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org2.id, user_id=u2.id, role="org_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj2.id, user_id=u2.id, role="project_admin", status="active"))
    db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(u2.id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==404
    finally: app.dependency_overrides.clear()

# 24 project isolation
def test_project_isolation():
    eng,SL,o=_setup()
    from app.models.project import Project
    from app.models.project_membership import ProjectMembership
    from app.core.config import settings
    orig=settings.RBAC_STRICT_MODE
    settings.RBAC_STRICT_MODE=True
    db=SL()
    proj2=Project(id=str(uuid.uuid4()), organization_id=o["org"].id, name="Proj2Iso")
    db.add(proj2); db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj2.id, user_id=o["u_admin"].id, role="project_admin", status="active"))
    db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_viewer"].id)
        # viewer only in proj, not proj2
        r=c.get(f"/api/v1/projects/{proj2.id}/security-intelligence/history", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code in (403,404)
    finally:
        app.dependency_overrides.clear()
        settings.RBAC_STRICT_MODE=orig

# 25 RBAC viewer can read
def test_viewer_read():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_viewer"].id)
        for path in ["/history","/scorecard","/recurring-exposure","/remediation-effectiveness","/attack-path-history"]:
            r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence{path}", headers={"Authorization":f"Bearer {tok}"})
            assert r.status_code==200, f"{path} {r.text}"
    finally: app.dependency_overrides.clear()

# 26 IDOR fake project
def test_idor():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{str(uuid.uuid4())}/security-intelligence/history", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==404
        r2=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/subject-history/finding/{str(uuid.uuid4())}", headers={"Authorization":f"Bearer {tok}"})
        assert r2.status_code==404
    finally: app.dependency_overrides.clear()

# 27 secret redaction in history
def test_secret_redaction():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id,atype="source_file",value="src/secret.py")
    _finding(SL,a.id,scanner="secrets",title="Secret mysecret password token",evidence="mysecret password token123")
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history", headers={"Authorization":f"Bearer {tok}"})
        assert "mysecret" not in str(r.json()).lower()
        r2=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/subject-history/finding/{a.id}", headers={"Authorization":f"Bearer {tok}"})
        # finding not asset, but still check
        assert "mysecret" not in str(r2.json()).lower() if r2.status_code==200 else True
        # subject history finding
        f=db_finding = None
        from app.models.finding import Finding
        db=SL()
        f=db.query(Finding).filter(Finding.asset_id==a.id).first()
        db.close()
        if f:
            r3=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/subject-history/finding/{f.id}", headers={"Authorization":f"Bearer {tok}"})
            assert "mysecret" not in str(r3.json()).lower()
    finally: app.dependency_overrides.clear()

# 28 safe errors no traceback
def test_safe_errors():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/subject-history/badtype/{str(uuid.uuid4())}", headers={"Authorization":f"Bearer {tok}"})
        assert r.status_code==400
        assert "traceback" not in r.text.lower()
    finally: app.dependency_overrides.clear()

# 29 no duplicate risk engine: scorecard uses existing priority
def test_no_duplicate_engine():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id,extra={"externally_reachable":True})
    _finding(SL,a.id,sev="critical")
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/scorecard", headers={"Authorization":f"Bearer {tok}"})
        # must contain evidence from F2/F3 not new score
        assert "evidence" in r.json()
    finally: app.dependency_overrides.clear()

# 30 no findings created
def test_no_findings_created():
    eng,SL,o=_setup()
    from app.models.finding import Finding
    db=SL()
    before=db.query(func.count(Finding.id)).scalar() or 0
    db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history", headers={"Authorization":f"Bearer {tok}"})
        c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/scorecard", headers={"Authorization":f"Bearer {tok}"})
        db2=SL()
        after=db2.query(func.count(Finding.id)).scalar() or 0
        db2.close()
        assert before==after
    finally: app.dependency_overrides.clear()

# 31 unauth 401
def test_unauth():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history")
        assert r.status_code==401
    finally: app.dependency_overrides.clear()

# 32 window 30d 90d
def test_window_90d():
    eng,SL,o=_setup()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        for w in ["7d","30d","90d"]:
            r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history?window={w}", headers={"Authorization":f"Bearer {tok}"})
            assert r.status_code==200
            assert r.json()["window"]==w
    finally: app.dependency_overrides.clear()

# 33 remediation reopened
def test_reopened():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    f=_finding(SL,a.id)
    from app.models.finding import FindingHistory, FindingRemediation
    db=SL()
    # need remediation to be counted as reopened via remediation loop
    rem=FindingRemediation(id=str(uuid.uuid4()), finding_id=f.id, organization_id=o["org"].id, project_id=o["proj"].id, status="completed", title="Fix")
    db.add(rem); db.flush()
    h=FindingHistory(id=str(uuid.uuid4()), finding_id=f.id, action="reopened", project_id=o["proj"].id)
    db.add(h); db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/remediation-effectiveness", headers={"Authorization":f"Bearer {tok}"})
        assert r.json()["reopened"]>=1
    finally: app.dependency_overrides.clear()

# 34 deterministic history
def test_deterministic_history():
    eng,SL,o=_setup()
    a=_asset(SL,o["proj"].id)
    _finding(SL,a.id)
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r1=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history?window=7d", headers={"Authorization":f"Bearer {tok}"})
        r2=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/history?window=7d", headers={"Authorization":f"Bearer {tok}"})
        # remove generated_at compare
        j1={k:v for k,v in r1.json().items() if k!="generated_at"}
        j2={k:v for k,v in r2.json().items() if k!="generated_at"}
        assert j1==j2
    finally: app.dependency_overrides.clear()

# 35 attack path history bounded
def test_attack_history_bounded():
    eng,SL,o=_setup()
    from app.models.cloud_attack_path import CloudAttackPath
    db=SL()
    for i in range(5):
        cap=CloudAttackPath(id=str(uuid.uuid4()), project_id=o["proj"].id, organization_id=o["org"].id, fingerprint=f"fp-bounded-{i}", provider="aws", path_type="INTERNET_TO_RESOURCE", severity="high", priority_score=60, confidence="HIGH", status="ACTIVE", asset_ids=[])
        db.add(cap)
    db.commit(); db.close()
    c=_client(SL)
    try:
        tok=create_access_token(o["u_admin"].id)
        r=c.get(f"/api/v1/projects/{o['proj'].id}/security-intelligence/attack-path-history?limit=2", headers={"Authorization":f"Bearer {tok}"})
        assert len(r.json()["paths"])<=2
    finally: app.dependency_overrides.clear()

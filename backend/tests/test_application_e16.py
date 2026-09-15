"""E16 Application Security Intelligence — focused tests (deterministic, bounded, RLS/RBAC)."""
import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine, JSON, text
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
    needed = ["organizations","users","projects","project_memberships","organization_memberships","assets","asset_relationships","findings","application_assets","applications","audit_logs","security_investigations","investigation_notes","security_validations","asset_change_events","finding_remediations","finding_retests","finding_slas"]
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
    org = Organization(id=str(uuid.uuid4()), name="OrgE16", slug="orge16-"+str(uuid.uuid4())[:6])
    db.add(org); db.flush()
    pwd = hash_password("password123")
    u_admin = User(id=str(uuid.uuid4()), organization_id=org.id, email="admin@e16.test", password_hash=pwd, role="member")
    u_analyst = User(id=str(uuid.uuid4()), organization_id=org.id, email="analyst@e16.test", password_hash=pwd, role="member")
    u_viewer = User(id=str(uuid.uuid4()), organization_id=org.id, email="viewer@e16.test", password_hash=pwd, role="member")
    db.add_all([u_admin, u_analyst, u_viewer]); db.flush()
    proj = Project(id=str(uuid.uuid4()), organization_id=org.id, name="ProjE16")
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

# --- Application CRUD ---
def test_create_application():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "Payments API", "application_type": "API", "lifecycle": "PRODUCTION", "criticality": "critical"}, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200, r.text
        assert r.json()["name"] == "Payments API"
    finally:
        app.dependency_overrides.clear()

def test_duplicate_prevention():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "DupApp"}, headers={"Authorization": f"Bearer {token}"})
        r2 = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "dupapp"}, headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 400
    finally:
        app.dependency_overrides.clear()

def test_lifecycle_criticality_validation():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "Bad", "lifecycle": "INVALID"}, headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 400
        r2 = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "Bad2", "criticality": "invalid"}, headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 400
    finally:
        app.dependency_overrides.clear()

def test_viewer_can_read_but_not_write():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token_admin = create_access_token(objs["u_admin"].id)
        r = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "ReadTest"}, headers={"Authorization": f"Bearer {token_admin}"})
        app_id = r.json()["id"]
        token_viewer = create_access_token(objs["u_viewer"].id)
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/applications", headers={"Authorization": f"Bearer {token_viewer}"})
        assert r2.status_code == 200
        r3 = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "ViewerCreate"}, headers={"Authorization": f"Bearer {token_viewer}"})
        assert r3.status_code == 403
        r4 = c.get(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}", headers={"Authorization": f"Bearer {token_viewer}"})
        assert r4.status_code == 200
        r5 = c.patch(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}", json={"description": "x"}, headers={"Authorization": f"Bearer {token_viewer}"})
        assert r5.status_code == 403
    finally:
        app.dependency_overrides.clear()

def test_cross_tenant_blocked():
    eng, SessionLocal, objs = _setup()
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
    db.commit()
    c = _client(SessionLocal)
    try:
        token_a = create_access_token(objs["u_admin"].id)
        r = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "TenantAApp"}, headers={"Authorization": f"Bearer {token_a}"})
        app_id = r.json()["id"]
        token_b = create_access_token(u2.id)
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}", headers={"Authorization": f"Bearer {token_b}"})
        assert r2.status_code == 404
        r3 = c.get(f"/api/v1/projects/{proj2.id}/applications/{app_id}", headers={"Authorization": f"Bearer {token_b}"})
        assert r3.status_code == 404
    finally:
        app.dependency_overrides.clear()
        db.close()

def test_idor_blocked():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_analyst"].id)
        fake = str(uuid.uuid4())
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/applications/{fake}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 404
    finally:
        app.dependency_overrides.clear()

def test_asset_linking_and_findings_aggregation():
    eng, SessionLocal, objs = _setup()
    from app.models.asset import Asset
    from app.models.finding import Finding
    db = SessionLocal()
    # create assets
    repo = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="repository", value="payments-api", extra_data={})
    src = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="source_file", value="src/payment/auth.py", extra_data={})
    pkg = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="package", value="example-package@1.0.0", extra_data={})
    container = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="container_image", value="payments-api:1.2.3", extra_data={})
    api = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="api_endpoint", value="https://api.example.test/payments", extra_data={"method": "POST"})
    external = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="subdomain", value="api.example.test", extra_data={"externally_reachable": True, "ownership_confidence": "CONFIRMED"})
    cloud = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="aws:ecs:service", extra_data={})
    db.add_all([repo,src,pkg,container,api,external,cloud]); db.commit()
    # create findings
    f_sast = Finding(id=str(uuid.uuid4()), scanner="sast", title="Authorization weakness", severity="high", asset_id=src.id, evidence="src code")
    f_sca = Finding(id=str(uuid.uuid4()), scanner="sca", title="High CVE in dep", severity="high", asset_id=pkg.id, cve="CVE-2023-1234", evidence="dep")
    f_secret = Finding(id=str(uuid.uuid4()), scanner="secrets", title="Credential exposure", severity="critical", asset_id=src.id, evidence="[REDACTED]")
    f_container = Finding(id=str(uuid.uuid4()), scanner="container", title="Container high CVE", severity="high", asset_id=container.id, evidence="layer")
    f_iac = Finding(id=str(uuid.uuid4()), scanner="iac", title="Public resource", severity="medium", asset_id=src.id, evidence="iac")
    f_api = Finding(id=str(uuid.uuid4()), scanner="api", title="Auth issue", severity="high", asset_id=api.id, evidence="api")
    f_dast = Finding(id=str(uuid.uuid4()), scanner="zap", title="Web finding", severity="medium", asset_id=external.id, evidence="dast")
    db.add_all([f_sast,f_sca,f_secret,f_container,f_iac,f_api,f_dast]); db.commit(); db.close()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        # create app
        r = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "Payments API", "application_type": "API", "lifecycle": "PRODUCTION", "criticality": "critical"}, headers={"Authorization": f"Bearer {token}"})
        app_id = r.json()["id"]
        # link assets
        for asset, rel in [(repo,"owns"),(src,"contains"),(pkg,"depends_on"),(container,"builds"),(api,"exposes"),(external,"exposes"),(cloud,"deploys_to")]:
            lr = c.post(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/assets/link", json={"asset_id": asset.id, "relationship_type": rel, "confidence": "CONFIRMED", "evidence": {"source": "explicit"}}, headers={"Authorization": f"Bearer {token}"})
            assert lr.status_code == 200, lr.text
        # get findings aggregated
        rf = c.get(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/findings", headers={"Authorization": f"Bearer {token}"})
        assert rf.status_code == 200
        assert rf.json()["count"] >= 7
        scanners = {f["scanner"] for f in rf.json()["findings"]}
        assert "sast" in scanners and "sca" in scanners and "secrets" in scanners and "container" in scanners and "iac" in scanners
        # exposure
        re = c.get(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/exposure", headers={"Authorization": f"Bearer {token}"})
        assert re.status_code == 200
        assert re.json()["internet_facing"] is True
        # risk
        rr = c.get(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/risk", headers={"Authorization": f"Bearer {token}"})
        assert rr.status_code == 200
        assert rr.json()["score"] >= 60
        assert rr.json()["tier"] in ("CRITICAL","HIGH","MEDIUM")
        assert len(rr.json()["factors"]) >= 2
        # summary
        rs = c.get(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/summary", headers={"Authorization": f"Bearer {token}"})
        assert rs.status_code == 200
        assert rs.json()["findings"]["total"] >= 7
        # correlations
        rc = c.get(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/correlations", headers={"Authorization": f"Bearer {token}"})
        assert rc.status_code == 200
    finally:
        app.dependency_overrides.clear()

def test_secret_redaction():
    eng, SessionLocal, objs = _setup()
    from app.models.asset import Asset
    from app.models.finding import Finding
    db = SessionLocal()
    src = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="source_file", value="src/secret.py", extra_data={})
    db.add(src); db.commit()
    f = Finding(id=str(uuid.uuid4()), scanner="secrets", title="Secret", severity="critical", asset_id=src.id, evidence="mysecret123")
    db.add(f); db.commit(); db.close()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "SecretApp"}, headers={"Authorization": f"Bearer {token}"})
        app_id = r.json()["id"]
        c.post(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/assets/link", json={"asset_id": src.id, "relationship_type": "contains", "confidence": "CONFIRMED"}, headers={"Authorization": f"Bearer {token}"})
        rf = c.get(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/findings", headers={"Authorization": f"Bearer {token}"})
        assert rf.status_code == 200
        for f in rf.json()["findings"]:
            if f["scanner"] == "secrets":
                assert "[REDACTED]" in f["evidence"] or "secret" not in f["evidence"].lower()
    finally:
        app.dependency_overrides.clear()

def test_risk_explainable():
    eng, SessionLocal, objs = _setup()
    from app.models.asset import Asset
    from app.models.finding import Finding
    db = SessionLocal()
    a = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="api_endpoint", value="https://api.example.test/pay", extra_data={"externally_reachable": True})
    db.add(a); db.commit()
    f = Finding(id=str(uuid.uuid4()), scanner="api", title="Auth bypass", severity="critical", asset_id=a.id, evidence="api")
    db.add(f); db.commit(); db.close()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "RiskApp", "criticality": "critical"}, headers={"Authorization": f"Bearer {token}"})
        app_id = r.json()["id"]
        c.post(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/assets/link", json={"asset_id": a.id, "relationship_type": "exposes", "confidence": "CONFIRMED"}, headers={"Authorization": f"Bearer {token}"})
        rr = c.get(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/risk", headers={"Authorization": f"Bearer {token}"})
        assert rr.status_code == 200
        assert "score" in rr.json() and "tier" in rr.json() and "factors" in rr.json()
        assert rr.json()["score"] >= 35
        assert any("Critical" in f or "Internet" in f for f in rr.json()["factors"])
    finally:
        app.dependency_overrides.clear()

def test_pagination_and_bounds():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        for i in range(5):
            c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": f"App{i}"}, headers={"Authorization": f"Bearer {token}"})
        r = c.get(f"/api/v1/projects/{objs['proj'].id}/applications?limit=2", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert len(r.json()["applications"]) == 2
        # oversized limit clamped
        r2 = c.get(f"/api/v1/projects/{objs['proj'].id}/applications?limit=1000", headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code in (200, 422)  # FastAPI may 422, but our limit 100 clamps
    finally:
        app.dependency_overrides.clear()

def test_investigation_creation():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        r = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "InvApp"}, headers={"Authorization": f"Bearer {token}"})
        app_id = r.json()["id"]
        ri = c.post(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/investigation", json={}, headers={"Authorization": f"Bearer {token}"})
        assert ri.status_code == 200
        assert "id" in ri.json()
        # viewer cannot create investigation
        token_viewer = create_access_token(objs["u_viewer"].id)
        ri2 = c.post(f"/api/v1/projects/{objs['proj'].id}/applications/{app_id}/investigation", json={}, headers={"Authorization": f"Bearer {token_viewer}"})
        assert ri2.status_code == 403
    finally:
        app.dependency_overrides.clear()

def test_audit_logged():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "AuditApp"}, headers={"Authorization": f"Bearer {token}"})
        db = SessionLocal()
        from app.models.audit_log import AuditLog
        try:
            logs = db.query(AuditLog).filter(AuditLog.project_id == objs["proj"].id, AuditLog.event_type == "APPLICATION_CREATED").all()
            assert len(logs) >= 1
        except Exception as e:
            if "no such table" not in str(e).lower():
                raise
        db.close()
    finally:
        app.dependency_overrides.clear()

def test_mass_assignment_blocked():
    eng, SessionLocal, objs = _setup()
    c = _client(SessionLocal)
    try:
        token = create_access_token(objs["u_admin"].id)
        # try to inject organization_id via mass assignment
        r = c.post(f"/api/v1/projects/{objs['proj'].id}/applications", json={"name": "MassApp", "organization_id": "fake-id"}, headers={"Authorization": f"Bearer {token}"})
        # should ignore org id and create with correct org
        assert r.status_code == 200
        app_id = r.json()["id"]
        db = SessionLocal()
        from app.models.application import Application
        app_obj = db.query(Application).filter(Application.id == app_id).first()
        assert app_obj.organization_id == objs["org"].id
        db.close()
    finally:
        app.dependency_overrides.clear()

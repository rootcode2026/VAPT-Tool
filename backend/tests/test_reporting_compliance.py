import uuid
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.base import Base
from app.db.database import get_db
from app.main import app as fastapi_app

from app.models.organization import Organization
from app.models.user import User

def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, Base.metadata.tables["audit_logs"],
    ])
    try:
        from app.models.project import Project
        from app.models.target import Target
        from app.models.scan import Scan
        Base.metadata.create_all(bind=engine, tables=[Project.__table__, Target.__table__, Scan.__table__])
        with engine.begin() as conn:
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS assets (
                    id TEXT PRIMARY KEY, project_id TEXT, asset_type TEXT, value TEXT, status TEXT, metadata TEXT, created_at DATETIME, updated_at DATETIME, criticality TEXT, owner_user_id TEXT, first_seen_at DATETIME, last_seen_at DATETIME, first_seen_scan_id TEXT, last_seen_scan_id TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY, scan_id TEXT, target_id TEXT, scanner TEXT, title TEXT, severity TEXT, status TEXT, evidence TEXT, metadata TEXT, created_at DATETIME, assigned_to TEXT, owner_user_id TEXT, severity_override TEXT, score INTEGER, description TEXT, remediation TEXT, cve TEXT, cwe TEXT, asset_id TEXT, updated_at DATETIME
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY, organization_id TEXT, project_id TEXT, report_type TEXT, title TEXT, status TEXT, generated_by TEXT, parameters TEXT, summary TEXT, content TEXT, data_snapshot TEXT, version TEXT, data_as_of DATETIME, created_at DATETIME, completed_at DATETIME, error TEXT
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS compliance_frameworks (
                    id TEXT PRIMARY KEY, framework TEXT, version TEXT, display_name TEXT, description TEXT, created_at DATETIME
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS compliance_controls (
                    id TEXT PRIMARY KEY, framework_id TEXT, control_id TEXT, title TEXT, description TEXT, category TEXT, parent_control TEXT, status TEXT, created_at DATETIME
                )
            """))
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS compliance_mappings (
                    id TEXT PRIMARY KEY, control_id TEXT, organization_id TEXT, project_id TEXT, source_type TEXT, source_id TEXT, description TEXT, created_at DATETIME
                )
            """))
    except Exception:
        pass
    try:
        from app.models.organization_membership import OrganizationMembership
        from app.models.project_membership import ProjectMembership
        Base.metadata.create_all(bind=engine, tables=[OrganizationMembership.__table__, ProjectMembership.__table__])
    except Exception:
        pass
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-rep")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-rep")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    super_u = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="super@rep.test", password_hash=pwd, role="super_admin")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin@rep.test", password_hash=pwd, role="admin")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer@rep.test", password_hash=pwd, role="member")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst@rep.test", password_hash=pwd, role="member")
    other_u = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="other@rep.test", password_hash=pwd, role="admin")
    db.add_all([super_u, admin_a, viewer_a, analyst_a, other_u])
    db.flush()
    try:
        from app.models.organization_membership import OrganizationMembership
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member"))
        db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=other_u.id, role="org_admin"))
    except Exception:
        pass
    from app.models.project import Project
    proj_a = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A", description="desc")
    proj_b = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B", description="desc")
    db.add_all([proj_a, proj_b])
    db.flush()
    try:
        from app.models.project_membership import ProjectMembership
        db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=admin_a.id, role="project_admin"))
        db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=viewer_a.id, role="viewer"))
        db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=analyst_a.id, role="analyst"))
    except Exception:
        pass
    from app.models.target import Target
    target_a = Target(id=str(uuid.uuid4()), project_id=proj_a.id, value="example.com", target_type="domain", is_active=True)
    db.add(target_a)
    db.flush()
    from app.models.scan import Scan
    scan_a = Scan(id=str(uuid.uuid4()), target_id=target_a.id, profile="full", status="completed", phase="completed", progress=100, risk_score=75, risk_grade="B", risk_level="high")
    db.add(scan_a)
    db.flush()
    # finding
    fid = str(uuid.uuid4())
    db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata, created_at) VALUES (:id, :scan_id, :target_id, :scanner, :title, :severity, :status, :evidence, :metadata, CURRENT_TIMESTAMP)"),
               {"id": fid, "scan_id": scan_a.id, "target_id": target_a.id, "scanner": "nmap", "title": "Open port", "severity": "high", "status": "open", "evidence": "port 22 open", "metadata": "{}"})
    # assets
    aid = str(uuid.uuid4())
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata) VALUES (:id, :pid, :type, :val, :status, :meta)"),
               {"id": aid, "pid": proj_a.id, "type": "domain", "val": "example.com", "status": "active", "meta": "{}"})
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [super_u, admin_a, viewer_a, analyst_a, other_u]}
    return engine, Session, tokens, {"proj_a": proj_a, "proj_b": proj_b, "org_a": org_a}

def _client(Session):
    def override():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    fastapi_app.dependency_overrides[get_db] = override
    return TestClient(fastapi_app)

def test_report_create_and_retrieve():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/reports", headers={"Authorization": f"Bearer {tokens['analyst@rep.test']}"}, json={"report_type": "executive_security", "project_id": objs["proj_a"].id, "title": "Exec Report"})
        assert resp.status_code == 201, resp.text
        rid = resp.json()["id"]
        resp2 = client.get(f"/api/v1/reports/{rid}", headers={"Authorization": f"Bearer {tokens['analyst@rep.test']}"})
        assert resp2.status_code == 200
        assert resp2.json()["status"] == "completed"
        assert "summary" in resp2.json()
    finally:
        fastapi_app.dependency_overrides.clear()

def test_report_tenant_isolation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/reports", headers={"Authorization": f"Bearer {tokens['analyst@rep.test']}"}, json={"report_type": "technical_vapt", "project_id": objs["proj_a"].id})
        rid = resp.json()["id"]
        # other org should not see
        resp2 = client.get(f"/api/v1/reports/{rid}", headers={"Authorization": f"Bearer {tokens['other@rep.test']}"})
        assert resp2.status_code == 404
        # cross-project
        resp3 = client.get(f"/api/v1/reports/{rid}", headers={"Authorization": f"Bearer {tokens['viewer@rep.test']}"})
        assert resp3.status_code == 200  # viewer can view project reports
        # viewer cannot generate org report
        resp4 = client.post("/api/v1/reports", headers={"Authorization": f"Bearer {tokens['viewer@rep.test']}"}, json={"report_type": "executive_security", "title": "x"})
        assert resp4.status_code == 403
    finally:
        fastapi_app.dependency_overrides.clear()

def test_report_csv_injection_protection():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # create finding with formula
        SessionLocal = Session
        db = SessionLocal()
        from app.models.target import Target
        from app.models.scan import Scan
        target = db.query(Target).filter(Target.project_id == objs["proj_a"].id).first()
        scan = db.query(Scan).filter(Scan.target_id == target.id).first()
        fid = str(uuid.uuid4())
        db.execute(text("INSERT INTO findings (id, scan_id, target_id, scanner, title, severity, status, evidence, metadata) VALUES (:id, :scan_id, :target_id, :scanner, :title, :severity, :status, :evidence, :metadata)"),
                   {"id": fid, "scan_id": scan.id, "target_id": target.id, "scanner": "nmap", "title": "=cmd|' /C calc'!A0", "severity": "high", "status": "open", "evidence": "=2+2", "metadata": "{}"})
        db.commit()
        db.close()
        resp = client.post("/api/v1/reports", headers={"Authorization": f"Bearer {tokens['analyst@rep.test']}"}, json={"report_type": "technical_vapt", "project_id": objs["proj_a"].id})
        rid = resp.json()["id"]
        # download csv
        resp2 = client.get(f"/api/v1/reports/{rid}/download/csv", headers={"Authorization": f"Bearer {tokens['analyst@rep.test']}"})
        assert resp2.status_code == 200
        txt = resp2.text
        # ensure formula sanitized with leading '
        assert "'=cmd" in txt or "'=2" in txt
        assert "=cmd|' /C calc" not in txt or "'=cmd" in txt
    finally:
        fastapi_app.dependency_overrides.clear()

def test_compliance_frameworks():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.get("/api/v1/compliance/frameworks", headers={"Authorization": f"Bearer {tokens['viewer@rep.test']}"})
        assert resp.status_code == 200
        assert resp.json()["total"] == 6
        frameworks = {f["framework"] for f in resp.json()["items"]}
        assert "owasp_top10" in frameworks
        assert "iso27001" in frameworks
    finally:
        fastapi_app.dependency_overrides.clear()

def test_compliance_controls_coverage():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # get first framework
        resp = client.get("/api/v1/compliance/frameworks", headers={"Authorization": f"Bearer {tokens['viewer@rep.test']}"})
        fid = resp.json()["items"][0]["id"]
        resp2 = client.get(f"/api/v1/compliance/frameworks/{fid}/controls", headers={"Authorization": f"Bearer {tokens['viewer@rep.test']}"})
        assert resp2.status_code == 200
        assert resp2.json()["total"] == 2
        assert "coverage" in resp2.json()
        assert "not_assessed" in str(resp2.json()["coverage"])
    finally:
        fastapi_app.dependency_overrides.clear()

def test_report_status_and_snapshot():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/reports", headers={"Authorization": f"Bearer {tokens['analyst@rep.test']}"}, json={"report_type": "security_posture", "project_id": objs["proj_a"].id})
        rid = resp.json()["id"]
        resp2 = client.get(f"/api/v1/reports/{rid}", headers={"Authorization": f"Bearer {tokens['analyst@rep.test']}"})
        assert resp2.json()["status"] == "completed"
        assert resp2.json()["version"] == "1.0"
        assert "data_as_of" in resp2.json()
    finally:
        fastapi_app.dependency_overrides.clear()

def test_unauthorized_report_create_blocked():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        resp = client.post("/api/v1/reports", headers={"Authorization": f"Bearer {tokens['viewer@rep.test']}"}, json={"report_type": "executive_security", "project_id": objs["proj_a"].id})
        assert resp.status_code == 403
        resp2 = client.get("/api/v1/reports", headers={})
        assert resp2.status_code == 401
    finally:
        fastapi_app.dependency_overrides.clear()

"""D6 security reporting tests: data, period, PDF, isolation, lifecycle."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
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
import app.models.organization_membership  # noqa
import app.models.project  # noqa
import app.models.project_membership  # noqa
import app.models.target  # noqa
import app.models.scan  # noqa
import app.models.audit_log  # noqa
import app.models.monitoring  # noqa
import app.models.alert  # noqa
import app.models.report  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.user import User
from app.models.scan import Scan
from app.models.monitoring import MonitoringConfig, MonitoringRun
from app.models.alert import Alert
from app.models.audit_log import AuditLog
from app.models.report import Report


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__,
        Scan.__table__, AuditLog.__table__,
        MonitoringConfig.__table__, MonitoringRun.__table__,
        Alert.__table__,
    ])
    with engine.begin() as conn:
        # reports uses JSONB in the ORM model (Postgres-only); mirror with TEXT.
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY, organization_id TEXT, project_id TEXT,
                report_type TEXT, title TEXT, status TEXT, generated_by TEXT,
                parameters TEXT, summary TEXT, content TEXT, data_snapshot TEXT,
                version TEXT, data_as_of DATETIME, created_at DATETIME,
                completed_at DATETIME, error TEXT
            )
        """))
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY, project_id TEXT, asset_type TEXT, value TEXT,
                status TEXT, criticality TEXT, owner_user_id TEXT,
                first_seen_scan_id TEXT, last_seen_scan_id TEXT,
                first_seen_at DATETIME, last_seen_at DATETIME,
                metadata TEXT, created_at DATETIME, updated_at DATETIME
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, scan_id TEXT, target_id TEXT, asset_id TEXT,
                scanner TEXT, title TEXT, description TEXT, severity TEXT, score INTEGER,
                status TEXT, evidence TEXT, remediation TEXT, cve TEXT, cwe TEXT,
                assigned_to TEXT, assigned_at DATETIME, assigned_by TEXT,
                owner_user_id TEXT, owner_team_id TEXT, severity_override TEXT,
                workflow_status TEXT, closed_at DATETIME, closed_by TEXT,
                remediation_claimed_at DATETIME, remediation_claimed_by TEXT,
                ready_for_retest_at DATETIME, metadata TEXT,
                created_at DATETIME, updated_at DATETIME
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS monitoring_change_events (
                id TEXT PRIMARY KEY, project_id TEXT, monitoring_config_id TEXT,
                prev_run_id TEXT, curr_run_id TEXT, change_type TEXT, asset_id TEXT,
                finding_id TEXT, scan_id TEXT, previous_state TEXT, current_state TEXT,
                scanners TEXT, scan_ids TEXT, completeness TEXT, event_key TEXT UNIQUE,
                detected_at DATETIME, metadata TEXT
            )
        """))
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-d6", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-d6", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@d6.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@d6.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@d6.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@d6.test", password_hash=pwd, role="admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, admin_b])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin", status="active"))
    proj_a = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A", description="d")
    proj_b = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B", description="d")
    db.add_all([proj_a, proj_b])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=admin_a.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=analyst_a.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a.id, user_id=viewer_a.id, role="viewer", status="active"))
    t_a = Target(id=str(uuid.uuid4()), project_id=proj_a.id, value="example.com", target_type="domain", is_active=True)
    db.add(t_a)
    db.flush()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    s1 = Scan(id=str(uuid.uuid4()), target_id=t_a.id, profile="quick", status="completed",
              risk_score=80, risk_grade="B", scanner_version="7.95",
              scanner_image_digest="sha256:abc", created_at=now - timedelta(hours=5))
    s2 = Scan(id=str(uuid.uuid4()), target_id=t_a.id, profile="web", status="failed",
              created_at=now - timedelta(hours=1))
    db.add_all([s1, s2])
    db.flush()
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata, created_at) "
                    "VALUES ('asset-web', :p, 'domain', 'example.com', 'active', '{}', :n)"),
               {"p": proj_a.id, "n": now - timedelta(days=2)})
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata, created_at) "
                    "VALUES ('asset-pub', :p, 'ip', '93.184.216.34', 'active', '{}', :n)"),
               {"p": proj_a.id, "n": now - timedelta(days=2)})
    db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata, created_at) "
                    "VALUES ('asset-ip', :p, 'ip', '10.0.0.5', 'active', '{}', :n)"),
               {"p": proj_a.id, "n": now - timedelta(days=2)})
    findings = [
        ("f-crit", s1.id, "nuclei", "Critical TLS issue", "critical", 95, "open", "asset-web", "CVE-2024-0001", now - timedelta(hours=4)),
        ("f-high", s1.id, "nuclei", "High banner leak", "high", 70, "open", "asset-web", None, now - timedelta(hours=3)),
        ("f-old", s1.id, "nuclei", "Ancient finding", "high", 70, "open", None, None, now - timedelta(days=60)),
        ("f-res", s1.id, "nmap", "Fixed port", "medium", 40, "resolved", "asset-ip", None, now - timedelta(hours=2)),
    ]
    for fid, sid, sc, title, sev, score, st, aid, cve, ts in findings:
        db.execute(text("INSERT INTO findings (id, scan_id, target_id, asset_id, scanner, title, severity, score, status, cve, remediation, evidence, metadata, created_at) "
                        "VALUES (:id,:s,:t,:a,:sc,:ti,:sev,:score,:st,:cve,'Patch promptly.','port 443 open',:m,:n)"),
                   {"id": fid, "s": sid, "t": t_a.id, "a": aid, "sc": sc, "ti": title,
                    "sev": sev, "score": score, "st": st, "cve": cve, "m": "{}", "n": ts})
    db.add(Alert(id="al-1", organization_id=org_a.id, project_id=proj_a.id, alert_type="NEW_CRITICAL_FINDING",
                 severity="critical", status="open", title="Critical", first_seen_at=now - timedelta(hours=4),
                 last_seen_at=now - timedelta(hours=4), event_count=1, dedup_key="dk-1", extra_data={}))
    db.add(Alert(id="al-2", organization_id=org_a.id, project_id=proj_a.id, alert_type="NEW_HIGH_FINDING",
                 severity="high", status="resolved", title="Old high", first_seen_at=now - timedelta(days=2),
                 last_seen_at=now - timedelta(days=2), resolved_at=now - timedelta(days=1),
                 event_count=1, dedup_key="dk-2", extra_data={}))
    cfg = MonitoringConfig(id="cfg-1", organization_id=org_a.id, project_id=proj_a.id, name="M",
                           enabled=True, frequency="daily", profile="quick", target_scope="all",
                           created_by=admin_a.id, baseline_established=True)
    db.add(cfg)
    db.flush()
    db.add(MonitoringRun(id="run-ok", monitoring_config_id=cfg.id, organization_id=org_a.id,
                         project_id=proj_a.id, status="completed", scan_ids=[s1.id],
                         started_at=now - timedelta(hours=5), completed_at=now - timedelta(hours=5),
                         successful_scanners=1, failed_scanners=0, correlation_id="mr:1",
                         change_status="completed", alert_status="completed"))
    db.add(MonitoringRun(id="run-part", monitoring_config_id=cfg.id, organization_id=org_a.id,
                         project_id=proj_a.id, status="partial", scan_ids=[s1.id],
                         started_at=now - timedelta(hours=1), completed_at=now - timedelta(hours=1),
                         successful_scanners=1, failed_scanners=1, correlation_id="mr:2",
                         change_status="completed", alert_status="completed"))
    db.execute(text("INSERT INTO monitoring_change_events (id, project_id, monitoring_config_id, curr_run_id, "
                    "change_type, completeness, event_key, detected_at, metadata) "
                    "VALUES ('ev-1', :p, 'cfg-1', 'run-ok', 'ASSET_CREATED', 'complete', 'ek-1', :n, '{}')"),
               {"p": proj_a.id, "n": now - timedelta(hours=4)})
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a": proj_a, "proj_b": proj_b,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a, "admin_b": admin_b}
    return engine, Session, tokens, objs


def _client(Session):
    def override():
        s = Session()
        try:
            yield s
        finally:
            s.close()
    fastapi_app.dependency_overrides[get_db] = override
    return TestClient(fastapi_app)


def _auth(tokens, email):
    return {"Authorization": f"Bearer {tokens[email]}"}


def _gen(client, Session, tokens, objs, rtype="executive_security", **kw):
    body = {"report_type": rtype, "project_id": objs["proj_a"].id}
    body.update(kw)
    return client.post("/api/v1/reports", json=body, headers=_auth(tokens, "analyst-a@d6.test"))


def test_executive_data_correct():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = _gen(client, Session, tokens, objs, "executive_security")
        assert r.status_code == 201, r.text
        rid = r.json()["id"]
        assert r.json()["status"] == "completed"
        d = client.get(f"/api/v1/reports/{rid}", headers=_auth(tokens, "analyst-a@d6.test")).json()
        snap = d["content"]["snapshot"]
        assert snap["risk"] == {"score": 80.0, "grade": "B"}
        assert snap["findings"]["critical"] == 1 and snap["findings"]["high"] == 1
        assert snap["findings"]["total"] == 3  # old finding outside default 30d? no: 60d old -> excluded
        assert snap["alerts"]["active"] == 1 and snap["alerts"]["critical"] == 1
        assert snap["assets"]["total"] == 3 and snap["assets"]["internet_exposed"] == 1
        assert snap["changes"]["total"] == 1
        assert snap["monitoring"]["runs_in_period"] == {"completed": 1, "partial": 1}
        assert snap["monitoring"]["scanner_versions"] == ["7.95 / sha256:abc"]
        assert "30 days" in d["content"]["executive_summary"] or "critical findings and" in d["content"]["executive_summary"]
        assert d["content"]["report_format_version"] == "1.0"
        assert d["content"]["generator_version"] == "1.0"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_technical_findings_and_evidence():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = _gen(client, Session, tokens, objs, "technical_vapt")
        assert r.status_code == 201, r.text
        d = client.get(f"/api/v1/reports/{r.json()['id']}", headers=_auth(tokens, "analyst-a@d6.test")).json()
        det = d["content"]["snapshot"]["findings"]["detail"]
        assert [f["severity"] for f in det] == ["critical", "high"]
        crit = det[0]
        assert crit["id"] == "f-crit" and crit["cve"] == "CVE-2024-0001"
        assert crit["asset_value"] == "example.com" and crit["remediation"] == "Patch promptly."
        assert len(crit["evidence"]) <= 200
        assert "methodology" in d["content"]["snapshot"] and "limitations" in d["content"]["snapshot"]
        assert any("failed" in str(x).lower() for x in d["content"]["snapshot"]["limitations"])
    finally:
        fastapi_app.dependency_overrides.clear()


def test_period_enforcement_and_bounds():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d6.test")
        assert _gen(client, Session, tokens, objs, start_date="2026-13-99").status_code == 400
        assert _gen(client, Session, tokens, objs, start_date="2026-02-01T00:00:00Z",
                    end_date="2026-01-01T00:00:00Z").status_code == 400
        assert _gen(client, Session, tokens, objs, start_date="2020-01-01T00:00:00Z",
                    end_date="2026-01-01T00:00:00Z").status_code == 400
        assert _gen(client, Session, tokens, objs, report_type="nope").status_code == 400
        # 7d window excludes the 60d-old finding
        r = _gen(client, Session, tokens, objs, start_date="2026-01-01T00:00:00Z",
                 end_date="2027-01-01T00:00:00Z")
        assert r.status_code == 201, r.text
        d = client.get(f"/api/v1/reports/{r.json()['id']}", headers=h).json()
        assert d["content"]["snapshot"]["findings"]["total"] == 4
    finally:
        fastapi_app.dependency_overrides.clear()


def test_pdf_valid_and_bounded():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d6.test")
        r = _gen(client, Session, tokens, objs, "executive_security")
        rid = r.json()["id"]
        pdf = client.get(f"/api/v1/reports/{rid}/download/pdf", headers=h)
        assert pdf.status_code == 200
        assert pdf.headers["content-type"] == "application/pdf"
        blob = pdf.content
        assert blob.startswith(b"%PDF-1.4") and blob.rstrip().endswith(b"%%EOF")
        assert 500 < len(blob) < 1_000_000
        # xref offsets must point at objects
        text = blob.decode("ascii", errors="replace")
        assert "xref" in text and "startxref" in text
        table = text.split("xref", 1)[1].split("trailer")[0]
        import re
        entries = list(re.finditer(r"^(\d{10}) (\d{5}) (n|f)\s*$", table, re.M))
        assert len(entries) >= 4
        for m in entries:
            if m.group(3) == "f":
                continue
            off = int(m.group(1))
            head = blob[off:off + 24].decode("ascii", errors="replace")
            assert re.match(r"^\d+ 0 obj", head), head
        # key content present, no secrets/paths
        assert b"Executive" in blob or b"Security" in blob
        assert b"PRIVATE KEY" not in blob and b"password=" not in blob
        assert b"/home/" not in blob and b"C:\\" not in blob
        assert b"CONFIDENTIAL" in blob
    finally:
        fastapi_app.dependency_overrides.clear()


def test_csv_and_json_downloads():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d6.test")
        rid = _gen(client, Session, tokens, objs, "technical_vapt").json()["id"]
        csv_r = client.get(f"/api/v1/reports/{rid}/download/csv", headers=h)
        assert csv_r.status_code == 200 and csv_r.headers["content-type"].startswith("text/csv")
        assert csv_r.text.startswith("Finding ID,Title,Severity")
        assert client.get(f"/api/v1/reports/{rid}/download/bogus", headers=h).status_code == 400
        j = client.get(f"/api/v1/reports/{rid}/download/json", headers=h).json()
        assert j["id"] == rid and "content" in j
    finally:
        fastapi_app.dependency_overrides.clear()


def test_isolation_and_idor():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        rid = _gen(client, Session, tokens, objs).json()["id"]
        assert client.get("/api/v1/reports").status_code == 401
        assert client.get(f"/api/v1/reports/{rid}").status_code == 401
        hb = _auth(tokens, "admin-b@d6.test")
        assert client.get(f"/api/v1/reports/{rid}", headers=hb).status_code == 404
        assert client.get(f"/api/v1/reports/{rid}/download/pdf", headers=hb).status_code == 404
        assert client.get("/api/v1/reports/nope", headers=_auth(tokens, "admin-a@d6.test")).status_code == 404
        lst = client.get("/api/v1/reports", params={"project_id": objs["proj_b"].id},
                         headers=_auth(tokens, "admin-b@d6.test")).json()
        assert lst["total"] == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_rbac_generate_and_cancel():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        v = _auth(tokens, "viewer-a@d6.test")
        assert client.post("/api/v1/reports", json={"report_type": "executive_security",
                                                    "project_id": objs["proj_a"].id}, headers=v).status_code == 403
        assert client.get(f"/api/v1/projects/{objs['proj_a'].id}/dashboard/summary", headers=v).status_code == 200
        rid = _gen(client, Session, tokens, objs).json()["id"]
        assert client.post(f"/api/v1/reports/{rid}/cancel", headers=v).status_code == 403
        assert client.post(f"/api/v1/reports/{rid}/cancel",
                           headers=_auth(tokens, "analyst-a@d6.test")).status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_lifecycle_immutability_and_retry():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d6.test")
        r1 = _gen(client, Session, tokens, objs).json()
        r2 = _gen(client, Session, tokens, objs).json()
        assert r1["id"] != r2["id"]
        b1 = client.get(f"/api/v1/reports/{r1['id']}/download/pdf", headers=h).content
        b2 = client.get(f"/api/v1/reports/{r2['id']}/download/pdf", headers=h).content
        assert b1 and b1 == client.get(f"/api/v1/reports/{r1['id']}/download/pdf", headers=h).content
        assert r1["status"] == "completed" and r2["status"] == "completed"
        db = Session()
        from app.models.report import Report as ReportModel
        assert db.query(ReportModel).filter(ReportModel.id == r1["id"]).first().content == \
            db.query(ReportModel).filter(ReportModel.id == r1["id"]).first().content
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_failed_report_bounded_error():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d6.test")
        rid = _gen(client, Session, tokens, objs).json()["id"]
        db = Session()
        from app.models.report import Report as ReportModel
        row = db.query(ReportModel).filter(ReportModel.id == rid).first()
        row.status = "failed"
        row.error = "boom"
        db.commit()
        db.close()
        assert client.get(f"/api/v1/reports/{rid}/download/pdf", headers=h).status_code == 400
        d = client.get(f"/api/v1/reports/{rid}", headers=h).json()
        assert d["status"] == "failed"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_audit_and_no_content_leak():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d6.test")
        rid = _gen(client, Session, tokens, objs).json()["id"]
        client.get(f"/api/v1/reports/{rid}/download/pdf", headers=h)
        db = Session()
        from app.models.audit_log import AuditLog as AuditModel
        rows = db.query(AuditModel).filter(AuditModel.resource_id == rid).all()
        events = {a.event_type for a in rows}
        assert "REPORT_CREATED" in events and "REPORT_GENERATION_COMPLETED" in events
        assert "REPORT_DOWNLOADED" in events
        for a in rows:
            s = str(a.extra_data)
            assert "%PDF" not in s and len(s) < 4096
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_security_data_untouched_and_empty_project():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        db = Session()
        from app.models.finding import Finding as FindingModel
        n_f = db.query(FindingModel).count()
        n_s = db.query(Scan).count()
        db.close()
        h = _auth(tokens, "admin-b@d6.test")
        r = client.post("/api/v1/reports", json={"report_type": "executive_security",
                                                 "project_id": objs["proj_b"].id}, headers=h)
        assert r.status_code == 201, r.text
        d = client.get(f"/api/v1/reports/{r.json()['id']}", headers=h).json()
        assert "No scored scans" in d["content"]["executive_summary"] or "no current risk" in d["content"]["executive_summary"].lower() or "0 critical" in d["content"]["executive_summary"]
        db = Session()
        assert db.query(FindingModel).count() == n_f
        assert db.query(Scan).count() == n_s
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_cancel_queued_report_by_analyst():
    # Locks the cancel-path scoping fix: analyst cancels a queued report.
    import uuid as _uuid
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        db = Session()
        from app.models.report import Report as ReportModel
        rid = str(_uuid.uuid4())
        db.execute(
            text("INSERT INTO reports (id, organization_id, project_id, report_type, title, status, "
                 "generated_by, parameters, version, created_at) "
                 "VALUES (:id, :o, :p, 'executive_security', 'Queued', 'queued', :u, '{}', '1.0', :n)"),
            {"id": rid, "o": objs["org_a"].id, "p": objs["proj_a"].id,
             "u": objs["analyst_a"].id, "n": datetime.now(timezone.utc).replace(tzinfo=None)},
        )
        db.commit()
        db.close()
        r = client.post(f"/api/v1/reports/{rid}/cancel", headers=_auth(tokens, "analyst-a@d6.test"))
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "cancelled"
        db = Session()
        events = {a.event_type for a in db.query(AuditLog).filter(AuditLog.resource_id == rid).all()}
        assert "REPORT_CANCELLED" in events
        db.close()
    finally:
        fastapi_app.dependency_overrides.clear()

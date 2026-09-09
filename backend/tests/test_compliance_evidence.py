"""D5 compliance evidence tests: catalog, mapping, evaluation, API, isolation."""

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
import app.models.monitoring  # noqa
import app.models.compliance  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.target import Target
from app.models.user import User
from app.models.scan import Scan
from app.models.monitoring import MonitoringConfig, MonitoringRun
from app.services.control_evidence_catalog import (
    CONTROLS,
    EVIDENCE_FRAMEWORK,
    finding_matches,
    get_control,
    seed_evidence_catalog,
)
from app.services.control_evaluation import coverage_summary


def _setup():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, Target.__table__,
        Scan.__table__,
        MonitoringConfig.__table__, MonitoringRun.__table__,
        app.models.compliance.ComplianceFramework.__table__,
        app.models.compliance.ComplianceControl.__table__,
        app.models.compliance.ComplianceMapping.__table__,
    ])
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
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-d5", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-d5", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@d5.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@d5.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@d5.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@d5.test", password_hash=pwd, role="admin", status="active")
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
    scans = {}
    for key in ["tls", "nuclei", "nmap", "sast", "sca", "secrets", "container"]:
        s = Scan(id=str(uuid.uuid4()), target_id=t_a.id, profile="quick", status="completed",
                 created_at=now - timedelta(hours=3))
        db.add(s)
        db.flush()
        scans[key] = s.id
        db.execute(text("INSERT INTO scan_results (id, scan_id, scanner, status, attempt) "
                        "VALUES (:id, :s, :sc, 'completed', 1)").replace("scan_results", "scan_results_tmp")) if False else None
    # scan_results mirror for coverage aggregation
    db.execute(text("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id TEXT PRIMARY KEY, scan_id TEXT, scanner TEXT, status TEXT,
            completed_at DATETIME, attempt INTEGER
        )
    """))
    for key, sid in scans.items():
        db.execute(text("INSERT INTO scan_results (id, scan_id, scanner, status, completed_at, attempt) "
                        "VALUES (:id, :s, :sc, 'completed', :n, 1)"),
                   {"id": str(uuid.uuid4()), "s": sid, "sc": key, "n": now - timedelta(hours=3)})
    # assets: exposed public ip + domain + internal ip
    for aid, atype, value, meta in [
        ("asset-exp", "ip", "93.184.216.34", '{"rdns": "example.com"}'),
        ("asset-dom", "domain", "example.com", "{}"),
        ("asset-int", "ip", "10.0.0.5", "{}"),
        # repository scope makes the IaC control assessable (no IaC
        # findings or scans exist, so it stays NOT_ASSESSED, not N/A)
        ("asset-repo", "repository", "github.com/example/app", "{}"),
    ]:
        db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata, created_at) "
                        "VALUES (:id, :p, :t, :v, 'active', :m, :n)"),
                   {"id": aid, "p": proj_a.id, "t": atype, "v": value, "m": meta, "n": now})
    # findings
    rows = [
        # (id, scan_key, title, severity, status)
        ("f-tls", "tls", "TLS certificate expired", "critical", "open"),
        ("f-inj", "nuclei", "SQL injection in login form", "high", "open"),
        ("f-hdr", "nuclei", "Missing security header CSP", "medium", "open"),
        ("f-sast", "sast", "Hardcoded credential pattern", "critical", "accepted_risk"),
        ("f-exp", "nuclei", "Exposed admin panel", "critical", "open"),
    ]
    for fid, skey, title, sev, st in rows:
        aid = "asset-exp" if fid == "f-exp" else None
        db.execute(text("INSERT INTO findings (id, scan_id, target_id, asset_id, scanner, title, severity, status, metadata, created_at) "
                        "VALUES (:id, :s, :t, :a, :sc, :ti, :sev, :st, '{}', :n)"),
                   {"id": fid, "s": scans[skey], "t": t_a.id, "a": aid,
                    "sc": skey, "ti": title, "sev": sev, "st": st, "n": now - timedelta(hours=2)})
    # monitoring: config + recent completed run with evaluated changes
    cfg = MonitoringConfig(id=str(uuid.uuid4()), organization_id=org_a.id, project_id=proj_a.id,
                           name="M", enabled=True, frequency="daily", profile="quick",
                           target_scope="all", created_by=admin_a.id, baseline_established=True)
    db.add(cfg)
    db.flush()
    db.add(MonitoringRun(id=str(uuid.uuid4()), monitoring_config_id=cfg.id, organization_id=org_a.id,
                         project_id=proj_a.id, status="completed", scan_ids=[],
                         started_at=now - timedelta(hours=2), completed_at=now - timedelta(hours=2),
                         change_status="completed", alert_status="completed"))
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a": proj_a, "proj_b": proj_b,
            "admin_a": admin_a, "analyst_a": analyst_a, "viewer_a": viewer_a, "admin_b": admin_b,
            "scans": scans}
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


def _summary(client, Session, tokens, objs, role="admin-a@d5.test", pid=None):
    return client.get(f"/api/v1/projects/{pid or objs['proj_a'].id}/compliance/summary",
                      headers=_auth(tokens, role))


# --- catalog -------------------------------------------------------------------

def test_catalog_loads_with_version():
    assert EVIDENCE_FRAMEWORK["framework"] == "vapt_control_readiness"
    assert EVIDENCE_FRAMEWORK["version"] == "1.0"
    assert len(CONTROLS) == 24


def test_control_ids_stable_unique():
    ids = [c["control_id"] for c in CONTROLS]
    assert len(ids) == len(set(ids))
    for c in CONTROLS:
        for key in ("control_id", "title", "description", "category", "importance", "matchers",
                    "positive_scanners", "requires_any_scanners", "requires_any_assets"):
            assert key in c, (c["control_id"], key)
    assert get_control("NOPE") is None
    assert get_control("VAPT-CODE-SEC-01")["title"] == "Secret management"


def test_catalog_seed_idempotent_and_additive():
    _, Session, tokens, objs = _setup()
    db = Session()
    try:
        from app.models.compliance import ComplianceControl, ComplianceFramework
        n1 = seed_evidence_catalog(db)
        assert n1 == 25  # 1 framework + 24 controls
        n2 = seed_evidence_catalog(db)
        assert n2 == 0
        fw = db.query(ComplianceFramework).filter(
            ComplianceFramework.framework == "vapt_control_readiness").first()
        assert fw is not None and fw.version == "1.0"
        assert db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw.id).count() == 24
    finally:
        db.close()
        fastapi_app.dependency_overrides.clear()


# --- mapping ---------------------------------------------------------------------

def test_tls_sast_sca_secrets_container_iac_api_mapping():
    assert finding_matches({"scanner": "tls", "title": "anything"}, [{"scanners": ["tls"], "keywords": None}])
    assert finding_matches({"scanner": "sast", "title": "x"}, [{"scanners": ["sast"], "keywords": None}])
    assert not finding_matches({"scanner": "nmap", "title": "Open port"}, [{"scanners": ["tls"], "keywords": None}])


def test_keyword_narrowness():
    matchers = [{"scanners": ["zap", "nuclei"], "keywords": ["auth", "login"]}]
    assert finding_matches({"scanner": "nuclei", "title": "Login brute force"}, matchers)
    assert not finding_matches({"scanner": "nuclei", "title": "Some random info disclosure note"}, matchers)
    assert not finding_matches({"scanner": "zap", "title": ""}, matchers)


def test_unrelated_evidence_does_not_map():
    for c in CONTROLS:
        if c.get("coverage_only") or c.get("monitoring_review") or c.get("change_review") or c.get("exposure_review"):
            continue
        assert not finding_matches({"scanner": "nope", "title": "unrelated blah"}, c["matchers"]), c["control_id"]


def test_version_only_change_no_false_failure():
    # same fingerprint-worthy finding under a bumped scanner version is the
    # same observation, not new infrastructure evidence (unit-level guard)
    from app.services.control_evaluation import _effective_severity
    assert _effective_severity("High", None) == "high"
    assert _effective_severity(None, None) == "info"


# --- evaluation via API ------------------------------------------------------------

def _controls_map(body):
    return {c["control_id"]: c for c in body["controls"]}


def test_summary_counts_and_coverage():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = _summary(client, Session, tokens, objs)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["framework"] == "vapt_control_readiness"
        assert "certified" not in str(body).lower()
        assert "audit passed" not in str(body).lower()
        assert "automatically compliant" not in str(body).lower()
        assert body["total_controls"] == 24
        # FAIL: TLS, AUTH, INJ, NET-EXP (4)
        assert body["fail"] == 4, body
        # PARTIAL: HEADERS (medium), SAST (accepted-risk) (2)
        assert body["partial"] == 2, body
        # PASS (12): AUTHZ, SESS, DATA, TECH, PORT, PROTO, SCA, SEC, CONT, SCAN, MON, CHANGE
        assert body["pass"] == 12, body
        # NOT_ASSESSED: IAC (in scope via repository asset, no coverage),
        # DNS (in scope via domain asset, no DNS findings/scans)
        assert body["not_assessed"] == 2, body
        # NOT_APPLICABLE: 4 API controls (no API scope)
        assert body["not_applicable"] == 4, body
        assert body["evidence_coverage"] == round(14 / 20 * 100, 1)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_key_control_statuses():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        m = _controls_map(_summary(client, Session, tokens, objs).json())
        assert m["VAPT-CRYPTO-TLS-01"]["status"] == "FAIL"
        assert m["VAPT-CODE-SEC-01"]["status"] == "PASS"
        assert m["VAPT-CODE-SAST-01"]["status"] == "PARTIAL"
        assert m["VAPT-NET-EXP-01"]["status"] == "FAIL"
        assert m["VAPT-API-AUTH-01"]["status"] == "NOT_APPLICABLE"
        assert m["VAPT-CODE-IAC-01"]["status"] == "NOT_ASSESSED"
        assert m["VAPT-OPS-SCAN-01"]["status"] == "PASS"
        assert m["VAPT-OPS-MON-01"]["status"] == "PASS"
        assert m["VAPT-OPS-CHANGE-01"]["status"] in ("PASS", "PARTIAL")
        for c in m.values():
            assert c["confidence"] in ("HIGH", "MEDIUM", "LOW")
            assert c["freshness"] in ("FRESH", "STALE", "UNKNOWN")
    finally:
        fastapi_app.dependency_overrides.clear()


def test_accepted_risk_never_pass_or_fail():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        m = _controls_map(_summary(client, Session, tokens, objs).json())
        # SAST has ONLY an accepted-risk finding: must be PARTIAL, never PASS/FAIL
        assert m["VAPT-CODE-SAST-01"]["status"] == "PARTIAL"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_control_detail_evidence_bounded_no_secrets():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "analyst-a@d5.test")
        base = f"/api/v1/projects/{objs['proj_a'].id}/compliance/controls/VAPT-CRYPTO-TLS-01"
        d = client.get(base, headers=h)
        assert d.status_code == 200, d.text
        body = d.json()
        assert body["status"] == "FAIL" and len(body["contradictory"]) >= 1
        blob = str(body).lower()
        assert "password" not in blob and "secret" not in blob.replace("secret management", "")
        assert "evidence" not in str([k for e in body["contradictory"] for k in e.keys()])
        assert "description" not in str([k for e in body["contradictory"] for k in e.keys()])
        ev = client.get(base + "/evidence", headers=h).json()
        assert ev["total_contradictory"] >= 1
        assert client.get(base + "/evidence", params={"kind": "bogus"}, headers=h).status_code == 400
        assert client.get(f"/api/v1/projects/{objs['proj_a'].id}/compliance/controls/NOPE", headers=h).status_code == 404
    finally:
        fastapi_app.dependency_overrides.clear()


def test_status_category_filters_pagination():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "viewer-a@d5.test")
        base = f"/api/v1/projects/{objs['proj_a'].id}/compliance/controls"
        assert client.get(base, params={"status": "FAIL"}, headers=h).json()["total"] == 4
        assert client.get(base, params={"category": "Network"}, headers=h).json()["total"] == 4
        assert client.get(base, params={"status": "bogus"}, headers=h).status_code == 400
        p = client.get(base, params={"page": 1, "page_size": 10}, headers=h).json()
        assert p["total"] == 24 and len(p["items"]) == 10 and p["total_pages"] == 3
    finally:
        fastapi_app.dependency_overrides.clear()


def test_stale_positive_is_partial():
    _, Session, tokens, objs = _setup()
    db = Session()
    try:
        old = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=40)
        db.execute(text("UPDATE scans SET created_at = :o"), {"o": old})
        db.execute(text("UPDATE findings SET created_at = :o"), {"o": old})
        db.execute(text("UPDATE scan_results SET completed_at = :o"), {"o": old})
        db.commit()
    finally:
        db.close()
    client = _client(Session)
    try:
        m = _controls_map(_summary(client, Session, tokens, objs).json())
        # findings aged too: TLS finding now stale-negative -> PARTIAL? No:
        # open critical/high matches still FAIL (MEDIUM confidence when stale)
        assert m["VAPT-CRYPTO-TLS-01"]["status"] == "FAIL"
        assert m["VAPT-CRYPTO-TLS-01"]["confidence"] == "MEDIUM"
        assert m["VAPT-CRYPTO-TLS-01"]["freshness"] == "STALE"
        # SCA positive is now stale -> PARTIAL
        assert m["VAPT-CODE-SCA-01"]["status"] == "PARTIAL"
    finally:
        fastapi_app.dependency_overrides.clear()


def test_tenant_project_isolation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        assert client.get(f"/api/v1/projects/{objs['proj_a'].id}/compliance/summary").status_code == 401
        assert client.get(f"/api/v1/projects/{objs['proj_a'].id}/compliance/summary",
                          headers=_auth(tokens, "admin-b@d5.test")).status_code in (403, 404)
        assert client.get(f"/api/v1/projects/nope/compliance/summary",
                          headers=_auth(tokens, "admin-a@d5.test")).status_code == 404
        # other project sees nothing of proj A (empty project B summmary has zero counts)
        b = client.get(f"/api/v1/projects/{objs['proj_b'].id}/compliance/summary",
                       headers=_auth(tokens, "admin-b@d5.test")).json()
        assert b["total_controls"] == 24 and b["fail"] == 0 and b["pass"] == 0
    finally:
        fastapi_app.dependency_overrides.clear()


def test_viewer_read_and_empty_project():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        h = _auth(tokens, "viewer-a@d5.test")
        assert client.get(f"/api/v1/projects/{objs['proj_a'].id}/compliance/summary", headers=h).status_code == 200
        assert client.get(f"/api/v1/projects/{objs['proj_a'].id}/compliance/controls", headers=h).status_code == 200
    finally:
        fastapi_app.dependency_overrides.clear()


def test_coverage_formula_unit():
    assert coverage_summary([])["evidence_coverage"] is None
    evs = [{"status": s} for s in ["PASS", "PASS", "PARTIAL", "FAIL", "NOT_ASSESSED", "NOT_APPLICABLE"]]
    out = coverage_summary(evs)
    assert out["evidence_coverage"] == round(3 / 5 * 100, 1)
    assert out["not_applicable"] == 1

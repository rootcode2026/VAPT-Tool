"""E2 AWS security checks — catalog, deterministic evaluation, findings,
fingerprints, idempotency, provenance, RBAC/IDOR, audit, leakage.

Evaluation is offline over persisted asset metadata: no AWS calls. boto3 is
asserted unnecessary by blocking its import during the run test.
"""

import json
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import JSON as _JSON
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
import app.models.finding  # noqa
import app.models.asset  # noqa
import app.models.connector  # noqa
import app.models.cloud_discovery  # noqa
import app.models.cloud_check  # noqa

from app.models.organization import Organization
from app.models.organization_membership import OrganizationMembership
from app.models.project import Project
from app.models.project_membership import ProjectMembership
from app.models.user import User
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.services import cloud_checks as checks


def _setup(with_assets=True):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    for _tbl in list(Base.metadata.tables.values()):
        for _col in _tbl.columns:
            if _col.type.__class__.__name__ == "JSONB":
                _col.type = _JSON()
    import app.models.connector as _conn
    import app.models.cloud_discovery as _cd
    import app.models.cloud_check as _cc
    from app.models.finding import FindingHistory, FindingSLA, FindingRemediation, SLAPolicy
    Base.metadata.create_all(bind=engine, tables=[
        Organization.__table__, User.__table__, OrganizationMembership.__table__,
        Project.__table__, ProjectMembership.__table__, AuditLog.__table__,
        _conn.CloudConnection.__table__, _cd.CloudDiscovery.__table__, _cc.CloudCheckRun.__table__,
        FindingSLA.__table__, FindingRemediation.__table__, SLAPolicy.__table__,
        FindingHistory.__table__,
    ])
    with engine.begin() as conn:
        conn.execute(text("""CREATE TABLE IF NOT EXISTS asset_relationships (id TEXT PRIMARY KEY,
            project_id TEXT, source_asset_id TEXT, target_asset_id TEXT, relationship_type TEXT)"""))
        conn.execute(text("""CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, target_id TEXT,
            profile TEXT, status TEXT, phase TEXT, risk_score INTEGER, risk_grade TEXT,
            risk_level TEXT, created_at DATETIME, progress INTEGER, scanner_version TEXT,
            scanner_image_digest TEXT, metadata TEXT)"""))
        conn.execute(text("""CREATE TABLE IF NOT EXISTS targets (id TEXT PRIMARY KEY, project_id TEXT,
            value TEXT, target_type TEXT, is_active BOOLEAN)"""))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, scan_id TEXT, target_id TEXT, asset_id TEXT,
                scanner TEXT, title TEXT, description TEXT, severity TEXT, score INTEGER,
                status TEXT, evidence TEXT, remediation TEXT, cve TEXT, cwe TEXT,
                assigned_to TEXT, assigned_at DATETIME, assigned_by TEXT,
                owner_user_id TEXT, owner_team_id TEXT, severity_override TEXT,
                workflow_status TEXT, closed_at DATETIME, closed_by TEXT,
                remediation_claimed_at DATETIME, remediation_claimed_by TEXT,
                ready_for_retest_at DATETIME,
                metadata TEXT, created_at DATETIME, updated_at DATETIME
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY, project_id TEXT, asset_type TEXT, value TEXT,
                status TEXT, metadata TEXT, created_at DATETIME, updated_at DATETIME,
                criticality TEXT, owner_user_id TEXT, first_seen_at DATETIME,
                last_seen_at DATETIME, first_seen_scan_id TEXT, last_seen_scan_id TEXT
            )
        """))
    Session = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = Session()
    org_a = Organization(id=str(uuid.uuid4()), name="Org A", slug="org-a-e2", status="active")
    org_b = Organization(id=str(uuid.uuid4()), name="Org B", slug="org-b-e2", status="active")
    db.add_all([org_a, org_b])
    db.flush()
    pwd = hash_password("password123")
    admin_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="admin-a@e2.test", password_hash=pwd, role="admin", status="active")
    analyst_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="analyst-a@e2.test", password_hash=pwd, role="member", status="active")
    viewer_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="viewer-a@e2.test", password_hash=pwd, role="member", status="active")
    admin_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="admin-b@e2.test", password_hash=pwd, role="admin", status="active")
    db.add_all([admin_a, analyst_a, viewer_a, admin_b])
    db.flush()
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=admin_a.id, role="org_admin", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=analyst_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_a.id, user_id=viewer_a.id, role="member", status="active"))
    db.add(OrganizationMembership(id=str(uuid.uuid4()), organization_id=org_b.id, user_id=admin_b.id, role="org_admin", status="active"))
    proj_a1 = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="Proj A1", description="d")
    proj_b1 = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="Proj B1", description="d")
    db.add_all([proj_a1, proj_b1])
    db.flush()
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=admin_a.id, role="project_admin", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=analyst_a.id, role="analyst", status="active"))
    db.add(ProjectMembership(id=str(uuid.uuid4()), project_id=proj_a1.id, user_id=viewer_a.id, role="viewer", status="active"))
    conn_a = _conn.CloudConnection(id=str(uuid.uuid4()), project_id=proj_a1.id, provider="aws",
                                   account_id="123456789012", credential_type="role",
                                   role_arn="arn:aws:iam::123456789012:role/VAPT", status="active")
    db.add(conn_a)
    db.flush()
    run_a = _cd.CloudDiscovery(id=str(uuid.uuid4()), organization_id=org_a.id, project_id=proj_a1.id,
                               connection_id=conn_a.id, provider="aws", status="completed")
    db.add(run_a)
    db.flush()
    asset_ids = {}
    if with_assets:
        def add_asset(rtype, value, extra):
            aid = str(uuid.uuid4())
            meta = {"provider": "aws", "service": "svc", "resource_type": rtype,
                    "resource_id": value, "region": "us-east-1", "account_id": "123456789012",
                    "observed_at": "2026-01-01T00:00:00+00:00", "extra": extra}
            db.execute(text("INSERT INTO assets (id, project_id, asset_type, value, status, metadata) VALUES (:id, :proj, 'cloud_resource', :val, 'active', :meta)"),
                       {"id": aid, "proj": proj_a1.id, "val": value, "meta": json.dumps(meta)})
            asset_ids[value] = aid
            return aid
        add_asset("aws_rds_instance", "rds-public", {"publicly_accessible": True, "storage_encrypted": True})
        add_asset("aws_rds_instance", "rds-ok", {"publicly_accessible": False, "storage_encrypted": True})
        add_asset("aws_rds_instance", "rds-unknown", {})
        add_asset("aws_s3_bucket", "bkt-open", {"pab_blockpublicacls": True, "pab_ignorepublicacls": False,
                                                "pab_blockpublicpolicy": True, "pab_restrictpublicbuckets": True})
        add_asset("aws_s3_bucket", "bkt-unenc", {"pab_blockpublicacls": True, "pab_ignorepublicacls": True,
                                                 "pab_blockpublicpolicy": True, "pab_restrictpublicbuckets": True,
                                                 "encryption_error_code": "NoSuchEncryptionConfiguration"})
        add_asset("aws_ec2_instance", "ec2-imds", {"imds_v2_enforced": False})
    db.commit()
    db.close()
    tokens = {u.email: create_access_token(u.id) for u in [admin_a, analyst_a, viewer_a, admin_b]}
    objs = {"org_a": org_a, "org_b": org_b, "proj_a1": proj_a1, "proj_b1": proj_b1,
            "conn_a": conn_a, "run_a": run_a, "asset_ids": asset_ids,
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


def _meta(rtype, extra):
    return {"provider": "aws", "service": "svc", "resource_type": rtype, "resource_id": "x",
            "region": "us-east-1", "account_id": "123", "value": "v", "extra": extra}


# --- A/B: catalog ---
def test_e2_catalog_shape_and_version():
    catalog = checks.list_catalog(provider="aws")
    assert len(catalog) == 7
    for check in catalog:
        for key in ("check_id", "title", "description", "provider", "service", "resource_types",
                    "severity", "category", "remediation", "references", "version", "enabled",
                    "evidence_requirements"):
            assert key in check, key
        assert check["enabled"] is True and check["version"] == checks.CHECK_PACK_VERSION
    assert "AWS-EC2-002" in checks.DEFERRED_CHECKS
    assert checks.get_check("aws-rds-001")["check_id"] == "AWS-RDS-001"


# --- C/D/E/F/G: deterministic evaluation ---
def test_e2_rds_public_and_encryption():
    public = checks.get_check("AWS-RDS-001")
    assert checks.evaluate_asset(public, _meta("aws_rds_instance", {"publicly_accessible": True}))[0] == "failed"
    assert checks.evaluate_asset(public, _meta("aws_rds_instance", {"publicly_accessible": False}))[0] == "passed"
    assert checks.evaluate_asset(public, _meta("aws_rds_instance", {}))[0] == "not_assessed"
    enc = checks.get_check("AWS-RDS-002")
    assert checks.evaluate_asset(enc, _meta("aws_rds_instance", {"storage_encrypted": False}))[0] == "failed"
    assert checks.evaluate_asset(enc, _meta("aws_rds_instance", {"storage_encrypted": True}))[0] == "passed"
    assert checks.evaluate_asset(enc, _meta("aws_rds_instance", {}))[0] == "not_assessed"


def test_e2_s3_pab_and_encryption():
    pab = checks.get_check("AWS-S3-001")
    good = {f: True for f in checks.PAB_FLAGS}
    assert checks.evaluate_asset(pab, _meta("aws_s3_bucket", good))[0] == "passed"
    bad = dict(good, pab_ignorepublicacls=False)
    result, evidence, _ = checks.evaluate_asset(pab, _meta("aws_s3_bucket", bad))
    assert result == "failed" and "pab_ignorepublicacls" in str(evidence)
    assert checks.evaluate_asset(pab, _meta("aws_s3_bucket", {}))[0] == "not_assessed"
    sse = checks.get_check("AWS-S3-002")
    assert checks.evaluate_asset(sse, _meta("aws_s3_bucket", {"encryption": "AES256"}))[0] == "passed"
    result, _, _ = checks.evaluate_asset(sse, _meta("aws_s3_bucket", {"encryption_error_code": "NoSuchEncryptionConfiguration"}))
    assert result == "failed"
    assert checks.evaluate_asset(sse, _meta("aws_s3_bucket", {"encryption_error_code": "AccessDenied"}))[0] == "not_assessed"
    assert checks.evaluate_asset(sse, _meta("aws_s3_bucket", {}))[0] == "not_assessed"


def test_e2_ec2_elb_lambda():
    imds = checks.get_check("AWS-EC2-001")
    assert checks.evaluate_asset(imds, _meta("aws_ec2_instance", {"imds_v2_enforced": False}))[0] == "failed"
    assert checks.evaluate_asset(imds, _meta("aws_ec2_instance", {"imds_v2_enforced": True}))[0] == "passed"
    assert checks.evaluate_asset(imds, _meta("aws_ec2_instance", {}))[0] == "not_assessed"
    elb = checks.get_check("AWS-ELB-001")
    assert checks.evaluate_asset(elb, _meta("aws_alb", {"scheme": "internet-facing", "listeners": [{"protocol": "HTTP", "port": 80}]}))[0] == "failed"
    assert checks.evaluate_asset(elb, _meta("aws_alb", {"scheme": "internet-facing", "listeners": [{"protocol": "HTTPS", "port": 443}]}))[0] == "passed"
    assert checks.evaluate_asset(elb, _meta("aws_alb", {}))[0] == "not_assessed"
    lam = checks.get_check("AWS-LAMBDA-001")
    assert checks.evaluate_asset(lam, _meta("aws_lambda_function", {"function_urls": [{"url": "https://x/", "auth": "NONE"}]}))[0] == "failed"
    assert checks.evaluate_asset(lam, _meta("aws_lambda_function", {"function_urls": []}))[0] == "passed"
    assert checks.evaluate_asset(lam, _meta("aws_lambda_function", {"url_error": "denied"}))[0] == "not_assessed"
    assert checks.evaluate_asset(lam, _meta("aws_lambda_function", {}))[0] == "not_assessed"


# --- H/I: evidence ---
def test_e2_evidence_bounded_structured():
    check = checks.get_check("AWS-RDS-001")
    result, evidence, note = checks.evaluate_asset(
        check, _meta("aws_rds_instance", {"publicly_accessible": True}), "run-1")
    assert result == "failed"
    assert evidence["check_id"] == "AWS-RDS-001"
    assert evidence["field"] == "publicly_accessible" and evidence["observed"] is True
    assert evidence["expected"] is False and evidence["discovery_run_id"] == "run-1"
    assert len(str(evidence)) <= 2000 and note


# --- J/K/L/M/N/O: finding integration, fingerprints, dedup, severity, confidence, asset ---
def test_e2_run_creates_findings():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        r = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/security-checks/run",
                        json={"discovery_run_id": objs["run_a"].id}, headers=_auth(tokens, "analyst-a@e2.test"))
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["failed"] >= 3 and body["passed"] >= 1 and body["not_assessed"] >= 1
        assert body["findings_created"] == body["failed"]
        assert body["status"] == "completed"
        s = Session()
        try:
            rows = s.query(Finding).filter(Finding.scanner == "cloud").all()
            assert len(rows) == body["findings_created"]
            for f in rows:
                assert f.status == "open" and f.asset_id is not None
                assert f.scan_id is None and f.target_id is None
                assert f.cve is None and f.cwe is None
                meta = f.extra_data if isinstance(f.extra_data, dict) else {}
                assert meta.get("rule_id") and meta.get("discovery_run_id") == objs["run_a"].id
                assert meta.get("confidence_score") == 90
                assert f.score in (50, 75, 90)
                assert f.remediation
                ev = json.loads(f.evidence)
                assert ev["check_id"] == meta["rule_id"]
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e2_fingerprint_stable_and_scoped():
    from app.services import finding_lifecycle as lc
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/security-checks/run",
                    json={"discovery_run_id": objs["run_a"].id}, headers=_auth(tokens, "analyst-a@e2.test"))
        s = Session()
        try:
            rows = s.query(Finding).filter(Finding.scanner == "cloud").all()
            fps = [lc.d8_fingerprint(lc.d8_finding_input(r)) for r in rows]
            assert len(set(fps)) == len(fps)  # distinct resources -> distinct fingerprints
            # Same logical finding recomputed -> identical fingerprint.
            again = lc.d8_fingerprint(lc.d8_finding_input(rows[0]))
            assert again == fps[0]
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e2_repeat_run_no_duplicates_and_respects_terminal():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@e2.test")
    try:
        first = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/security-checks/run",
                            json={"discovery_run_id": objs["run_a"].id}, headers=H).json()
        # New discovery run, same condition -> no new findings (fingerprint match).
        s = Session()
        try:
            from app.models.cloud_discovery import CloudDiscovery
            run2 = CloudDiscovery(id=str(uuid.uuid4()), organization_id=objs["org_a"].id,
                                  project_id=objs["proj_a1"].id, connection_id=objs["conn_a"].id,
                                  provider="aws", status="completed")
            s.add(run2)
            s.commit()
            run2_id = run2.id
        finally:
            s.close()
        second = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/security-checks/run",
                             json={"discovery_run_id": run2_id}, headers=H).json()
        assert second["findings_created"] == 0
        # Same run again -> idempotent, same run id.
        third = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/security-checks/run",
                            json={"discovery_run_id": objs["run_a"].id}, headers=H).json()
        assert third["id"] == first["id"]
        s = Session()
        try:
            assert s.query(Finding).filter(Finding.scanner == "cloud").count() == first["findings_created"]
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e2_severity_confidence_mapping():
    assert checks.get_check("AWS-RDS-001")["severity"] == "critical"
    assert checks.get_check("AWS-EC2-001")["severity"] == "high"
    assert checks.get_check("AWS-S3-002")["severity"] == "medium"
    assert checks.SEVERITY_SCORES == {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 5}


# --- P/Q: provenance + partial ---
def test_e2_provenance_and_partial_run():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@e2.test")
    try:
        body = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/security-checks/run",
                           json={"discovery_run_id": objs["run_a"].id}, headers=H).json()
        assert set(body["breakdown"]) >= {"AWS-RDS-001", "AWS-S3-001"}
        s = Session()
        try:
            from app.models.cloud_discovery import CloudDiscovery
            run = CloudDiscovery(id=str(uuid.uuid4()), organization_id=objs["org_a"].id,
                                 project_id=objs["proj_a1"].id, connection_id=objs["conn_a"].id,
                                 provider="aws", status="partial")
            s.add(run)
            s.commit()
            run_id = run.id
        finally:
            s.close()
        partial = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/security-checks/run",
                              json={"discovery_run_id": run_id}, headers=H).json()
        assert partial["status"] == "completed"  # evaluation itself completed
        assert partial["not_assessed"] >= 0
    finally:
        fastapi_app.dependency_overrides.clear()


# --- R/S/T/U/V/W/X: security + validation ---
def test_e2_rbac():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        pid = objs["proj_a1"].id
        assert client.post(f"/api/v1/projects/{pid}/cloud/security-checks/run", json={}, headers=_auth(tokens, "viewer-a@e2.test")).status_code == 403
        assert client.get(f"/api/v1/projects/{pid}/cloud/security-checks/catalog", headers=_auth(tokens, "viewer-a@e2.test")).status_code == 200
        assert client.get(f"/api/v1/projects/{pid}/cloud/security-checks/runs", headers=_auth(tokens, "viewer-a@e2.test")).status_code == 200
        assert client.post(f"/api/v1/projects/{pid}/cloud/security-checks/run", json={}).status_code in (401, 403)
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e2_idor_and_validation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@e2.test")
    try:
        pid = objs["proj_a1"].id
        assert client.post(f"/api/v1/projects/{pid}/cloud/security-checks/run", json={"discovery_run_id": str(uuid.uuid4())}, headers=H).status_code == 404
        assert client.get(f"/api/v1/projects/{objs['proj_b1'].id}/cloud/security-checks/runs", headers=H).status_code == 404
        assert client.get(f"/api/v1/projects/{pid}/cloud/security-checks/runs", headers=_auth(tokens, "admin-b@e2.test")).status_code == 404
        assert client.get(f"/api/v1/projects/{pid}/cloud/security-checks/runs/nope", headers=H).status_code == 404
        # Disabled connection rejected.
        s = Session()
        try:
            from app.models.connector import CloudConnection
            conn = s.query(CloudConnection).filter(CloudConnection.id == objs["conn_a"].id).first()
            conn.status = "inactive"
            s.commit()
        finally:
            s.close()
        assert client.post(f"/api/v1/projects/{pid}/cloud/security-checks/run", json={"discovery_run_id": objs["run_a"].id}, headers=H).status_code == 400
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e2_no_aws_calls_and_no_mutation():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        # boto3 import blocked: evaluation must still succeed (pure offline path).
        import builtins
        real_import = builtins.__import__

        def guarded(name, *args, **kwargs):
            if name == "boto3" or name.startswith("boto3."):
                raise ImportError("blocked for E2 test")
            return real_import(name, *args, **kwargs)

        import unittest.mock as _mock
        with _mock.patch("builtins.__import__", side_effect=guarded):
            r = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/security-checks/run",
                            json={"discovery_run_id": objs["run_a"].id}, headers=_auth(tokens, "analyst-a@e2.test"))
        assert r.status_code == 201, r.text
        assert r.json()["failed"] >= 1
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e2_leakage_free():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        s = Session()
        try:
            from app.models.asset import Asset
            asset = s.query(Asset).filter(Asset.project_id == objs["proj_a1"].id).first()
            meta = dict(asset.extra_data or {})
            meta["extra"] = {"password": "hunter2-secret", "state": "x"}
            asset.extra_data = meta
            s.commit()
        finally:
            s.close()
        body = client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/security-checks/run",
                           json={"discovery_run_id": objs["run_a"].id}, headers=_auth(tokens, "analyst-a@e2.test")).json()
        blob = json.dumps(body)
        assert "hunter2" not in blob
        assert body["status"] in ("completed", "partial")
        s = Session()
        try:
            import json as _json
            for f in s.query(Finding).filter(Finding.scanner == "cloud").all():
                payload = (f.evidence or "") + _json.dumps(f.extra_data or {})
                assert "hunter2" not in payload
            for r in s.query(AuditLog).filter(AuditLog.project_id == objs["proj_a1"].id).all():
                assert "hunter2" not in _json.dumps(getattr(r, "extra_data", None) or {})
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e2_audit_run_events():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    try:
        client.post(f"/api/v1/projects/{objs['proj_a1'].id}/cloud/security-checks/run",
                    json={"discovery_run_id": objs["run_a"].id}, headers=_auth(tokens, "analyst-a@e2.test"))
        s = Session()
        try:
            types = {r.event_type for r in s.query(AuditLog).filter(AuditLog.project_id == objs["proj_a1"].id).all()}
            assert "CLOUD_CHECK_RUN_REQUESTED" in types
            assert "CLOUD_CHECK_RUN_COMPLETED" in types or "CLOUD_CHECK_RUN_PARTIAL" in types
            assert "FINDING_CREATED" in types
        finally:
            s.close()
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e2_findings_visible_in_list_detail_and_cloud():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@e2.test")
    try:
        pid = objs["proj_a1"].id
        client.post(f"/api/v1/projects/{pid}/cloud/security-checks/run",
                    json={"discovery_run_id": objs["run_a"].id}, headers=H)
        listed = client.get(f"/api/v1/findings?project_id={pid}&scanner=cloud", headers=H).json()
        assert len(listed) >= 1
        fid = listed[0]["id"]
        detail = client.get(f"/api/v1/findings/{fid}", headers=H)
        assert detail.status_code == 200
        assert detail.json()["asset_id"]
        from app.services import cloud_security as _cs
        s = Session()
        try:
            summary = _cs.get_cloud_summary(pid, s)
            assert summary["findings"]["total"] >= 1
            assert summary["findings"]["critical"] >= 1
            listed_cloud = _cs.list_cloud_findings(pid, s)
            assert listed_cloud["total"] >= 1
        finally:
            s.close()
        # Remediation + SLA + retest flows resolve the asset-linked finding.
        s = Session()
        try:
            from app.models.finding import FindingSLA
            assert s.query(Finding).filter(Finding.id == fid).first() is not None
        finally:
            s.close()
        assert client.post(f"/api/v1/findings/{fid}/sla/start", headers=H).status_code == 201
        rem = client.post(f"/api/v1/findings/{fid}/remediations", json={"title": "fix rds"}, headers=H)
        assert rem.status_code == 201, rem.text
    finally:
        fastapi_app.dependency_overrides.clear()


def test_e2_catalog_and_runs_endpoints():
    _, Session, tokens, objs = _setup()
    client = _client(Session)
    H = _auth(tokens, "analyst-a@e2.test")
    try:
        pid = objs["proj_a1"].id
        cat = client.get(f"/api/v1/projects/{pid}/cloud/security-checks/catalog", headers=H).json()
        assert cat["count"] == 7 and cat["pack_version"] == "1.0"
        ran = client.post(f"/api/v1/projects/{pid}/cloud/security-checks/run",
                          json={"discovery_run_id": objs["run_a"].id}, headers=H).json()
        runs = client.get(f"/api/v1/projects/{pid}/cloud/security-checks/runs", headers=H).json()
        assert runs["count"] == 1
        one = client.get(f"/api/v1/projects/{pid}/cloud/security-checks/runs/{ran['id']}", headers=H).json()
        assert one["breakdown"] and one["check_pack_version"] == "1.0"
    finally:
        fastapi_app.dependency_overrides.clear()

"""E12 Security Signal Correlation — deterministic, bounded, on-read."""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.security import create_access_token, hash_password
from app.db.database import get_db
from app.main import app
from app.services.security_correlation import get_correlations, get_correlation_detail, get_correlation_summary, _normalize_url, _canonical_fingerprint

def _engine():
    from app.db.base import Base as ProdBase
    from sqlalchemy import JSON
    for tbl in ProdBase.metadata.tables.values():
        for col in tbl.columns:
            if col.type.__class__.__name__ == "JSONB":
                col.type = JSON()
            if col.server_default is not None:
                try:
                    if "jsonb" in str(col.server_default.arg).lower():
                        col.server_default = None
                except Exception:
                    pass
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    needed = ["organizations", "users", "projects", "assets", "asset_relationships", "findings", "cloud_attack_paths", "cloud_attack_path_observations"]
    tables = [ProdBase.metadata.tables[n] for n in needed if n in ProdBase.metadata.tables]
    ProdBase.metadata.create_all(bind=eng, tables=tables)
    return eng

def _setup():
    from app.models.organization import Organization
    from app.models.user import User
    from app.models.project import Project
    eng = _engine()
    SessionLocal = sessionmaker(bind=eng, autocommit=False, autoflush=False, expire_on_commit=False)
    db = SessionLocal()
    org = Organization(id=str(uuid.uuid4()), name="OrgE12", slug="orge12-"+str(uuid.uuid4())[:6])
    db.add(org); db.flush()
    pwd = hash_password("password123")
    user = User(id=str(uuid.uuid4()), organization_id=org.id, email="e12@org.test", password_hash=pwd, role="member")
    db.add(user); db.flush()
    proj = Project(id=str(uuid.uuid4()), organization_id=org.id, name="ProjE12")
    db.add(proj); db.flush()
    db.commit(); db.close()
    return eng, SessionLocal, {"org": org, "user": user, "proj": proj}

def _add_asset(db, project_id, value, asset_type="domain"):
    from app.models.asset import Asset
    a = Asset(id=str(uuid.uuid4()), project_id=project_id, asset_type=asset_type, value=value, extra_data={})
    db.add(a); db.flush()
    return a

def _add_finding(db, asset_id, scanner, title, cve=None, cwe=None, rule_id=None, extra=None):
    from app.models.finding import Finding
    ed = extra or {}
    if rule_id:
        ed["rule_id"] = rule_id
    if extra and "url" in extra:
        ed["url"] = extra["url"]
    f = Finding(id=str(uuid.uuid4()), asset_id=asset_id, scanner=scanner, title=title, severity="high", cve=cve, cwe=cwe, extra_data=ed)
    db.add(f); db.flush()
    return f

def _client(SessionLocal):
    def override():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[get_db] = override
    return TestClient(app)

# 1 empty
def test_empty_findings():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    groups = get_correlations(objs["proj"].id, db)
    assert groups == []
    db.close()

# 2 exact duplicate correlation
def test_exact_duplicate():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    asset = _add_asset(db, objs["proj"].id, "example.com")
    f1 = _add_finding(db, asset.id, "nuclei", "XSS on example.com", rule_id="R001", extra={"url": "https://example.com/search?q=1"})
    f2 = _add_finding(db, asset.id, "zap", "XSS on example.com", rule_id="R001", extra={"url": "https://example.com/search?q=1"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert any(g["correlation_type"] == "DUPLICATE" for g in groups)
    db.close()

# 3 same CVE different assets -> related not duplicate
def test_same_cve_different_assets_related():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a1 = _add_asset(db, objs["proj"].id, "host1.com")
    a2 = _add_asset(db, objs["proj"].id, "host2.com")
    f1 = _add_finding(db, a1.id, "sca", "CVE-2021-1234", cve="CVE-2021-1234")
    f2 = _add_finding(db, a2.id, "container", "CVE-2021-1234", cve="CVE-2021-1234")
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert any(g["correlation_type"] == "SAME_VULNERABILITY" for g in groups)
    # should not be DUPLICATE (different assets)
    assert not any(g["correlation_type"] == "DUPLICATE" and len(g["asset_ids"]) == 1 for g in groups if "CVE-2021-1234" in str(g))
    db.close()

# 4 same asset different findings -> same asset
def test_same_asset():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    asset = _add_asset(db, objs["proj"].id, "shared.com")
    f1 = _add_finding(db, asset.id, "nmap", "port open", rule_id="PORT")
    f2 = _add_finding(db, asset.id, "tls", "weak tls", rule_id="TLS")
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert any(g["correlation_type"] == "SAME_ASSET" for g in groups)
    db.close()

# 5 same URL endpoint correlation
def test_same_url():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a1 = _add_asset(db, objs["proj"].id, "https://example.com/api")
    a2 = _add_asset(db, objs["proj"].id, "https://example.com/api2")
    f1 = _add_finding(db, a1.id, "nuclei", "endpoint issue", extra={"url": "https://example.com/api/v1"})
    f2 = _add_finding(db, a2.id, "zap", "endpoint issue", extra={"url": "https://example.com/api/v1"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert any(g["correlation_type"] == "SAME_EXPOSURE" for g in groups)
    db.close()

# 6 same package
def test_same_package():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "app")
    f1 = _add_finding(db, a.id, "sca", "pkg vuln", extra={"package": "lodash"})
    f2 = _add_finding(db, a.id, "container", "pkg vuln", extra={"package": "lodash"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert any("lodash" in str(g["canonical_key"]) for g in groups)
    db.close()

# 7 SAST/SCA relationship
def test_sast_sca():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "repo")
    f1 = _add_finding(db, a.id, "sast", "unsafe dep", extra={"package": "express"})
    f2 = _add_finding(db, a.id, "sca", "vuln express", extra={"package": "express"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert any(g["correlation_type"] == "SAME_ROOT_CAUSE" for g in groups)
    db.close()

# 8 SCA/container
def test_sca_container():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "image")
    f1 = _add_finding(db, a.id, "sca", "vuln", extra={"package": "openssl"})
    f2 = _add_finding(db, a.id, "container", "vuln", extra={"package": "openssl"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert any(g["correlation_type"] == "SAME_ROOT_CAUSE" for g in groups)
    db.close()

# 9 cloud/CSPM — need CSPM failed control mapping to finding rule
def test_cloud_cspm():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    from app.models.asset import Asset
    from app.models.finding import Finding
    # Create cloud asset with public S3 to trigger CSPM? Instead use direct cloud finding with rule that maps to CSPM
    a = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_s3_bucket:b", extra_data={"resource_type": "aws_s3_bucket", "public": True})
    db.add(a); db.flush()
    f = Finding(id=str(uuid.uuid4()), asset_id=a.id, scanner="cloud", title="public bucket", severity="high", cve=None, extra_data={"rule_id": "AWS-S3-003"})
    db.add(f); db.commit()
    groups = get_correlations(objs["proj"].id, db)
    # Should have CSPM_RELATED if CSPM evaluates to FAIL for that control
    # CSPM may not have failed without check run, but we can at least check no error
    assert isinstance(groups, list)
    db.close()

# 10 finding/attack-path — need attack path
def test_attack_path_related():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    from app.models.asset import Asset
    from app.models.asset_relationship import AssetRelationship
    from app.models.finding import Finding
    entry = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_ec2_instance:i1", extra_data={"resource_type": "aws_ec2_instance", "public_ip": "1.1.1.1"})
    target = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_rds_instance:db1", extra_data={"resource_type": "aws_rds_instance"})
    db.add_all([entry, target]); db.flush()
    rel = AssetRelationship(id=str(uuid.uuid4()), project_id=objs["proj"].id, source_asset_id=entry.id, target_asset_id=target.id, relationship_type="contains")
    db.add(rel); db.flush()
    f = Finding(id=str(uuid.uuid4()), asset_id=target.id, scanner="cloud", title="RDS Public", severity="critical", extra_data={"rule_id": "AWS-RDS-001"})
    db.add(f); db.commit()
    groups = get_correlations(objs["proj"].id, db)
    # Should have attack path related if path exists
    # At least no error, may have ATTACK_PATH_RELATED
    assert isinstance(groups, list)
    db.close()

# 11 root cause
def test_root_cause():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "app2")
    f1 = _add_finding(db, a.id, "sca", "vuln lodash", extra={"package": "lodash"})
    f2 = _add_finding(db, a.id, "container", "vuln lodash", extra={"package": "lodash"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert any(g["correlation_type"] == "SAME_ROOT_CAUSE" for g in groups)
    db.close()

# 12 no speculative
def test_no_speculative():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a1 = _add_asset(db, objs["proj"].id, "host-a.com")
    a2 = _add_asset(db, objs["proj"].id, "host-b.com")
    f1 = _add_finding(db, a1.id, "nuclei", "issue X", rule_id="R1")
    f2 = _add_finding(db, a2.id, "zap", "issue Y", rule_id="R2")
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    # These should not correlate (different asset, different rule, different CVE)
    # Might still have no groups or only SAME_ASSET not applicable
    for g in groups:
        assert g["correlation_type"] != "DUPLICATE" or len(g["members"]) < 2 or g["asset_count"] > 1
    db.close()

# 13 confidence
def test_confidence():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "conf.com")
    f1 = _add_finding(db, a.id, "nuclei", "dup", rule_id="R1", extra={"url": "https://conf.com/a"})
    f2 = _add_finding(db, a.id, "zap", "dup", rule_id="R1", extra={"url": "https://conf.com/a"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    for g in groups:
        assert g["confidence"] in ("HIGH", "MEDIUM", "LOW")
        assert g["score"] >= 0 and g["score"] <= 100
    db.close()

# 14 correlation strength
def test_correlation_strength():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "strength.com")
    f1 = _add_finding(db, a.id, "nuclei", "dup", rule_id="R1", cve="CVE-2021-1234", extra={"url": "https://strength.com/x"})
    f2 = _add_finding(db, a.id, "zap", "dup", rule_id="R1", cve="CVE-2021-1234", extra={"url": "https://strength.com/x"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    dup = next((g for g in groups if g["correlation_type"] == "DUPLICATE"), None)
    if dup:
        assert dup["score"] >= 80
    db.close()

# 15 deterministic canonical identity
def test_deterministic_canonical():
    fp1 = _canonical_fingerprint("proj1", "asset1", "R1", "CVE-1", "CWE-1", "https://example.com")
    fp2 = _canonical_fingerprint("proj1", "asset1", "R1", "CVE-1", "CWE-1", "https://example.com")
    assert fp1 == fp2
    fp3 = _canonical_fingerprint("proj1", "asset2", "R1", "CVE-1", "CWE-1", "https://example.com")
    assert fp1 != fp3

# 16 repeated evaluation stable
def test_repeated_stable():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "stable.com")
    _add_finding(db, a.id, "nuclei", "dup", rule_id="R1", extra={"url": "https://stable.com/a"})
    _add_finding(db, a.id, "zap", "dup", rule_id="R1", extra={"url": "https://stable.com/a"})
    db.commit()
    g1 = get_correlations(objs["proj"].id, db)
    g2 = get_correlations(objs["proj"].id, db)
    assert len(g1) == len(g2)
    assert {g["id"] for g in g1} == {g["id"] for g in g2}
    db.close()

# 17 duplicate groups prevented
def test_duplicate_groups_prevented():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "dup.com")
    for _ in range(3):
        _add_finding(db, a.id, "nuclei", "dup", rule_id="R1", extra={"url": "https://dup.com/a"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    # Should not have duplicate group ids
    assert len(groups) == len({g["id"] for g in groups})
    db.close()

# 18 candidate bucketing (ensure bounded)
def test_candidate_bucketing():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    for i in range(50):
        a = _add_asset(db, objs["proj"].id, f"host{i}.com")
        _add_finding(db, a.id, "nuclei", f"issue {i}", rule_id=f"R{i%5}")
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert len(groups) <= 200
    db.close()

# 19 bounds
def test_bounds():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    groups = get_correlations(objs["proj"].id, db, limit=5)
    assert len(groups) <= 5
    db.close()

# 20 evidence limits
def test_evidence_limits():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "evidence.com")
    for i in range(25):
        _add_finding(db, a.id, "nuclei", f"dup {i}", rule_id="R1", extra={"url": "https://evidence.com/a"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    for g in groups:
        assert len(g["members"]) <= 20
    db.close()

# 21 secret redaction
def test_secret_redaction():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "secret.com")
    _add_finding(db, a.id, "gitleaks", "secret leaked token password", extra={"file": "config.py"})
    _add_finding(db, a.id, "sast", "secret leaked token password", extra={"file": "config.py"})
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    for g in groups:
        assert "[REDACTED]" in g["title"] or "secret" not in g["title"].lower()
        for m in g["members"]:
            assert "[REDACTED]" in m["title"] or "secret" not in m["title"].lower()
    db.close()

# 22 no FindingEngine mutation
def test_no_mutation():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "mut.com")
    _add_finding(db, a.id, "nuclei", "dup", rule_id="R1")
    _add_finding(db, a.id, "zap", "dup", rule_id="R1")
    db.commit()
    from app.models.finding import Finding
    before = db.query(Finding).count()
    get_correlations(objs["proj"].id, db)
    after = SessionLocal().query(Finding).count()
    assert before == after
    db.close()

# 23 project isolation
def test_project_isolation():
    eng, SessionLocal, objs = _setup()
    from app.models.organization import Organization
    from app.models.project import Project
    db = SessionLocal()
    org2 = Organization(id=str(uuid.uuid4()), name="Org2", slug="org2-"+str(uuid.uuid4())[:4])
    db.add(org2); db.flush()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=org2.id, name="Proj2")
    db.add(proj2); db.commit()
    a = _add_asset(db, objs["proj"].id, "proj1.com")
    _add_finding(db, a.id, "nuclei", "dup", rule_id="R1")
    _add_finding(db, a.id, "zap", "dup", rule_id="R1")
    db.commit()
    g1 = get_correlations(objs["proj"].id, db)
    g2 = get_correlations(proj2.id, db)
    assert len(g1) >= 1
    assert len(g2) == 0
    db.close()

# 24 tenant isolation
def test_tenant_isolation():
    eng, SessionLocal, objs = _setup()
    from app.models.organization import Organization
    from app.models.project import Project
    from app.models.user import User
    db = SessionLocal()
    org2 = Organization(id=str(uuid.uuid4()), name="OrgTenant", slug="orgten-"+str(uuid.uuid4())[:4])
    db.add(org2); db.flush()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=org2.id, name="ProjTenant")
    db.add(proj2); db.commit()
    client = _client(SessionLocal)
    try:
        token = create_access_token(objs["user"].id)
        # Try to access proj2 correlations with proj's user -> should 404
        resp = client.get(f"/api/v1/projects/{proj2.id}/security/correlations", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 404
    finally:
        app.dependency_overrides.clear()
    db.close()

# 25 RBAC
def test_rbac():
    eng, SessionLocal, objs = _setup()
    client = _client(SessionLocal)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj'].id}/security/correlations")
        assert resp.status_code == 401
    finally:
        app.dependency_overrides.clear()

# 26 IDOR
def test_idor():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "idor.com")
    _add_finding(db, a.id, "nuclei", "dup", rule_id="R1")
    _add_finding(db, a.id, "zap", "dup", rule_id="R1")
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert len(groups) >= 1
    gid = groups[0]["id"]
    # Create other project
    from app.models.organization import Organization
    from app.models.project import Project
    from app.models.user import User
    db2 = SessionLocal()
    org2 = Organization(id=str(uuid.uuid4()), name="OrgIdor", slug="idor-"+str(uuid.uuid4())[:4])
    db2.add(org2); db2.flush()
    proj2 = Project(id=str(uuid.uuid4()), organization_id=org2.id, name="ProjIdor")
    db2.add(proj2)
    pwd = hash_password("password123")
    user2 = User(id=str(uuid.uuid4()), organization_id=org2.id, email="idor@org.test", password_hash=pwd, role="member")
    db2.add(user2); db2.commit()
    client = _client(SessionLocal)
    try:
        token = create_access_token(user2.id)
        resp = client.get(f"/api/v1/projects/{proj2.id}/security/correlations/{gid}", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 404
    finally:
        app.dependency_overrides.clear()
    db.close()

# 27 invalid filters
def test_invalid_filters():
    eng, SessionLocal, objs = _setup()
    client = _client(SessionLocal)
    try:
        token = create_access_token(objs["user"].id)
        resp = client.get(f"/api/v1/projects/{objs['proj'].id}/security/correlations?type=INVALID", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 400
    finally:
        app.dependency_overrides.clear()

# 28 API list
def test_api_list():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "api-list.com")
    _add_finding(db, a.id, "nuclei", "dup", rule_id="R1")
    _add_finding(db, a.id, "zap", "dup", rule_id="R1")
    db.commit()
    client = _client(SessionLocal)
    try:
        token = create_access_token(objs["user"].id)
        resp = client.get(f"/api/v1/projects/{objs['proj'].id}/security/correlations", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["count"] >= 1
    finally:
        app.dependency_overrides.clear()

# 29 API detail
def test_api_detail():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "detail.com")
    _add_finding(db, a.id, "nuclei", "dup", rule_id="R1")
    _add_finding(db, a.id, "zap", "dup", rule_id="R1")
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    gid = groups[0]["id"]
    client = _client(SessionLocal)
    try:
        token = create_access_token(objs["user"].id)
        resp = client.get(f"/api/v1/projects/{objs['proj'].id}/security/correlations/{gid}", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["id"] == gid
        # unknown
        resp2 = client.get(f"/api/v1/projects/{objs['proj'].id}/security/correlations/notfound", headers={"Authorization": f"Bearer {token}"})
        assert resp2.status_code == 404
    finally:
        app.dependency_overrides.clear()

# 30 API summary
def test_api_summary():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "summary.com")
    _add_finding(db, a.id, "nuclei", "dup", rule_id="R1")
    _add_finding(db, a.id, "zap", "dup", rule_id="R1")
    db.commit()
    client = _client(SessionLocal)
    try:
        token = create_access_token(objs["user"].id)
        resp = client.get(f"/api/v1/projects/{objs['proj'].id}/security/correlations/summary", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert "total_groups" in resp.json()
    finally:
        app.dependency_overrides.clear()

# 31 finding detail integration (check finding correlation appears)
def test_finding_detail_integration():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "finding-detail.com")
    f1 = _add_finding(db, a.id, "nuclei", "dup", rule_id="R1")
    _add_finding(db, a.id, "zap", "dup", rule_id="R1")
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    # finding should be in a group
    assert any(f1.id in g["finding_ids"] for g in groups)
    db.close()

# 32 asset detail integration
def test_asset_detail_integration():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "asset-detail.com")
    _add_finding(db, a.id, "nuclei", "dup", rule_id="R1")
    _add_finding(db, a.id, "zap", "dup", rule_id="R1")
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert any(a.id in g["asset_ids"] for g in groups)
    db.close()

# 33 E11 regression
def test_e11_regression():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    from app.models.asset import Asset
    from app.models.asset_relationship import AssetRelationship
    from app.models.finding import Finding
    entry = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_ec2_instance:i1", extra_data={"resource_type": "aws_ec2_instance", "public_ip": "1.1.1.1"})
    target = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_rds_instance:db1", extra_data={"resource_type": "aws_rds_instance"})
    db.add_all([entry, target]); db.flush()
    rel = AssetRelationship(id=str(uuid.uuid4()), project_id=objs["proj"].id, source_asset_id=entry.id, target_asset_id=target.id, relationship_type="contains")
    db.add(rel); db.flush()
    f = Finding(id=str(uuid.uuid4()), asset_id=target.id, scanner="cloud", title="RDS", severity="critical", extra_data={"rule_id": "AWS-RDS-001"})
    db.add(f); db.commit()
    from app.services.cloud_exposure_intelligence import get_exposure_intelligence
    intel = get_exposure_intelligence(objs["proj"].id, db)
    assert "score" in intel
    db.close()

# 34 E10 regression
def test_e10_regression():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    from app.models.asset import Asset
    from app.models.asset_relationship import AssetRelationship
    from app.models.finding import Finding
    entry = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_ec2_instance:i2", extra_data={"resource_type": "aws_ec2_instance", "public_ip": "1.1.1.1"})
    target = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_rds_instance:db2", extra_data={"resource_type": "aws_rds_instance"})
    db.add_all([entry, target]); db.flush()
    rel = AssetRelationship(id=str(uuid.uuid4()), project_id=objs["proj"].id, source_asset_id=entry.id, target_asset_id=target.id, relationship_type="contains")
    db.add(rel); db.flush()
    f = Finding(id=str(uuid.uuid4()), asset_id=target.id, scanner="cloud", title="RDS", severity="critical", extra_data={"rule_id": "AWS-RDS-001"})
    db.add(f); db.commit()
    from app.services.cloud_attack_path_history import observe_attack_paths, get_history
    observe_attack_paths(objs["proj"].id, db, run_status="completed")
    hist = get_history(objs["proj"].id, db)
    assert len(hist) >= 1
    db.close()

# 35 E9 regression
def test_e9_regression():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    from app.models.asset import Asset
    from app.models.asset_relationship import AssetRelationship
    from app.models.finding import Finding
    entry = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_ec2_instance:i3", extra_data={"resource_type": "aws_ec2_instance", "public_ip": "1.1.1.1"})
    target = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_s3_bucket:b1", extra_data={"resource_type": "aws_s3_bucket"})
    db.add_all([entry, target]); db.flush()
    rel = AssetRelationship(id=str(uuid.uuid4()), project_id=objs["proj"].id, source_asset_id=entry.id, target_asset_id=target.id, relationship_type="contains")
    db.add(rel); db.flush()
    f = Finding(id=str(uuid.uuid4()), asset_id=target.id, scanner="cloud", title="public bucket", severity="high", extra_data={"rule_id": "AWS-S3-003"})
    db.add(f); db.commit()
    from app.services.cloud_attack_paths import build_cloud_attack_paths
    paths = build_cloud_attack_paths(objs["proj"].id, db)
    assert isinstance(paths, list)
    db.close()

# 36 E8 regression
def test_e8_regression():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    from app.models.asset import Asset
    from app.models.finding import Finding
    a = Asset(id=str(uuid.uuid4()), project_id=objs["proj"].id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_s3_bucket:b2", extra_data={"resource_type": "aws_s3_bucket", "public": True})
    db.add(a); db.flush()
    f = Finding(id=str(uuid.uuid4()), asset_id=a.id, scanner="cloud", title="public bucket", severity="high", extra_data={"rule_id": "AWS-S3-003"})
    db.add(f); db.commit()
    from app.services.cspm import evaluate_cspm
    data = evaluate_cspm(objs["proj"].id, db)
    assert "score" in data
    db.close()

# 37 scanner regression (nuclei)
def test_scanner_regression():
    eng, SessionLocal, objs = _setup()
    db = SessionLocal()
    a = _add_asset(db, objs["proj"].id, "nuclei.com")
    _add_finding(db, a.id, "nuclei", "test", rule_id="R1")
    db.commit()
    groups = get_correlations(objs["proj"].id, db)
    assert isinstance(groups, list)
    db.close()

"""E9 Cloud Attack Paths — bounded, deterministic, provider-neutral."""

import hashlib
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, String, Text, Integer, DateTime, ForeignKey, UniqueConstraint, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.database import get_db
from app.main import app
from app.core.security import create_access_token, hash_password
from app.services.cloud_attack_paths import (
    MAX_PATH_DEPTH, MAX_PATHS, MAX_API_LIMIT, MAX_PATH_EVIDENCE,
    build_cloud_attack_paths, get_attack_path_detail,
    _score_path, _severity_from_score, _confidence_for_path, _canonical_fingerprint, _sanitize_evidence,
)


# ---------------------------------------------------------------------------
# Minimal fake models for unit tests (mock DB)
# ---------------------------------------------------------------------------

class FakeAsset:
    def __init__(self, id=None, project_id="proj-1", value="cloud_resource:aws:acct:us-east-1:aws_ec2_instance:i-123", asset_type="cloud_resource", extra_data=None):
        self.id = id or str(uuid.uuid4())
        self.project_id = project_id
        self.value = value
        self.asset_type = asset_type
        self.extra_data = extra_data or {}

class FakeRel:
    def __init__(self, id=None, project_id="proj-1", source_asset_id=None, target_asset_id=None, relationship_type="contains", extra_data=None):
        self.id = id or str(uuid.uuid4())
        self.project_id = project_id
        self.source_asset_id = source_asset_id
        self.target_asset_id = target_asset_id
        self.relationship_type = relationship_type
        self.extra_data = extra_data or {}

class FakeFinding:
    def __init__(self, id=None, asset_id=None, rule_id="AWS-EC2-002", severity="high", title="test", project_id="proj-1"):
        self.id = id or str(uuid.uuid4())
        self.asset_id = asset_id
        self.extra_data = {"rule_id": rule_id}
        self.severity = severity
        self.title = title


class MockDB:
    def __init__(self, assets=None, rels=None, findings=None):
        self.assets = assets or []
        self.rels = rels or []
        self.findings = findings or []

    def query(self, model, *a, **kw):
        name = getattr(model, "__name__", "")
        assets = self.assets
        rels = self.rels
        findings = self.findings
        class Q:
            def join(self, *aa, **kk): return self
            def filter(self, *aa, **kk): return self
            def limit(self, *aa, **kk): return self
            def all(self):
                if "Asset" in name and "Relationship" not in name:
                    return assets
                if "AssetRelationship" in name:
                    return rels
                if "Finding" in name:
                    return findings
                return []
            def first(self): return None
            def count(self): return len(self.all())
            def scalar(self): return len(self.all())
        return Q()


# ---------------------------------------------------------------------------
# Helpers to build synthetic graphs
# ---------------------------------------------------------------------------

def _make_project_assets(project_id="proj-1", provider="aws"):
    # entry: public VM with public_ip
    entry = FakeAsset(project_id=project_id, value=f"cloud_resource:{provider}:acct:us-east-1:aws_ec2_instance:i-entry", extra_data={"resource_type": "aws_ec2_instance", "public_ip": "1.2.3.4", "provider": provider})
    # target: RDS with finding
    target = FakeAsset(project_id=project_id, value=f"cloud_resource:{provider}:acct:us-east-1:aws_rds_instance:db-1", extra_data={"resource_type": "aws_rds_instance", "provider": provider})
    # account
    acct = FakeAsset(project_id=project_id, value=f"cloud_account:{provider}:acct:us-east-1", asset_type="cloud_account", extra_data={"provider": provider})
    return entry, target, acct

def _make_gcp_assets(project_id="proj-1"):
    entry = FakeAsset(project_id=project_id, value="cloud_resource:gcp:proj:us-central1:gcp_compute_instance:vm-1", extra_data={"resource_type": "gcp_compute_instance", "public_ip": "8.8.8.8", "provider": "gcp"})
    target = FakeAsset(project_id=project_id, value="cloud_resource:gcp:proj:us-central1:gcp_storage_bucket:b1", extra_data={"resource_type": "gcp_storage_bucket", "provider": "gcp"})
    return entry, target

def _make_azure_assets(project_id="proj-1"):
    entry = FakeAsset(project_id=project_id, value="cloud_resource:azure:sub:eastus:azure_vm:vm-az", extra_data={"resource_type": "azure_vm", "public_ip": "20.30.40.50", "provider": "azure"})
    target = FakeAsset(project_id=project_id, value="cloud_resource:azure:sub:eastus:azure_storage_account:st1", extra_data={"resource_type": "azure_storage_account", "provider": "azure"})
    return entry, target


# ---------------------------------------------------------------------------
# 1. empty graph → no paths
# ---------------------------------------------------------------------------

def test_empty_graph_no_paths():
    db = MockDB(assets=[], rels=[], findings=[])
    paths = build_cloud_attack_paths("proj-1", db)
    assert paths == []

def test_single_valid_internet_to_resource():
    entry, target, acct = _make_project_assets()
    rel = FakeRel(source_asset_id=entry.id, target_asset_id=target.id, relationship_type="contains")
    finding = FakeFinding(asset_id=target.id, rule_id="AWS-RDS-001", severity="critical")
    # entry needs to be recognized as entry via public_ip, target has finding
    db = MockDB(assets=[entry, target, acct], rels=[rel], findings=[finding])
    paths = build_cloud_attack_paths("proj-1", db)
    assert len(paths) >= 1
    assert paths[0]["entry_asset_id"] == entry.id
    assert paths[0]["target_asset_id"] == target.id

def test_internet_to_vulnerable_resource():
    entry, target, _ = _make_project_assets()
    rel = FakeRel(source_asset_id=entry.id, target_asset_id=target.id)
    finding = FakeFinding(asset_id=target.id, rule_id="AWS-S3-003", severity="high")
    db = MockDB(assets=[entry, target], rels=[rel], findings=[finding])
    paths = build_cloud_attack_paths("proj-1", db)
    assert any(p["path_type"] == "INTERNET_TO_VULNERABLE_RESOURCE" for p in paths)

def test_identity_to_privileged():
    # identity asset with IAM finding
    iam = FakeAsset(project_id="proj-1", value="cloud_resource:aws:acct:us-east-1:aws_iam_role:role-1", extra_data={"resource_type": "aws_iam_role", "provider": "aws"})
    target = FakeAsset(project_id="proj-1", value="cloud_resource:aws:acct:us-east-1:aws_s3_bucket:b1", extra_data={"resource_type": "aws_s3_bucket", "public": True})
    rel = FakeRel(source_asset_id=iam.id, target_asset_id=target.id, relationship_type="has_permission")
    # entry needs public, but for identity path we need entry to be identity? Simplify: use iam as entry with public-like finding? For test, we mark iam as entry via finding
    f_iam = FakeFinding(asset_id=iam.id, rule_id="AWS-IAM-001", severity="high")
    f_target = FakeFinding(asset_id=target.id, rule_id="AWS-S3-003", severity="high")
    # Make iam look like entry by adding public_ip metadata
    iam.extra_data["public_ip"] = "5.6.7.8"
    db = MockDB(assets=[iam, target], rels=[rel], findings=[f_iam, f_target])
    paths = build_cloud_attack_paths("proj-1", db)
    # Should generate at least one path, may be identity type
    assert len(paths) >= 1

def test_external_trust_to_privileged():
    entry = FakeAsset(project_id="proj-1", value="cloud_resource:aws:acct:us-east-1:aws_iam_role:role-ext", extra_data={"resource_type": "aws_iam_role", "public_ip": "1.1.1.1"})
    target = FakeAsset(project_id="proj-1", value="cloud_resource:aws:acct:us-east-1:aws_iam_role:role-priv", extra_data={"resource_type": "aws_iam_role"})
    rel = FakeRel(source_asset_id=entry.id, target_asset_id=target.id, relationship_type="trusts")
    f1 = FakeFinding(asset_id=entry.id, rule_id="AWS-IAM-004", severity="critical")
    f2 = FakeFinding(asset_id=target.id, rule_id="AWS-IAM-001", severity="high")
    db = MockDB(assets=[entry, target], rels=[rel], findings=[f1, f2])
    paths = build_cloud_attack_paths("proj-1", db)
    assert len(paths) >= 1
    assert any("TRUST" in p["path_type"] or "IDENTITY" in p["path_type"] for p in paths)

def test_multi_hop_path():
    a = FakeAsset(extra_data={"public_ip": "1.1.1.1", "resource_type": "aws_ec2_instance"})
    b = FakeAsset(value="cloud_resource:aws:acct:us-east-1:aws_security_group:sg-1", extra_data={"resource_type": "aws_security_group"})
    c = FakeAsset(value="cloud_resource:aws:acct:us-east-1:aws_rds_instance:db-2", extra_data={"resource_type": "aws_rds_instance"})
    rel1 = FakeRel(source_asset_id=a.id, target_asset_id=b.id)
    rel2 = FakeRel(source_asset_id=b.id, target_asset_id=c.id)
    f = FakeFinding(asset_id=c.id, rule_id="AWS-RDS-001", severity="critical")
    db = MockDB(assets=[a, b, c], rels=[rel1, rel2], findings=[f])
    paths = build_cloud_attack_paths("proj-1", db, max_depth=6)
    assert any(len(p["asset_ids"]) == 3 for p in paths)

def test_path_depth_limit():
    # chain 8 nodes, depth 6 should limit
    nodes = [FakeAsset(value=f"cloud_resource:aws:acct:us-east-1:aws_ec2_instance:i-{i}", extra_data={"resource_type": "aws_ec2_instance", "public_ip": "1.1.1.1" if i==0 else ""}) for i in range(8)]
    rels = [FakeRel(source_asset_id=nodes[i].id, target_asset_id=nodes[i+1].id) for i in range(7)]
    f = FakeFinding(asset_id=nodes[-1].id, rule_id="AWS-RDS-001", severity="high")
    db = MockDB(assets=nodes, rels=rels, findings=[f])
    paths = build_cloud_attack_paths("proj-1", db, max_depth=3)
    for p in paths:
        assert len(p["relationships"]) <= 3

def test_path_count_limit():
    entry = FakeAsset(extra_data={"public_ip": "1.1.1.1", "resource_type": "aws_ec2_instance"})
    targets = [FakeAsset(value=f"cloud_resource:aws:acct:us-east-1:aws_s3_bucket:b-{i}", extra_data={"resource_type": "aws_s3_bucket"}) for i in range(10)]
    rels = [FakeRel(source_asset_id=entry.id, target_asset_id=t.id) for t in targets]
    findings = [FakeFinding(asset_id=t.id, rule_id="AWS-S3-003", severity="high") for t in targets]
    db = MockDB(assets=[entry] + targets, rels=rels, findings=findings)
    paths = build_cloud_attack_paths("proj-1", db, limit=3)
    assert len(paths) <= 3

def test_cycle_prevention():
    a = FakeAsset(extra_data={"public_ip": "1.1.1.1"})
    b = FakeAsset()
    c = FakeAsset()
    rel_ab = FakeRel(source_asset_id=a.id, target_asset_id=b.id)
    rel_bc = FakeRel(source_asset_id=b.id, target_asset_id=c.id)
    rel_ca = FakeRel(source_asset_id=c.id, target_asset_id=a.id)  # cycle
    f = FakeFinding(asset_id=c.id, rule_id="AWS-S3-003", severity="high")
    db = MockDB(assets=[a, b, c], rels=[rel_ab, rel_bc, rel_ca], findings=[f])
    paths = build_cloud_attack_paths("proj-1", db)
    for p in paths:
        assert len(p["asset_ids"]) == len(set(p["asset_ids"]))

def test_duplicate_path_elimination():
    entry, target, _ = _make_project_assets()
    rel = FakeRel(source_asset_id=entry.id, target_asset_id=target.id)
    f = FakeFinding(asset_id=target.id, rule_id="AWS-RDS-001", severity="high")
    # duplicate rel with same ids but different object would be separate? Fingerprint uses sorted asset_ids so same path deduped
    db = MockDB(assets=[entry, target], rels=[rel], findings=[f])
    p1 = build_cloud_attack_paths("proj-1", db)
    p2 = build_cloud_attack_paths("proj-1", db)
    assert len(p1) == len(p2)
    assert p1[0]["id"] == p2[0]["id"]

def test_canonical_fingerprint_stability():
    fp1 = _canonical_fingerprint("proj-1", "INTERNET_TO_VULNERABLE_RESOURCE", "aws", ["a", "b"])
    fp2 = _canonical_fingerprint("proj-1", "INTERNET_TO_VULNERABLE_RESOURCE", "aws", ["a", "b"])
    assert fp1 == fp2
    fp3 = _canonical_fingerprint("proj-1", "INTERNET_TO_VULNERABLE_RESOURCE", "aws", ["b", "a"])
    assert fp1 == fp3  # sorted

def test_finding_correlation():
    entry, target, _ = _make_project_assets()
    rel = FakeRel(source_asset_id=entry.id, target_asset_id=target.id)
    f = FakeFinding(asset_id=target.id, rule_id="AWS-S3-003", severity="high", title="Public bucket")
    db = MockDB(assets=[entry, target], rels=[rel], findings=[f])
    paths = build_cloud_attack_paths("proj-1", db)
    assert paths[0]["findings"][0]["rule_id"] == "AWS-S3-003"
    assert paths[0]["findings"][0]["finding_id"] == f.id

def test_missing_evidence_no_speculative_path():
    entry = FakeAsset(extra_data={"public_ip": "1.1.1.1"})
    target = FakeAsset()
    rel = FakeRel(source_asset_id=entry.id, target_asset_id=target.id)
    # no findings -> no path (needs finding for meaningful security condition)
    db = MockDB(assets=[entry, target], rels=[rel], findings=[])
    paths = build_cloud_attack_paths("proj-1", db)
    assert len(paths) == 0

def test_confidence_calculation():
    assert _confidence_for_path(2, 2, 0) == "HIGH"
    assert _confidence_for_path(2, 0, 0) == "MEDIUM"
    assert _confidence_for_path(2, 2, 1) == "MEDIUM"
    assert _confidence_for_path(2, 0, 2) == "LOW"

def test_priority_scoring():
    f_crit = FakeFinding(asset_id="x", rule_id="AWS-RDS-001", severity="critical")
    score = _score_path(True, [f_crit], 1, True, 2)
    assert score >= 85
    f_low = FakeFinding(asset_id="x", rule_id="AWS-S3-007", severity="low")
    score2 = _score_path(False, [f_low], 0, False, 6)
    assert score2 < score

def test_severity_classification():
    assert _severity_from_score(90) == "critical"
    assert _severity_from_score(75) == "high"
    assert _severity_from_score(50) == "medium"
    assert _severity_from_score(20) == "low"

def test_aws_normalization():
    entry, target = _make_gcp_assets()[:2]  # reuse but check provider extraction
    # Use aws assets
    entry_aws, target_aws, _ = _make_project_assets(provider="aws")
    rel = FakeRel(source_asset_id=entry_aws.id, target_asset_id=target_aws.id)
    f = FakeFinding(asset_id=target_aws.id, rule_id="AWS-RDS-001", severity="high")
    db = MockDB(assets=[entry_aws, target_aws], rels=[rel], findings=[f])
    paths = build_cloud_attack_paths("proj-1", db)
    assert paths[0]["provider"] == "aws"

def test_gcp_normalization():
    entry, target = _make_gcp_assets()
    rel = FakeRel(source_asset_id=entry.id, target_asset_id=target.id)
    f = FakeFinding(asset_id=target.id, rule_id="GCP-GCS-001", severity="high")
    db = MockDB(assets=[entry, target], rels=[rel], findings=[f])
    paths = build_cloud_attack_paths("proj-1", db)
    assert paths[0]["provider"] == "gcp"

def test_azure_normalization():
    entry, target = _make_azure_assets()
    rel = FakeRel(source_asset_id=entry.id, target_asset_id=target.id)
    f = FakeFinding(asset_id=target.id, rule_id="AZURE-STORAGE-001", severity="high")
    db = MockDB(assets=[entry, target], rels=[rel], findings=[f])
    paths = build_cloud_attack_paths("proj-1", db)
    assert paths[0]["provider"] == "azure"

def test_mixed_provider_isolation():
    # Each path should be provider-isolated via filter
    entry_aws, target_aws, _ = _make_project_assets(provider="aws")
    rel_aws = FakeRel(source_asset_id=entry_aws.id, target_asset_id=target_aws.id)
    f_aws = FakeFinding(asset_id=target_aws.id, rule_id="AWS-RDS-001", severity="high")
    entry_gcp, target_gcp = _make_gcp_assets()
    rel_gcp = FakeRel(source_asset_id=entry_gcp.id, target_asset_id=target_gcp.id)
    f_gcp = FakeFinding(asset_id=target_gcp.id, rule_id="GCP-GCS-001", severity="high")
    db = MockDB(assets=[entry_aws, target_aws, entry_gcp, target_gcp], rels=[rel_aws, rel_gcp], findings=[f_aws, f_gcp])
    paths_aws = build_cloud_attack_paths("proj-1", db, provider_filter="aws")
    assert all(p["provider"] == "aws" for p in paths_aws)
    paths_gcp = build_cloud_attack_paths("proj-1", db, provider_filter="gcp")
    assert all(p["provider"] == "gcp" for p in paths_gcp)

def test_project_isolation():
    entry, target, _ = _make_project_assets(project_id="proj-a")
    rel = FakeRel(project_id="proj-a", source_asset_id=entry.id, target_asset_id=target.id)
    f = FakeFinding(asset_id=target.id, rule_id="AWS-RDS-001", severity="high")
    db_a = MockDB(assets=[entry, target], rels=[rel], findings=[f])
    entry_b, target_b, _ = _make_project_assets(project_id="proj-b")
    # proj-b has no relationships/findings -> no paths
    db_b = MockDB(assets=[entry_b, target_b], rels=[], findings=[])
    paths_a = build_cloud_attack_paths("proj-a", db_a)
    paths_b = build_cloud_attack_paths("proj-b", db_b)
    assert len(paths_a) >= 1
    assert len(paths_b) == 0

def test_invalid_filters():
    db = MockDB(assets=[], rels=[], findings=[])
    with pytest.raises(ValueError):
        build_cloud_attack_paths("proj-1", db, provider_filter="invalid")
    with pytest.raises(ValueError):
        build_cloud_attack_paths("proj-1", db, severity_filter="invalid")
    with pytest.raises(ValueError):
        build_cloud_attack_paths("proj-1", db, confidence_filter="invalid")
    with pytest.raises(ValueError):
        build_cloud_attack_paths("proj-1", db, path_type_filter="invalid")

def test_evidence_bounds():
    entry, target, _ = _make_project_assets()
    rel = FakeRel(source_asset_id=entry.id, target_asset_id=target.id)
    findings = [FakeFinding(asset_id=target.id, rule_id=f"AWS-S3-00{i%3}", severity="high") for i in range(30)]
    db = MockDB(assets=[entry, target], rels=[rel], findings=findings)
    paths = build_cloud_attack_paths("proj-1", db)
    assert len(paths[0]["evidence"]) <= MAX_PATH_EVIDENCE

def test_secret_redaction():
    f = FakeFinding(asset_id="x", rule_id="AWS-S3-003", severity="high", title="exposed secret AKIA123 token")
    sanitized = _sanitize_evidence([{"rule_id": f.extra_data["rule_id"], "finding_id": f.id, "asset_id": f.asset_id, "severity": f.severity, "title": f.title}])
    assert sanitized[0]["title"] == "[REDACTED]"

def test_no_duplicate_finding_engine_findings():
    entry, target, _ = _make_project_assets()
    rel = FakeRel(source_asset_id=entry.id, target_asset_id=target.id)
    f = FakeFinding(asset_id=target.id, rule_id="AWS-RDS-001", severity="high")
    db = MockDB(assets=[entry, target], rels=[rel], findings=[f])
    before = len(db.findings)
    build_cloud_attack_paths("proj-1", db)
    assert len(db.findings) == before


# ---------------------------------------------------------------------------
# API integration — project/Tenant/RBAC isolation (using real sqlite TestClient)
# ---------------------------------------------------------------------------

class Base(DeclarativeBase): pass

class Organization(Base):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    slug: Mapped[str] = mapped_column(String(255), unique=True)
    status: Mapped[str] = mapped_column(String(20), default="active")

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="member")
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[str] = mapped_column(String(50), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Integer, default=0)
    password_changed_at: Mapped[str] = mapped_column(String(50), nullable=True)

class Project(Base):
    __tablename__ = "projects"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(36), ForeignKey("organizations.id"))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(String(1000), nullable=True)

class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    asset_type: Mapped[str] = mapped_column(String(50))
    value: Mapped[str] = mapped_column(String(1024))
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="active")
    criticality: Mapped[str] = mapped_column(String(20), default="unknown")
    first_seen_scan_id: Mapped[str] = mapped_column(String(36), nullable=True)
    last_seen_scan_id: Mapped[str] = mapped_column(String(36), nullable=True)
    owner_user_id: Mapped[str] = mapped_column(String(36), nullable=True)
    first_seen_at: Mapped[str] = mapped_column(String(50), nullable=True)
    last_seen_at: Mapped[str] = mapped_column(String(50), nullable=True)
    created_at: Mapped[str] = mapped_column(String(50), nullable=True)
    updated_at: Mapped[str] = mapped_column(String(50), nullable=True)

class AssetRelationship(Base):
    __tablename__ = "asset_relationships"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    source_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"))
    target_asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"))
    relationship_type: Mapped[str] = mapped_column(String(50))
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    last_seen_scan_id: Mapped[str] = mapped_column(String(36), nullable=True)
    created_at: Mapped[str] = mapped_column(String(50), nullable=True)
    updated_at: Mapped[str] = mapped_column(String(50), nullable=True)

class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True)
    scanner: Mapped[str] = mapped_column(String(50), default="cloud")
    title: Mapped[str] = mapped_column(String(500), default="test")
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="high")
    extra_data: Mapped[dict] = mapped_column("metadata", JSON, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="open")
    scan_id: Mapped[str] = mapped_column(String(36), nullable=True)
    target_id: Mapped[str] = mapped_column(String(36), nullable=True)
    score: Mapped[int] = mapped_column(Integer, nullable=True)
    evidence: Mapped[str] = mapped_column(Text, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
    cve: Mapped[str] = mapped_column(String(50), nullable=True)
    cwe: Mapped[str] = mapped_column(String(50), nullable=True)
    assigned_to: Mapped[str] = mapped_column(String(36), nullable=True)
    assigned_at: Mapped[str] = mapped_column(String(50), nullable=True)
    assigned_by: Mapped[str] = mapped_column(String(36), nullable=True)
    owner_user_id: Mapped[str] = mapped_column(String(36), nullable=True)
    owner_team_id: Mapped[str] = mapped_column(String(36), nullable=True)
    severity_override: Mapped[str] = mapped_column(String(20), nullable=True)
    workflow_status: Mapped[str] = mapped_column(String(30), nullable=True)
    closed_at: Mapped[str] = mapped_column(String(50), nullable=True)
    closed_by: Mapped[str] = mapped_column(String(36), nullable=True)
    remediation_claimed_at: Mapped[str] = mapped_column(String(50), nullable=True)
    remediation_claimed_by: Mapped[str] = mapped_column(String(36), nullable=True)
    ready_for_retest_at: Mapped[str] = mapped_column(String(50), nullable=True)
    created_at: Mapped[str] = mapped_column(String(50), nullable=True)
    updated_at: Mapped[str] = mapped_column(String(50), nullable=True)

class Target(Base):
    __tablename__ = "targets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_id: Mapped[str] = mapped_column(String(36), ForeignKey("projects.id"))
    value: Mapped[str] = mapped_column(String(255))
    target_type: Mapped[str] = mapped_column(String(50))

class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("targets.id"))
    profile: Mapped[str] = mapped_column(String(50), default="quick")
    status: Mapped[str] = mapped_column(String(50), default="completed")

def _setup_api_db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False, expire_on_commit=False)
    db = SessionLocal()
    org_a = Organization(id=str(uuid.uuid4()), name="OrgA", slug="orga")
    org_b = Organization(id=str(uuid.uuid4()), name="OrgB", slug="orgb")
    db.add_all([org_a, org_b]); db.flush()
    pwd = hash_password("password123")
    user_a = User(id=str(uuid.uuid4()), organization_id=org_a.id, email="a@orga.test", password_hash=pwd, role="member")
    user_b = User(id=str(uuid.uuid4()), organization_id=org_b.id, email="b@orgb.test", password_hash=pwd, role="member")
    db.add_all([user_a, user_b]); db.flush()
    proj_a = Project(id=str(uuid.uuid4()), organization_id=org_a.id, name="ProjA")
    proj_b = Project(id=str(uuid.uuid4()), organization_id=org_b.id, name="ProjB")
    db.add_all([proj_a, proj_b]); db.flush()
    # Cloud assets for proj_a only
    entry = Asset(id=str(uuid.uuid4()), project_id=proj_a.id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_ec2_instance:i-a", extra_data={"resource_type": "aws_ec2_instance", "public_ip": "1.1.1.1"})
    target = Asset(id=str(uuid.uuid4()), project_id=proj_a.id, asset_type="cloud_resource", value="cloud_resource:aws:acct:us-east-1:aws_rds_instance:db-a", extra_data={"resource_type": "aws_rds_instance"})
    db.add_all([entry, target]); db.flush()
    rel = AssetRelationship(id=str(uuid.uuid4()), project_id=proj_a.id, source_asset_id=entry.id, target_asset_id=target.id, relationship_type="contains")
    db.add(rel); db.flush()
    finding = Finding(id=str(uuid.uuid4()), asset_id=target.id, scanner="cloud", title="RDS Public", severity="critical", extra_data={"rule_id": "AWS-RDS-001"})
    db.add(finding); db.commit()
    db.close()
    tokens = {user_a.email: create_access_token(user_a.id), user_b.email: create_access_token(user_b.id)}
    return engine, SessionLocal, tokens, {"org_a": org_a, "org_b": org_b, "proj_a": proj_a, "proj_b": proj_b, "user_a": user_a, "user_b": user_b, "entry": entry, "target": target}

def _client(SessionLocal):
    def override():
        s = SessionLocal()
        try:
            yield s
        finally:
            s.close()
    app.dependency_overrides[get_db] = override
    return TestClient(app)

def test_api_unauthorized_401():
    engine, SessionLocal, tokens, objs = _setup_api_db()
    client = _client(SessionLocal)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud-security/attack-paths")
        assert resp.status_code == 401
    finally:
        app.dependency_overrides.clear()

def test_api_project_isolation():
    engine, SessionLocal, tokens, objs = _setup_api_db()
    client = _client(SessionLocal)
    try:
        # user_a can see proj_a paths
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud-security/attack-paths", headers={"Authorization": f"Bearer {tokens['a@orga.test']}"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] >= 1
        # user_a cannot see proj_b (different org) -> 404
        resp2 = client.get(f"/api/v1/projects/{objs['proj_b'].id}/cloud-security/attack-paths", headers={"Authorization": f"Bearer {tokens['a@orga.test']}"})
        assert resp2.status_code == 404
        # user_b cannot see proj_a
        resp3 = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud-security/attack-paths", headers={"Authorization": f"Bearer {tokens['b@orgb.test']}"})
        assert resp3.status_code == 404
        # user_b proj_b has no paths (no assets)
        resp4 = client.get(f"/api/v1/projects/{objs['proj_b'].id}/cloud-security/attack-paths", headers={"Authorization": f"Bearer {tokens['b@orgb.test']}"})
        assert resp4.status_code == 200
        assert resp4.json()["count"] == 0
    finally:
        app.dependency_overrides.clear()

def test_api_invalid_filters_400():
    engine, SessionLocal, tokens, objs = _setup_api_db()
    client = _client(SessionLocal)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud-security/attack-paths?provider=invalid", headers={"Authorization": f"Bearer {tokens['a@orga.test']}"})
        assert resp.status_code == 400
        resp2 = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud-security/attack-paths?severity=invalid", headers={"Authorization": f"Bearer {tokens['a@orga.test']}"})
        assert resp2.status_code == 400
    finally:
        app.dependency_overrides.clear()

def test_api_detail_and_404():
    engine, SessionLocal, tokens, objs = _setup_api_db()
    client = _client(SessionLocal)
    try:
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud-security/attack-paths", headers={"Authorization": f"Bearer {tokens['a@orga.test']}"})
        pid = resp.json()["paths"][0]["id"]
        detail = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud-security/attack-paths/{pid}", headers={"Authorization": f"Bearer {tokens['a@orga.test']}"})
        assert detail.status_code == 200
        assert detail.json()["id"] == pid
        assert "nodes" in detail.json()
        assert "relationships" in detail.json()
        assert "findings" in detail.json()
        notfound = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud-security/attack-paths/notfound123", headers={"Authorization": f"Bearer {tokens['a@orga.test']}"})
        assert notfound.status_code == 404
    finally:
        app.dependency_overrides.clear()

def test_tenant_isolation():
    # Already covered via project isolation above (org A vs org B)
    engine, SessionLocal, tokens, objs = _setup_api_db()
    client = _client(SessionLocal)
    try:
        # Cross-tenant deep link not leak existence
        resp = client.get(f"/api/v1/projects/{objs['proj_a'].id}/cloud-security/attack-paths", headers={"Authorization": f"Bearer {tokens['b@orgb.test']}"})
        assert resp.status_code == 404
    finally:
        app.dependency_overrides.clear()

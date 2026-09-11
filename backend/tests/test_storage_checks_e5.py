"""E5 storage checks — deterministic."""

from app.services import cloud_checks as checks

def _meta(extra, rtype="aws_s3_bucket"):
    return {"extra": extra, "value": f"cloud_resource:aws:123:us-east-1:s3:{rtype}:test-bucket", "resource_id": "test-bucket", "resource_type": rtype, "account_id": "123", "region": "us-east-1"}

def test_s3_public_policy():
    stmts = [{"effect": "Allow", "principals": ["*"], "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::b/*"]}]
    extra = {"bucket_policy_statements": stmts}
    assert checks.evaluate_asset(checks.get_check("AWS-S3-003"), _meta(extra))[0] == "failed"
    extra2 = {"bucket_policy_statements": [{"effect": "Allow", "principals": ["AWS:arn:aws:iam::123:user/alice"], "actions": ["s3:GetObject"], "resources": ["*"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-S3-003"), _meta(extra2))[0] == "passed"

def test_s3_public_acl():
    extra = {"acl_grants": [{"type": "Group", "uri": "http://acs.amazonaws.com/groups/global/AllUsers", "permission": "READ", "public": True}], "object_ownership": "ObjectWriter"}
    assert checks.evaluate_asset(checks.get_check("AWS-S3-005"), _meta(extra))[0] == "failed"
    extra2 = {"acl_grants": [], "object_ownership": "BucketOwnerEnforced"}
    assert checks.evaluate_asset(checks.get_check("AWS-S3-005"), _meta(extra2))[0] == "passed"

def test_s3_versioning():
    assert checks.evaluate_asset(checks.get_check("AWS-S3-006"), _meta({"versioning": "Enabled"}))[0] == "passed"
    assert checks.evaluate_asset(checks.get_check("AWS-S3-006"), _meta({"versioning": "Suspended"}))[0] == "failed"

def test_s3_logging():
    assert checks.evaluate_asset(checks.get_check("AWS-S3-007"), _meta({"logging_enabled": True}))[0] == "passed"
    assert checks.evaluate_asset(checks.get_check("AWS-S3-007"), _meta({"logging_enabled": False}))[0] == "failed"

def test_s3_ownership():
    assert checks.evaluate_asset(checks.get_check("AWS-S3-008"), _meta({"object_ownership": "BucketOwnerEnforced"}))[0] == "passed"
    assert checks.evaluate_asset(checks.get_check("AWS-S3-008"), _meta({"object_ownership": "ObjectWriter"}))[0] == "failed"

def test_s3_weak_encryption():
    assert checks.evaluate_asset(checks.get_check("AWS-S3-004"), _meta({"encryption": "AES256"}))[0] == "failed"
    assert checks.evaluate_asset(checks.get_check("AWS-S3-004"), _meta({"encryption": "aws:kms"}))[0] == "passed"
    assert checks.evaluate_asset(checks.get_check("AWS-S3-004"), _meta({}))[0] == "not_assessed"

def test_ebs_volume():
    assert checks.evaluate_asset(checks.get_check("AWS-EBS-001"), _meta({"encrypted": False}, "aws_ebs_volume"))[0] == "failed"
    assert checks.evaluate_asset(checks.get_check("AWS-EBS-001"), _meta({"encrypted": True}, "aws_ebs_volume"))[0] == "passed"

def test_ebs_snapshot():
    assert checks.evaluate_asset(checks.get_check("AWS-EBS-002"), _meta({"is_public": True}, "aws_ebs_snapshot"))[0] == "failed"
    assert checks.evaluate_asset(checks.get_check("AWS-EBS-002"), _meta({"is_public": False}, "aws_ebs_snapshot"))[0] == "passed"
    assert checks.evaluate_asset(checks.get_check("AWS-EBS-002"), _meta({}, "aws_ebs_snapshot"))[0] == "not_assessed"

def test_efs():
    assert checks.evaluate_asset(checks.get_check("AWS-EFS-001"), _meta({"encrypted": False}, "aws_efs_filesystem"))[0] == "failed"
    assert checks.evaluate_asset(checks.get_check("AWS-EFS-001"), _meta({"encrypted": True}, "aws_efs_filesystem"))[0] == "passed"

def test_fingerprint_storage():
    from app.services import finding_lifecycle as lc
    from types import SimpleNamespace
    def proxy(bucket):
        return SimpleNamespace(title="AWS-S3-003: S3 bucket allows public access", cve=None, cwe=None, evidence=None, asset_id="id-1", extra_data={"rule_id": "AWS-S3-003", "asset_type": "cloud_resource", "asset_value": f"cloud_resource:aws:123:us-east-1:s3:aws_s3_bucket:{bucket}"})
    fp1 = lc.d8_fingerprint(lc.d8_finding_input(proxy("bucket-a")))
    fp2 = lc.d8_fingerprint(lc.d8_finding_input(proxy("bucket-b")))
    assert fp1 != fp2
    fp3 = lc.d8_fingerprint(lc.d8_finding_input(proxy("bucket-a")))
    assert fp1 == fp3

def test_not_assessed():
    assert checks.evaluate_asset(checks.get_check("AWS-S3-003"), _meta({}, "aws_s3_bucket"))[0] == "not_assessed"
    assert checks.evaluate_asset(checks.get_check("AWS-EBS-001"), _meta({}, "aws_ebs_volume"))[0] == "not_assessed"

def test_catalog_storage():
    ids = {c["check_id"] for c in checks.list_catalog(provider="aws")}
    assert "AWS-S3-003" in ids
    assert "AWS-EBS-001" in ids
    assert "AWS-EFS-001" in ids

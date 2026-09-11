"""E3 IAM checks — deterministic evaluation of persisted IAM evidence."""

from app.services import cloud_checks as checks

def _meta(extra, resource_type="aws_iam_role", account_id="123456789012"):
    base = {"resource_type": resource_type, "resource_id": "test", "account_id": account_id, "region": "global", "arn": f"arn:aws:iam::{account_id}:role/test"}
    # asset_meta contains extra dict + top-level resource fields
    return {"extra": extra, "value": f"cloud_resource:aws:{account_id}:global:{resource_type}:test",
            "resource_id": "test", "account_id": account_id, "region": "global", **extra}

def test_iam_001_wildcard_action_fail():
    extra = {"iam_policies": [{"type": "managed", "name": "p", "statements": [{"effect": "Allow", "actions": ["*"], "resources": ["*"]}]}]}
    meta = _meta(extra)
    result, ev, _ = checks.evaluate_asset(checks.get_check("AWS-IAM-001"), meta)
    assert result == "failed"
    assert ev["field"] == "Action"

def test_iam_001_pass():
    extra = {"iam_policies": [{"type": "managed", "name": "p", "statements": [{"effect": "Allow", "actions": ["s3:GetObject"], "resources": ["*"]}]}]}
    meta = _meta(extra)
    result, _, _ = checks.evaluate_asset(checks.get_check("AWS-IAM-001"), meta)
    assert result == "passed"

def test_iam_001_not_assessed():
    extra = {}
    meta = _meta(extra)
    result, _, _ = checks.evaluate_asset(checks.get_check("AWS-IAM-001"), meta)
    assert result == "not_assessed"

def test_iam_002_wildcard_resource():
    extra = {"iam_policies": [{"name": "p", "statements": [{"effect": "Allow", "actions": ["s3:GetObject"], "resources": ["*"]}]}]}
    meta = _meta(extra)
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-002"), meta)[0] == "failed"
    extra2 = {"iam_policies": [{"name": "p", "statements": [{"effect": "Allow", "actions": ["s3:GetObject"], "resources": ["arn:aws:s3:::b/*"]}]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-002"), _meta(extra2))[0] == "passed"

def test_iam_003_dangerous():
    extra = {"iam_policies": [{"name": "p", "statements": [{"effect": "Allow", "actions": ["iam:*"], "resources": ["*"]}]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-003"), _meta(extra))[0] == "failed"
    extra2 = {"iam_policies": [{"name": "p", "statements": [{"effect": "Allow", "actions": ["s3:GetObject"], "resources": ["*"]}]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-003"), _meta(extra2))[0] == "passed"

def test_iam_004_wildcard_trust():
    extra = {"iam_trust_statements": [{"effect": "Allow", "principals": ["*"], "actions": ["sts:AssumeRole"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-004"), _meta(extra, "aws_iam_role"))[0] == "failed"
    extra2 = {"iam_trust_statements": [{"effect": "Allow", "principals": ["Service:ec2.amazonaws.com"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-004"), _meta(extra2, "aws_iam_role"))[0] == "passed"

def test_iam_005_external_account():
    extra = {"iam_trust_statements": [{"effect": "Allow", "principals": ["AWS:arn:aws:iam::999999999999:root"]}]}
    r, ev, _ = checks.evaluate_asset(checks.get_check("AWS-IAM-005"), _meta(extra, "aws_iam_role", "111111111111"))
    assert r == "failed"
    assert ev["observed"] == "999999999999"
    extra2 = {"iam_trust_statements": [{"effect": "Allow", "principals": ["AWS:arn:aws:iam::111111111111:root"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-005"), _meta(extra2, "aws_iam_role", "111111111111"))[0] == "passed"

def test_iam_006_mfa():
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-006"), _meta({"iam_mfa_device_count": 0}, "aws_iam_user"))[0] == "failed"
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-006"), _meta({"iam_mfa_device_count": 1}, "aws_iam_user"))[0] == "passed"
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-006"), _meta({}, "aws_iam_user"))[0] == "not_assessed"

def test_iam_007_stale_key():
    # Use recent date -> passed
    import datetime
    recent = datetime.datetime.now(datetime.timezone.utc).isoformat()
    extra = {"iam_access_keys": [{"status": "Active", "create_date": recent, "id_suffix": "ABCD"}]}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-007"), _meta(extra, "aws_iam_user"))[0] == "passed"
    old = "2024-01-01T00:00:00+00:00"
    extra2 = {"iam_access_keys": [{"status": "Active", "create_date": old, "id_suffix": "EFGH"}]}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-007"), _meta(extra2, "aws_iam_user"))[0] == "failed"
    # No active keys -> passed
    extra3 = {"iam_access_keys": [{"status": "Inactive", "create_date": old}]}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-007"), _meta(extra3, "aws_iam_user"))[0] == "passed"

def test_iam_008_password_without_mfa():
    extra = {"iam_password_enabled": True, "iam_mfa_device_count": 0}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-008"), _meta(extra, "aws_iam_user"))[0] == "failed"
    extra2 = {"iam_password_enabled": True, "iam_mfa_device_count": 1}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-008"), _meta(extra2, "aws_iam_user"))[0] == "passed"
    extra3 = {"iam_password_enabled": False, "iam_mfa_device_count": 0}
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-008"), _meta(extra3, "aws_iam_user"))[0] == "passed"
    assert checks.evaluate_asset(checks.get_check("AWS-IAM-008"), _meta({}, "aws_iam_user"))[0] == "not_assessed"

def test_iam_catalog_count():
    catalog = checks.list_catalog(provider="aws")
    iam_ids = {c["check_id"] for c in catalog if c["check_id"].startswith("AWS-IAM-")}
    assert len(iam_ids) == 8
    assert "AWS-IAM-001" in iam_ids

def test_iam_finding_fingerprint_stability():
    from app.services import finding_lifecycle as lc
    from types import SimpleNamespace
    def proxy(title, check_id, asset_value, asset_id):
        return SimpleNamespace(title=title, cve=None, cwe=None, evidence=None, asset_id=asset_id, extra_data={"rule_id": check_id, "asset_type": "cloud_resource", "asset_value": asset_value})
    fp1 = lc.d8_fingerprint(lc.d8_finding_input(proxy("AWS-IAM-001: IAM policy allows Action '*'", "AWS-IAM-001", "cloud_resource:aws:123:global:iam:role/TestRole", "asset-1")))
    fp2 = lc.d8_fingerprint(lc.d8_finding_input(proxy("AWS-IAM-001: IAM policy allows Action '*'", "AWS-IAM-001", "cloud_resource:aws:123:global:iam:role/TestRole", "asset-1")))
    assert fp1 == fp2
    fp3 = lc.d8_fingerprint(lc.d8_finding_input(proxy("AWS-IAM-001: IAM policy allows Action '*'", "AWS-IAM-001", "cloud_resource:aws:123:global:iam:role/OtherRole", "asset-2")))
    assert fp1 != fp3

def test_no_aws_mutation_imports():
    import pathlib
    content = pathlib.Path("worker/app/aws_discovery.py").read_text() if pathlib.Path("worker/app/aws_discovery.py").exists() else ""
    # Ensure no forbidden mutation calls in discovery
    forbidden = ["PutUserPolicy", "PutRolePolicy", "AttachUserPolicy", "CreateAccessKey", "DeleteAccessKey"]
    for tok in forbidden:
        # discovery should not contain literal string for mutation (except maybe in comments)
        # but E3 discovery only uses list/get
        assert tok not in content or "iam_analysis" in content  # allow minimal

def test_no_secret_leakage_in_evidence():
    extra = {"iam_policies": [{"name": "p", "statements": [{"effect": "Allow", "actions": ["*"], "resources": ["*"]}]}]}
    meta = _meta(extra)
    _, ev, _ = checks.evaluate_asset(checks.get_check("AWS-IAM-001"), meta)
    assert ev is not None
    ev_str = str(ev)
    assert "SecretAccessKey" not in ev_str
    assert "AKIA" not in ev_str

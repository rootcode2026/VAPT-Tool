"""GCP checks — deterministic."""

from app.services import cloud_checks as checks

def _meta(extra, rtype="gcp_firewall"):
    return {"extra": extra, "value": f"cloud_resource:gcp:proj-123:global:{rtype}:test", "resource_id": "test", "resource_type": rtype, "account_id": "proj-123", "region": "global"}

def test_gcp_iam_public():
    extra = {"bindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}], "public_iam_members": [{"role": "roles/storage.objectViewer", "member": "allUsers"}]}
    assert checks.evaluate_asset(checks.get_check("GCP-IAM-001"), _meta(extra, "gcp_iam_policy"))[0] == "failed"
    extra2 = {"bindings": [{"role": "roles/viewer", "members": ["user:alice@example.com"]}], "public_iam_members": []}
    assert checks.evaluate_asset(checks.get_check("GCP-IAM-001"), _meta(extra2, "gcp_iam_policy"))[0] == "passed"

def test_gcp_iam_owner():
    extra = {"bindings": [{"role": "roles/owner", "members": ["user:bob@example.com"]}]}
    assert checks.evaluate_asset(checks.get_check("GCP-IAM-002"), _meta(extra, "gcp_iam_policy"))[0] == "failed"

def test_gcp_firewall_ssh():
    extra = {"allowed": [{"protocol": "tcp", "ports": ["22"]}], "source_ranges": ["0.0.0.0/0"]}
    assert checks.evaluate_asset(checks.get_check("GCP-NET-001"), _meta(extra))[0] == "failed"
    extra2 = {"allowed": [{"protocol": "tcp", "ports": ["22"]}], "source_ranges": ["10.0.0.0/8"]}
    assert checks.evaluate_asset(checks.get_check("GCP-NET-001"), _meta(extra2))[0] == "passed"

def test_gcp_firewall_rdp():
    extra = {"allowed": [{"protocol": "tcp", "ports": ["3389"]}], "source_ranges": ["0.0.0.0/0"]}
    assert checks.evaluate_asset(checks.get_check("GCP-NET-002"), _meta(extra))[0] == "failed"

def test_gcp_firewall_db():
    extra = {"allowed": [{"protocol": "tcp", "ports": ["5432"]}], "source_ranges": ["0.0.0.0/0"]}
    assert checks.evaluate_asset(checks.get_check("GCP-NET-003"), _meta(extra))[0] == "failed"

def test_gcp_firewall_all():
    extra = {"allowed": [{"protocol": "all", "ports": []}], "source_ranges": ["0.0.0.0/0"]}
    assert checks.evaluate_asset(checks.get_check("GCP-NET-004"), _meta(extra))[0] == "failed"

def test_gcp_storage_public():
    extra = {"public_iam_members": [{"role": "roles/storage.objectViewer", "member": "allUsers"}]}
    assert checks.evaluate_asset(checks.get_check("GCP-GCS-001"), _meta(extra, "gcp_storage_bucket"))[0] == "failed"

def test_gcp_versioning():
    assert checks.evaluate_asset(checks.get_check("GCP-GCS-003"), _meta({"versioning": "True"}, "gcp_storage_bucket"))[0] == "passed"
    assert checks.evaluate_asset(checks.get_check("GCP-GCS-003"), _meta({"versioning": "False"}, "gcp_storage_bucket"))[0] == "failed"

def test_gcp_compute_shielded():
    assert checks.evaluate_asset(checks.get_check("GCP-COMPUTE-001"), _meta({"shielded_vm": False}, "gcp_compute_instance"))[0] == "failed"
    assert checks.evaluate_asset(checks.get_check("GCP-COMPUTE-001"), _meta({"shielded_vm": True}, "gcp_compute_instance"))[0] == "passed"

def test_fingerprint_gcp():
    from app.services import finding_lifecycle as lc
    from types import SimpleNamespace
    def proxy(bucket):
        return SimpleNamespace(title="GCP-GCS-001: public", cve=None, cwe=None, evidence=None, asset_id="id-1", extra_data={"rule_id": "GCP-GCS-001", "asset_type": "cloud_resource", "asset_value": f"cloud_resource:gcp:proj:global:gcp_storage_bucket:{bucket}"})
    fp1 = lc.d8_fingerprint(lc.d8_finding_input(proxy("b1")))
    fp2 = lc.d8_fingerprint(lc.d8_finding_input(proxy("b2")))
    assert fp1 != fp2

def test_catalog_gcp():
    ids = {c["check_id"] for c in checks.list_catalog(provider="gcp")}
    assert "GCP-IAM-001" in ids
    assert "GCP-NET-001" in ids
    assert "GCP-GCS-001" in ids

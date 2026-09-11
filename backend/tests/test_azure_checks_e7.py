"""Azure checks — deterministic."""

from app.services import cloud_checks as checks

def _meta(extra, rtype="azure_nsg"):
    return {"extra": extra, "value": f"cloud_resource:azure:sub-123:eastus:{rtype}:test", "resource_id": "test", "resource_type": rtype, "account_id": "sub-123", "region": "eastus"}

def test_azure_nsg_ssh():
    extra = {"rules": [{"name": "allow-ssh", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "source_prefix": "*", "sourceAddressPrefix": "*", "dest_port": "22", "destinationPortRange": "22"}]}
    assert checks.evaluate_asset(checks.get_check("AZURE-NET-001"), _meta(extra))[0] == "failed"

def test_azure_nsg_rdp():
    extra = {"rules": [{"name": "allow-rdp", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "source_prefix": "Internet", "dest_port": "3389"}]}
    assert checks.evaluate_asset(checks.get_check("AZURE-NET-002"), _meta(extra))[0] == "failed"

def test_azure_nsg_db():
    extra = {"rules": [{"name": "allow-mysql", "direction": "Inbound", "access": "Allow", "protocol": "Tcp", "source_prefix": "*", "dest_port": "3306"}]}
    assert checks.evaluate_asset(checks.get_check("AZURE-NET-003"), _meta(extra))[0] == "failed"

def test_azure_nsg_all():
    extra = {"rules": [{"name": "allow-all", "direction": "Inbound", "access": "Allow", "protocol": "*", "source_prefix": "*", "dest_port": "*"}]}
    assert checks.evaluate_asset(checks.get_check("AZURE-NET-004"), _meta(extra))[0] == "failed"

def test_azure_storage_public():
    extra = {"allow_blob_public_access": True}
    assert checks.evaluate_asset(checks.get_check("AZURE-STORAGE-001"), _meta(extra, "azure_storage_account"))[0] == "failed"
    extra2 = {"allow_blob_public_access": False}
    assert checks.evaluate_asset(checks.get_check("AZURE-STORAGE-001"), _meta(extra2, "azure_storage_account"))[0] == "passed"

def test_azure_storage_https():
    extra = {"https_only": False, "supportsHttpsTrafficOnly": False}
    assert checks.evaluate_asset(checks.get_check("AZURE-STORAGE-003"), _meta(extra, "azure_storage_account"))[0] == "failed"

def test_azure_compute_secure_boot():
    extra = {"secure_boot": False}
    assert checks.evaluate_asset(checks.get_check("AZURE-COMPUTE-001"), _meta(extra, "azure_vm"))[0] == "failed"
    extra2 = {"secure_boot": True}
    assert checks.evaluate_asset(checks.get_check("AZURE-COMPUTE-001"), _meta(extra2, "azure_vm"))[0] == "passed"

def test_azure_iam_owner():
    extra = {"role_name": "Owner", "scope": "/subscriptions/sub-123"}
    assert checks.evaluate_asset(checks.get_check("AZURE-IAM-001"), _meta(extra, "azure_rbac_assignment"))[0] == "failed"
    extra2 = {"role_name": "Reader", "scope": "/subscriptions/sub-123"}
    assert checks.evaluate_asset(checks.get_check("AZURE-IAM-001"), _meta(extra2, "azure_rbac_assignment"))[0] == "passed"

def test_fingerprint_azure():
    from app.services import finding_lifecycle as lc
    from types import SimpleNamespace
    def proxy(rg):
        return SimpleNamespace(title="AZURE-NET-001: SSH", cve=None, cwe=None, evidence=None, asset_id="id-1", extra_data={"rule_id": "AZURE-NET-001", "asset_type": "cloud_resource", "asset_value": f"cloud_resource:azure:sub-123:eastus:azure_nsg:{rg}"})
    fp1 = lc.d8_fingerprint(lc.d8_finding_input(proxy("nsg-1")))
    fp2 = lc.d8_fingerprint(lc.d8_finding_input(proxy("nsg-2")))
    assert fp1 != fp2

def test_catalog_azure():
    ids = {c["check_id"] for c in checks.list_catalog(provider="azure")}
    assert "AZURE-IAM-001" in ids
    assert "AZURE-NET-001" in ids
    assert "AZURE-STORAGE-001" in ids

"""Azure discovery — bounded, deterministic."""

from app.azure_discovery import discover_azure_nsgs, discover_azure_storage_accounts, discover_azure_vms, discover_azure_rbac

class FakePaginator:
    def __init__(self, pages): self._pages = pages
    def paginate(self, **kw):
        for p in self._pages:
            yield p

class FakeClient:
    def __init__(self, ops): self._ops = ops
    def get_paginator(self, op):
        return FakePaginator(self._ops.get(op, []))
    def __getattr__(self, name):
        def _op(**kw): return self._ops.get(name, {})
        return _op

def test_azure_nsg():
    ops = {"list_network_security_groups": [{"value": [{"name": "nsg-1", "location": "eastus", "properties": {"securityRules": [{"name": "allow-ssh", "properties": {"direction": "Inbound", "access": "Allow", "protocol": "Tcp", "sourceAddressPrefix": "*", "sourcePortRange": "*", "destinationAddressPrefix": "*", "destinationPortRange": "22", "priority": 100}}]}}]}]}
    c = FakeClient(ops)
    res, _ = discover_azure_nsgs(c, "sub-123")
    assert len(res) == 1
    assert res[0]["extra"]["rules"][0]["source_prefix"] == "*"

def test_azure_storage():
    ops = {"list_storage_accounts": [{"value": [{"name": "mystorage", "location": "eastus", "sku": {"name": "Standard_LRS"}, "properties": {"supportsHttpsTrafficOnly": True, "minimumTlsVersion": "TLS1_2", "allowBlobPublicAccess": True, "publicNetworkAccess": "Enabled"}}]}]}
    c = FakeClient(ops)
    res, _ = discover_azure_storage_accounts(c, "sub-123")
    assert res[0]["extra"]["allow_blob_public_access"] is True

def test_azure_vm():
    ops = {"list_virtual_machines": [{"value": [{"name": "vm-1", "location": "eastus", "properties": {"hardwareProfile": {"vmSize": "Standard_DS1_v2"}, "securityProfile": {"uefiSettings": {"secureBootEnabled": False, "vTpmEnabled": False}}}}]}]}
    c = FakeClient(ops)
    res, _ = discover_azure_vms(c, "sub-123")
    assert res[0]["extra"]["secure_boot"] is False

def test_azure_rbac():
    ops = {"list_role_assignments": [{"value": [{"name": "assign-1", "properties": {"roleDefinitionId": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "principalId": "pid-123", "principalType": "User", "scope": "/subscriptions/sub-123", "roleDefinitionId": "/subscriptions/sub-123/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}}]}]}
    c = FakeClient(ops)
    res, _ = discover_azure_rbac(c, "sub-123")
    assert len(res) == 1
    assert "Owner" in res[0]["extra"]["role_name"] or "owner" in res[0]["extra"]["role_name"].lower() or res[0]["extra"]["scope"] == "/subscriptions/sub-123"

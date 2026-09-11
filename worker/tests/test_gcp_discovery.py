"""GCP discovery — bounded, deterministic."""

from app.gcp_discovery import discover_gcp_firewalls, discover_gcp_storage_buckets, discover_gcp_iam_bindings, discover_gcp_compute_instances

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

def test_gcp_firewall():
    ops = {"list_firewalls": [{"items": [{"name": "allow-ssh", "direction": "INGRESS", "sourceRanges": ["0.0.0.0/0"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "targetTags": []}]}]}
    c = FakeClient(ops)
    res, _ = discover_gcp_firewalls(c, "proj-123")
    assert len(res) == 1
    assert res[0]["extra"]["source_ranges"] == ["0.0.0.0/0"]
    assert res[0]["extra"]["allowed"][0]["protocol"] == "tcp"

def test_gcp_storage_public():
    ops = {"list_buckets": [{"items": [{"name": "my-bucket", "location": "US", "iamBindings": [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]}]}]}
    c = FakeClient(ops)
    res, _ = discover_gcp_storage_buckets(c, "proj-123")
    assert res[0]["extra"]["public_iam_members"][0]["member"] == "allUsers"

def test_gcp_iam_bindings():
    # Use get_iam_policy via paginate
    ops = {"get_iam_policy": [{"bindings": [{"role": "roles/owner", "members": ["user:alice@example.com", "allUsers"]}]}]}
    c = FakeClient(ops)
    res, _ = discover_gcp_iam_bindings(c, "proj-123")
    assert len(res) == 1
    assert any(m == "allUsers" for b in res[0]["extra"]["bindings"] for m in b["members"])

def test_gcp_compute():
    ops = {"list_instances": [{"items": [{"id": "123", "name": "vm-1", "networkInterfaces": [{"network": "global/networks/default", "accessConfigs": [{"natIP": "35.1.1.1"}], "networkIP": "10.0.0.2"}], "status": "RUNNING", "shieldedInstanceConfig": {"enableSecureBoot": False}}]}]}
    c = FakeClient(ops)
    res, _ = discover_gcp_compute_instances(c, "proj-123", "us-central1-a")
    assert res[0]["extra"]["external_ip"] == "35.1.1.1"
    assert res[0]["extra"]["shielded_vm"] is False

"""E5 storage discovery — bounded, deterministic."""

import json
from app.aws_discovery import discover_s3_buckets, discover_ebs_volumes, discover_ebs_snapshots, discover_efs_filesystems

class FakeClient:
    def __init__(self, ops):
        self._ops = ops
    def get_paginator(self, op):
        class P:
            def __init__(self, pages): self._pages = pages
            def paginate(self, **kw): yield from self._pages
        return P(self._ops.get(op, []))
    def __getattr__(self, name):
        def _op(**kw):
            fn = self._ops.get(name)
            if callable(fn):
                return fn(**kw)
            return fn if fn is not None else {}
        return _op

def _s3_ops_with_bucket(name, policy_doc=None, acl_grants=None, versioning="Enabled", logging=False, ownership="BucketOwnerEnforced"):
    ops = {
        "list_buckets": {"Buckets": [{"Name": name, "CreationDate": "2024-01-01"}]},
        "get_bucket_location": {"LocationConstraint": "us-east-1"},
        "get_public_access_block": {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
        "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms", "KMSMasterKeyID": "arn:aws:kms:us-east-1:123:key/abc"}}]}},
    }
    if policy_doc is not None:
        ops["get_bucket_policy"] = {"Policy": policy_doc if isinstance(policy_doc, str) else json.dumps(policy_doc)}
    else:
        # NoSuchBucketPolicy simulation via exception
        def _no_policy(**kw):
            e = Exception("NoSuchBucketPolicy")
            e.response = {"Error": {"Code": "NoSuchBucketPolicy", "Message": "no policy"}}
            raise e
        ops["get_bucket_policy"] = _no_policy
    ops["get_bucket_acl"] = {"Grants": acl_grants or [], "Owner": {"ID": "owner123"}}
    ops["get_bucket_versioning"] = {"Status": versioning}
    ops["get_bucket_logging"] = {"LoggingEnabled": {"TargetBucket": "log-bucket"}} if logging else {}
    ops["get_bucket_ownership_controls"] = {"OwnershipControls": {"Rules": [{"ObjectOwnership": ownership}]}}
    ops["get_bucket_website"] = {}
    # Make get_bucket_website raise NoSuchWebsiteConfiguration if not enabled
    def _no_website(**kw):
        e = Exception("NoSuchWebsiteConfiguration")
        e.response = {"Error": {"Code": "NoSuchWebsiteConfiguration", "Message": "no website"}}
        raise e
    if not ops.get("get_bucket_website"):
        ops["get_bucket_website"] = _no_website
    return ops

def test_s3_public_policy():
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]}
    ops = _s3_ops_with_bucket("my-bucket", policy_doc=policy)
    client = FakeClient(ops)
    res, _ = discover_s3_buckets(client, "123")
    assert len(res) == 1
    stmts = res[0]["extra"]["bucket_policy_statements"]
    assert len(stmts) == 1
    assert stmts[0]["actions"] == ["s3:GetObject"]

def test_s3_non_public_policy():
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123:user/alice"}, "Action": "s3:GetObject", "Resource": "*"}]}
    ops = _s3_ops_with_bucket("my-bucket", policy_doc=policy)
    client = FakeClient(ops)
    res, _ = discover_s3_buckets(client, "123")
    stmts = res[0]["extra"]["bucket_policy_statements"]
    assert stmts[0]["principals"] == ["AWS:arn:aws:iam::123:user/alice"]

def test_s3_public_acl():
    grants = [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}]
    ops = _s3_ops_with_bucket("my-bucket", acl_grants=grants)
    client = FakeClient(ops)
    res, _ = discover_s3_buckets(client, "123")
    assert res[0]["extra"]["acl_grants"][0]["public"] is True

def test_s3_versioning_logging():
    ops = _s3_ops_with_bucket("my-bucket", versioning="Enabled", logging=True, ownership="BucketOwnerEnforced")
    client = FakeClient(ops)
    res, _ = discover_s3_buckets(client, "123")
    assert res[0]["extra"]["versioning"] == "Enabled"
    assert res[0]["extra"]["logging_enabled"] is True
    assert res[0]["extra"]["object_ownership"] == "BucketOwnerEnforced"

def test_ebs_volume():
    ops = {"describe_volumes": [{"Volumes": [{"VolumeId": "vol-123", "Encrypted": False, "Size": 100, "AvailabilityZone": "us-east-1a", "State": "in-use", "Attachments": [{"InstanceId": "i-123"}]}]}]}
    client = FakeClient(ops)
    res, _ = discover_ebs_volumes(client, "us-east-1", "123")
    assert res[0]["extra"]["encrypted"] is False
    assert res[0]["extra"]["attached_instance"] == "i-123"

def test_ebs_snapshot_public():
    ops = {
        "describe_snapshots": [{"Snapshots": [{"SnapshotId": "snap-123", "Encrypted": True, "OwnerId": "123", "VolumeId": "vol-123"}]}],
        "describe_snapshot_attribute": {"CreateVolumePermissions": [{"Group": "all"}]}
    }
    client = FakeClient(ops)
    res, _ = discover_ebs_snapshots(client, "us-east-1", "123")
    assert res[0]["extra"]["is_public"] is True

def test_efs():
    ops = {"describe_file_systems": [{"FileSystems": [{"FileSystemId": "fs-123", "Encrypted": False, "LifeCycleState": "available"}]}]}
    client = FakeClient(ops)
    res, _ = discover_efs_filesystems(client, "us-east-1", "123")
    assert res[0]["extra"]["encrypted"] is False

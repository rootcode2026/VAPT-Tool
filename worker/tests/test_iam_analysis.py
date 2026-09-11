"""E3 IAM policy analysis + discovery — bounded, deterministic, no SDK."""

import json
import urllib.parse

from app.iam_analysis import (
    decode_policy_document,
    has_dangerous_action,
    has_external_account_principal,
    has_wildcard_action,
    has_wildcard_principal,
    has_wildcard_resource,
    normalize_policy_document,
    statement_identity,
)
from app.aws_discovery import discover_iam


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages
    def paginate(self, **kwargs):
        yield from self._pages


class FakeIamClient:
    def __init__(self, ops=None, fail=None):
        self._ops = ops or {}
        self._fail = fail or {}
        self.calls = []
    def get_paginator(self, op):
        self.calls.append(("paginator", op))
        if op in self._fail:
            raise self._fail[op]
        return FakePaginator(self._ops.get(op, []))
    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        def _op(**kwargs):
            self.calls.append((name, kwargs))
            if name in self._fail:
                raise self._fail[name]
            return self._ops.get(name, {})
        return _op


def test_decode_url_encoded():
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    encoded = urllib.parse.quote(json.dumps(doc))
    out, err = decode_policy_document(encoded)
    assert err is None
    assert out["Version"] == "2012-10-17"

def test_decode_json_direct():
    doc = {"Version": "2012-10-17", "Statement": []}
    out, err = decode_policy_document(json.dumps(doc))
    assert err is None
    assert out is not None

def test_decode_malformed():
    out, err = decode_policy_document("{not json")
    assert out is None
    assert "malformed" in err.lower()

def test_decode_oversized():
    big = "x" * (70 * 1024)
    out, err = decode_policy_document(big)
    assert out is None
    assert "oversized" in err.lower()

def test_normalize_bounded():
    doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["arn:aws:s3:::b/*"]}]}
    stmts, trunc = normalize_policy_document(doc, policy_name="test")
    assert len(stmts) == 1
    assert stmts[0]["effect"] == "Allow"
    assert trunc["truncated"] is False

def test_normalize_truncation():
    stmts = [{"Effect": "Allow", "Action": "*", "Resource": "*"} for _ in range(60)]
    doc = {"Version": "2012-10-17", "Statement": stmts}
    out, trunc = normalize_policy_document(doc)
    assert len(out) == 50
    assert trunc["truncated"] is True

def test_wildcard_action():
    assert has_wildcard_action({"effect": "Allow", "actions": ["*"]}) is True
    assert has_wildcard_action({"effect": "Allow", "actions": ["s3:GetObject"]}) is False
    assert has_wildcard_action({"effect": "Deny", "actions": ["*"]}) is False

def test_wildcard_resource():
    assert has_wildcard_resource({"effect": "Allow", "resources": ["*"]}) is True
    assert has_wildcard_resource({"effect": "Allow", "resources": ["arn:aws:s3:::b"]}) is False

def test_dangerous():
    assert "iam:*" in has_dangerous_action({"effect": "Allow", "actions": ["iam:*"]})
    assert has_dangerous_action({"effect": "Allow", "actions": ["s3:GetObject"]}) == []

def test_wildcard_principal():
    assert has_wildcard_principal({"principals": ["*"]}) is True
    assert has_wildcard_principal({"principals": ["AWS:*"]}) is True
    assert has_wildcard_principal({"principals": ["Service:ec2.amazonaws.com"]}) is False

def test_external_account():
    stmt = {"effect": "Allow", "principals": ["AWS:arn:aws:iam::999999999999:root"]}
    ext = has_external_account_principal(stmt, "111111111111")
    assert "999999999999" in ext
    assert "111111111111" not in ext

def test_statement_identity_sid():
    s = {"effect": "Allow", "actions": ["*"], "resources": ["*"], "principals": [], "sid": "MySid"}
    h1 = statement_identity("arn:aws:iam::123:policy/test", s, 0)
    h2 = statement_identity("arn:aws:iam::123:policy/test", s, 0)
    assert h1 == h2
    assert len(h1) == 16

def test_statement_identity_no_sid():
    s = {"effect": "Allow", "actions": ["s3:Get*"], "resources": ["*"], "principals": []}
    h1 = statement_identity("policyA", s, 0)
    s2 = {"effect": "Allow", "actions": ["s3:Get*"], "resources": ["*"], "principals": []}
    h2 = statement_identity("policyA", s2, 0)
    assert h1 == h2

def test_discover_iam_collects_policies():
    role_policy_doc = json.dumps({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]})
    ops = {
        "list_roles": [{"Roles": [{"RoleName": "TestRole", "Arn": "arn:aws:iam::123456789012:role/TestRole", "Path": "/", "AssumeRolePolicyDocument": json.dumps({"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]})}]}],
        "list_users": [{"Users": []}],
        "list_groups": [{"Groups": []}],
        "list_attached_role_policies": [{"AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123456789012:policy/TestPolicy", "PolicyName": "TestPolicy"}]}],
        "list_role_policies": [{"PolicyNames": []}],
        "get_policy": {"Policy": {"DefaultVersionId": "v1"}},
        "get_policy_version": {"PolicyVersion": {"Document": role_policy_doc}},
    }
    client = FakeIamClient(ops=ops)
    resources, warning = discover_iam(client, "123456789012")
    assert len(resources) == 1
    assert resources[0]["resource_type"] == "aws_iam_role"
    extra = resources[0]["extra"]
    assert "iam_policies" in extra
    assert extra["iam_policies"][0]["statements"][0]["actions"] == ["*"]

def test_discover_iam_mfa_and_keys():
    ops = {
        "list_roles": [{"Roles": []}],
        "list_users": [{"Users": [{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice", "Path": "/"}]}],
        "list_groups": [{"Groups": []}],
        "list_attached_user_policies": [{"AttachedPolicies": []}],
        "list_user_policies": [{"PolicyNames": []}],
        "list_mfa_devices": {"MFADevices": []},
        "list_access_keys": {"AccessKeyMetadata": [{"AccessKeyId": "AKIAIOSFODNN7EXAMPLE", "Status": "Active", "CreateDate": "2024-01-01T00:00:00Z"}]},
        "get_access_key_last_used": {"AccessKeyLastUsed": {"LastUsedDate": "2024-06-01T00:00:00Z"}},
        "get_login_profile": Exception("NoSuchEntity"),
    }
    # Need code to simulate NoSuchEntity
    class FailClient(FakeIamClient):
        def __getattr__(self, name):
            if name == "get_login_profile":
                def _fail(**kwargs):
                    e = Exception("NoSuchEntity")
                    e.response = {"Error": {"Code": "NoSuchEntity", "Message": "not found"}}
                    raise e
                return _fail
            return super().__getattr__(name)
    client = FailClient(ops=ops)
    resources, _ = discover_iam(client, "123456789012")
    assert len(resources) == 1
    extra = resources[0]["extra"]
    assert extra["iam_mfa_device_count"] == 0
    assert extra["iam_access_keys"][0]["id_suffix"] == "MPLE"
    assert extra["iam_password_enabled"] is False

def test_discover_iam_permission_denied_becomes_not_assessed():
    class Denied(Exception):
        response = {"Error": {"Code": "AccessDenied", "Message": "denied"}}
    ops = {
        "list_roles": [{"Roles": [{"RoleName": "R", "Arn": "arn:aws:iam::123:role/R", "Path": "/"}]}],
        "list_users": [{"Users": []}],
        "list_groups": [{"Groups": []}],
    }
    fail = {"list_attached_role_policies": Denied("denied"), "list_role_policies": Denied("denied")}
    client = FakeIamClient(ops=ops, fail=fail)
    resources, _ = discover_iam(client, "123")
    assert resources[0]["extra"]["iam_policies_unavailable"] == "permission_denied"

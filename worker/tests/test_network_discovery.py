"""E4 network discovery — bounded, deterministic."""

from app.aws_discovery import _normalize_sg_permissions, discover_security_groups, discover_route_tables, discover_network_acls
from app.aws_discovery import discover_subnets, discover_vpcs

class FakePaginator:
    def __init__(self, pages): self._pages = pages
    def paginate(self, **kw): yield from self._pages

class FakeClient:
    def __init__(self, ops): self._ops = ops
    def get_paginator(self, op):
        return FakePaginator(self._ops.get(op, []))
    def __getattr__(self, name):
        def _op(**kw): return self._ops.get(name, {})
        return _op

def test_normalize_sg():
    perms = [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    out = _normalize_sg_permissions(perms)
    assert out[0]["protocol"] == "tcp"
    assert out[0]["from_port"] == 22
    assert out[0]["cidr_v4"] == ["0.0.0.0/0"]

def test_normalize_sg_all():
    perms = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]
    out = _normalize_sg_permissions(perms)
    assert out[0]["protocol"] == "-1"

def test_discover_sg_ingress():
    ops = {"describe_security_groups": [{"SecurityGroups": [{"GroupId": "sg-123", "GroupName": "test", "VpcId": "vpc-1", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}], "IpPermissionsEgress": []}]}]}
    client = FakeClient(ops)
    res, _ = discover_security_groups(client, "us-east-1", "123")
    assert len(res) == 1
    assert len(res[0]["extra"]["ingress"]) == 2
    assert res[0]["extra"]["ingress"][0]["cidr_v4"] == ["0.0.0.0/0"]

def test_discover_route_tables():
    ops = {"describe_route_tables": [{"RouteTables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-1", "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-123", "State": "active"}], "Associations": [{"SubnetId": "subnet-1", "Main": False}]}]}]}
    client = FakeClient(ops)
    res, _ = discover_route_tables(client, "us-east-1", "123")
    assert res[0]["extra"]["routes"][0]["gateway_id"] == "igw-123"
    assert res[0]["extra"]["associations"][0]["subnet_id"] == "subnet-1"

def test_discover_nacl():
    ops = {"describe_network_acls": [{"NetworkAcls": [{"NetworkAclId": "acl-1", "VpcId": "vpc-1", "Associations": [{"SubnetId": "subnet-1"}], "Entries": [{"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"}]}]}]}
    client = FakeClient(ops)
    res, _ = discover_network_acls(client, "us-east-1", "123")
    assert res[0]["extra"]["entries"][0]["cidr"] == "0.0.0.0/0"

def test_discover_vpc_ipv6():
    ops = {"describe_vpcs": [{"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16", "Ipv6CidrBlockAssociationSet": [{"Ipv6CidrBlock": "2600:1f00::/56"}]}]}]}
    client = FakeClient(ops)
    res, _ = discover_vpcs(client, "us-east-1", "123")
    assert res[0]["extra"]["ipv6_cidr"] == "2600:1f00::/56"

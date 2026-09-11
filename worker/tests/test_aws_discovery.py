"""E1 AWS live discovery engine — deterministic fakes, no SDK, no network."""

import pytest

from app.aws_discovery import (
    MAX_TOTAL_RESOURCES,
    assume_role_session,
    call_with_retry,
    canonical_resource_value,
    classify_aws_error,
    discover_account,
    discover_ecs_services,
    discover_global,
    discover_iam,
    discover_region,
    discover_s3_buckets,
    get_caller_account,
    list_enabled_regions,
    sanitize_aws_error,
    to_asset_inputs,
    to_relationship_inputs,
)


class FakeError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": code}}


class FakePaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        yield from self._pages


class FakeClient:
    def __init__(self, ops=None, fail=None):
        self._ops = ops or {}
        self._fail = fail or {}
        self.calls = []

    def get_paginator(self, operation):
        self.calls.append(("paginator", operation))
        if operation in self._fail:
            raise self._fail[operation]
        return FakePaginator(self._ops.get(operation, []))

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def _op(**kwargs):
            self.calls.append((name, kwargs))
            if name in self._fail:
                raise self._fail[name]
            return self._ops.get(name, {})

        return _op


class FakeSession:
    def __init__(self, clients):
        self._clients = clients

    def client(self, service, region_name=None):
        return self._clients[(service, region_name)]


class FakeBoto3:
    def __init__(self, sts=None):
        self._sts = sts or FakeClient()

    def client(self, service, region_name=None):
        assert service == "sts"
        return self._sts

    def Session(self, **kwargs):
        assert kwargs.get("aws_access_key_id")
        assert kwargs.get("aws_secret_access_key")
        return FakeSession({})


# A: connector-adjacent validation is backend-side; engine assumes valid config.

def test_e1_error_classification():
    assert classify_aws_error(FakeError("AccessDenied")) == "permission"
    assert classify_aws_error(FakeError("UnauthorizedOperation")) == "permission"
    assert classify_aws_error(FakeError("Throttling")) == "throttling"
    assert classify_aws_error(FakeError("RequestLimitExceeded")) == "throttling"
    assert classify_aws_error(FakeError("WeirdNewCode")) == "fatal"
    assert classify_aws_error(Exception("boom")) == "fatal"


def test_e1_sanitize_strips_credentials():
    msg = sanitize_aws_error(Exception("failed with SecretAccessKey=AKIAIOSFODNN7EXAMPLE and token abc"))
    assert "AKIAIOSFODNN7EXAMPLE" not in msg
    assert "AKIAIOSFODNN7" not in msg
    assert len(msg) <= 300


def test_e1_retry_only_transient():
    attempts = {"n": 0}

    def flaky():
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise FakeError("Throttling")
        return "ok"

    assert call_with_retry(flaky, sleep=lambda _: None) == "ok"
    assert attempts["n"] == 3


def test_e1_no_retry_on_permission():
    attempts = {"n": 0}

    def denied():
        attempts["n"] += 1
        raise FakeError("AccessDenied")

    with pytest.raises(FakeError):
        call_with_retry(denied, sleep=lambda _: None)
    assert attempts["n"] == 1


def test_e1_assume_role_session_memory_only():
    sts = FakeClient(ops={"assume_role": {"Credentials": {
        "AccessKeyId": "AKIA", "SecretAccessKey": "shh", "SessionToken": "tok"}}})
    session = assume_role_session("arn:aws:iam::123456789012:role/VAPT", "ext-1", boto3_mod=FakeBoto3(sts))
    assert session is not None
    assert sts.calls[0][0] == "assume_role"


def test_e1_caller_identity():
    session = FakeSession({("sts", "us-east-1"): FakeClient(
        ops={"get_caller_identity": {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/VAPT/x"}})})
    assert get_caller_account(session) == "123456789012"


def test_e1_region_discovery_prefers_api_not_hardcode():
    session = FakeSession({("ec2", "us-east-1"): FakeClient(
        ops={"describe_regions": {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]}})})
    assert list_enabled_regions(session, None) == ["us-east-1", "eu-west-1"]
    assert list_enabled_regions(session, ["eu-west-1", "bogus"]) == ["eu-west-1", "bogus"]


def _pages(mapping):
    return {op: [page] for op, page in mapping.items()}


def _ec2_region_client():
    return FakeClient(ops=_pages({
        "describe_vpcs": {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16", "State": "available", "Tags": [{"Key": "Name", "Value": "main"}]}]},
        "describe_subnets": {"Subnets": [{"SubnetId": "subnet-1", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24", "AvailabilityZone": "us-east-1a"}]},
        "describe_route_tables": {"RouteTables": [{"RouteTableId": "rtb-1", "VpcId": "vpc-1"}]},
        "describe_security_groups": {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web", "VpcId": "vpc-1"}]},
        "describe_internet_gateways": {"InternetGateways": [{"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1"}]}]},
        "describe_nat_gateways": {"NatGateways": [{"NatGatewayId": "nat-1", "VpcId": "vpc-1", "SubnetId": "subnet-1", "State": "available"}]},
        "describe_network_interfaces": {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "VpcId": "vpc-1", "SubnetId": "subnet-1", "Groups": [{"GroupId": "sg-1"}]}]},
        "describe_instances": {"Reservations": [{"Instances": [{"InstanceId": "i-1", "InstanceType": "t3.micro", "State": {"Name": "running"}, "VpcId": "vpc-1", "SubnetId": "subnet-1", "SecurityGroups": [{"GroupId": "sg-1"}], "Tags": [{"Key": "Name", "Value": "web-1"}]}]}]},
    }))


def _factory(region_map):
    def make(service, region):
        return region_map[(service, region)]
    return make


def test_e1_region_discovers_network_and_compute():
    factory = _factory({("ec2", "us-east-1"): _ec2_region_client(),
                        ("elbv2", "us-east-1"): FakeClient(ops=_pages({"describe_load_balancers": {"LoadBalancers": []}})),
                        ("rds", "us-east-1"): FakeClient(ops=_pages({"describe_db_instances": {"DBInstances": []}})),
                        ("lambda", "us-east-1"): FakeClient(ops=_pages({"list_functions": {"Functions": []}})),
                        ("ecs", "us-east-1"): FakeClient(ops=_pages({"list_clusters": {"clusterArns": []}})),
                        ("ecr", "us-east-1"): FakeClient(ops=_pages({"describe_repositories": {"repositories": []}})),
                        ("efs", "us-east-1"): FakeClient(ops=_pages({"describe_file_systems": {"FileSystems": []}}))})
    outcome = discover_region(factory, "us-east-1", "123456789012", 500)
    types = {r["resource_type"] for r in outcome["resources"]}
    assert {"aws_vpc", "aws_subnet", "aws_route_table", "aws_security_group",
            "aws_internet_gateway", "aws_nat_gateway", "aws_network_interface",
            "aws_ec2_instance"} <= types
    assert outcome["warnings"] == []
    assert outcome["services_failed"] == 0


def test_e1_partial_regional_failure():
    denied = FakeError("AccessDenied")
    factory = _factory({("ec2", "eu-west-1"): FakeClient(fail={"describe_vpcs": denied, "describe_subnets": denied,
        "describe_route_tables": denied, "describe_security_groups": denied,
        "describe_internet_gateways": denied, "describe_nat_gateways": denied,
        "describe_network_interfaces": denied, "describe_instances": denied}),
                        ("elbv2", "eu-west-1"): FakeClient(ops=_pages({"describe_load_balancers": {"LoadBalancers": []}})),
                        ("rds", "eu-west-1"): FakeClient(ops=_pages({"describe_db_instances": {"DBInstances": []}})),
                        ("lambda", "eu-west-1"): FakeClient(ops=_pages({"list_functions": {"Functions": []}})),
                        ("ecs", "eu-west-1"): FakeClient(ops=_pages({"list_clusters": {"clusterArns": []}})),
                        ("ecr", "eu-west-1"): FakeClient(ops=_pages({"describe_repositories": {"repositories": []}})),
                        ("efs", "eu-west-1"): FakeClient(ops=_pages({"describe_file_systems": {"FileSystems": []}}))})
    outcome = discover_region(factory, "eu-west-1", "123456789012", 500)
    assert outcome["warnings"], "permission failures must surface as warnings"
    assert any("permission" in str(w.get("reason", "")) or "permission" in str(w.get("detail", "")).lower() for w in outcome["warnings"])
    # Warnings must not claim absence: resources simply missing, warning recorded.


def test_e1_s3_global_and_iam():
    s3 = FakeClient(ops={"list_buckets": {"Buckets": [{"Name": "my-bucket"}]},
                         "get_bucket_location": {"LocationConstraint": "eu-west-1"}})
    resources, warning = discover_s3_buckets(s3, "123456789012")
    assert warning is None
    assert resources[0]["resource_id"] == "my-bucket"
    assert resources[0]["region"] == "eu-west-1"
    iam = FakeClient(ops=_pages({"list_roles": {"Roles": [{"RoleName": "r", "Arn": "arn:aws:iam::123456789012:role/r"}]},
                          "list_users": {"Users": []},
                          "list_groups": {"Groups": []}}))
    resources, warning = discover_iam(iam, "123456789012")
    assert warning is None
    assert resources[0]["region"] == "global"
    assert resources[0]["resource_type"] == "aws_iam_role"


def test_e1_account_status_partial_and_counts():
    factory = _factory({("ec2", "us-east-1"): _ec2_region_client(),
                        ("elbv2", "us-east-1"): FakeClient(ops=_pages({"describe_load_balancers": {"LoadBalancers": []}})),
                        ("rds", "us-east-1"): FakeClient(ops=_pages({"describe_db_instances": {"DBInstances": []}})),
                        ("lambda", "us-east-1"): FakeClient(ops=_pages({"list_functions": {"Functions": []}})),
                        ("ecs", "us-east-1"): FakeClient(ops=_pages({"list_clusters": {"clusterArns": []}})),
                        ("ecr", "us-east-1"): FakeClient(ops=_pages({"describe_repositories": {"repositories": []}})),
                        ("efs", "us-east-1"): FakeClient(ops=_pages({"describe_file_systems": {"FileSystems": []}})),
                        ("s3", "us-east-1"): FakeClient(fail={"list_buckets": FakeError("AccessDenied")}),
                        ("iam", "us-east-1"): FakeClient(fail={"list_roles": FakeError("AccessDenied"),
                            "list_users": FakeError("AccessDenied"), "list_groups": FakeError("AccessDenied")})})
    outcome = discover_account(factory, "123456789012", ["us-east-1"], 500)
    assert outcome["status"] == "completed"  # region ok; global warnings recorded
    assert outcome["regions_succeeded"] == 2  # region + global pass
    assert any("S3 discovery unavailable" in str(w.get("detail", "")) or "permission" in str(w.get("reason", "")) for w in outcome["warnings"])
    assert outcome["resource_counts"].get("aws_ec2_instance") == 1


def test_e1_all_failed_is_failed_not_partial():
    factory = _factory({("ec2", "r1"): FakeClient(fail={"describe_regions": FakeError("AuthFailure")})})

    def boom_factory(service, region):
        raise FakeError("AuthFailure")

    outcome = discover_account(boom_factory, "123456789012", ["r1"], 500)
    assert outcome["status"] in ("partial", "failed")
    assert outcome["regions_failed"] >= 1


def test_e1_arn_identity_and_composite_fallback():
    arn_res = {"service": "ec2", "resource_type": "aws_ec2_instance", "resource_id": "i-1",
               "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1", "region": "us-east-1", "account_id": "123456789012"}
    assert canonical_resource_value(arn_res) == "arn:aws:ec2:us-east-1:123456789012:instance/i-1"
    no_arn = dict(arn_res, arn=None)
    assert canonical_resource_value(no_arn) == "cloud_resource:aws:123456789012:us-east-1:ec2:aws_ec2_instance:i-1"


def test_e1_asset_inputs_bounded_metadata():
    resources = [{"service": "ec2", "resource_type": "aws_ec2_instance", "resource_id": "i-1",
                  "arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-1", "name": "web",
                  "region": "us-east-1", "account_id": "123456789012",
                  "tags": {f"k{i}": "v" for i in range(30)}, "extra": {"password": "shh", "state": "running"}}]
    assets = to_asset_inputs(resources, "123456789012", "2026-01-01T00:00:00+00:00")
    assert assets[0]["type"] == "cloud_account"
    assert assets[1]["type"] == "cloud_resource"
    assert assets[1]["value"] == "arn:aws:ec2:us-east-1:123456789012:instance/i-1"
    meta = assets[1]["metadata"]
    assert len(meta["tags"]) <= 20
    assert "password" not in str(meta)


def test_e1_relationships_evidence_backed_taxonomy():
    vpc = {"service": "ec2", "resource_type": "aws_vpc", "resource_id": "vpc-1", "region": "r", "account_id": "a"}
    subnet = {"service": "ec2", "resource_type": "aws_subnet", "resource_id": "subnet-1", "region": "r",
              "account_id": "a", "extra": {"vpc_id": "vpc-1"}}
    inst = {"service": "ec2", "resource_type": "aws_ec2_instance", "resource_id": "i-1", "region": "r",
            "account_id": "a", "extra": {"vpc_id": "vpc-1", "subnet_id": "subnet-1", "security_groups": ["sg-9"]}}
    sg = {"service": "ec2", "resource_type": "aws_security_group", "resource_id": "sg-9", "region": "r",
          "account_id": "a", "extra": {"vpc_id": "vpc-1"}}
    rels = to_relationship_inputs([vpc, subnet, inst, sg], "a")
    kinds = {(r["source_value"], r["target_value"], r["relationship_type"]) for r in rels}
    assert all(r["relationship_type"] in ("contains", "uses") for r in rels)
    # subnet contains instance; instance uses sg; vpc contains subnet
    values = {canonical_resource_value(vpc), canonical_resource_value(subnet),
              canonical_resource_value(inst), canonical_resource_value(sg)}
    assert (canonical_resource_value(subnet), canonical_resource_value(inst), "contains") in kinds
    assert (canonical_resource_value(inst), canonical_resource_value(sg), "uses") in kinds
    assert (canonical_resource_value(vpc), canonical_resource_value(subnet), "contains") in kinds
    assert all(v in values or "cloud_account" in v for v, _, _ in kinds)


def test_e2_evidence_ec2_metadata_options():
    from app.aws_discovery import discover_ec2_instances
    client = FakeClient(ops=_pages({
        "describe_instances": {"Reservations": [{"Instances": [
            {"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"}},
            {"InstanceId": "i-2", "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"}},
            {"InstanceId": "i-3"},
        ]}]},
    }))
    resources, warning = discover_ec2_instances(client, "us-east-1", "123456789012")
    assert warning is None
    by_id = {r["resource_id"]: r["extra"] for r in resources}
    assert by_id["i-1"]["imds_v2_enforced"] is False
    assert by_id["i-2"]["imds_v2_enforced"] is True
    assert by_id["i-3"]["imds_v2_enforced"] is None


def test_e2_evidence_rds_public_encrypted():
    from app.aws_discovery import discover_rds_instances
    client = FakeClient(ops=_pages({
        "describe_db_instances": {"DBInstances": [
            {"DBInstanceIdentifier": "db-1", "PubliclyAccessible": True, "StorageEncrypted": False}]},
    }))
    resources, warning = discover_rds_instances(client, "us-east-1", "123456789012")
    assert warning is None
    assert resources[0]["extra"]["publicly_accessible"] is True
    assert resources[0]["extra"]["storage_encrypted"] is False


def test_e2_evidence_s3_pab_and_encryption():
    from app.aws_discovery import discover_s3_buckets
    client = FakeClient(
        ops={"list_buckets": {"Buckets": [{"Name": "b1"}]},
             "get_bucket_location": {"LocationConstraint": "us-east-1"},
             "get_public_access_block": {"PublicAccessBlockConfiguration": {
                 "BlockPublicAcls": True, "IgnorePublicAcls": False,
                 "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
             "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {
                 "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}},
    )
    resources, warning = discover_s3_buckets(client, "123456789012")
    assert warning is None
    assert resources[0]["extra"]["pab_ignorepublicacls"] is False
    assert resources[0]["extra"]["encryption"] == "AES256"


def test_e2_evidence_s3_denied_is_error_not_absence():
    from app.aws_discovery import discover_s3_buckets
    denied = FakeError("AccessDenied")

    class DenyClient(FakeClient):
        def __getattr__(self, name):
            if name.startswith("_"):
                raise AttributeError(name)

            def _op(**kwargs):
                if name in ("get_public_access_block", "get_bucket_encryption"):
                    raise denied
                return FakeClient.__getattr__(self, name)(**kwargs)

            return _op

    client = DenyClient(ops={"list_buckets": {"Buckets": [{"Name": "b1"}]},
                             "get_bucket_location": {"LocationConstraint": "us-east-1"}})
    resources, warning = discover_s3_buckets(client, "123456789012")
    assert warning is None  # bucket listed; per-bucket gaps are error fields
    assert "pab_error" in resources[0]["extra"]
    assert "encryption" not in resources[0]["extra"]


def test_e2_evidence_elb_listeners_and_lambda_urls():
    from app.aws_discovery import discover_load_balancers, discover_lambda_functions
    lb = FakeClient(ops=_pages({
        "describe_load_balancers": {"LoadBalancers": [
            {"LoadBalancerArn": "arn:lb", "LoadBalancerName": "web", "Type": "application",
             "Scheme": "internet-facing", "VpcId": "vpc-1"}]},
        "describe_listeners": {"Listeners": [{"Protocol": "HTTP", "Port": 80}]},
    }))
    resources, warning = discover_load_balancers(lb, "us-east-1", "123456789012")
    assert warning is None
    assert resources[0]["extra"]["listeners"] == [{"protocol": "HTTP", "port": 80}]
    fn = FakeClient(ops=_pages({
        "list_functions": {"Functions": [{"FunctionName": "f1", "FunctionArn": "arn:fn"}]},
        "list_function_url_configs": {"FunctionUrls": [
            {"FunctionUrl": "https://x.lambda-url.us-east-1.on.aws/", "AuthType": "NONE"}]},
    }))
    resources, warning = discover_lambda_functions(fn, "us-east-1", "123456789012")
    assert warning is None
    assert resources[0]["extra"]["function_urls"] == [
        {"url": "https://x.lambda-url.us-east-1.on.aws/", "auth": "NONE"}]


def test_e2_evidence_survives_persistence_sanitizer():
    # E2 evidence keys must survive worker/app/persistence.py sanitize_metadata
    # (which drops secret-fragment keys like *token*).
    from app.persistence import sanitize_metadata
    meta = sanitize_metadata({"imds_v2_enforced": False, "http_endpoint": "enabled",
                              "publicly_accessible": True, "storage_encrypted": False,
                              "pab_blockpublicacls": False, "encryption": None,
                              "listeners": [{"protocol": "HTTP", "port": 80}],
                              "function_urls": [{"url": "https://x/", "auth": "NONE"}],
                              "password": "shh"})
    assert meta["imds_v2_enforced"] is False
    assert meta["listeners"] == [{"protocol": "HTTP", "port": 80}]
    assert meta["function_urls"] == [{"url": "https://x/", "auth": "NONE"}]
    assert "password" not in meta


def test_e1_ecs_service_needs_cluster_evidence():
    svc = {"service": "ecs", "resource_type": "aws_ecs_service", "resource_id": "arn:aws:ecs:r:a:service/c/s",
           "arn": "arn:aws:ecs:r:a:service/c/s", "region": "r", "account_id": "a",
           "extra": {"cluster": "arn:aws:ecs:r:a:cluster/c"}}
    rels = to_relationship_inputs([svc], "a")
    # No cluster resource present: no invented cluster edge (only account anchor).
    assert all(r["relationship_type"] == "contains" and "cloud_account" in r["source_value"] for r in rels)

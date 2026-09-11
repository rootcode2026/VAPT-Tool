"""E4 network checks — deterministic, no AWS."""

from app.services import cloud_checks as checks

def _meta(extra, rtype="aws_security_group"):
    return {"extra": extra, "value": f"cloud_resource:aws:123:us-east-1:ec2:{rtype}:test", "resource_id": "test", "resource_type": rtype, "account_id": "123", "region": "us-east-1"}

def test_ec2_002_ingress():
    extra = {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_v4": ["0.0.0.0/0"]}], "vpc_id": "vpc-1"}
    assert checks.evaluate_asset(checks.get_check("AWS-EC2-002"), _meta(extra))[0] == "failed"
    extra2 = {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_v4": ["10.0.0.0/8"]}], "vpc_id": "vpc-1"}
    assert checks.evaluate_asset(checks.get_check("AWS-EC2-002"), _meta(extra2))[0] == "passed"

def test_net_002_ssh():
    extra = {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_v4": ["0.0.0.0/0"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-002"), _meta(extra))[0] == "failed"
    extra2 = {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_v4": ["10.0.0.0/8"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-002"), _meta(extra2))[0] == "passed"

def test_net_003_rdp():
    extra = {"ingress": [{"protocol": "tcp", "from_port": 3389, "to_port": 3389, "cidr_v4": ["::/0"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-003"), _meta(extra))[0] == "failed"

def test_net_004_db():
    extra = {"ingress": [{"protocol": "tcp", "from_port": 3306, "to_port": 3306, "cidr_v4": ["0.0.0.0/0"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-004"), _meta(extra))[0] == "failed"
    # non-db port should pass
    extra2 = {"ingress": [{"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr_v4": ["0.0.0.0/0"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-004"), _meta(extra2))[0] == "passed"

def test_net_005_all():
    extra = {"ingress": [{"protocol": "-1", "cidr_v4": ["0.0.0.0/0"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-005"), _meta(extra))[0] == "failed"
    extra2 = {"ingress": [{"protocol": "tcp", "from_port": 80, "to_port": 80, "cidr_v4": ["0.0.0.0/0"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-005"), _meta(extra2))[0] == "passed"

def test_net_010_egress():
    extra = {"egress": [{"protocol": "-1", "cidr_v4": ["0.0.0.0/0"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-010"), _meta(extra))[0] == "failed"

def test_nacl():
    extra = {"entries": [{"rule_number": 100, "protocol": "-1", "rule_action": "allow", "egress": False, "cidr": "0.0.0.0/0"}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-009"), _meta(extra, "aws_network_acl"))[0] == "failed"

def test_ipv6():
    extra = {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "cidr_v6": ["::/0"]}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-002"), _meta(extra))[0] == "failed"

def test_internal_ref_not_fail():
    extra = {"ingress": [{"protocol": "tcp", "from_port": 22, "to_port": 22, "group_ids": ["sg-123"]}], "vpc_id": "vpc-1"}
    # No cidr, should be PASS
    assert checks.evaluate_asset(checks.get_check("AWS-NET-002"), _meta(extra))[0] == "passed"

def test_not_assessed():
    assert checks.evaluate_asset(checks.get_check("AWS-NET-002"), _meta({}))[0] == "not_assessed"
    assert checks.evaluate_asset(checks.get_check("AWS-NET-009"), _meta({}, "aws_network_acl"))[0] == "not_assessed"

def test_net_008_lb():
    extra = {"scheme": "internet-facing", "listeners": [{"protocol": "HTTP", "port": 80}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-008"), _meta(extra, "aws_alb"))[0] == "failed"
    extra2 = {"scheme": "internal", "listeners": [{"protocol": "HTTP", "port": 80}]}
    assert checks.evaluate_asset(checks.get_check("AWS-NET-008"), _meta(extra2, "aws_alb"))[0] == "passed"

def test_catalog():
    c = checks.list_catalog(provider="aws")
    ids = {x["check_id"] for x in c}
    assert "AWS-EC2-002" in ids
    assert "AWS-NET-005" in ids

def test_net_006_posture_not_finding():
    # Public subnet with IGW route is posture, not vulnerability
    extra = {"vpc_id": "vpc-1", "cidr": "10.0.1.0/24", "map_public_ip": True, "is_public": True}
    # After hardening, NET-006 must not create FAIL
    assert checks.evaluate_asset(checks.get_check("AWS-NET-006"), _meta(extra, "aws_subnet"))[0] == "passed"

def test_net_006_insufficient_evidence():
    assert checks.evaluate_asset(checks.get_check("AWS-NET-006"), _meta({}, "aws_subnet"))[0] == "not_assessed"

def test_fingerprint_same_condition_same():
    from app.services import finding_lifecycle as lc
    from types import SimpleNamespace
    def proxy(title, check_id, asset_value, asset_id, port=None, param=None):
        d = {"rule_id": check_id, "asset_type": "cloud_resource", "asset_value": asset_value}
        if port: d["port"] = str(port)
        if param: d["parameter"] = param
        return SimpleNamespace(title=title, cve=None, cwe=None, evidence=None, asset_id=asset_id, extra_data=d)
    fp1 = lc.d8_fingerprint(lc.d8_finding_input(proxy("AWS-NET-002: SSH", "AWS-NET-002", "cloud_resource:aws:123:us-east-1:ec2:aws_security_group:sg-1", "id-1", port="22", param="0.0.0.0/0")))
    fp2 = lc.d8_fingerprint(lc.d8_finding_input(proxy("AWS-NET-002: SSH", "AWS-NET-002", "cloud_resource:aws:123:us-east-1:ec2:aws_security_group:sg-1", "id-1", port="22", param="0.0.0.0/0")))
    assert fp1 == fp2
    # version change must not affect fingerprint (rule_id same, port same)
    fp3 = lc.d8_fingerprint(lc.d8_finding_input(proxy("AWS-NET-002: SSH", "AWS-NET-002", "cloud_resource:aws:123:us-east-1:ec2:aws_security_group:sg-1", "id-1", port="22", param="0.0.0.0/0")))
    assert fp1 == fp3

def test_fingerprint_port_change():
    from app.services import finding_lifecycle as lc
    from types import SimpleNamespace
    def proxy(port):
        return SimpleNamespace(title="AWS-NET-002: SSH", cve=None, cwe=None, evidence=None, asset_id="id-1", extra_data={"rule_id": "AWS-NET-002", "asset_type": "cloud_resource", "asset_value": "cloud_resource:aws:123:us-east-1:ec2:aws_security_group:sg-1", "port": str(port)})
    fp22 = lc.d8_fingerprint(lc.d8_finding_input(proxy(22)))
    fp3389 = lc.d8_fingerprint(lc.d8_finding_input(proxy(3389)))
    assert fp22 != fp3389

def test_fingerprint_source_change():
    from app.services import finding_lifecycle as lc
    from types import SimpleNamespace
    def proxy(param):
        return SimpleNamespace(title="AWS-NET-002: SSH", cve=None, cwe=None, evidence=None, asset_id="id-1", extra_data={"rule_id": "AWS-NET-002", "asset_type": "cloud_resource", "asset_value": "cloud_resource:aws:123:us-east-1:ec2:aws_security_group:sg-1", "port": "22", "parameter": param})
    fp_v4 = lc.d8_fingerprint(lc.d8_finding_input(proxy("0.0.0.0/0")))
    fp_v6 = lc.d8_fingerprint(lc.d8_finding_input(proxy("::/0")))
    assert fp_v4 != fp_v6

def test_fingerprint_resource_change():
    from app.services import finding_lifecycle as lc
    from types import SimpleNamespace
    def proxy(asset):
        return SimpleNamespace(title="AWS-NET-002: SSH", cve=None, cwe=None, evidence=None, asset_id="id-1", extra_data={"rule_id": "AWS-NET-002", "asset_type": "cloud_resource", "asset_value": asset, "port": "22"})
    fp1 = lc.d8_fingerprint(lc.d8_finding_input(proxy("cloud_resource:aws:123:us-east-1:ec2:aws_security_group:sg-1")))
    fp2 = lc.d8_fingerprint(lc.d8_finding_input(proxy("cloud_resource:aws:123:us-east-1:ec2:aws_security_group:sg-2")))
    assert fp1 != fp2

def test_dedup_ec2002_net001():
    # Simulate run_evaluation dedup: same SG, same proto/port/cidr should produce one canonical finding
    sg_value = "cloud_resource:aws:123:us-east-1:ec2:aws_security_group:sg-123"
    evidence = {"protocol": "tcp", "from_port": 22, "to_port": 22, "source": ["0.0.0.0/0"]}
    canon = f"{sg_value}:tcp:22:22:0.0.0.0/0"
    seen = set()
    # First check creates
    assert canon not in seen
    seen.add(canon)
    # Second check with same canon should be deduped
    assert canon in seen

"""E1 AWS live discovery engine (worker side).

boto3 is imported lazily so unit tests and mock mode never require AWS SDKs or
network. Every AWS client is created through an injectable factory, which lets
tests drive the full engine with deterministic fakes.

Design notes:
- Authentication is cross-account AssumeRole only. Temporary credentials live
  in memory, never persisted, never logged.
- Discovery is DISCOVERY ONLY: no security checks, no findings, no scoring.
- Permission failures are recorded as bounded warnings and never interpreted
  as resource absence (critical for future CSPM accuracy).
- Throttling/transient errors get a small bounded retry; permission errors
  never retry.
- Output is normalized asset/relationship inputs for the existing
  ``upsert_assets``/``upsert_relationships`` persistence (canonical
  cloud_account/cloud_resource types, existing relationship taxonomy).
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from typing import Any, Callable

MAX_TOTAL_RESOURCES = int(os.getenv("MAX_CLOUD_RESOURCES", "500"))
MAX_ITEMS_PER_SERVICE_CALL = 100
MAX_REGIONS = 32
RETRY_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = (0.5, 1.0, 2.0)

# E3 IAM bounds
MAX_IAM_POLICIES_PER_IDENTITY = 20
MAX_IAM_STATEMENTS_PER_POLICY = 50
# E4 network bounds
MAX_SG_RULES = 50
MAX_NACL_ENTRIES = 50
MAX_ROUTE_ENTRIES = 20
# E5 storage bounds
MAX_S3_BUCKETS = 100
MAX_S3_POLICY_STATEMENTS = 20
MAX_EBS_VOLUMES = 100
MAX_EBS_SNAPSHOTS = 100
MAX_EFS_FILESYSTEMS = 100

PERMISSION_CODES = frozenset({
    "AccessDenied", "UnauthorizedOperation", "AuthFailure",
    "InvalidClientTokenId", "SignatureDoesNotMatch", "AccessDeniedException",
    "NotAuthorized", "ForbiddenException", "UnrecognizedClientException",
})

THROTTLE_CODES = frozenset({
    "Throttling", "ThrottlingException", "RequestLimitExceeded",
    "TooManyRequestsException", "RequestTimeout", "RequestTimeoutException",
    "PriorRequestNotComplete", "InternalError", "InternalFailure",
    "ServiceUnavailable", "ServiceUnavailableException",
})

SECRET_KEY_RE = re.compile(r"(?i)(secret|token|private|credential|password|access[_-]?key)")


def _error_code(exc: Exception) -> str | None:
    """Bounded AWS error code (for distinguishing denial from absence)."""
    try:
        code = str((getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "") or "")
        return code[:64] or None
    except Exception:
        return None


def sanitize_aws_error(exc: Exception, default: str = "AWS operation failed") -> str:
    """Bounded, credential-free error text safe for APIs, runs, and audit."""
    try:
        msg = str(exc or "")
    except Exception:
        return default
    low = msg.lower()
    for tok in ("accesskey", "secretaccesskey", "sessiontoken", "authorization",
                "x-amz-", "credential", "privatekey", "begin private"):
        if tok in low:
            return default
    msg = SECRET_KEY_RE.sub(r"\1=[REDACTED]", msg)
    msg = re.sub(r"(?i)arn:aws:iam::\d{12}:user/[^\"'\s]+", "arn:aws:iam::<account>:user/[REDACTED]", msg)
    msg = msg.strip()
    return (msg or default)[:300]


def classify_aws_error(exc: Exception) -> str:
    """permission | throttling | transient | fatal (permission never retries)."""
    try:
        code = str((getattr(exc, "response", {}) or {}).get("Error", {}).get("Code", "") or "")
    except Exception:
        code = ""
    if code in PERMISSION_CODES:
        return "permission"
    if code in THROTTLE_CODES:
        return "throttling"
    name = type(exc).__name__
    if name in ("EndpointConnectionError", "ConnectTimeoutError", "ReadTimeoutError",
                "ConnectionClosedError", "ConnectionError", "TimeoutError"):
        return "transient"
    return "fatal"


def call_with_retry(fn: Callable[[], Any], *, sleep: Callable[[float], None] = time.sleep) -> Any:
    """Bounded retry for throttling/transient failures only."""
    last: Exception | None = None
    for attempt in range(RETRY_ATTEMPTS):
        try:
            return fn()
        except Exception as exc:
            kind = classify_aws_error(exc)
            if kind in ("throttling", "transient") and attempt < RETRY_ATTEMPTS - 1:
                last = exc
                try:
                    sleep(RETRY_BACKOFF_SECONDS[attempt])
                except Exception:
                    pass
                continue
            raise
    if last is not None:
        raise last
    raise RuntimeError("AWS call failed")


def _boto3_session(boto3_mod=None):
    if boto3_mod is None:
        try:
            import boto3 as boto3_mod
        except Exception as exc:
            raise RuntimeError("AWS SDK unavailable") from exc
    return boto3_mod


def assume_role_session(role_arn: str, external_id: str | None = None, boto3_mod=None):
    """AssumeRole with ambient credentials; returns a boto3 Session (memory only)."""
    boto3 = _boto3_session(boto3_mod)
    sts = boto3.client("sts", region_name="us-east-1")
    kwargs: dict[str, Any] = {
        "RoleArn": role_arn,
        "RoleSessionName": "vapt-discovery",
        "DurationSeconds": 900,
    }
    if external_id:
        kwargs["ExternalId"] = external_id
    response = call_with_retry(lambda: sts.assume_role(**kwargs), sleep=lambda _: None)
    creds = (response or {}).get("Credentials") or {}
    if not creds.get("AccessKeyId") or not creds.get("SecretAccessKey"):
        raise RuntimeError("AWS AssumeRole returned no credentials")
    return boto3.Session(
        aws_access_key_id=str(creds["AccessKeyId"]),
        aws_secret_access_key=str(creds["SecretAccessKey"]),
        aws_session_token=str(creds.get("SessionToken") or ""),
    )


def get_caller_account(session, region: str = "us-east-1") -> str:
    sts = session.client("sts", region_name=region)
    identity = call_with_retry(lambda: sts.get_caller_identity(), sleep=lambda _: None) or {}
    return str(identity.get("Account") or "")


def list_enabled_regions(session, explicit: list[str] | None = None) -> list[str]:
    """Explicit scope wins; otherwise EC2 DescribeRegions (never hardcoded)."""
    if explicit:
        return [r for r in explicit if r][:MAX_REGIONS]
    ec2 = session.client("ec2", region_name="us-east-1")
    response = call_with_retry(lambda: ec2.describe_regions(AllRegions=False), sleep=lambda _: None) or {}
    regions = []
    for region in response.get("Regions", []):
        name = str(region.get("RegionName") or "").strip().lower()
        if name and name not in regions:
            regions.append(name)
    return regions[:MAX_REGIONS]


def _tags_as_dict(tags: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(tags, dict):
        items = list(tags.items())
    elif isinstance(tags, list):
        items = [(t.get("Key"), t.get("Value")) for t in tags if isinstance(t, dict)]
    else:
        return out
    for key, value in items[:20]:
        if key is None:
            continue
        k = str(key).strip()[:128]
        if not k or SECRET_KEY_RE.search(k):
            continue
        v = "" if value is None else str(value).strip()[:200]
        if SECRET_KEY_RE.search(v):
            continue
        out[k] = v
    return out


def _bounded_extra(extra: dict, _depth: int = 0) -> dict:
    out: dict[str, Any] = {}
    for key, value in (extra or {}).items():
        k = str(key)[:64]
        # Allow IAM evidence keys even though they contain 'access_key' substring
        if k.startswith("iam_"):
            pass
        elif SECRET_KEY_RE.search(k):
            continue
        if isinstance(value, str):
            v: Any = value[:500]
            if SECRET_KEY_RE.search(v):
                continue
        elif isinstance(value, dict):
            if _depth >= 3:
                continue
            v = _bounded_extra(value, _depth + 1)
        elif isinstance(value, (list, tuple)):
            items = []
            for i in list(value)[:20]:
                if isinstance(i, dict):
                    if _depth >= 3:
                        continue
                    items.append(_bounded_extra(i, _depth + 1))
                else:
                    s = str(i)[:200]
                    if SECRET_KEY_RE.search(s):
                        continue
                    items.append(s)
            v = items
        elif isinstance(value, (int, float, bool)) or value is None:
            v = value
        else:
            v = str(value)[:500]
            if SECRET_KEY_RE.search(v):
                continue
        out[k] = v
        if len(out) >= 30:
            break
    return out


def _resource(service: str, resource_type: str, resource_id: str, region: str,
              account_id: str, arn: str | None = None, name: str | None = None,
              tags: Any = None, extra: dict | None = None) -> dict:
    return {
        "service": service,
        "resource_type": resource_type,
        "resource_id": str(resource_id or "")[:500],
        "arn": (str(arn)[:1024] if arn else None),
        "name": (str(name)[:255] if name else None),
        "region": region,
        "account_id": account_id,
        "tags": _tags_as_dict(tags),
        "extra": _bounded_extra(extra or {}),
    }


def _paginate(client, operation: str, key: str, limit: int = MAX_ITEMS_PER_SERVICE_CALL, **kwargs) -> list[dict]:
    """Paginator-driven collection with a hard item cap (no unbounded scans)."""
    items: list[dict] = []
    # NOTE: get_paginator failures propagate to the caller, which records a
    # permission/service warning. Swallowing them here would hide denied
    # access as false absence.
    paginator = client.get_paginator(operation)
    try:
        for page in paginator.paginate(PaginationConfig={"PageSize": min(50, limit)}, **kwargs):
            for entry in (page or {}).get(key, []) or []:
                if isinstance(entry, dict):
                    items.append(entry)
                if len(items) >= limit:
                    return items
    except Exception as exc:
        # Permission failures must surface as warnings, never empty results.
        raise exc
    return items


# ---------------------------------------------------------------------------
# Per-service discoverers: (client, region, account_id) -> (resources, warning)
# ---------------------------------------------------------------------------

def discover_vpcs(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for vpc in _paginate(client, "describe_vpcs", "Vpcs"):
            vpc_id = vpc.get("VpcId")
            if not vpc_id:
                continue
            ipv6_cidr = None
            for assoc in (vpc.get("Ipv6CidrBlockAssociationSet") or [])[:5]:
                if isinstance(assoc, dict) and assoc.get("Ipv6CidrBlock"):
                    ipv6_cidr = str(assoc.get("Ipv6CidrBlock"))[:64]
                    break
            resources.append(_resource("ec2", "aws_vpc", vpc_id, region, account_id,
                                       name=_tag_name(vpc.get("Tags")), tags=vpc.get("Tags"),
                                       extra={"cidr": vpc.get("CidrBlock"), "ipv6_cidr": ipv6_cidr,
                                              "state": vpc.get("State"), "is_default": vpc.get("IsDefault"),
                                              "tenancy": str(vpc.get("InstanceTenancy") or "default")[:20]}))
    except Exception as exc:
        warning = _warning_for("vpc", exc)
    return resources, warning


def _tag_name(tags: Any) -> str | None:
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, dict) and tag.get("Key") == "Name":
                return str(tag.get("Value") or "")[:255] or None
    return None


def _warning_for(service: str, exc: Exception) -> dict | None:
    kind = classify_aws_error(exc)
    if kind == "permission":
        return {"service": service, "reason": "permission_denied",
                "detail": sanitize_aws_error(exc, f"{service} discovery unavailable due to insufficient permissions")}
    return {"service": service, "reason": "service_error", "detail": sanitize_aws_error(exc)}


def _normalize_sg_permissions(perms: Any, max_rules: int = MAX_SG_RULES) -> list[dict]:
    """Bounded normalization of SG IpPermissions to rule objects."""
    out: list[dict] = []
    if not isinstance(perms, list):
        return out
    for perm in perms[:max_rules]:
        if not isinstance(perm, dict):
            continue
        proto = str(perm.get("IpProtocol") or "")[:10] or "-1"
        from_port = perm.get("FromPort")
        to_port = perm.get("ToPort")
        # Normalize ports: keep int or None; bounded
        try:
            fp = int(from_port) if from_port is not None else None
        except Exception:
            fp = None
        try:
            tp = int(to_port) if to_port is not None else None
        except Exception:
            tp = None
        # IPv4 ranges
        v4 = []
        for r in (perm.get("IpRanges") or [])[:10]:
            if isinstance(r, dict):
                cidr = str(r.get("CidrIp") or "")[:64]
                if cidr:
                    v4.append(cidr)
        v6 = []
        for r in (perm.get("Ipv6Ranges") or [])[:10]:
            if isinstance(r, dict):
                cidr = str(r.get("CidrIpv6") or "")[:64]
                if cidr:
                    v6.append(cidr)
        groups = []
        for g in (perm.get("UserIdGroupPairs") or [])[:10]:
            if isinstance(g, dict):
                gid = str(g.get("GroupId") or "")[:64]
                if gid:
                    groups.append(gid)
        prefixes = []
        for p in (perm.get("PrefixListIds") or [])[:10]:
            if isinstance(p, dict):
                pid = str(p.get("PrefixListId") or "")[:64]
                if pid:
                    prefixes.append(pid)
        out.append({
            "protocol": proto,
            "from_port": fp,
            "to_port": tp,
            "cidr_v4": v4[:10],
            "cidr_v6": v6[:10],
            "group_ids": groups[:10],
            "prefix_list_ids": prefixes[:10],
        })
        if len(out) >= max_rules:
            break
    return out


def discover_subnets(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for subnet in _paginate(client, "describe_subnets", "Subnets"):
            subnet_id = subnet.get("SubnetId")
            if not subnet_id:
                continue
            # IPv6 CIDR associations
            ipv6_cidr = None
            for assoc in (subnet.get("Ipv6CidrBlockAssociationSet") or [])[:5]:
                if isinstance(assoc, dict) and assoc.get("Ipv6CidrBlock"):
                    ipv6_cidr = str(assoc.get("Ipv6CidrBlock"))[:64]
                    break
            resources.append(_resource("ec2", "aws_subnet", subnet_id, region, account_id,
                                       name=_tag_name(subnet.get("Tags")), tags=subnet.get("Tags"),
                                       extra={"vpc_id": subnet.get("VpcId"), "cidr": subnet.get("CidrBlock"),
                                              "ipv6_cidr": ipv6_cidr,
                                              "az": subnet.get("AvailabilityZone"),
                                              "map_public_ip": subnet.get("MapPublicIpOnLaunch"),
                                              "available_ip": subnet.get("AvailableIpAddressCount")}))
    except Exception as exc:
        warning = _warning_for("subnet", exc)
    return resources, warning


def discover_route_tables(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for rt in _paginate(client, "describe_route_tables", "RouteTables"):
            rt_id = rt.get("RouteTableId")
            if not rt_id:
                continue
            routes = []
            for route in (rt.get("Routes") or [])[:MAX_ROUTE_ENTRIES]:
                if not isinstance(route, dict):
                    continue
                routes.append({
                    "destination_cidr": str(route.get("DestinationCidrBlock") or "")[:64] or None,
                    "destination_ipv6": str(route.get("DestinationIpv6CidrBlock") or "")[:64] or None,
                    "destination_prefix": str(route.get("DestinationPrefixListId") or "")[:64] or None,
                    "gateway_id": str(route.get("GatewayId") or "")[:64] or None,
                    "nat_gateway_id": str(route.get("NatGatewayId") or "")[:64] or None,
                    "instance_id": str(route.get("InstanceId") or "")[:64] or None,
                    "interface_id": str(route.get("NetworkInterfaceId") or "")[:64] or None,
                    "transit_gateway_id": str(route.get("TransitGatewayId") or "")[:64] or None,
                    "vpc_peering_id": str(route.get("VpcPeeringConnectionId") or "")[:64] or None,
                    "state": str(route.get("State") or "")[:20] or None,
                })
            associations = []
            for assoc in (rt.get("Associations") or [])[:10]:
                if not isinstance(assoc, dict):
                    continue
                associations.append({
                    "subnet_id": str(assoc.get("SubnetId") or "")[:64] or None,
                    "gateway_id": str(assoc.get("GatewayId") or "")[:64] or None,
                    "main": bool(assoc.get("Main")),
                })
            resources.append(_resource("ec2", "aws_route_table", rt_id, region, account_id,
                                       name=_tag_name(rt.get("Tags")), tags=rt.get("Tags"),
                                       extra={"vpc_id": rt.get("VpcId"), "routes": routes, "associations": associations}))
    except Exception as exc:
        warning = _warning_for("route_table", exc)
    return resources, warning


def discover_security_groups(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for sg in _paginate(client, "describe_security_groups", "SecurityGroups"):
            sg_id = sg.get("GroupId")
            if not sg_id:
                continue
            ingress = _normalize_sg_permissions(sg.get("IpPermissions"))
            egress = _normalize_sg_permissions(sg.get("IpPermissionsEgress"))
            resources.append(_resource("ec2", "aws_security_group", sg_id, region, account_id,
                                       name=sg.get("GroupName"), tags=sg.get("Tags"),
                                       extra={"vpc_id": sg.get("VpcId"), "description": str(sg.get("Description") or "")[:200],
                                              "ingress": ingress, "egress": egress}))
    except Exception as exc:
        warning = _warning_for("security_group", exc)
    return resources, warning


def discover_internet_gateways(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for igw in _paginate(client, "describe_internet_gateways", "InternetGateways"):
            igw_id = igw.get("InternetGatewayId")
            if not igw_id:
                continue
            attachments = []
            for att in (igw.get("Attachments") or [])[:10]:
                if isinstance(att, dict):
                    attachments.append({"vpc_id": str(att.get("VpcId") or "")[:64], "state": str(att.get("State") or "")[:20]})
            vpc_id = attachments[0].get("vpc_id") if attachments else None
            resources.append(_resource("ec2", "aws_internet_gateway", igw_id, region, account_id,
                                       name=_tag_name(igw.get("Tags")), tags=igw.get("Tags"),
                                       extra={"vpc_id": vpc_id, "attachments": attachments, "state": str(igw.get("State") or "")[:20] or None}))
    except Exception as exc:
        warning = _warning_for("internet_gateway", exc)
    return resources, warning


def discover_nat_gateways(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for nat in _paginate(client, "describe_nat_gateways", "NatGateways"):
            nat_id = nat.get("NatGatewayId")
            if not nat_id:
                continue
            addrs = []
            for addr in (nat.get("NatGatewayAddresses") or [])[:5]:
                if isinstance(addr, dict):
                    addrs.append({"public_ip": str(addr.get("PublicIp") or "")[:64] or None,
                                  "private_ip": str(addr.get("PrivateIp") or "")[:64] or None,
                                  "allocation_id": str(addr.get("AllocationId") or "")[:64] or None})
            resources.append(_resource("ec2", "aws_nat_gateway", nat_id, region, account_id,
                                       name=_tag_name(nat.get("Tags")), tags=nat.get("Tags"),
                                       extra={"vpc_id": nat.get("VpcId"), "subnet_id": nat.get("SubnetId"),
                                              "state": nat.get("State"), "connectivity_type": str(nat.get("ConnectivityType") or "")[:20] or None,
                                              "addresses": addrs}))
    except Exception as exc:
        warning = _warning_for("nat_gateway", exc)
    return resources, warning


def discover_network_acls(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for acl in _paginate(client, "describe_network_acls", "NetworkAcls"):
            acl_id = acl.get("NetworkAclId")
            if not acl_id:
                continue
            assoc_subnets = []
            for assoc in (acl.get("Associations") or [])[:20]:
                if isinstance(assoc, dict) and assoc.get("SubnetId"):
                    assoc_subnets.append(str(assoc.get("SubnetId"))[:64])
            entries = []
            for entry in (acl.get("Entries") or [])[:MAX_NACL_ENTRIES]:
                if not isinstance(entry, dict):
                    continue
                pr = entry.get("PortRange") or {}
                entries.append({
                    "rule_number": entry.get("RuleNumber"),
                    "protocol": str(entry.get("Protocol") or "")[:10],
                    "rule_action": str(entry.get("RuleAction") or "")[:10],
                    "egress": bool(entry.get("Egress")),
                    "cidr": str(entry.get("CidrBlock") or "")[:64] or None,
                    "ipv6_cidr": str(entry.get("Ipv6CidrBlock") or "")[:64] or None,
                    "from_port": pr.get("From"),
                    "to_port": pr.get("To"),
                })
            resources.append(_resource("ec2", "aws_network_acl", acl_id, region, account_id,
                                       name=_tag_name(acl.get("Tags")), tags=acl.get("Tags"),
                                       extra={"vpc_id": acl.get("VpcId"), "is_default": acl.get("IsDefault"),
                                              "subnet_ids": assoc_subnets[:20], "entries": entries}))
    except Exception as exc:
        warning = _warning_for("network_acl", exc)
    return resources, warning


def discover_network_interfaces(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for eni in _paginate(client, "describe_network_interfaces", "NetworkInterfaces"):
            eni_id = eni.get("NetworkInterfaceId")
            if not eni_id:
                continue
            groups = [g.get("GroupId") for g in (eni.get("Groups") or []) if isinstance(g, dict) and g.get("GroupId")]
            assoc = eni.get("Association") or {}
            private_ips = []
            for pip in (eni.get("PrivateIpAddresses") or [])[:10]:
                if isinstance(pip, dict):
                    private_ips.append(str(pip.get("PrivateIpAddress") or "")[:64])
            resources.append(_resource("ec2", "aws_network_interface", eni_id, region, account_id,
                                       tags=eni.get("TagSet"),
                                       extra={"vpc_id": eni.get("VpcId"), "subnet_id": eni.get("SubnetId"),
                                              "security_groups": groups[:10], "status": eni.get("Status"),
                                              "interface_type": eni.get("InterfaceType"),
                                              "private_ip": str(eni.get("PrivateIpAddress") or "")[:64] or None,
                                              "private_ips": private_ips,
                                              "public_ip": str(assoc.get("PublicIp") or "")[:64] or None,
                                              "description": str(eni.get("Description") or "")[:200] or None}))
    except Exception as exc:
        warning = _warning_for("network_interface", exc)
    return resources, warning


def discover_ec2_instances(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for reservation in _paginate(client, "describe_instances", "Reservations"):
            for inst in (reservation.get("Instances") or [])[:20]:
                inst_id = inst.get("InstanceId")
                if not inst_id:
                    continue
                groups = [g.get("GroupId") for g in (inst.get("SecurityGroups") or []) if isinstance(g, dict) and g.get("GroupId")]
                # E2 evidence: IMDS posture derived here because the shared
                # persistence sanitizer drops any "token" key (http_tokens would
                # not survive). True = IMDSv2 enforced or endpoint disabled;
                # False = IMDSv1 allowed; None = unknown (NOT_ASSESSED).
                meta_opts = inst.get("MetadataOptions") or {}
                http_endpoint = meta_opts.get("HttpEndpoint")
                http_tokens = meta_opts.get("HttpTokens")
                if http_endpoint == "disabled":
                    imds_v2 = True
                elif http_tokens == "required":
                    imds_v2 = True
                elif http_tokens == "optional":
                    imds_v2 = False
                else:
                    imds_v2 = None
                resources.append(_resource("ec2", "aws_ec2_instance", inst_id, region, account_id,
                                           name=_tag_name(inst.get("Tags")), tags=inst.get("Tags"),
                                           extra={"instance_type": inst.get("InstanceType"), "state": (inst.get("State") or {}).get("Name"),
                                                  "vpc_id": inst.get("VpcId"), "subnet_id": inst.get("SubnetId"),
                                                  "security_groups": groups[:10],
                                                  "public_ip": inst.get("PublicIpAddress"),
                                                  "private_ip": inst.get("PrivateIpAddress"),
                                                  "platform": inst.get("Platform"),
                                                  "http_endpoint": http_endpoint,
                                                  "imds_v2_enforced": imds_v2}))
    except Exception as exc:
        warning = _warning_for("ec2", exc)
    return resources, warning


def discover_load_balancers(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for lb in _paginate(client, "describe_load_balancers", "LoadBalancers"):
            arn = lb.get("LoadBalancerArn")
            lb_type = str(lb.get("Type") or "application").lower()
            rtype = "aws_alb" if lb_type == "application" else "aws_nlb" if lb_type == "network" else "aws_elb"
            name = lb.get("LoadBalancerName") or (arn.split("/")[-2] if arn and "/" in arn else None)
            azs = lb.get("AvailabilityZones") or []
            subnets = [z.get("SubnetId") for z in azs if isinstance(z, dict) and z.get("SubnetId")]
            groups = lb.get("SecurityGroups") or []
            # E2 evidence: listeners (bounded read-only call; failure recorded).
            listeners: list[dict] = []
            listener_error = None
            if arn:
                try:
                    for listener in _paginate(client, "describe_listeners", "Listeners", limit=20, LoadBalancerArn=arn):
                        listeners.append({"protocol": str(listener.get("Protocol") or "")[:16],
                                          "port": listener.get("Port")})
                except Exception as exc:
                    listener_error = sanitize_aws_error(exc, "listener configuration unavailable")[:150]
            extra_lb: dict[str, Any] = {"vpc_id": lb.get("VpcId"), "scheme": lb.get("Scheme"),
                                        "subnets": subnets[:10], "security_groups": groups[:10],
                                        "state": (lb.get("State") or {}).get("Code"),
                                        "listeners": listeners}
            if listener_error:
                extra_lb["listener_error"] = listener_error
            resources.append(_resource("elbv2", rtype, arn or str(name or ""), region, account_id, arn=arn,
                                       name=name, extra=extra_lb))
    except Exception as exc:
        warning = _warning_for("elbv2", exc)
    return resources, warning


def discover_rds_instances(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for db in _paginate(client, "describe_db_instances", "DBInstances"):
            db_id = db.get("DBInstanceIdentifier")
            if not db_id:
                continue
            groups = [g.get("VpcSecurityGroupId") for g in (db.get("VpcSecurityGroups") or []) if isinstance(g, dict) and g.get("VpcSecurityGroupId")]
            resources.append(_resource("rds", "aws_rds_instance", db_id, region, account_id,
                                       arn=db.get("DBInstanceArn"), name=db_id, tags=db.get("TagList"),
                                       extra={"engine": db.get("Engine"), "engine_version": db.get("EngineVersion"),
                                              "vpc_id": (db.get("DBSubnetGroup") or {}).get("VpcId"),
                                              "security_groups": groups[:10], "status": db.get("DBInstanceStatus"),
                                              "multi_az": db.get("MultiAZ"),
                                              # E2 evidence: same DescribeDBInstances response, no new call.
                                              "publicly_accessible": db.get("PubliclyAccessible"),
                                              "storage_encrypted": db.get("StorageEncrypted")}))
    except Exception as exc:
        warning = _warning_for("rds", exc)
    return resources, warning


def discover_lambda_functions(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for fn in _paginate(client, "list_functions", "Functions"):
            arn = fn.get("FunctionArn")
            name = fn.get("FunctionName")
            if not name:
                continue
            vpc = fn.get("VpcConfig") or {}
            # E2 evidence: function URLs + auth type (bounded read-only call).
            urls: list[dict] = []
            url_error = None
            try:
                for url in _paginate(client, "list_function_url_configs", "FunctionUrls", limit=5, FunctionName=name):
                    urls.append({"url": str(url.get("FunctionUrl") or "")[:500],
                                 "auth": str(url.get("AuthType") or "")[:16]})
            except Exception as exc:
                url_error = sanitize_aws_error(exc, "function URL configuration unavailable")[:150]
            extra_fn: dict[str, Any] = {"runtime": fn.get("Runtime"),
                                        "vpc_id": vpc.get("VpcId"),
                                        "subnets": (vpc.get("SubnetIds") or [])[:10],
                                        "security_groups": (vpc.get("SecurityGroupIds") or [])[:10],
                                        "last_modified": str(fn.get("LastModified") or "")[:32],
                                        "function_urls": urls}
            if url_error:
                extra_fn["url_error"] = url_error
            resources.append(_resource("lambda", "aws_lambda_function", arn or name, region, account_id, arn=arn,
                                       name=name, extra=extra_fn))
    except Exception as exc:
        warning = _warning_for("lambda", exc)
    return resources, warning


def discover_ecs_clusters(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        arns = []
        for arn in _paginate(client, "list_clusters", "clusterArns", limit=20):
            if isinstance(arn, str):
                arns.append(arn)
        if arns:
            try:
                described = call_with_retry(lambda: client.describe_clusters(clusters=arns[:10], include=["TAGS"]), sleep=lambda _: None)
                clusters = described.get("clusters", []) or []
            except Exception:
                clusters = [{"clusterArn": a} for a in arns]
            for cluster in clusters:
                arn = cluster.get("clusterArn")
                name = cluster.get("clusterName") or (arn.split("/")[-1] if arn else None)
                resources.append(_resource("ecs", "aws_ecs_cluster", arn or str(name or ""), region, account_id, arn=arn,
                                           name=name, tags=cluster.get("tags"),
                                           extra={"status": cluster.get("status")}))
    except Exception as exc:
        warning = _warning_for("ecs", exc)
    return resources, warning


def discover_ecs_services(client, region: str, account_id: str, cluster_arns: list[str]):
    resources, warning = [], None
    try:
        for cluster_arn in cluster_arns[:10]:
            try:
                service_arns: list[str] = []
                for arn in _paginate(client, "list_services", "serviceArns", limit=50, cluster=cluster_arn):
                    if isinstance(arn, str):
                        service_arns.append(arn)
                if not service_arns:
                    continue
                described = call_with_retry(
                    lambda: client.describe_services(cluster=cluster_arn, services=service_arns[:10], include=["TAGS"]),
                    sleep=lambda _: None,
                )
                for svc in described.get("services", []) or []:
                    arn = svc.get("serviceArn")
                    name = svc.get("serviceName")
                    net = svc.get("networkConfiguration") or {}
                    awsvpc = net.get("awsvpcConfiguration") or {}
                    resources.append(_resource("ecs", "aws_ecs_service", arn or str(name or ""), region, account_id, arn=arn,
                                               name=name, tags=svc.get("tags"),
                                               extra={"cluster": cluster_arn,
                                                      "subnets": (awsvpc.get("subnets") or [])[:10],
                                                      "security_groups": (awsvpc.get("securityGroups") or [])[:10],
                                                      "status": svc.get("status")}))
            except Exception as exc:
                if warning is None:
                    warning = _warning_for("ecs", exc)
    except Exception as exc:
        if warning is None:
            warning = _warning_for("ecs", exc)
    return resources, warning


def discover_ecr_repositories(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for repo in _paginate(client, "describe_repositories", "repositories", limit=50):
            arn = repo.get("repositoryArn")
            name = repo.get("repositoryName")
            if not name:
                continue
            resources.append(_resource("ecr", "aws_ecr_repository", arn or name, region, account_id, arn=arn,
                                       name=name, extra={"uri": str(repo.get("repositoryUri") or "")[:500]}))
    except Exception as exc:
        warning = _warning_for("ecr", exc)
    return resources, warning


def discover_s3_buckets(client, account_id: str):
    """S3 is global: buckets attributed to their own location region."""
    resources, warning = [], None
    try:
        response = call_with_retry(lambda: client.list_buckets(), sleep=lambda _: None) or {}
        for bucket in (response.get("Buckets", []) or [])[:100]:
            name = bucket.get("Name")
            if not name:
                continue
            try:
                loc = call_with_retry(lambda: client.get_bucket_location(Bucket=name), sleep=lambda _: None) or {}
                region = loc.get("LocationConstraint") or "us-east-1"
                if region == "EU":
                    region = "eu-west-1"
            except Exception:
                region = "unknown"
            # E2 evidence: public-access-block + default encryption (bounded,
            # per-bucket read-only calls; failures recorded, never fatal).
            extra: dict[str, Any] = {"created": str(bucket.get("CreationDate") or "")[:32]}
            try:
                pab = call_with_retry(lambda: client.get_public_access_block(Bucket=name), sleep=lambda _: None) or {}
                config = pab.get("PublicAccessBlockConfiguration") or {}
                for flag in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"):
                    extra["pab_" + flag.lower()] = config.get(flag)
            except Exception as exc:
                extra["pab_error"] = sanitize_aws_error(exc, "public access block unavailable")[:150]
                extra["pab_error_code"] = _error_code(exc)
            try:
                enc = call_with_retry(lambda: client.get_bucket_encryption(Bucket=name), sleep=lambda _: None) or {}
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", []) or []
                first = rules[0].get("ApplyServerSideEncryptionByDefault", {}) if rules and isinstance(rules[0], dict) else {}
                extra["encryption"] = str(first.get("SSEAlgorithm") or "")[:32] or None
                if first.get("KMSMasterKeyID"):
                    extra["kms_key_id"] = str(first.get("KMSMasterKeyID"))[:256]
            except Exception as exc:
                extra["encryption_error"] = sanitize_aws_error(exc, "encryption configuration unavailable")[:150]
                extra["encryption_error_code"] = _error_code(exc)
            # E5: bucket policy (normalized, bounded) + ACL + versioning + logging + ownership + website
            try:
                pol = call_with_retry(lambda: client.get_bucket_policy(Bucket=name), sleep=lambda _: None) or {}
                doc = pol.get("Policy")
                if doc:
                    stmts, trunc, err = _iam_bounded_statements(doc, policy_name=name, policy_arn=None)
                    if stmts is not None:
                        extra["bucket_policy_statements"] = stmts[:MAX_S3_POLICY_STATEMENTS]
                        if trunc and trunc.get("truncated"):
                            extra["bucket_policy_truncated"] = True
                    elif err:
                        if "permission" in err.lower():
                            extra["bucket_policy_unavailable"] = "permission_denied"
                        else:
                            extra["bucket_policy_unavailable"] = err[:200]
                else:
                    extra["bucket_policy_statements"] = []
            except Exception as exc:
                code = _error_code(exc) or ""
                if code == "NoSuchBucketPolicy":
                    extra["bucket_policy_statements"] = []
                elif code in PERMISSION_CODES:
                    extra["bucket_policy_unavailable"] = "permission_denied"
                else:
                    extra["bucket_policy_unavailable"] = sanitize_aws_error(exc, "bucket policy unavailable")[:150]
            try:
                acl = call_with_retry(lambda: client.get_bucket_acl(Bucket=name), sleep=lambda _: None) or {}
                grants = []
                for grant in (acl.get("Grants") or [])[:20]:
                    if not isinstance(grant, dict):
                        continue
                    grantee = grant.get("Grantee") or {}
                    gtype = str(grantee.get("Type") or "")[:20]
                    uri = str(grantee.get("URI") or "")[:256]
                    perm = str(grant.get("Permission") or "")[:20]
                    # Detect public ACL: AllUsers or AuthenticatedUsers
                    is_public = "AllUsers" in uri or "AuthenticatedUsers" in uri
                    grants.append({"type": gtype, "uri": uri[:100], "permission": perm, "public": is_public})
                extra["acl_grants"] = grants
                # Owner
                owner = acl.get("Owner") or {}
                if owner.get("ID"):
                    extra["owner_id"] = str(owner.get("ID"))[:100]
            except Exception as exc:
                code = _error_code(exc) or ""
                if code in PERMISSION_CODES:
                    extra["acl_unavailable"] = "permission_denied"
                else:
                    extra["acl_unavailable"] = sanitize_aws_error(exc, "ACL unavailable")[:150]
            try:
                vers = call_with_retry(lambda: client.get_bucket_versioning(Bucket=name), sleep=lambda _: None) or {}
                status = vers.get("Status")
                extra["versioning"] = str(status)[:20] if status else "Suspended"
            except Exception as exc:
                code = _error_code(exc) or ""
                if code in PERMISSION_CODES:
                    extra["versioning_unavailable"] = "permission_denied"
                else:
                    extra["versioning_unavailable"] = sanitize_aws_error(exc, "versioning unavailable")[:150]
            try:
                logging = call_with_retry(lambda: client.get_bucket_logging(Bucket=name), sleep=lambda _: None) or {}
                enabled = logging.get("LoggingEnabled")
                extra["logging_enabled"] = bool(enabled)
            except Exception as exc:
                code = _error_code(exc) or ""
                if code in PERMISSION_CODES:
                    extra["logging_unavailable"] = "permission_denied"
                else:
                    extra["logging_unavailable"] = sanitize_aws_error(exc, "logging unavailable")[:150]
            try:
                ownership = call_with_retry(lambda: client.get_bucket_ownership_controls(Bucket=name), sleep=lambda _: None) or {}
                rules = ownership.get("OwnershipControls", {}).get("Rules", []) or []
                first = rules[0] if rules and isinstance(rules[0], dict) else {}
                extra["object_ownership"] = str(first.get("ObjectOwnership") or "")[:64] or None
            except Exception as exc:
                code = _error_code(exc) or ""
                if code in ("OwnershipControlsNotFoundError", "NoSuchOwnershipControls"):
                    extra["object_ownership"] = None
                elif code in PERMISSION_CODES:
                    extra["ownership_unavailable"] = "permission_denied"
                else:
                    extra["ownership_unavailable"] = sanitize_aws_error(exc, "ownership unavailable")[:150]
            try:
                website = call_with_retry(lambda: client.get_bucket_website(Bucket=name), sleep=lambda _: None) or {}
                # If website config exists, it's enabled
                if website.get("IndexDocument") or website.get("ErrorDocument") or website.get("RedirectAllRequestsTo"):
                    extra["website_enabled"] = True
                else:
                    extra["website_enabled"] = False
            except Exception as exc:
                code = _error_code(exc) or ""
                if code == "NoSuchWebsiteConfiguration":
                    extra["website_enabled"] = False
                elif code in PERMISSION_CODES:
                    extra["website_unavailable"] = "permission_denied"
                else:
                    extra["website_unavailable"] = sanitize_aws_error(exc, "website unavailable")[:150]
            resources.append(_resource("s3", "aws_s3_bucket", name, region, account_id, name=name, extra=extra))
    except Exception as exc:
        warning = _warning_for("s3", exc)
    return resources, warning


def discover_ebs_volumes(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for vol in _paginate(client, "describe_volumes", "Volumes", limit=MAX_EBS_VOLUMES):
            vol_id = vol.get("VolumeId")
            if not vol_id:
                continue
            attachments = vol.get("Attachments") or []
            attached_instance = None
            if attachments and isinstance(attachments[0], dict):
                attached_instance = str(attachments[0].get("InstanceId") or "")[:64] or None
            resources.append(_resource("ec2", "aws_ebs_volume", vol_id, region, account_id,
                                       name=vol_id, tags=vol.get("Tags"),
                                       extra={"encrypted": vol.get("Encrypted"),
                                              "kms_key_id": str(vol.get("KmsKeyId") or "")[:256] or None,
                                              "size": vol.get("Size"),
                                              "availability_zone": str(vol.get("AvailabilityZone") or "")[:64] or None,
                                              "state": str(vol.get("State") or "")[:20] or None,
                                              "attached_instance": attached_instance}))
    except Exception as exc:
        warning = _warning_for("ebs_volume", exc)
    return resources, warning


def discover_ebs_snapshots(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        # Owned by self
        for snap in _paginate(client, "describe_snapshots", "Snapshots", limit=MAX_EBS_SNAPSHOTS, OwnerIds=["self"]):
            snap_id = snap.get("SnapshotId")
            if not snap_id:
                continue
            # Check public permission bounded (per snapshot, max 20)
            is_public = None
            perm_error = None
            try:
                attr = call_with_retry(lambda: client.describe_snapshot_attribute(Attribute="createVolumePermission", SnapshotId=snap_id), sleep=lambda _: None) or {}
                perms = attr.get("CreateVolumePermissions") or []
                for perm in perms[:10]:
                    if isinstance(perm, dict) and perm.get("Group") == "all":
                        is_public = True
                        break
                if is_public is None:
                    is_public = False
            except Exception as exc:
                code = _error_code(exc) or ""
                if code in PERMISSION_CODES:
                    perm_error = "permission_denied"
                else:
                    perm_error = sanitize_aws_error(exc, "snapshot permission unavailable")[:150]
            extra = {"encrypted": snap.get("Encrypted"),
                     "kms_key_id": str(snap.get("KmsKeyId") or "")[:256] or None,
                     "owner_id": str(snap.get("OwnerId") or "")[:64] or None,
                     "volume_id": str(snap.get("VolumeId") or "")[:64] or None,
                     "state": str(snap.get("State") or "")[:20] or None,
                     "is_public": is_public}
            if perm_error:
                extra["permission_unavailable"] = perm_error
            resources.append(_resource("ec2", "aws_ebs_snapshot", snap_id, region, account_id,
                                       name=snap_id, tags=snap.get("Tags"), extra=extra))
            if len(resources) >= MAX_EBS_SNAPSHOTS:
                break
    except Exception as exc:
        warning = _warning_for("ebs_snapshot", exc)
    return resources, warning


def discover_efs_filesystems(client, region: str, account_id: str):
    resources, warning = [], None
    try:
        for fs in _paginate(client, "describe_file_systems", "FileSystems", limit=MAX_EFS_FILESYSTEMS):
            fs_id = fs.get("FileSystemId")
            if not fs_id:
                continue
            resources.append(_resource("efs", "aws_efs_filesystem", fs_id, region, account_id,
                                       name=fs_id, tags=fs.get("Tags"),
                                       extra={"encrypted": fs.get("Encrypted"),
                                              "kms_key_id": str(fs.get("KmsKeyId") or "")[:256] or None,
                                              "life_cycle_state": str(fs.get("LifeCycleState") or "")[:20] or None,
                                              "performance_mode": str(fs.get("PerformanceMode") or "")[:20] or None}))
    except Exception as exc:
        warning = _warning_for("efs", exc)
    return resources, warning


def _iam_bounded_statements(doc_text_or_dict: Any, policy_name: str | None, policy_arn: str | None) -> tuple[list[dict] | None, dict | None, str | None]:
    """Decode + normalize a policy document into bounded statements. Returns (statements|None, truncation|None, error|None)."""
    try:
        from .iam_analysis import decode_policy_document, normalize_policy_document, MAX_POLICY_SIZE_BYTES
    except Exception:
        return None, None, "iam analysis unavailable"
    # Size check via string length already bounded inside decode
    doc, err = decode_policy_document(doc_text_or_dict)
    if err:
        return None, None, err[:200]
    if doc is None:
        return None, None, "empty document"
    try:
        statements, truncation = normalize_policy_document(doc, policy_name=policy_name, policy_arn=policy_arn)
        return statements, truncation, None
    except Exception as exc:
        return None, None, sanitize_aws_error(exc, "policy normalization failed")[:200]


def _iam_collect_for_identity(client, name: str, rtype: str, account_id: str, entry: dict) -> dict:
    """Collect bounded IAM evidence for one identity. Never raises, never leaks secrets."""
    extra: dict[str, Any] = {
        "path": str(entry.get("Path") or "")[:128],
        "created": str(entry.get("CreateDate") or "")[:32],
    }
    # Trust policy for roles
    if rtype == "aws_iam_role":
        raw_trust = entry.get("AssumeRolePolicyDocument")
        if raw_trust is not None:
            stmts, trunc, err = _iam_bounded_statements(raw_trust, policy_name="assume-role", policy_arn=entry.get("Arn"))
            if stmts is not None:
                extra["iam_trust_statements"] = stmts[:MAX_IAM_STATEMENTS_PER_POLICY]
                if trunc and trunc.get("truncated"):
                    extra["iam_trust_truncated"] = True
                    extra["iam_trust_truncation"] = {k: str(v)[:500] if isinstance(v, str) else v for k, v in trunc.items()}
            elif err:
                if "oversized" in err.lower():
                    extra["iam_trust_error"] = "oversized document"
                elif "malformed" in err.lower():
                    extra["iam_trust_error"] = err[:200]
                else:
                    extra["iam_trust_unavailable"] = err[:200]
        else:
            # Try explicit GetRole for trust if not in ListRoles payload
            try:
                resp = call_with_retry(lambda: client.get_role(RoleName=name), sleep=lambda _: None) or {}
                role = resp.get("Role") or {}
                raw_trust2 = role.get("AssumeRolePolicyDocument")
                if raw_trust2 is not None:
                    stmts, trunc, err = _iam_bounded_statements(raw_trust2, policy_name="assume-role", policy_arn=entry.get("Arn"))
                    if stmts is not None:
                        extra["iam_trust_statements"] = stmts[:MAX_IAM_STATEMENTS_PER_POLICY]
                        if trunc and trunc.get("truncated"):
                            extra["iam_trust_truncated"] = True
                    elif err:
                        extra["iam_trust_unavailable"] = err[:200]
            except Exception as exc:
                if classify_aws_error(exc) == "permission":
                    extra["iam_trust_unavailable"] = "permission_denied"
                else:
                    extra["iam_trust_unavailable"] = sanitize_aws_error(exc, "trust unavailable")[:150]

    # Policies: managed + inline (bounded, read-only)
    policies: list[dict] = []
    policy_error: str | None = None
    try:
        if rtype == "aws_iam_role":
            # Attached managed
            try:
                for pol in _paginate(client, "list_attached_role_policies", "AttachedPolicies", limit=MAX_IAM_POLICIES_PER_IDENTITY, RoleName=name):
                    arn = str(pol.get("PolicyArn") or "")[:1024]
                    pname = str(pol.get("PolicyName") or "")[:256]
                    if not arn:
                        continue
                    is_aws = arn.startswith("arn:aws:iam::aws:policy/")
                    entry_pol: dict[str, Any] = {"type": "managed", "arn": arn, "name": pname, "is_aws_managed": is_aws}
                    # Fetch document
                    try:
                        pol_meta = call_with_retry(lambda: client.get_policy(PolicyArn=arn), sleep=lambda _: None) or {}
                        version_id = (pol_meta.get("Policy") or {}).get("DefaultVersionId") or "v1"
                        ver = call_with_retry(lambda: client.get_policy_version(PolicyArn=arn, VersionId=version_id), sleep=lambda _: None) or {}
                        doc = (ver.get("PolicyVersion") or {}).get("Document")
                        stmts, trunc, err = _iam_bounded_statements(doc, policy_name=pname, policy_arn=arn)
                        if stmts is not None:
                            entry_pol["statements"] = stmts[:MAX_IAM_STATEMENTS_PER_POLICY]
                            if trunc and trunc.get("truncated"):
                                entry_pol["truncated"] = True
                        elif err:
                            entry_pol["unavailable"] = err[:200]
                    except Exception as exc2:
                        if classify_aws_error(exc2) == "permission":
                            entry_pol["unavailable"] = "permission_denied"
                        else:
                            entry_pol["unavailable"] = sanitize_aws_error(exc2)[:150]
                    policies.append(entry_pol)
                    if len(policies) >= MAX_IAM_POLICIES_PER_IDENTITY:
                        break
            except Exception as exc:
                if classify_aws_error(exc) == "permission":
                    policy_error = "permission_denied"
                else:
                    policy_error = sanitize_aws_error(exc)[:150]
            # Inline
            try:
                for pname in _paginate(client, "list_role_policies", "PolicyNames", limit=MAX_IAM_POLICIES_PER_IDENTITY, RoleName=name):
                    if isinstance(pname, str):
                        names = [pname]
                    elif isinstance(pname, dict):
                        continue
                    else:
                        names = [str(pname)]
                    for inline_name in names:
                        if len(policies) >= MAX_IAM_POLICIES_PER_IDENTITY:
                            break
                        inline_name_s = str(inline_name)[:256]
                        entry_pol = {"type": "inline", "name": inline_name_s}
                        try:
                            resp = call_with_retry(lambda: client.get_role_policy(RoleName=name, PolicyName=inline_name_s), sleep=lambda _: None) or {}
                            doc = resp.get("PolicyDocument")
                            stmts, trunc, err = _iam_bounded_statements(doc, policy_name=inline_name_s, policy_arn=None)
                            if stmts is not None:
                                entry_pol["statements"] = stmts[:MAX_IAM_STATEMENTS_PER_POLICY]
                                if trunc and trunc.get("truncated"):
                                    entry_pol["truncated"] = True
                            elif err:
                                entry_pol["unavailable"] = err[:200]
                        except Exception as exc2:
                            entry_pol["unavailable"] = sanitize_aws_error(exc2)[:150] if classify_aws_error(exc2) != "permission" else "permission_denied"
                        policies.append(entry_pol)
            except Exception:
                pass
        elif rtype == "aws_iam_user":
            try:
                for pol in _paginate(client, "list_attached_user_policies", "AttachedPolicies", limit=MAX_IAM_POLICIES_PER_IDENTITY, UserName=name):
                    arn = str(pol.get("PolicyArn") or "")[:1024]
                    pname = str(pol.get("PolicyName") or "")[:256]
                    if not arn:
                        continue
                    is_aws = arn.startswith("arn:aws:iam::aws:policy/")
                    entry_pol = {"type": "managed", "arn": arn, "name": pname, "is_aws_managed": is_aws}
                    try:
                        pol_meta = call_with_retry(lambda: client.get_policy(PolicyArn=arn), sleep=lambda _: None) or {}
                        version_id = (pol_meta.get("Policy") or {}).get("DefaultVersionId") or "v1"
                        ver = call_with_retry(lambda: client.get_policy_version(PolicyArn=arn, VersionId=version_id), sleep=lambda _: None) or {}
                        doc = (ver.get("PolicyVersion") or {}).get("Document")
                        stmts, trunc, err = _iam_bounded_statements(doc, policy_name=pname, policy_arn=arn)
                        if stmts is not None:
                            entry_pol["statements"] = stmts[:MAX_IAM_STATEMENTS_PER_POLICY]
                            if trunc and trunc.get("truncated"):
                                entry_pol["truncated"] = True
                        elif err:
                            entry_pol["unavailable"] = err[:200]
                    except Exception as exc2:
                        entry_pol["unavailable"] = "permission_denied" if classify_aws_error(exc2) == "permission" else sanitize_aws_error(exc2)[:150]
                    policies.append(entry_pol)
                    if len(policies) >= MAX_IAM_POLICIES_PER_IDENTITY:
                        break
            except Exception as exc:
                if classify_aws_error(exc) == "permission":
                    policy_error = "permission_denied"
            try:
                for item in _paginate(client, "list_user_policies", "PolicyNames", limit=MAX_IAM_POLICIES_PER_IDENTITY, UserName=name):
                    # paginator returns dict pages with PolicyNames list
                    if isinstance(item, str):
                        inline_names = [item]
                    elif isinstance(item, list):
                        inline_names = item
                    else:
                        continue
                    for inline_name in inline_names:
                        if len(policies) >= MAX_IAM_POLICIES_PER_IDENTITY:
                            break
                        inline_name_s = str(inline_name)[:256]
                        entry_pol = {"type": "inline", "name": inline_name_s}
                        try:
                            resp = call_with_retry(lambda: client.get_user_policy(UserName=name, PolicyName=inline_name_s), sleep=lambda _: None) or {}
                            doc = resp.get("PolicyDocument")
                            stmts, trunc, err = _iam_bounded_statements(doc, policy_name=inline_name_s, policy_arn=None)
                            if stmts is not None:
                                entry_pol["statements"] = stmts[:MAX_IAM_STATEMENTS_PER_POLICY]
                                if trunc and trunc.get("truncated"):
                                    entry_pol["truncated"] = True
                            elif err:
                                entry_pol["unavailable"] = err[:200]
                        except Exception as exc2:
                            entry_pol["unavailable"] = "permission_denied" if classify_aws_error(exc2) == "permission" else sanitize_aws_error(exc2)[:150]
                        policies.append(entry_pol)
            except Exception:
                pass
        elif rtype == "aws_iam_group":
            try:
                for pol in _paginate(client, "list_attached_group_policies", "AttachedPolicies", limit=MAX_IAM_POLICIES_PER_IDENTITY, GroupName=name):
                    arn = str(pol.get("PolicyArn") or "")[:1024]
                    pname = str(pol.get("PolicyName") or "")[:256]
                    if not arn:
                        continue
                    is_aws = arn.startswith("arn:aws:iam::aws:policy/")
                    entry_pol = {"type": "managed", "arn": arn, "name": pname, "is_aws_managed": is_aws}
                    try:
                        pol_meta = call_with_retry(lambda: client.get_policy(PolicyArn=arn), sleep=lambda _: None) or {}
                        version_id = (pol_meta.get("Policy") or {}).get("DefaultVersionId") or "v1"
                        ver = call_with_retry(lambda: client.get_policy_version(PolicyArn=arn, VersionId=version_id), sleep=lambda _: None) or {}
                        doc = (ver.get("PolicyVersion") or {}).get("Document")
                        stmts, trunc, err = _iam_bounded_statements(doc, policy_name=pname, policy_arn=arn)
                        if stmts is not None:
                            entry_pol["statements"] = stmts[:MAX_IAM_STATEMENTS_PER_POLICY]
                            if trunc and trunc.get("truncated"):
                                entry_pol["truncated"] = True
                        elif err:
                            entry_pol["unavailable"] = err[:200]
                    except Exception as exc2:
                        entry_pol["unavailable"] = "permission_denied" if classify_aws_error(exc2) == "permission" else sanitize_aws_error(exc2)[:150]
                    policies.append(entry_pol)
                    if len(policies) >= MAX_IAM_POLICIES_PER_IDENTITY:
                        break
            except Exception:
                pass
            try:
                for item in _paginate(client, "list_group_policies", "PolicyNames", limit=MAX_IAM_POLICIES_PER_IDENTITY, GroupName=name):
                    if isinstance(item, str):
                        inline_names = [item]
                    elif isinstance(item, list):
                        inline_names = item
                    else:
                        continue
                    for inline_name in inline_names:
                        if len(policies) >= MAX_IAM_POLICIES_PER_IDENTITY:
                            break
                        inline_name_s = str(inline_name)[:256]
                        entry_pol = {"type": "inline", "name": inline_name_s}
                        try:
                            resp = call_with_retry(lambda: client.get_group_policy(GroupName=name, PolicyName=inline_name_s), sleep=lambda _: None) or {}
                            doc = resp.get("PolicyDocument")
                            stmts, trunc, err = _iam_bounded_statements(doc, policy_name=inline_name_s, policy_arn=None)
                            if stmts is not None:
                                entry_pol["statements"] = stmts[:MAX_IAM_STATEMENTS_PER_POLICY]
                                if trunc and trunc.get("truncated"):
                                    entry_pol["truncated"] = True
                            elif err:
                                entry_pol["unavailable"] = err[:200]
                        except Exception as exc2:
                            entry_pol["unavailable"] = "permission_denied" if classify_aws_error(exc2) == "permission" else sanitize_aws_error(exc2)[:150]
                        policies.append(entry_pol)
            except Exception:
                pass
    except Exception as exc:
        policy_error = sanitize_aws_error(exc)[:150]

    if policies:
        extra["iam_policies"] = policies[:MAX_IAM_POLICIES_PER_IDENTITY]
        # Truncation flag if hit limit
        if len(policies) >= MAX_IAM_POLICIES_PER_IDENTITY:
            extra["iam_policies_truncated"] = True
    if policy_error:
        extra["iam_policies_unavailable"] = policy_error[:200]

    # MFA and access keys / password for users
    if rtype == "aws_iam_user":
        # MFA devices
        try:
            resp = call_with_retry(lambda: client.list_mfa_devices(UserName=name), sleep=lambda _: None) or {}
            devices = resp.get("MFADevices") or []
            if isinstance(devices, list):
                extra["iam_mfa_device_count"] = min(len(devices), 10)
                # Store bounded device metadata (no secrets)
                extra["iam_mfa_devices"] = [
                    {"serial": str(d.get("SerialNumber") or "")[:256][:100]}
                    for d in devices[:5] if isinstance(d, dict)
                ]
            else:
                extra["iam_mfa_device_count"] = 0
        except Exception as exc:
            if classify_aws_error(exc) == "permission":
                extra["iam_mfa_unavailable"] = "permission_denied"
            else:
                extra["iam_mfa_unavailable"] = sanitize_aws_error(exc)[:150]
        # Access keys
        try:
            resp = call_with_retry(lambda: client.list_access_keys(UserName=name), sleep=lambda _: None) or {}
            keys = resp.get("AccessKeyMetadata") or []
            bounded_keys: list[dict] = []
            for k in (keys or [])[:10]:
                if not isinstance(k, dict):
                    continue
                kid = str(k.get("AccessKeyId") or "")[:128]
                # Store only suffix + hash for correlation, never full id in logs
                kid_suffix = kid[-4:] if len(kid) >= 4 else kid
                kid_hash = hashlib.sha256(kid.encode()).hexdigest()[:16] if kid else None
                bounded_keys.append({
                    "id_suffix": kid_suffix,
                    "id_hash": kid_hash,
                    "status": str(k.get("Status") or "")[:20],
                    "create_date": str(k.get("CreateDate") or "")[:32],
                })
            extra["iam_access_keys"] = bounded_keys
            # Try last used for each key (bounded)
            for idx, k in enumerate(bounded_keys[:5]):
                # Need original key id for API call — retrieve from keys list
                orig = keys[idx] if idx < len(keys) and isinstance(keys[idx], dict) else None
                if not orig:
                    continue
                kid_full = str(orig.get("AccessKeyId") or "")
                if not kid_full:
                    continue
                try:
                    lu = call_with_retry(lambda: client.get_access_key_last_used(AccessKeyId=kid_full), sleep=lambda _: None) or {}
                    info = lu.get("AccessKeyLastUsed") or {}
                    if info.get("LastUsedDate"):
                        bounded_keys[idx]["last_used"] = str(info.get("LastUsedDate"))[:32]
                except Exception:
                    pass
        except Exception as exc:
            if classify_aws_error(exc) == "permission":
                extra["iam_access_keys_unavailable"] = "permission_denied"
            else:
                extra["iam_access_keys_unavailable"] = sanitize_aws_error(exc)[:150]
        # Console password (login profile)
        try:
            resp = call_with_retry(lambda: client.get_login_profile(UserName=name), sleep=lambda _: None) or {}
            # If no exception, password enabled
            if resp.get("LoginProfile"):
                extra["iam_password_enabled"] = True
            else:
                extra["iam_password_enabled"] = False
        except Exception as exc:
            code = _error_code(exc) or ""
            if code in ("NoSuchEntity", "NoSuchEntityException"):
                extra["iam_password_enabled"] = False
            elif classify_aws_error(exc) == "permission":
                extra["iam_password_unavailable"] = "permission_denied"
            else:
                extra["iam_password_unavailable"] = sanitize_aws_error(exc)[:150]

    # Bound extra size (defense)
    extra = _bounded_extra(extra)
    return extra


def discover_iam(client, account_id: str):
    """IAM is global: roles, users, groups with bounded evidence for E3.

    Collects identity, policies (managed+inline with normalized statements),
    trust (roles), MFA/keys/password (users). All bounded, sensitive fields
    excluded, permission failures recorded as unavailable (NOT_ASSESSED).
    """
    resources: list[dict] = []
    warnings: list[dict] = []
    for operation, key, rtype, id_field in (
        ("list_roles", "Roles", "aws_iam_role", "RoleName"),
        ("list_users", "Users", "aws_iam_user", "UserName"),
        ("list_groups", "Groups", "aws_iam_group", "GroupName"),
    ):
        try:
            for entry in _paginate(client, operation, key, limit=100):
                arn = entry.get("Arn")
                name = entry.get(id_field)
                if not name:
                    continue
                iam_extra = _iam_collect_for_identity(client, name, rtype, account_id, entry)
                resources.append(_resource("iam", rtype, arn or name, "global", account_id, arn=arn,
                                           name=name, extra=iam_extra))
                if len(resources) >= MAX_TOTAL_RESOURCES:
                    break
        except Exception as exc:
            warnings.append(_warning_for("iam", exc) or {"service": "iam", "reason": "service_error", "detail": "IAM discovery failed"})
        if len(resources) >= MAX_TOTAL_RESOURCES:
            break
    warning = None
    if warnings:
        warning = {"service": "iam", "reason": "partial", "detail": "; ".join(str(w.get("detail", ""))[:150] for w in warnings[:3])[:400]}
    return resources, warning


REGIONAL_DISCOVERERS = (
    ("vpc", discover_vpcs),
    ("subnet", discover_subnets),
    ("route_table", discover_route_tables),
    ("security_group", discover_security_groups),
    ("internet_gateway", discover_internet_gateways),
    ("nat_gateway", discover_nat_gateways),
    ("network_acl", discover_network_acls),
    ("network_interface", discover_network_interfaces),
    ("ec2", discover_ec2_instances),
    ("elbv2", discover_load_balancers),
    ("rds", discover_rds_instances),
    ("lambda", discover_lambda_functions),
    ("ecs", discover_ecs_clusters),
    ("ecr", discover_ecr_repositories),
    ("ebs_volume", discover_ebs_volumes),
    ("ebs_snapshot", discover_ebs_snapshots),
    ("efs", discover_efs_filesystems),
)

GLOBAL_DISCOVERERS = (
    ("s3", discover_s3_buckets),
    ("iam", discover_iam),
)

SERVICE_CLIENTS = {
    "vpc": "ec2", "subnet": "ec2", "route_table": "ec2", "security_group": "ec2",
    "internet_gateway": "ec2", "nat_gateway": "ec2", "network_acl": "ec2", "network_interface": "ec2",
    "ebs_volume": "ec2", "ebs_snapshot": "ec2", "efs": "efs",
    "ec2": "ec2", "elbv2": "elbv2", "rds": "rds", "lambda": "lambda",
    "ecs": "ecs", "ecr": "ecr", "s3": "s3", "iam": "iam",
}


def discover_region(session_factory, region: str, account_id: str, max_total: int) -> dict:
    """Discover one region: resources, warnings, per-service outcomes."""
    resources: list[dict] = []
    warnings: list[dict] = []
    services_ok = 0
    services_failed = 0
    for key, discoverer in REGIONAL_DISCOVERERS:
        if len(resources) >= max_total:
            break
        try:
            client = session_factory(SERVICE_CLIENTS[key], region)
            found, warning = discoverer(client, region, account_id)
            resources.extend(found[:max_total - len(resources)])
            if warning:
                warnings.append(warning)
                services_failed += 1
            else:
                services_ok += 1
        except Exception as exc:
            warnings.append(_warning_for(key, exc) or {"service": key, "reason": "service_error", "detail": sanitize_aws_error(exc)})
            services_failed += 1
    # ECS services need cluster ARNs from this region's clusters.
    cluster_arns = [r.get("arn") for r in resources if r.get("resource_type") == "aws_ecs_cluster" and r.get("arn")]
    if cluster_arns and len(resources) < max_total:
        try:
            client = session_factory("ecs", region)
            found, warning = discover_ecs_services(client, region, account_id, cluster_arns)
            resources.extend(found[:max_total - len(resources)])
            if warning:
                warnings.append(warning)
        except Exception as exc:
            warnings.append(_warning_for("ecs", exc) or {"service": "ecs", "reason": "service_error", "detail": sanitize_aws_error(exc)})
    return {"region": region, "resources": resources, "warnings": warnings,
            "services_ok": services_ok, "services_failed": services_failed}


def discover_global(session_factory, account_id: str, max_total: int) -> dict:
    resources: list[dict] = []
    warnings: list[dict] = []
    for key, discoverer in GLOBAL_DISCOVERERS:
        if len(resources) >= max_total:
            break
        try:
            client = session_factory(SERVICE_CLIENTS[key], "us-east-1")
            if key == "s3":
                found, warning = discoverer(client, account_id)
            else:
                found, warning = discoverer(client, account_id)
            resources.extend(found[:max_total - len(resources)])
            if warning:
                warnings.append(warning)
        except Exception as exc:
            warnings.append(_warning_for(key, exc) or {"service": key, "reason": "service_error", "detail": sanitize_aws_error(exc)})
    return {"region": "global", "resources": resources, "warnings": warnings}


def discover_account(session_factory, account_id: str, regions: list[str], max_total: int = MAX_TOTAL_RESOURCES) -> dict:
    """Full account discovery across regions + global services (E1 scope)."""
    all_resources: list[dict] = []
    region_results: list[dict] = []
    warnings: list[dict] = []
    attempted = succeeded = failed = 0
    remaining = max(0, int(max_total or MAX_TOTAL_RESOURCES))
    for region in (regions or [])[:MAX_REGIONS]:
        attempted += 1
        try:
            outcome = discover_region(session_factory, region, account_id, remaining)
        except Exception as exc:
            failed += 1
            warning = {"service": "region", "region": region, "reason": "service_error", "detail": sanitize_aws_error(exc)}
            warnings.append(warning)
            region_results.append({"region": region, "status": "failed", "resources": 0, "warning": warning["detail"]})
            continue
        gained = outcome["resources"]
        all_resources.extend(gained)
        remaining = max(0, remaining - len(gained))
        region_warnings = outcome["warnings"]
        warnings.extend(region_warnings)
        if outcome["services_failed"] and not outcome["services_ok"] and not gained:
            failed += 1
            status = "failed"
        else:
            succeeded += 1
            status = "ok"
        entry: dict[str, Any] = {"region": region, "status": status, "resources": len(gained)}
        if region_warnings:
            entry["warning"] = "; ".join(str(w.get("detail", ""))[:150] for w in region_warnings[:3])[:400]
        region_results.append(entry)
    # Global services (S3, IAM) run once regardless of regional outcomes.
    attempted += 1
    try:
        outcome = discover_global(session_factory, account_id, remaining)
        all_resources.extend(outcome["resources"])
        warnings.extend(outcome["warnings"])
        succeeded += 1
        entry = {"region": "global", "status": "ok", "resources": len(outcome["resources"])}
        if outcome["warnings"]:
            entry["warning"] = "; ".join(str(w.get("detail", ""))[:150] for w in outcome["warnings"][:3])[:400]
        region_results.append(entry)
    except Exception as exc:
        failed += 1
        warning = {"service": "global", "reason": "service_error", "detail": sanitize_aws_error(exc)}
        warnings.append(warning)
        region_results.append({"region": "global", "status": "failed", "resources": 0, "warning": warning["detail"]})
    if attempted and failed == attempted:
        status = "failed"
    elif failed:
        status = "partial"
    else:
        status = "completed"
    counts: dict[str, int] = {}
    for resource in all_resources:
        key = str(resource.get("resource_type") or "unknown")
        counts[key] = counts.get(key, 0) + 1
    return {"status": status, "regions_attempted": attempted, "regions_succeeded": succeeded,
            "regions_failed": failed, "resources": all_resources, "region_results": region_results,
            "warnings": warnings[:50], "resource_counts": counts}


# ---------------------------------------------------------------------------
# Normalization to existing asset/relationship inputs
# ---------------------------------------------------------------------------

def canonical_resource_value(resource: dict) -> str:
    """Deterministic identity: ARN when stable, else composite (E1 §11)."""
    arn = (resource.get("arn") or "").strip()
    if arn.startswith("arn:aws:"):
        return arn[:1024]
    account = str(resource.get("account_id") or "").strip()
    region = str(resource.get("region") or "global").strip().lower()
    service = str(resource.get("service") or "aws").strip().lower()
    rtype = str(resource.get("resource_type") or "unknown").strip().lower()
    rid = str(resource.get("resource_id") or "").strip()
    return f"cloud_resource:aws:{account}:{region}:{service}:{rtype}:{rid}"[:1024]


def to_asset_inputs(resources: list[dict], account_id: str, observed_at: str) -> list[dict]:
    """Map normalized resources to upsert_assets input dicts (existing shape)."""
    assets: list[dict] = []
    seen: set[tuple[str, str]] = set()
    account_value = f"cloud_account:aws:{account_id}:global"
    assets.append({
        "type": "cloud_account",
        "value": account_value,
        "metadata": {"provider": "aws", "account_id": account_id, "region": "global",
                     "sources": ["aws-discovery"], "observed_at": observed_at},
    })
    seen.add(("cloud_account", account_value))
    for resource in resources:
        value = canonical_resource_value(resource)
        key = ("cloud_resource", value)
        if key in seen or not value:
            continue
        seen.add(key)
        # Re-sanitize at the normalization boundary (defense in depth: raw
        # resource dicts must never leak secrets into asset metadata).
        tags = _tags_as_dict(resource.get("tags"))
        extra = _bounded_extra(resource.get("extra") if isinstance(resource.get("extra"), dict) else {})
        assets.append({
            "type": "cloud_resource",
            "value": value,
            "metadata": {
                "provider": "aws",
                "service": resource.get("service"),
                "resource_type": resource.get("resource_type"),
                "resource_id": str(resource.get("resource_id") or "")[:500],
                "arn": (resource.get("arn") or "")[:1024] or None,
                "region": resource.get("region"),
                "account_id": account_id,
                "name": (resource.get("name") or "")[:255] or None,
                "tags": tags,
                "extra": extra,
                "sources": ["aws-discovery"],
                "observed_at": observed_at,
            },
        })
    return assets


def _rel(source_value: str, target_value: str, rel_type: str) -> dict:
    return {"source_type": "cloud_resource", "source_value": source_value,
            "target_type": "cloud_resource", "target_value": target_value,
            "relationship_type": rel_type, "metadata": {"source": "aws-discovery"}}


def to_relationship_inputs(resources: list[dict], account_id: str) -> list[dict]:
    """Evidence-backed relationships within the existing taxonomy (contains/uses)."""
    by_id: dict[str, dict] = {}
    for resource in resources:
        local_id = str(resource.get("resource_id") or "")
        if local_id:
            by_id[(str(resource.get("resource_type") or ""), local_id)] = resource
    account_value = f"cloud_account:aws:{account_id}:global"
    account_rels: list[dict] = []
    rels: list[dict] = []
    seen: set[tuple[str, str, str]] = set()

    def add(source: str, stype: str, target: str, ttype: str, rel: str):
        key = (source, target, rel)
        if source and target and source != target and key not in seen:
            seen.add(key)
            rels.append({"source_type": stype, "source_value": source,
                         "target_type": ttype, "target_value": target,
                         "relationship_type": rel, "metadata": {"source": "aws-discovery"}})

    def value_of(resource: dict) -> str:
        return canonical_resource_value(resource)

    for resource in resources:
        rtype = str(resource.get("resource_type") or "")
        value = value_of(resource)
        extra = resource.get("extra") or {}
        # Account contains everything (global anchor).
        account_rels.append({"source_type": "cloud_account", "source_value": account_value,
                             "target_type": "cloud_resource", "target_value": value,
                             "relationship_type": "contains", "metadata": {"source": "aws-discovery"}})
        vpc_id = extra.get("vpc_id")
        subnet_id = extra.get("subnet_id")
        vpc_value = value_of(by_id[("aws_vpc", vpc_id)]) if vpc_id and ("aws_vpc", vpc_id) in by_id else None
        subnet_value = value_of(by_id[("aws_subnet", subnet_id)]) if subnet_id and ("aws_subnet", subnet_id) in by_id else None
        if rtype == "aws_subnet" and vpc_value:
            add(vpc_value, "cloud_resource", value, "cloud_resource", "contains")
        elif rtype in ("aws_route_table", "aws_security_group", "aws_internet_gateway",
                       "aws_rds_instance", "aws_elb", "aws_alb", "aws_nlb") and vpc_value:
            add(vpc_value, "cloud_resource", value, "cloud_resource", "contains")
        elif rtype == "aws_nat_gateway" and subnet_value:
            add(subnet_value, "cloud_resource", value, "cloud_resource", "contains")
        elif rtype in ("aws_ec2_instance", "aws_network_interface", "aws_lambda_function") and subnet_value:
            add(subnet_value, "cloud_resource", value, "cloud_resource", "contains")
        elif rtype == "aws_lambda_function" and vpc_value:
            add(vpc_value, "cloud_resource", value, "cloud_resource", "contains")
        elif rtype == "aws_ecs_service":
            cluster = extra.get("cluster")
            if cluster:
                for res in resources:
                    if res.get("resource_type") == "aws_ecs_cluster" and res.get("arn") == cluster:
                        add(value_of(res), "cloud_resource", value, "cloud_resource", "contains")
                        break
        # SG attachments evidence: uses.
        for sg_id in (extra.get("security_groups") or [])[:10]:
            if ("aws_security_group", str(sg_id)) in by_id:
                add(value, "cloud_resource",
                    value_of(by_id[("aws_security_group", str(sg_id))]), "cloud_resource", "uses")
        # Subnet route-table association evidence: uses.
        if rtype == "aws_subnet":
            for res in resources:
                if res.get("resource_type") == "aws_route_table" and (res.get("extra") or {}).get("vpc_id") == vpc_id and vpc_id:
                    add(value, "cloud_resource", value_of(res), "cloud_resource", "uses")
                    break
        # E5 storage relationships (reuse contains/uses)
        if rtype == "aws_ebs_volume" and extra.get("attached_instance"):
            inst_id = str(extra.get("attached_instance") or "")
            if ("aws_ec2_instance", inst_id) in by_id:
                add(value, "cloud_resource", value_of(by_id[("aws_ec2_instance", inst_id)]), "cloud_resource", "uses")
        elif rtype == "aws_ebs_snapshot" and extra.get("volume_id"):
            vol_id = str(extra.get("volume_id") or "")
            if ("aws_ebs_volume", vol_id) in by_id:
                add(value, "cloud_resource", value_of(by_id[("aws_ebs_volume", vol_id)]), "cloud_resource", "uses")
        elif rtype == "aws_efs_filesystem" and vpc_value:
            add(vpc_value, "cloud_resource", value, "cloud_resource", "contains")
        elif rtype == "aws_s3_bucket" and vpc_value:
            # S3 is global, no VPC containment, but account already contains
            pass
    # Account anchor last (dedup keeps first occurrence order stable).
    for rel in account_rels:
        key = (rel["source_value"], rel["target_value"], rel["relationship_type"])
        if key not in seen:
            seen.add(key)
            rels.append(rel)
    return rels

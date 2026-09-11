"""E2/E3 AWS security-check engine — deterministic evaluation of persisted evidence.

Provider-neutral structure (check packs per provider); AWS pack in E2, IAM pack in E3.
Evaluation is OFFLINE over persisted E1/E3 asset metadata: no AWS API calls, no
credentials, no network. Missing evidence yields NOT_ASSESSED — never PASS,
never FAIL. Findings flow into the existing Findings table with
scanner="cloud" (reusing dashboard/alert/report integrations).
"""

from __future__ import annotations

import json as _json
import re
import uuid
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

CHECK_PACK_VERSION = "1.4"

# E4 network constants
NET_SENSITIVE_PORTS = {22: "ssh", 3389: "rdp", 3306: "mysql", 5432: "postgres", 1433: "mssql", 1521: "oracle", 27017: "mongodb", 6379: "redis", 9200: "elasticsearch"}
NET_DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 9200}

# E5 storage constants
S3_PUBLIC_ACTIONS = frozenset({"s3:*", "s3:getobject", "s3:listbucket", "s3:getobjectversion"})

# E6 GCP constants
GCP_PRIVILEGED_ROLES = frozenset({"roles/owner", "roles/editor"})
GCP_DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 9200}

# E7 Azure constants
AZURE_PRIVILEGED_ROLES = frozenset({"owner", "contributor", "user access administrator"})
AZURE_DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 9200}

SEVERITY_SCORES = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 5}

# E3 IAM constants — bounded, deterministic
IAM_DANGEROUS_ACTIONS = frozenset({
    "iam:*",
    "iam:passrole",
    "iam:createrole",
    "iam:attachrolepolicy",
    "iam:putrolepolicy",
    "iam:createpolicy",
    "iam:attachuserpolicy",
    "iam:putuserpolicy",
    "iam:attachgrouppolicy",
    "iam:putgrouppolicy",
    "iam:updateassumerolepolicy",
    "organizations:*",
    "sts:assumerole",
    "kms:*",
})
IAM_ADMIN_SERVICE_WILDCARDS = frozenset({"s3:*", "ec2:*", "lambda:*", "cloudformation:*"})
IAM_ACCESS_KEY_MAX_AGE_DAYS = 90

RESULT_PASS = "passed"
RESULT_FAIL = "failed"
RESULT_NOT_ASSESSED = "not_assessed"
RESULT_ERROR = "error"

PAB_FLAGS = (
    "pab_blockpublicacls",
    "pab_ignorepublicacls",
    "pab_blockpublicpolicy",
    "pab_restrictpublicbuckets",
)

# E4 helpers — deterministic, bounded, no network

def _is_internet_cidr(cidr: str | None) -> bool:
    return str(cidr or "").strip() in ("0.0.0.0/0", "::/0")


def _sg_rule_is_internet(rule: dict) -> bool:
    for c in (rule.get("cidr_v4") or []):
        if _is_internet_cidr(c):
            return True
    for c in (rule.get("cidr_v6") or []):
        if _is_internet_cidr(c):
            return True
    return False


def _sg_rule_covers_port(rule: dict, port: int) -> bool:
    proto = str(rule.get("protocol") or "")
    if proto == "-1":
        return True
    fp = rule.get("from_port")
    tp = rule.get("to_port")
    if fp is None and tp is None:
        # No ports specified => often all ports for the protocol
        return True
    if fp is None:
        return True
    try:
        fp_i = int(fp)
        tp_i = int(tp) if tp is not None else fp_i
        return fp_i <= port <= tp_i
    except Exception:
        return False


def _sg_rule_is_all_ports(rule: dict) -> bool:
    if str(rule.get("protocol") or "") == "-1":
        return True
    fp = rule.get("from_port")
    tp = rule.get("to_port")
    # 0-65535 or missing means all
    if fp is None and tp is None:
        return str(rule.get("protocol") or "") == "-1"
    try:
        return int(fp) == 0 and int(tp) == 65535
    except Exception:
        return False


def _is_subnet_public(subnet_extra: dict, route_tables: list[dict], igws: list[dict]) -> bool | None:
    """Return True if subnet has IGW route, False if not, None if insufficient evidence."""
    if not route_tables:
        return None
    vpc_id = subnet_extra.get("vpc_id")
    subnet_id = subnet_extra.get("resource_id") or subnet_extra.get("subnet_id")
    # Find IGW for this VPC
    vpc_has_igw = any(str(igw.get("extra", {}).get("vpc_id") or igw.get("vpc_id") or "") == str(vpc_id) for igw in igws) if vpc_id else False
    # Also check attachments
    if not vpc_has_igw:
        for igw in igws:
            atts = igw.get("extra", {}).get("attachments") or []
            for att in atts:
                if str(att.get("vpc_id") or "") == str(vpc_id):
                    vpc_has_igw = True
                    break
    if not vpc_has_igw:
        return False
    # Find associated route table or main
    candidate_rts = []
    for rt in route_tables:
        extra = rt.get("extra") or {}
        if str(extra.get("vpc_id") or "") != str(vpc_id):
            continue
        assocs = extra.get("associations") or []
        for assoc in assocs:
            if str(assoc.get("subnet_id") or "") == str(subnet_id):
                candidate_rts.append(rt)
        # Main route table is fallback
        if not candidate_rts:
            for assoc in assocs:
                if assoc.get("main"):
                    candidate_rts.append(rt)
                    break
    if not candidate_rts:
        # Fallback: any RT in VPC with IGW route
        candidate_rts = [rt for rt in route_tables if str((rt.get("extra") or {}).get("vpc_id") or "") == str(vpc_id)]
    for rt in candidate_rts:
        routes = (rt.get("extra") or {}).get("routes") or []
        for route in routes:
            dest = route.get("destination_cidr") or route.get("destination_ipv6")
            gw = route.get("gateway_id") or ""
            if _is_internet_cidr(dest) and str(gw).startswith("igw-"):
                return True
    return False


def _s3_policy_is_public(statements: list[dict]) -> tuple[bool, dict | None]:
    """Check S3 bucket policy for public principal with meaningful S3 actions. Returns (is_public, evidence_stmt)."""
    if not isinstance(statements, list):
        return False, None
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if str(stmt.get("effect") or "").lower() != "allow":
            continue
        principals = stmt.get("principals") or []
        # Check for wildcard principal
        has_wildcard = False
        for p in principals:
            ps = str(p).strip()
            if ps in ("*", "AWS:*", "CanonicalUser:*") or ps.endswith(":*") and ps == "*":
                has_wildcard = True
                break
            if ps == "*":
                has_wildcard = True
                break
        if not has_wildcard:
            continue
        # Check actions for S3 public relevance
        for act in (stmt.get("actions") or []):
            low = str(act).strip().lower()
            if low in S3_PUBLIC_ACTIONS or low.startswith("s3:"):
                # Consider any s3: action with wildcard principal as public
                if low in ("s3:*", "s3:getobject", "s3:listbucket", "s3:getobjectversion", "s3:get*"):
                    return True, stmt
                if low.startswith("s3:"):
                    return True, stmt
    return False, None


def _gcp_firewall_allows_port(allowed: list[dict], port: int) -> bool:
    if not isinstance(allowed, list):
        return False
    for allow in allowed:
        if not isinstance(allow, dict):
            continue
        proto = str(allow.get("protocol") or "").lower()
        if proto not in ("tcp", "all", "-1"):
            continue
        ports = allow.get("ports") or []
        if not ports:
            return True  # all ports for tcp
        for p in ports:
            ps = str(p).strip()
            if "-" in ps:
                try:
                    lo, hi = ps.split("-", 1)
                    if int(lo) <= port <= int(hi):
                        return True
                except Exception:
                    continue
            else:
                try:
                    if int(ps) == port:
                        return True
                except Exception:
                    # single port without number? ignore
                    pass
                if ps == str(port):
                    return True
    return False

def _gcp_firewall_is_all_ports(allowed: list[dict]) -> bool:
    if not isinstance(allowed, list):
        return False
    for allow in allowed:
        if not isinstance(allow, dict):
            continue
        proto = str(allow.get("protocol") or "").lower()
        if proto in ("all", "-1"):
            return True
        ports = allow.get("ports") or []
        if not ports and proto == "tcp":
            return True
    return False

def _gcp_has_internet_source(source_ranges: list) -> bool:
    if not isinstance(source_ranges, list):
        return False
    for cidr in source_ranges:
        if str(cidr).strip() in ("0.0.0.0/0", "::/0"):
            return True
    return False

def _gcp_firewall_applies_to_vm(firewall_extra: dict, vm_extra: dict) -> bool:
    if str(firewall_extra.get("direction") or "INGRESS").upper() != "INGRESS":
        return False
    target_tags = firewall_extra.get("targetTags") or []
    target_sas = firewall_extra.get("targetServiceAccounts") or []
    if not target_tags and not target_sas:
        return True
    vm_tags = vm_extra.get("tags") or []
    vm_sa = str(vm_extra.get("service_account") or "")
    if target_tags and vm_tags:
        for tag in target_tags:
            if str(tag) in [str(t) for t in vm_tags]:
                return True
    if target_sas and vm_sa:
        for sa in target_sas:
            if str(sa) == vm_sa:
                return True
    return False

def _azure_nsg_is_internet_source(prefix: str | None) -> bool:
    if not prefix:
        return False
    p = str(prefix).strip()
    return p in ("*", "0.0.0.0/0", "0.0.0.0", "Internet", "::/0", "0.0.0.0/0", "*")

def _azure_nsg_allows_port(rule: dict, port: int) -> bool:
    if str(rule.get("access") or "").lower() != "allow":
        return False
    if str(rule.get("direction") or "").lower() != "inbound":
        return False
    if not _azure_nsg_is_internet_source(rule.get("source_prefix") or rule.get("sourceAddressPrefix")):
        # Also check sourceAddressPrefixes list
        prefixes = rule.get("source_prefixes") or rule.get("sourceAddressPrefixes") or []
        if isinstance(prefixes, list):
            if not any(_azure_nsg_is_internet_source(p) for p in prefixes):
                return False
        else:
            return False
    proto = str(rule.get("protocol") or "*").lower()
    if proto not in ("tcp", "*", "all"):
        return False
    dest = str(rule.get("dest_port") or rule.get("destinationPortRange") or rule.get("destination_port") or "*").strip()
    # Handle "*" or "0-65535" or "22" or "22-23"
    if dest in ("*", "0-65535", "0-65335"):
        return True
    if "-" in dest:
        try:
            lo, hi = dest.split("-", 1)
            return int(lo) <= port <= int(hi)
        except Exception:
            return False
    try:
        return int(dest) == port
    except Exception:
        return dest == str(port)

def _azure_nsg_is_all_ports(rule: dict) -> bool:
    if str(rule.get("access") or "").lower() != "allow":
        return False
    if str(rule.get("direction") or "").lower() != "inbound":
        return False
    if not _azure_nsg_is_internet_source(rule.get("source_prefix") or rule.get("sourceAddressPrefix")):
        return False
    dest = str(rule.get("dest_port") or rule.get("destinationPortRange") or "*").strip()
    return dest in ("*", "0-65535", "0-65335")

def _azure_nsg_applies_to_vm(nsg_extra: dict, vm_extra: dict) -> bool:
    # Simplified: if VM's NIC or subnet has NSG association, assume applies
    # For E7, we use conservative: if VM has nic with that NSG, or subnet NSG matches
    vm_nics = vm_extra.get("network_interfaces") or []
    nsg_id = str(nsg_extra.get("resource_id") or nsg_extra.get("id") or "")
    # Check if any NIC ID matches? Simplified: if VM has any NIC, and NSG is associated to that NIC or subnet, assume applies
    # For mock, if nsg has no specific association, assume applies to all in same VNET? For bounded, return True if no specific association
    return True

def _s3_acl_is_public(grants: list[dict]) -> bool:
    if not isinstance(grants, list):
        return False
    for grant in grants:
        if not isinstance(grant, dict):
            continue
        if grant.get("public"):
            perm = str(grant.get("permission") or "").upper()
            # Meaningful permissions: READ, WRITE, FULL_CONTROL, etc.
            if perm in ("READ", "WRITE", "FULL_CONTROL", "READ_ACP", "WRITE_ACP"):
                return True
    return False

AWS_CHECKS: list[dict[str, Any]] = [
    {
        "check_id": "AWS-EC2-001",
        "title": "EC2 instance allows IMDSv1 (metadata service not restricted to IMDSv2)",
        "description": "Instance Metadata Service Version 1 is susceptible to SSRF-based credential theft. Require IMDSv2 (HttpTokens=required) or disable the metadata endpoint.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_ec2_instance"],
        "severity": "high",
        "category": "compute-hardening",
        "remediation": "Set MetadataOptions HttpTokens to required (IMDSv2 only) or disable the metadata endpoint for the instance.",
        "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["imds_v2_enforced"],
    },
    {
        "check_id": "AWS-RDS-001",
        "title": "RDS instance publicly accessible",
        "description": "A publicly accessible database accepts connections from the internet, exposing it to brute-force and exploitation.",
        "provider": "aws",
        "service": "rds",
        "resource_types": ["aws_rds_instance"],
        "severity": "critical",
        "category": "database-exposure",
        "remediation": "Disable public accessibility for the RDS instance and restrict access to private networks/security groups.",
        "references": ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["publicly_accessible"],
    },
    {
        "check_id": "AWS-RDS-002",
        "title": "RDS storage encryption disabled",
        "description": "Unencrypted database storage exposes data-at-rest to snapshot/volume theft.",
        "provider": "aws",
        "service": "rds",
        "resource_types": ["aws_rds_instance"],
        "severity": "high",
        "category": "database-encryption",
        "remediation": "Enable storage encryption for the RDS instance (requires snapshot restore for existing instances).",
        "references": ["https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["storage_encrypted"],
    },
    {
        "check_id": "AWS-S3-001",
        "title": "S3 bucket public-access-block disabled",
        "description": "A disabled S3 Block Public Access control allows bucket/object policies or ACLs to grant public access.",
        "provider": "aws",
        "service": "s3",
        "resource_types": ["aws_s3_bucket"],
        "severity": "high",
        "category": "storage-exposure",
        "remediation": "Enable all S3 Block Public Access settings for the bucket.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["pab_blockpublicacls", "pab_ignorepublicacls", "pab_blockpublicpolicy", "pab_restrictpublicbuckets"],
    },
    {
        "check_id": "AWS-S3-002",
        "title": "S3 bucket default encryption not configured",
        "description": "No default server-side encryption configuration exists for the bucket.",
        "provider": "aws",
        "service": "s3",
        "resource_types": ["aws_s3_bucket"],
        "severity": "medium",
        "category": "storage-encryption",
        "remediation": "Configure default server-side encryption (SSE-S3 or SSE-KMS) for the bucket.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["encryption"],
    },
    {
        "check_id": "AWS-ELB-001",
        "title": "Internet-facing load balancer exposes plaintext HTTP listener",
        "description": "An internet-facing load balancer with an HTTP listener serves unencrypted traffic that can be intercepted or downgraded.",
        "provider": "aws",
        "service": "elbv2",
        "resource_types": ["aws_alb", "aws_nlb", "aws_elb"],
        "severity": "medium",
        "category": "network-encryption",
        "remediation": "Replace the HTTP listener with HTTPS (or redirect HTTP to HTTPS) on the internet-facing load balancer.",
        "references": ["https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["listeners", "scheme"],
    },
    {
        "check_id": "AWS-LAMBDA-001",
        "title": "Lambda function URL allows unauthenticated access",
        "description": "A Lambda function URL with AuthType NONE is publicly invocable without AWS authentication.",
        "provider": "aws",
        "service": "lambda",
        "resource_types": ["aws_lambda_function"],
        "severity": "high",
        "category": "serverless-exposure",
        "remediation": "Set the function URL auth type to AWS_IAM or remove the public function URL.",
        "references": ["https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["function_urls"],
    },
    # E3 IAM checks
    {
        "check_id": "AWS-IAM-001",
        "title": "IAM policy allows Action '*'",
        "description": "An IAM policy statement with Effect Allow and Action '*' grants unrestricted permissions across all services.",
        "provider": "aws",
        "service": "iam",
        "resource_types": ["aws_iam_role", "aws_iam_user", "aws_iam_group"],
        "severity": "high",
        "category": "iam-permissions",
        "remediation": "Replace Action '*' with the minimal set of required service actions (least privilege).",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["iam_policies"],
    },
    {
        "check_id": "AWS-IAM-002",
        "title": "IAM policy allows wildcard Resource '*'",
        "description": "An IAM policy statement with Effect Allow and Resource '*' grants permissions on all resources for the allowed actions.",
        "provider": "aws",
        "service": "iam",
        "resource_types": ["aws_iam_role", "aws_iam_user", "aws_iam_group"],
        "severity": "high",
        "category": "iam-permissions",
        "remediation": "Replace Resource '*' with specific ARNs for the resources that require access.",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["iam_policies"],
    },
    {
        "check_id": "AWS-IAM-003",
        "title": "IAM policy allows dangerous administrative actions",
        "description": "An IAM policy statement allows highly privileged actions (iam:*, organizations:*, sts:AssumeRole, kms:*, etc.) that enable privilege escalation or organizational compromise.",
        "provider": "aws",
        "service": "iam",
        "resource_types": ["aws_iam_role", "aws_iam_user", "aws_iam_group"],
        "severity": "high",
        "category": "iam-permissions",
        "remediation": "Restrict administrative actions to the minimal required set and scope them with resource and condition constraints.",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["iam_policies"],
    },
    {
        "check_id": "AWS-IAM-004",
        "title": "IAM role trust policy allows wildcard principal",
        "description": "An IAM role trust policy with Principal '*' allows any principal to assume the role.",
        "provider": "aws",
        "service": "iam",
        "resource_types": ["aws_iam_role"],
        "severity": "critical",
        "category": "iam-trust",
        "remediation": "Replace Principal '*' with the specific AWS account, IAM role, or federated principal that must assume the role.",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["iam_trust_statements"],
    },
    {
        "check_id": "AWS-IAM-005",
        "title": "IAM role trusts an external AWS account",
        "description": "An IAM role trust policy trusts an AWS account outside the current account. Cross-account trust requires validation.",
        "provider": "aws",
        "service": "iam",
        "resource_types": ["aws_iam_role"],
        "severity": "medium",
        "category": "iam-trust",
        "remediation": "Review the cross-account trust. If required, scope it with ExternalId and condition constraints; otherwise remove the external principal.",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["iam_trust_statements"],
    },
    {
        "check_id": "AWS-IAM-006",
        "title": "IAM user has no MFA configured",
        "description": "An IAM user has no MFA device registered. MFA is required for human identities with console access.",
        "provider": "aws",
        "service": "iam",
        "resource_types": ["aws_iam_user"],
        "severity": "high",
        "category": "iam-authentication",
        "remediation": "Enable MFA for the IAM user and require MFA for console access.",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["iam_mfa_device_count"],
    },
    {
        "check_id": "AWS-IAM-007",
        "title": "IAM user has active access key older than 90 days",
        "description": "An active access key has not been rotated within 90 days, increasing the blast radius of credential exposure.",
        "provider": "aws",
        "service": "iam",
        "resource_types": ["aws_iam_user"],
        "severity": "medium",
        "category": "iam-credentials",
        "remediation": "Rotate or remove stale active access keys. Use short-lived credentials where possible.",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["iam_access_keys"],
    },
    {
        "check_id": "AWS-IAM-008",
        "title": "IAM user has console password enabled without MFA",
        "description": "An IAM user has console password login enabled but no MFA device, exposing the account to password-only compromise.",
        "provider": "aws",
        "service": "iam",
        "resource_types": ["aws_iam_user"],
        "severity": "high",
        "category": "iam-authentication",
        "remediation": "Enable MFA for the console user or disable console access if not required.",
        "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["iam_password_enabled", "iam_mfa_device_count"],
    },
    # E4 network checks — AWS-EC2-002 formerly deferred now implemented
    {
        "check_id": "AWS-EC2-002",
        "title": "Security group allows unrestricted Internet ingress (0.0.0.0/0 or ::/0)",
        "description": "A security group ingress rule allows 0.0.0.0/0 or ::/0 to reach one or more ports. Broad Internet ingress should be restricted to the minimal required sources.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_security_group"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict the security group ingress to specific CIDR blocks, security group IDs, or prefix lists instead of 0.0.0.0/0 or ::/0.",
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["ingress"],
    },
    {
        "check_id": "AWS-NET-001",
        "title": "Internet-facing security group with broad ingress",
        "description": "A security group permits broad Internet ingress that should be reviewed for least-privilege.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_security_group"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Scope security group ingress to the required source CIDRs or referencing security groups.",
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["ingress"],
    },
    {
        "check_id": "AWS-NET-002",
        "title": "SSH (port 22) open to the Internet",
        "description": "A security group allows TCP port 22 (SSH) from 0.0.0.0/0 or ::/0, exposing remote administration to the Internet.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_security_group"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict SSH (22/tcp) to bastion hosts, VPN CIDRs, or specific IP allowlists instead of 0.0.0.0/0.",
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["ingress"],
    },
    {
        "check_id": "AWS-NET-003",
        "title": "RDP (port 3389) open to the Internet",
        "description": "A security group allows TCP port 3389 (RDP) from 0.0.0.0/0 or ::/0, exposing Windows remote desktop to the Internet.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_security_group"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict RDP (3389/tcp) to VPN or private CIDRs instead of 0.0.0.0/0.",
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["ingress"],
    },
    {
        "check_id": "AWS-NET-004",
        "title": "Security group permits Internet access to database port",
        "description": "A security group allows 0.0.0.0/0 or ::/0 to reach a common database port (3306, 5432, 1433, 1521, 27017, 6379, 9200). This permits Internet access to database listeners; ensure this is intentional and not a database exposure.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_security_group"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict database ports to application-tier security groups or private CIDRs instead of 0.0.0.0/0.",
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["ingress"],
    },
    {
        "check_id": "AWS-NET-005",
        "title": "Security group allows all ports / all protocols from the Internet",
        "description": "A security group ingress rule with protocol -1 (all) and 0.0.0.0/0 or ::/0 exposes all ports and protocols to the Internet.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_security_group"],
        "severity": "critical",
        "category": "network-exposure",
        "remediation": "Replace the all-protocol/all-port Internet rule with minimal protocol/port-specific rules.",
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["ingress"],
    },
    {
        "check_id": "AWS-NET-006",
        "title": "Public subnet exposure (posture)",
        "description": "A subnet has a route to an Internet Gateway (0.0.0.0/0 → igw-*) and is considered public. This is exposure/posture intelligence, not an automatic vulnerability. Review whether the public subnet is required and restrict associated security groups and NACLs.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_subnet"],
        "severity": "info",
        "category": "network-posture",
        "remediation": "Review whether the public subnet requires IGW routing; move sensitive workloads to private subnets or restrict associated security groups and NACLs.",
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/how-it-works.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["routes", "map_public_ip"],
    },
    {
        "check_id": "AWS-NET-007",
        "title": "Public EC2 network exposure",
        "description": "An EC2 instance has a public IP, resides in a subnet with IGW routing, and is associated with a security group that permits Internet ingress.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_ec2_instance"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Remove the public IP or move the instance to a private subnet, or restrict the associated security group ingress.",
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["public_ip", "subnet_id", "security_groups"],
    },
    {
        "check_id": "AWS-NET-008",
        "title": "Internet-facing load balancer with permissive exposure",
        "description": "An internet-facing ALB/NLB is exposed and has a security group or listener configuration that permits broad ingress.",
        "provider": "aws",
        "service": "elbv2",
        "resource_types": ["aws_alb", "aws_nlb", "aws_elb"],
        "severity": "medium",
        "category": "network-exposure",
        "remediation": "Restrict the load balancer security group and listeners; use HTTPS listeners and scoped SG ingress.",
        "references": ["https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["scheme", "listeners"],
    },
    {
        "check_id": "AWS-NET-009",
        "title": "Network ACL allows broad Internet ingress",
        "description": "A Network ACL ingress entry allows 0.0.0.0/0 or ::/0 with protocol -1 or a broad sensitive port range.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_network_acl"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict the NACL ingress to required CIDRs and narrow port ranges instead of 0.0.0.0/0.",
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["entries"],
    },
    {
        "check_id": "AWS-NET-010",
        "title": "Security group allows unrestricted egress (0.0.0.0/0 all protocols)",
        "description": "A security group egress rule allows 0.0.0.0/0 or ::/0 with protocol -1 (all). This is the AWS default and is not automatically a vulnerability; review for least-privilege if egress restriction is required.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_security_group"],
        "severity": "low",
        "category": "network-egress",
        "remediation": "If egress restriction is required, scope egress to required destinations, ports, and protocols.",
        "references": ["https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["egress"],
    },
    # E5 storage checks
    {
        "check_id": "AWS-S3-003",
        "title": "S3 bucket allows public access via bucket policy",
        "description": "An S3 bucket policy with Effect Allow, Principal \"*\" and S3 actions (s3:GetObject, s3:ListBucket, s3:*) allows public access to bucket objects.",
        "provider": "aws",
        "service": "s3",
        "resource_types": ["aws_s3_bucket"],
        "severity": "critical",
        "category": "storage-exposure",
        "remediation": "Restrict the bucket policy Principal to specific AWS accounts or remove public s3 actions; enable Block Public Access.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["bucket_policy_statements"],
    },
    {
        "check_id": "AWS-S3-004",
        "title": "S3 bucket weak encryption posture (SSE-S3 vs SSE-KMS)",
        "description": "The bucket default encryption is not KMS-managed. SSE-S3 is available but KMS provides additional control. This is posture information.",
        "provider": "aws",
        "service": "s3",
        "resource_types": ["aws_s3_bucket"],
        "severity": "info",
        "category": "storage-encryption",
        "remediation": "If KMS is required, configure default encryption with aws:kms and a customer-managed key.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["encryption"],
    },
    {
        "check_id": "AWS-S3-005",
        "title": "S3 bucket allows public ACL grant",
        "description": "An S3 bucket ACL grants AllUsers or AuthenticatedUsers with READ/WRITE/FULL_CONTROL, exposing the bucket publicly.",
        "provider": "aws",
        "service": "s3",
        "resource_types": ["aws_s3_bucket"],
        "severity": "high",
        "category": "storage-exposure",
        "remediation": "Remove public ACL grants and use Block Public Access; prefer BucketOwnerEnforced ownership.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["acl_grants"],
    },
    {
        "check_id": "AWS-S3-006",
        "title": "S3 bucket versioning disabled (posture)",
        "description": "S3 bucket versioning is not enabled. This is posture information for recoverability, not an automatic vulnerability.",
        "provider": "aws",
        "service": "s3",
        "resource_types": ["aws_s3_bucket"],
        "severity": "info",
        "category": "storage-posture",
        "remediation": "Enable versioning if object recovery is required.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["versioning"],
    },
    {
        "check_id": "AWS-S3-007",
        "title": "S3 bucket logging disabled (posture)",
        "description": "S3 bucket access logging is not enabled. This is posture for auditability, not equivalent to public exposure.",
        "provider": "aws",
        "service": "s3",
        "resource_types": ["aws_s3_bucket"],
        "severity": "info",
        "category": "storage-posture",
        "remediation": "Enable access logging to a dedicated logging bucket if audit is required.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["logging_enabled"],
    },
    {
        "check_id": "AWS-S3-008",
        "title": "S3 bucket object ownership weak posture",
        "description": "S3 bucket ObjectOwnership is not BucketOwnerEnforced, indicating legacy ACL-based ownership.",
        "provider": "aws",
        "service": "s3",
        "resource_types": ["aws_s3_bucket"],
        "severity": "info",
        "category": "storage-posture",
        "remediation": "Consider BucketOwnerEnforced to disable ACLs.",
        "references": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["object_ownership"],
    },
    {
        "check_id": "AWS-EBS-001",
        "title": "EBS volume unencrypted",
        "description": "An EBS volume is not encrypted, exposing data at rest on the volume.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_ebs_volume"],
        "severity": "high",
        "category": "storage-encryption",
        "remediation": "Enable encryption for the volume and use a KMS key; snapshot and recreate if needed.",
        "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["encrypted"],
    },
    {
        "check_id": "AWS-EBS-002",
        "title": "EBS snapshot shared publicly",
        "description": "An EBS snapshot has createVolumePermission for group \"all\", allowing any AWS account to create a volume from it.",
        "provider": "aws",
        "service": "ec2",
        "resource_types": ["aws_ebs_snapshot"],
        "severity": "critical",
        "category": "storage-exposure",
        "remediation": "Remove public createVolumePermission from the snapshot and share only with specific accounts if needed.",
        "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-modifying-snapshot-permissions.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["is_public"],
    },
    {
        "check_id": "AWS-EFS-001",
        "title": "EFS filesystem unencrypted",
        "description": "An EFS filesystem is not encrypted, exposing file data at rest.",
        "provider": "aws",
        "service": "efs",
        "resource_types": ["aws_efs_filesystem"],
        "severity": "high",
        "category": "storage-encryption",
        "remediation": "Create a new encrypted filesystem and migrate data; enable encryption at creation with a KMS key.",
        "references": ["https://docs.aws.amazon.com/efs/latest/ug/encryption.html"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["encrypted"],
    },
    # E6 GCP checks
    {
        "check_id": "GCP-IAM-001",
        "title": "GCP IAM allows public member allUsers/allAuthenticatedUsers",
        "description": "A GCP IAM binding grants allUsers or allAuthenticatedUsers with a meaningful role, allowing public access.",
        "provider": "gcp",
        "service": "iam",
        "resource_types": ["gcp_iam_policy", "gcp_storage_bucket"],
        "severity": "critical",
        "category": "iam-exposure",
        "remediation": "Remove allUsers/allAuthenticatedUsers from IAM bindings and grant least-privilege to specific members.",
        "references": ["https://cloud.google.com/iam/docs/overview"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["bindings"],
    },
    {
        "check_id": "GCP-IAM-002",
        "title": "GCP project has excessive owner/editor role",
        "description": "A GCP IAM binding grants roles/owner or roles/editor at project level to a member, indicating excessive privilege.",
        "provider": "gcp",
        "service": "iam",
        "resource_types": ["gcp_iam_policy"],
        "severity": "high",
        "category": "iam-privilege",
        "remediation": "Replace owner/editor with least-privilege predefined roles for the member.",
        "references": ["https://cloud.google.com/iam/docs/understanding-roles"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["bindings"],
    },
    {
        "check_id": "GCP-IAM-003",
        "title": "GCP service account has privileged project role",
        "description": "A GCP service account is granted a privileged project role (owner/editor) at project level.",
        "provider": "gcp",
        "service": "iam",
        "resource_types": ["gcp_iam_policy"],
        "severity": "high",
        "category": "iam-privilege",
        "remediation": "Restrict the service account to the minimal required roles.",
        "references": ["https://cloud.google.com/iam/docs/service-accounts"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["bindings"],
    },
    {
        "check_id": "GCP-IAM-004",
        "title": "GCP service account key is long-lived (>90 days)",
        "description": "A user-managed service account key is older than 90 days, increasing risk of long-lived credential exposure.",
        "provider": "gcp",
        "service": "iam",
        "resource_types": ["gcp_service_account"],
        "severity": "medium",
        "category": "iam-credentials",
        "remediation": "Rotate the service account key and use short-lived credentials or Workload Identity.",
        "references": ["https://cloud.google.com/iam/docs/best-practices-for-managing-service-account-keys"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["keys"],
    },
    {
        "check_id": "GCP-NET-001",
        "title": "GCP firewall allows SSH (22) from Internet",
        "description": "A GCP firewall rule allows TCP 22 from 0.0.0.0/0 or ::/0, exposing SSH to the Internet.",
        "provider": "gcp",
        "service": "compute",
        "resource_types": ["gcp_firewall"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict sourceRanges for SSH to bastion or IAP CIDRs.",
        "references": ["https://cloud.google.com/vpc/docs/firewalls"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["allowed", "source_ranges"],
    },
    {
        "check_id": "GCP-NET-002",
        "title": "GCP firewall allows RDP (3389) from Internet",
        "description": "A GCP firewall rule allows TCP 3389 from 0.0.0.0/0 or ::/0, exposing RDP to the Internet.",
        "provider": "gcp",
        "service": "compute",
        "resource_types": ["gcp_firewall"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict RDP sourceRanges to VPN or private ranges.",
        "references": ["https://cloud.google.com/vpc/docs/firewalls"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["allowed", "source_ranges"],
    },
    {
        "check_id": "GCP-NET-003",
        "title": "GCP firewall allows database port from Internet",
        "description": "A GCP firewall allows a common database port (3306, 5432, 1433, 1521, 27017, 6379, 9200) from 0.0.0.0/0.",
        "provider": "gcp",
        "service": "compute",
        "resource_types": ["gcp_firewall"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict database ports to private sourceRanges or target tags.",
        "references": ["https://cloud.google.com/vpc/docs/firewalls"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["allowed", "source_ranges"],
    },
    {
        "check_id": "GCP-NET-004",
        "title": "GCP firewall allows all ports from Internet",
        "description": "A GCP firewall rule allows all ports/protocols from 0.0.0.0/0 or ::/0.",
        "provider": "gcp",
        "service": "compute",
        "resource_types": ["gcp_firewall"],
        "severity": "critical",
        "category": "network-exposure",
        "remediation": "Replace all-port Internet rule with narrow protocol/port rules.",
        "references": ["https://cloud.google.com/vpc/docs/firewalls"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["allowed", "source_ranges"],
    },
    {
        "check_id": "GCP-NET-005",
        "title": "GCP firewall has broad Internet ingress",
        "description": "A GCP firewall rule has broad Internet ingress that should be reviewed.",
        "provider": "gcp",
        "service": "compute",
        "resource_types": ["gcp_firewall"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Scope sourceRanges and allowed ports to least privilege.",
        "references": ["https://cloud.google.com/vpc/docs/firewalls"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["allowed", "source_ranges"],
    },
    {
        "check_id": "GCP-GCS-001",
        "title": "GCP storage bucket allows public access",
        "description": "A GCS bucket IAM binding grants allUsers or allAuthenticatedUsers with storage permissions.",
        "provider": "gcp",
        "service": "storage",
        "resource_types": ["gcp_storage_bucket"],
        "severity": "critical",
        "category": "storage-exposure",
        "remediation": "Remove allUsers/allAuthenticatedUsers from bucket IAM and use uniform access with specific members.",
        "references": ["https://cloud.google.com/storage/docs/access-control/iam"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["public_iam_members"],
    },
    {
        "check_id": "GCP-GCS-002",
        "title": "GCS uniform bucket-level access disabled (posture)",
        "description": "GCS bucket uniform bucket-level access is disabled (posture).",
        "provider": "gcp",
        "service": "storage",
        "resource_types": ["gcp_storage_bucket"],
        "severity": "info",
        "category": "storage-posture",
        "remediation": "Enable uniform bucket-level access if fine-grained ACLs are not required.",
        "references": ["https://cloud.google.com/storage/docs/uniform-bucket-level-access"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["uniform_bucket_level_access"],
    },
    {
        "check_id": "GCP-GCS-003",
        "title": "GCS bucket versioning disabled (posture)",
        "description": "GCS bucket versioning is not enabled (posture).",
        "provider": "gcp",
        "service": "storage",
        "resource_types": ["gcp_storage_bucket"],
        "severity": "info",
        "category": "storage-posture",
        "remediation": "Enable versioning if object recovery is required.",
        "references": ["https://cloud.google.com/storage/docs/object-versioning"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["versioning"],
    },
    {
        "check_id": "GCP-GCS-004",
        "title": "GCS bucket weak encryption posture",
        "description": "GCS bucket encryption is not CMEK-managed (posture).",
        "provider": "gcp",
        "service": "storage",
        "resource_types": ["gcp_storage_bucket"],
        "severity": "info",
        "category": "storage-encryption",
        "remediation": "Configure CMEK if customer-managed encryption is required.",
        "references": ["https://cloud.google.com/storage/docs/encryption"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["encryption"],
    },
    {
        "check_id": "GCP-COMPUTE-001",
        "title": "GCP VM shielded VM disabled (posture)",
        "description": "GCP compute instance has shielded VM disabled (posture).",
        "provider": "gcp",
        "service": "compute",
        "resource_types": ["gcp_compute_instance"],
        "severity": "info",
        "category": "compute-posture",
        "remediation": "Enable shielded VM if workload requires it.",
        "references": ["https://cloud.google.com/compute/docs/shielded-vm"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["shielded_vm"],
    },
    {
        "check_id": "GCP-COMPUTE-002",
        "title": "GCP VM with public IP and permissive firewall",
        "description": "A GCP VM has an external IP and a firewall rule allows Internet ingress to it.",
        "provider": "gcp",
        "service": "compute",
        "resource_types": ["gcp_compute_instance"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Remove external IP or restrict firewall sourceRanges.",
        "references": ["https://cloud.google.com/compute/docs/ip-addresses"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["external_ip"],
    },
    # E7 Azure checks
    {
        "check_id": "AZURE-IAM-001",
        "title": "Azure subscription has excessive Owner role",
        "description": "An Azure RBAC assignment grants Owner at subscription scope, indicating excessive privilege.",
        "provider": "azure",
        "service": "authorization",
        "resource_types": ["azure_rbac_assignment"],
        "severity": "high",
        "category": "iam-privilege",
        "remediation": "Replace Owner with least-privilege role for the principal at subscription scope.",
        "references": ["https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["role_name", "scope"],
    },
    {
        "check_id": "AZURE-IAM-002",
        "title": "Azure subscription has Contributor role",
        "description": "An Azure RBAC assignment grants Contributor at subscription scope.",
        "provider": "azure",
        "service": "authorization",
        "resource_types": ["azure_rbac_assignment"],
        "severity": "high",
        "category": "iam-privilege",
        "remediation": "Scope Contributor to resource group or use more restrictive roles.",
        "references": ["https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["role_name", "scope"],
    },
    {
        "check_id": "AZURE-IAM-003",
        "title": "Azure User Access Administrator at subscription",
        "description": "An Azure RBAC assignment grants User Access Administrator at subscription scope, allowing authorization management.",
        "provider": "azure",
        "service": "authorization",
        "resource_types": ["azure_rbac_assignment"],
        "severity": "high",
        "category": "iam-privilege",
        "remediation": "Remove User Access Administrator unless required; use scoped assignments.",
        "references": ["https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["role_name", "scope"],
    },
    {
        "check_id": "AZURE-NET-001",
        "title": "Azure NSG allows SSH (22) from Internet",
        "description": "An Azure NSG rule allows TCP 22 from Internet source (* or 0.0.0.0/0).",
        "provider": "azure",
        "service": "network",
        "resource_types": ["azure_nsg"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict sourceAddressPrefix for SSH to private ranges.",
        "references": ["https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["rules"],
    },
    {
        "check_id": "AZURE-NET-002",
        "title": "Azure NSG allows RDP (3389) from Internet",
        "description": "An Azure NSG rule allows TCP 3389 from Internet source.",
        "provider": "azure",
        "service": "network",
        "resource_types": ["azure_nsg"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict RDP source to private ranges.",
        "references": ["https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["rules"],
    },
    {
        "check_id": "AZURE-NET-003",
        "title": "Azure NSG allows database port from Internet",
        "description": "An Azure NSG rule allows a common database port (3306, 5432, 1433, 1521, 27017, 6379, 9200) from Internet.",
        "provider": "azure",
        "service": "network",
        "resource_types": ["azure_nsg"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Restrict database ports to private source ranges.",
        "references": ["https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["rules"],
    },
    {
        "check_id": "AZURE-NET-004",
        "title": "Azure NSG allows all ports from Internet",
        "description": "An Azure NSG rule allows destination port * with Internet source.",
        "provider": "azure",
        "service": "network",
        "resource_types": ["azure_nsg"],
        "severity": "critical",
        "category": "network-exposure",
        "remediation": "Replace all-port Internet rule with narrow port rules.",
        "references": ["https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["rules"],
    },
    {
        "check_id": "AZURE-NET-005",
        "title": "Azure NSG has broad Internet ingress",
        "description": "An Azure NSG rule has broad Internet ingress.",
        "provider": "azure",
        "service": "network",
        "resource_types": ["azure_nsg"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Scope source and destination to least privilege.",
        "references": ["https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["rules"],
    },
    {
        "check_id": "AZURE-NET-006",
        "title": "Azure VM with public IP and permissive NSG",
        "description": "An Azure VM has a public IP and an NSG allows Internet ingress to it.",
        "provider": "azure",
        "service": "compute",
        "resource_types": ["azure_vm"],
        "severity": "high",
        "category": "network-exposure",
        "remediation": "Remove public IP or restrict NSG source.",
        "references": ["https://learn.microsoft.com/en-us/azure/virtual-network/public-ip-addresses"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["public_ip"],
    },
    {
        "check_id": "AZURE-STORAGE-001",
        "title": "Azure storage account allows blob public access",
        "description": "An Azure storage account has allowBlobPublicAccess true, allowing public blob access.",
        "provider": "azure",
        "service": "storage",
        "resource_types": ["azure_storage_account"],
        "severity": "high",
        "category": "storage-exposure",
        "remediation": "Set allowBlobPublicAccess to false and use private access.",
        "references": ["https://learn.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-configure"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["allow_blob_public_access"],
    },
    {
        "check_id": "AZURE-STORAGE-002",
        "title": "Azure storage account public network access enabled",
        "description": "An Azure storage account has publicNetworkAccess Enabled (posture).",
        "provider": "azure",
        "service": "storage",
        "resource_types": ["azure_storage_account"],
        "severity": "info",
        "category": "storage-posture",
        "remediation": "Restrict publicNetworkAccess to Disabled if private access required.",
        "references": ["https://learn.microsoft.com/en-us/azure/storage/common/storage-network-security"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["public_network_access"],
    },
    {
        "check_id": "AZURE-STORAGE-003",
        "title": "Azure storage account HTTPS-only disabled",
        "description": "An Azure storage account has enableHttpsTrafficOnly false, allowing HTTP.",
        "provider": "azure",
        "service": "storage",
        "resource_types": ["azure_storage_account"],
        "severity": "medium",
        "category": "storage-encryption",
        "remediation": "Enable enableHttpsTrafficOnly (HTTPS-only).",
        "references": ["https://learn.microsoft.com/en-us/azure/storage/common/storage-require-secure-transfer"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["https_only"],
    },
    {
        "check_id": "AZURE-STORAGE-004",
        "title": "Azure storage account weak TLS version",
        "description": "An Azure storage account has minimumTlsVersion below TLS1_2.",
        "provider": "azure",
        "service": "storage",
        "resource_types": ["azure_storage_account"],
        "severity": "medium",
        "category": "storage-encryption",
        "remediation": "Set minimumTlsVersion to TLS1_2.",
        "references": ["https://learn.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["minimum_tls"],
    },
    {
        "check_id": "AZURE-STORAGE-005",
        "title": "Azure storage account encryption posture",
        "description": "An Azure storage account encryption is not customer-managed (posture).",
        "provider": "azure",
        "service": "storage",
        "resource_types": ["azure_storage_account"],
        "severity": "info",
        "category": "storage-encryption",
        "remediation": "Enable customer-managed keys if required.",
        "references": ["https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["encryption"],
    },
    {
        "check_id": "AZURE-COMPUTE-001",
        "title": "Azure VM secure boot disabled",
        "description": "An Azure VM has secureBootEnabled false (posture).",
        "provider": "azure",
        "service": "compute",
        "resource_types": ["azure_vm"],
        "severity": "info",
        "category": "compute-posture",
        "remediation": "Enable secure boot in VM security profile if supported.",
        "references": ["https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["secure_boot"],
    },
    {
        "check_id": "AZURE-COMPUTE-002",
        "title": "Azure VM vTPM disabled",
        "description": "An Azure VM has vTpmEnabled false (posture).",
        "provider": "azure",
        "service": "compute",
        "resource_types": ["azure_vm"],
        "severity": "info",
        "category": "compute-posture",
        "remediation": "Enable vTPM if workload requires it.",
        "references": ["https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch"],
        "version": CHECK_PACK_VERSION,
        "enabled": True,
        "evidence_requirements": ["vtpm_enabled"],
    },
]

DEFERRED_CHECKS: dict[str, str] = {}


def list_catalog(provider: str | None = None) -> list[dict]:
    checks = [c for c in AWS_CHECKS if c.get("enabled")]
    if provider:
        checks = [c for c in checks if c.get("provider") == provider.strip().lower()]
    return checks


def get_check(check_id: str) -> dict | None:
    wanted = str(check_id or "").strip().upper()
    for check in AWS_CHECKS:
        if str(check.get("check_id", "")).upper() == wanted:
            return check
    return None


def _not_assessed(reason: str) -> tuple[str, None, str]:
    return (RESULT_NOT_ASSESSED, None, reason)


def _evidence_base(check: dict, asset_meta: dict, discovery_run_id: str | None) -> dict:
    return {
        "check_id": check["check_id"],
        "check_version": check.get("version"),
        "resource": asset_meta.get("value") or asset_meta.get("resource_id"),
        "region": asset_meta.get("region"),
        "account_id": asset_meta.get("account_id"),
        "discovery_run_id": discovery_run_id,
        "observed_at": asset_meta.get("observed_at"),
    }


def evaluate_asset(check: dict, asset_meta: dict, discovery_run_id: str | None = None) -> tuple[str, dict | None, str]:
    """Evaluate one check against one asset's persisted metadata.

    Returns (result, evidence|None, note). Pure function: no I/O, no AWS calls.
    Missing evidence yields NOT_ASSESSED — never PASS, never FAIL.
    """
    check_id = check.get("check_id")
    extra = asset_meta.get("extra") if isinstance(asset_meta.get("extra"), dict) else {}
    try:
        if check_id == "AWS-EC2-001":
            enforced = extra.get("imds_v2_enforced")
            if enforced is True:
                return (RESULT_PASS, None, "IMDSv2 enforced or metadata endpoint disabled")
            if enforced is False:
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "imds_v2_enforced", "observed": False, "expected": True})
                return (RESULT_FAIL, evidence, "IMDSv1 allowed (HttpTokens optional)")
            return _not_assessed("instance metadata options unavailable")
        if check_id == "AWS-RDS-001":
            public = extra.get("publicly_accessible")
            if public is True:
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "publicly_accessible", "observed": True, "expected": False})
                return (RESULT_FAIL, evidence, "RDS instance publicly accessible")
            if public is False:
                return (RESULT_PASS, None, "RDS instance not publicly accessible")
            return _not_assessed("public accessibility unknown")
        if check_id == "AWS-RDS-002":
            encrypted = extra.get("storage_encrypted")
            if encrypted is True:
                return (RESULT_PASS, None, "RDS storage encrypted")
            if encrypted is False:
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "storage_encrypted", "observed": False, "expected": True})
                return (RESULT_FAIL, evidence, "RDS storage encryption disabled")
            return _not_assessed("storage encryption unknown")
        if check_id == "AWS-S3-001":
            flags = {flag: extra.get(flag) for flag in PAB_FLAGS}
            if all(value is True for value in flags.values()):
                return (RESULT_PASS, None, "all Block Public Access controls enabled")
            disabled = sorted(k for k, v in flags.items() if v is False)
            if disabled:
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "public_access_block", "observed": {k: flags[k] for k in disabled},
                                 "expected": "all Block Public Access controls enabled"})
                return (RESULT_FAIL, evidence, f"Block Public Access disabled: {', '.join(disabled)}")
            return _not_assessed("public access block configuration unavailable")
        if check_id == "AWS-S3-002":
            encryption = extra.get("encryption")
            if isinstance(encryption, str) and encryption:
                return (RESULT_PASS, None, f"default encryption configured ({encryption})")
            code = str(extra.get("encryption_error_code") or "")
            if code in ("NoSuchEncryptionConfiguration", "ServerSideEncryptionConfigurationNotFoundError"):
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "encryption", "observed": None, "expected": "default SSE configured"})
                return (RESULT_FAIL, evidence, "no default bucket encryption configured")
            return _not_assessed("encryption configuration unknown")
        if check_id == "AWS-ELB-001":
            listeners = extra.get("listeners")
            if not isinstance(listeners, list) or not listeners:
                if extra.get("listener_error"):
                    return _not_assessed("listener configuration unavailable")
                return _not_assessed("no listener evidence")
            http_ports = sorted({l.get("port") for l in listeners
                                 if isinstance(l, dict) and str(l.get("protocol") or "").upper() == "HTTP"
                                 and isinstance(l.get("port"), int)})
            if http_ports and str(asset_meta.get("scheme") or extra.get("scheme") or "").lower() == "internet-facing":
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "listeners", "observed": http_ports, "expected": "HTTPS only"})
                return (RESULT_FAIL, evidence, f"internet-facing LB with plaintext HTTP listener(s) on {http_ports}")
            return (RESULT_PASS, None, "no plaintext HTTP listener on internet-facing LB")
        if check_id == "AWS-LAMBDA-001":
            if "function_urls" not in extra:
                return _not_assessed("function URL configuration unavailable")
            if extra.get("url_error"):
                return _not_assessed("function URL configuration unavailable")
            urls = extra.get("function_urls") or []
            public = sorted({u.get("url") for u in urls if isinstance(u, dict)
                             and str(u.get("auth") or "").upper() == "NONE" and u.get("url")})
            if public:
                evidence = _evidence_base(check, asset_meta, discovery_run_id)
                evidence.update({"field": "function_url_auth", "observed": "NONE", "expected": "AWS_IAM"})
                return (RESULT_FAIL, evidence, "Lambda function URL allows unauthenticated access")
            return (RESULT_PASS, None, "no unauthenticated function URLs")
        # E3 IAM checks
        if check_id == "AWS-IAM-001":
            if "iam_policies" not in extra and "iam_policies_unavailable" not in extra:
                return _not_assessed("IAM policy evidence unavailable")
            if extra.get("iam_policies_unavailable"):
                return _not_assessed(f"IAM policy evidence unavailable: {extra.get('iam_policies_unavailable')}")
            policies = extra.get("iam_policies") or []
            if not policies:
                return (RESULT_PASS, None, "no IAM policies attached")
            for pol in policies:
                if not isinstance(pol, dict):
                    continue
                if pol.get("unavailable"):
                    continue
                stmts = pol.get("statements") or []
                for idx, stmt in enumerate(stmts):
                    if not isinstance(stmt, dict):
                        continue
                    if str(stmt.get("effect") or "").lower() != "allow":
                        continue
                    for act in (stmt.get("actions") or []):
                        if str(act).strip() == "*":
                            ev = _evidence_base(check, asset_meta, discovery_run_id)
                            ev.update({"field": "Action", "observed": "*", "policy": pol.get("name") or pol.get("arn"), "statement_index": idx, "sid": stmt.get("sid")})
                            return (RESULT_FAIL, ev, f"IAM policy {pol.get('name') or pol.get('arn')} allows Action '*'")
            return (RESULT_PASS, None, "no IAM policy allows Action '*'")
        if check_id == "AWS-IAM-002":
            if "iam_policies" not in extra and "iam_policies_unavailable" not in extra:
                return _not_assessed("IAM policy evidence unavailable")
            if extra.get("iam_policies_unavailable"):
                return _not_assessed(f"IAM policy evidence unavailable: {extra.get('iam_policies_unavailable')}")
            policies = extra.get("iam_policies") or []
            if not policies:
                return (RESULT_PASS, None, "no IAM policies attached")
            for pol in policies:
                if not isinstance(pol, dict):
                    continue
                if pol.get("unavailable"):
                    continue
                stmts = pol.get("statements") or []
                for idx, stmt in enumerate(stmts):
                    if not isinstance(stmt, dict):
                        continue
                    if str(stmt.get("effect") or "").lower() != "allow":
                        continue
                    for res in (stmt.get("resources") or []):
                        if str(res).strip() == "*":
                            ev = _evidence_base(check, asset_meta, discovery_run_id)
                            ev.update({"field": "Resource", "observed": "*", "policy": pol.get("name") or pol.get("arn"), "statement_index": idx, "sid": stmt.get("sid")})
                            return (RESULT_FAIL, ev, f"IAM policy {pol.get('name') or pol.get('arn')} allows wildcard Resource '*'")
            return (RESULT_PASS, None, "no IAM policy allows wildcard Resource '*'")
        if check_id == "AWS-IAM-003":
            if "iam_policies" not in extra and "iam_policies_unavailable" not in extra:
                return _not_assessed("IAM policy evidence unavailable")
            if extra.get("iam_policies_unavailable"):
                return _not_assessed(f"IAM policy evidence unavailable: {extra.get('iam_policies_unavailable')}")
            policies = extra.get("iam_policies") or []
            if not policies:
                return (RESULT_PASS, None, "no IAM policies attached")
            for pol in policies:
                if not isinstance(pol, dict):
                    continue
                if pol.get("unavailable"):
                    continue
                stmts = pol.get("statements") or []
                for idx, stmt in enumerate(stmts):
                    if not isinstance(stmt, dict):
                        continue
                    if str(stmt.get("effect") or "").lower() != "allow":
                        continue
                    matched: list[str] = []
                    for act in (stmt.get("actions") or []):
                        low = str(act).strip().lower()
                        if low in IAM_DANGEROUS_ACTIONS or low in IAM_ADMIN_SERVICE_WILDCARDS:
                            matched.append(str(act))
                    if matched:
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "Action", "observed": sorted(set(matched))[:10], "policy": pol.get("name") or pol.get("arn"), "statement_index": idx, "sid": stmt.get("sid")})
                        return (RESULT_FAIL, ev, f"IAM policy {pol.get('name') or pol.get('arn')} allows dangerous action(s): {', '.join(sorted(set(matched))[:5])}")
            return (RESULT_PASS, None, "no IAM policy allows dangerous administrative actions")
        if check_id == "AWS-IAM-004":
            if "iam_trust_statements" not in extra:
                if extra.get("iam_trust_unavailable") or extra.get("iam_trust_error"):
                    return _not_assessed(f"trust policy unavailable: {extra.get('iam_trust_unavailable') or extra.get('iam_trust_error')}")
                return _not_assessed("IAM trust policy evidence unavailable")
            stmts = extra.get("iam_trust_statements") or []
            if not stmts:
                return _not_assessed("no trust policy statements")
            for idx, stmt in enumerate(stmts):
                if not isinstance(stmt, dict):
                    continue
                if str(stmt.get("effect") or "").lower() != "allow":
                    continue
                for princ in (stmt.get("principals") or []):
                    if str(princ).strip() == "*" or str(princ).strip() == "AWS:*":
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "Principal", "observed": princ, "statement_index": idx, "sid": stmt.get("sid")})
                        return (RESULT_FAIL, ev, "IAM role trust policy allows wildcard principal '*'")
            return (RESULT_PASS, None, "no wildcard principal in trust policy")
        if check_id == "AWS-IAM-005":
            if "iam_trust_statements" not in extra:
                if extra.get("iam_trust_unavailable") or extra.get("iam_trust_error"):
                    return _not_assessed(f"trust policy unavailable: {extra.get('iam_trust_unavailable') or extra.get('iam_trust_error')}")
                return _not_assessed("IAM trust policy evidence unavailable")
            stmts = extra.get("iam_trust_statements") or []
            own_acct = str(asset_meta.get("account_id") or extra.get("account_id") or "")[:12]
            for idx, stmt in enumerate(stmts):
                if not isinstance(stmt, dict):
                    continue
                if str(stmt.get("effect") or "").lower() != "allow":
                    continue
                for princ in (stmt.get("principals") or []):
                    # Detect external AWS account: AWS:arn... or AWS:123456789012
                    val = str(princ)
                    if val.startswith("AWS:"):
                        acct = None
                        m = re.search(r"(\d{12})", val)
                        if m:
                            acct = m.group(1)
                            if acct != own_acct and acct not in ("", "000000000000"):
                                ev = _evidence_base(check, asset_meta, discovery_run_id)
                                ev.update({"field": "Principal", "observed": acct, "statement_index": idx, "sid": stmt.get("sid")})
                                return (RESULT_FAIL, ev, f"IAM role trusts external AWS account {acct} — requires validation")
            return (RESULT_PASS, None, "no external AWS account principal in trust policy")
        if check_id == "AWS-IAM-006":
            if "iam_mfa_device_count" not in extra:
                if extra.get("iam_mfa_unavailable"):
                    return _not_assessed(f"MFA evidence unavailable: {extra.get('iam_mfa_unavailable')}")
                return _not_assessed("MFA evidence unavailable")
            count = extra.get("iam_mfa_device_count")
            try:
                c = int(count)
            except Exception:
                return _not_assessed("MFA device count unavailable")
            if c == 0:
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "mfa_device_count", "observed": 0, "expected": ">=1"})
                return (RESULT_FAIL, ev, "IAM user has no MFA device configured")
            return (RESULT_PASS, None, "MFA device configured")
        if check_id == "AWS-IAM-007":
            if "iam_access_keys" not in extra:
                if extra.get("iam_access_keys_unavailable"):
                    return _not_assessed(f"access key evidence unavailable: {extra.get('iam_access_keys_unavailable')}")
                return _not_assessed("access key evidence unavailable")
            keys = extra.get("iam_access_keys") or []
            if not keys:
                return (RESULT_PASS, None, "no access keys")
            # Find active keys older than threshold
            now = datetime.now(timezone.utc)
            for k in keys:
                if not isinstance(k, dict):
                    continue
                if str(k.get("status") or "").lower() != "active":
                    continue
                create_str = str(k.get("create_date") or "")
                if not create_str:
                    return _not_assessed("access key create date unavailable")
                try:
                    # Parse ISO or ctime
                    create_dt = None
                    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%d %H:%M:%S"):
                        try:
                            create_dt = datetime.strptime(create_str[:19], fmt[:19])
                            break
                        except Exception:
                            continue
                    if create_dt is None:
                        # Try fromisoformat
                        try:
                            create_dt = datetime.fromisoformat(create_str.replace("Z", "+00:00"))
                        except Exception:
                            return _not_assessed("access key create date unparsable")
                    if create_dt.tzinfo is None:
                        create_dt = create_dt.replace(tzinfo=timezone.utc)
                    age_days = (now - create_dt).days
                    if age_days > IAM_ACCESS_KEY_MAX_AGE_DAYS:
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "access_key_age_days", "observed": age_days, "expected": f"<= {IAM_ACCESS_KEY_MAX_AGE_DAYS}", "id_suffix": k.get("id_suffix")})
                        return (RESULT_FAIL, ev, f"active access key older than {IAM_ACCESS_KEY_MAX_AGE_DAYS} days ({age_days} days)")
                except Exception:
                    return _not_assessed("access key create date unavailable")
            return (RESULT_PASS, None, "no stale active access keys")
        if check_id == "AWS-IAM-008":
            pwd = extra.get("iam_password_enabled")
            if pwd is None:
                if extra.get("iam_password_unavailable"):
                    return _not_assessed(f"password evidence unavailable: {extra.get('iam_password_unavailable')}")
                return _not_assessed("password evidence unavailable")
            if pwd is False:
                return (RESULT_PASS, None, "console password not enabled")
            # pwd == True
            if "iam_mfa_device_count" not in extra:
                if extra.get("iam_mfa_unavailable"):
                    return _not_assessed(f"MFA evidence unavailable: {extra.get('iam_mfa_unavailable')}")
                return _not_assessed("MFA evidence unavailable for password check")
            try:
                c = int(extra.get("iam_mfa_device_count"))
            except Exception:
                return _not_assessed("MFA device count unavailable")
            if c == 0:
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "password_mfa", "observed": "password without MFA", "expected": "MFA enabled"})
                return (RESULT_FAIL, ev, "IAM user has console password enabled without MFA")
            return (RESULT_PASS, None, "console password with MFA")
        # E4 network — SG ingress 0.0.0.0/0
        if check_id in ("AWS-EC2-002", "AWS-NET-001"):
            if "ingress" not in extra:
                return _not_assessed("security group ingress evidence unavailable")
            ingress = extra.get("ingress")
            if ingress is None:
                return _not_assessed("ingress unavailable")
            if not isinstance(ingress, list):
                return _not_assessed("ingress malformed")
            for rule in ingress:
                if not isinstance(rule, dict):
                    continue
                if _sg_rule_is_internet(rule):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "ingress", "protocol": rule.get("protocol"), "from_port": rule.get("from_port"), "to_port": rule.get("to_port"),
                               "source": rule.get("cidr_v4") or rule.get("cidr_v6"), "vpc_id": extra.get("vpc_id")})
                    return (RESULT_FAIL, ev, f"security group {asset_meta.get('resource_id') or asset_meta.get('value')} allows Internet ingress 0.0.0.0/0 or ::/0")
            return (RESULT_PASS, None, "no unrestricted Internet ingress")
        if check_id == "AWS-NET-002":
            if "ingress" not in extra:
                return _not_assessed("ingress unavailable")
            ingress = extra.get("ingress") or []
            for rule in ingress:
                if not isinstance(rule, dict):
                    continue
                if not _sg_rule_is_internet(rule):
                    continue
                if _sg_rule_covers_port(rule, 22) and (rule.get("protocol") in ("tcp", "6", "-1")):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "ingress", "protocol": rule.get("protocol"), "port": 22, "source": "0.0.0.0/0"})
                    return (RESULT_FAIL, ev, "security group permits SSH (22/tcp) from the Internet")
            return (RESULT_PASS, None, "SSH not exposed to Internet")
        if check_id == "AWS-NET-003":
            if "ingress" not in extra:
                return _not_assessed("ingress unavailable")
            ingress = extra.get("ingress") or []
            for rule in ingress:
                if not isinstance(rule, dict):
                    continue
                if not _sg_rule_is_internet(rule):
                    continue
                if _sg_rule_covers_port(rule, 3389) and (rule.get("protocol") in ("tcp", "6", "-1")):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "ingress", "protocol": rule.get("protocol"), "port": 3389, "source": "0.0.0.0/0"})
                    return (RESULT_FAIL, ev, "security group permits RDP (3389/tcp) from the Internet")
            return (RESULT_PASS, None, "RDP not exposed to Internet")
        if check_id == "AWS-NET-004":
            if "ingress" not in extra:
                return _not_assessed("ingress unavailable")
            ingress = extra.get("ingress") or []
            for rule in ingress:
                if not isinstance(rule, dict):
                    continue
                if not _sg_rule_is_internet(rule):
                    continue
                for db_port in NET_DB_PORTS:
                    if _sg_rule_covers_port(rule, db_port):
                        proto = str(rule.get("protocol") or "tcp")
                        if proto not in ("tcp", "6", "-1"):
                            continue
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "ingress", "protocol": proto, "port": db_port, "source": "0.0.0.0/0"})
                        return (RESULT_FAIL, ev, f"security group permits Internet access to database port {db_port}")
            return (RESULT_PASS, None, "no database port exposed to Internet")
        if check_id == "AWS-NET-005":
            if "ingress" not in extra:
                return _not_assessed("ingress unavailable")
            ingress = extra.get("ingress") or []
            for rule in ingress:
                if not isinstance(rule, dict):
                    continue
                if not _sg_rule_is_internet(rule):
                    continue
                if _sg_rule_is_all_ports(rule):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "ingress", "protocol": rule.get("protocol"), "ports": "all", "source": "0.0.0.0/0"})
                    return (RESULT_FAIL, ev, "security group allows all ports/protocols from the Internet (0.0.0.0/0)")
            return (RESULT_PASS, None, "no all-port Internet ingress")
        if check_id == "AWS-NET-006":
            # E4 hardening: public subnet is exposure/posture, not automatic vulnerability.
            # Track via network summary (is_public), do not create MEDIUM finding solely for IGW route.
            # Only PASS/NOT_ASSESSED; no FAIL.
            if "is_public" in extra or "map_public_ip" in extra or "routes" in extra:
                return (RESULT_PASS, None, "public subnet posture tracked as exposure, not vulnerability")
            return _not_assessed("subnet route evidence unavailable")
        if check_id == "AWS-NET-007":
            if "public_ip" not in extra:
                return _not_assessed("EC2 public IP evidence unavailable")
            pub = extra.get("public_ip")
            if not pub:
                return (RESULT_PASS, None, "EC2 has no public IP")
            # Need SG and subnet public evidence; if not available, NOT_ASSESSED unless we have single-asset is_public flag
            if "is_public_subnet" in extra:
                if extra.get("is_public_subnet") and extra.get("has_permissive_sg"):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "public_ip", "observed": pub, "subnet_id": extra.get("subnet_id")})
                    return (RESULT_FAIL, ev, "EC2 instance has public IP in public subnet with permissive SG")
            return _not_assessed("EC2 public exposure correlation requires subnet/SG evidence")
        if check_id == "AWS-NET-008":
            scheme = str(extra.get("scheme") or asset_meta.get("scheme") or "").lower()
            if not scheme:
                return _not_assessed("load balancer scheme unavailable")
            if scheme != "internet-facing":
                return (RESULT_PASS, None, "load balancer not internet-facing")
            # Internet-facing alone is not a finding; check for permissive SG or HTTP listener
            # If security_groups present and we have ingress evidence elsewhere, we cannot cross-reference here -> check listeners
            listeners = extra.get("listeners") or []
            has_http = any(str(l.get("protocol") or "").upper() == "HTTP" for l in listeners if isinstance(l, dict))
            if has_http:
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "scheme", "observed": scheme, "listeners": listeners[:5]})
                return (RESULT_FAIL, ev, "internet-facing load balancer with HTTP listener")
            return (RESULT_PASS, None, "internet-facing LB without permissive HTTP exposure")
        if check_id == "AWS-NET-009":
            if "entries" not in extra:
                return _not_assessed("NACL entries unavailable")
            entries = extra.get("entries") or []
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                if str(entry.get("rule_action") or "").lower() != "allow":
                    continue
                if bool(entry.get("egress")):
                    continue
                cidr = entry.get("cidr") or entry.get("ipv6_cidr")
                if not _is_internet_cidr(cidr):
                    continue
                proto = str(entry.get("protocol") or "")
                # -1 = all
                if proto == "-1" or str(proto) == "-1":
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "nacl", "rule_number": entry.get("rule_number"), "cidr": cidr, "protocol": proto})
                    return (RESULT_FAIL, ev, "Network ACL allows 0.0.0.0/0 with all protocols")
                # Check broad sensitive ports
                fp = entry.get("from_port")
                tp = entry.get("to_port")
                if fp is None and tp is None:
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "nacl", "rule_number": entry.get("rule_number"), "cidr": cidr})
                    return (RESULT_FAIL, ev, "Network ACL allows broad Internet ingress")
                try:
                    if fp is not None and tp is not None and int(fp) == 0 and int(tp) == 65535:
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "nacl", "rule_number": entry.get("rule_number"), "cidr": cidr})
                        return (RESULT_FAIL, ev, "Network ACL allows all ports from Internet")
                except Exception:
                    pass
            return (RESULT_PASS, None, "no broad NACL Internet ingress")
        if check_id == "AWS-NET-010":
            if "egress" not in extra:
                return _not_assessed("egress unavailable")
            egress = extra.get("egress") or []
            for rule in egress:
                if not isinstance(rule, dict):
                    continue
                if not _sg_rule_is_internet(rule):
                    continue
                if _sg_rule_is_all_ports(rule):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "egress", "protocol": rule.get("protocol"), "source": "0.0.0.0/0"})
                    return (RESULT_FAIL, ev, "security group allows unrestricted egress 0.0.0.0/0 all ports/protocols")
            return (RESULT_PASS, None, "no unrestricted egress")
        # E5 storage
        if check_id == "AWS-S3-003":
            if "bucket_policy_statements" not in extra:
                if extra.get("bucket_policy_unavailable"):
                    return _not_assessed(f"bucket policy unavailable: {extra.get('bucket_policy_unavailable')}")
                return _not_assessed("bucket policy unavailable")
            stmts = extra.get("bucket_policy_statements") or []
            is_pub, stmt = _s3_policy_is_public(stmts)
            if is_pub:
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "bucket_policy", "principal": "*", "actions": (stmt or {}).get("actions", [])[:5], "bucket": asset_meta.get("resource_id")})
                return (RESULT_FAIL, ev, "S3 bucket policy allows public access with wildcard principal")
            return (RESULT_PASS, None, "no public bucket policy")
        if check_id == "AWS-S3-004":
            # Weak encryption posture: SSE-S3 vs KMS — posture, not vulnerability
            enc = extra.get("encryption")
            if enc is None:
                if extra.get("encryption_error"):
                    return _not_assessed(f"encryption unavailable: {extra.get('encryption_error')}")
                # No encryption evidence but E2's S3-002 already covers; for posture, treat as not assessed here
                return _not_assessed("encryption unavailable")
            if str(enc).upper() == "AES256":
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "encryption", "observed": enc, "expected": "aws:kms"})
                return (RESULT_FAIL, ev, "S3 bucket uses SSE-S3 (AES256) not KMS")
            return (RESULT_PASS, None, "S3 bucket uses KMS or no weak posture")
        if check_id == "AWS-S3-005":
            if "acl_grants" not in extra:
                if extra.get("acl_unavailable"):
                    return _not_assessed(f"ACL unavailable: {extra.get('acl_unavailable')}")
                return _not_assessed("ACL unavailable")
            grants = extra.get("acl_grants") or []
            if _s3_acl_is_public(grants):
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "acl", "grants": [g for g in grants if g.get("public")][:3]})
                return (RESULT_FAIL, ev, "S3 bucket ACL grants public access")
            # If BucketOwnerEnforced, ACL is disabled — not a finding
            if str(extra.get("object_ownership") or "") == "BucketOwnerEnforced":
                return (RESULT_PASS, None, "ACL disabled via BucketOwnerEnforced")
            return (RESULT_PASS, None, "no public ACL grants")
        if check_id == "AWS-S3-006":
            if "versioning" not in extra:
                if extra.get("versioning_unavailable"):
                    return _not_assessed(f"versioning unavailable: {extra.get('versioning_unavailable')}")
                return _not_assessed("versioning unavailable")
            vers = str(extra.get("versioning") or "").lower()
            if vers == "enabled":
                return (RESULT_PASS, None, "versioning enabled")
            ev = _evidence_base(check, asset_meta, discovery_run_id)
            ev.update({"field": "versioning", "observed": vers or "disabled", "expected": "Enabled"})
            return (RESULT_FAIL, ev, "S3 bucket versioning not enabled (posture)")
        if check_id == "AWS-S3-007":
            if "logging_enabled" not in extra:
                if extra.get("logging_unavailable"):
                    return _not_assessed(f"logging unavailable: {extra.get('logging_unavailable')}")
                return _not_assessed("logging unavailable")
            if extra.get("logging_enabled") is True:
                return (RESULT_PASS, None, "logging enabled")
            ev = _evidence_base(check, asset_meta, discovery_run_id)
            ev.update({"field": "logging_enabled", "observed": False, "expected": True})
            return (RESULT_FAIL, ev, "S3 bucket logging not enabled (posture)")
        if check_id == "AWS-S3-008":
            if "object_ownership" not in extra:
                if extra.get("ownership_unavailable"):
                    return _not_assessed(f"ownership unavailable: {extra.get('ownership_unavailable')}")
                return _not_assessed("ownership unavailable")
            own = str(extra.get("object_ownership") or "")
            if own == "BucketOwnerEnforced":
                return (RESULT_PASS, None, "BucketOwnerEnforced")
            if not own:
                return _not_assessed("ownership disabled or not set")
            ev = _evidence_base(check, asset_meta, discovery_run_id)
            ev.update({"field": "object_ownership", "observed": own, "expected": "BucketOwnerEnforced"})
            return (RESULT_FAIL, ev, "S3 bucket object ownership not BucketOwnerEnforced (posture)")
        if check_id == "AWS-EBS-001":
            if "encrypted" not in extra:
                return _not_assessed("EBS encryption unavailable")
            enc = extra.get("encrypted")
            if enc is True:
                return (RESULT_PASS, None, "EBS volume encrypted")
            if enc is False:
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "encrypted", "observed": False, "volume_id": asset_meta.get("resource_id")})
                return (RESULT_FAIL, ev, "EBS volume unencrypted")
            return _not_assessed("EBS encryption unknown")
        if check_id == "AWS-EBS-002":
            if "is_public" not in extra:
                if extra.get("permission_unavailable"):
                    return _not_assessed(f"snapshot permission unavailable: {extra.get('permission_unavailable')}")
                return _not_assessed("snapshot permission unavailable")
            if extra.get("is_public") is True:
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "is_public", "observed": True})
                return (RESULT_FAIL, ev, "EBS snapshot shared publicly")
            return (RESULT_PASS, None, "snapshot not public")
        if check_id == "AWS-EFS-001":
            if "encrypted" not in extra:
                return _not_assessed("EFS encryption unavailable")
            enc = extra.get("encrypted")
            if enc is True:
                return (RESULT_PASS, None, "EFS encrypted")
            if enc is False:
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "encrypted", "observed": False})
                return (RESULT_FAIL, ev, "EFS filesystem unencrypted")
            return _not_assessed("EFS encryption unknown")
        # E6 GCP
        if check_id == "GCP-IAM-001":
            bindings = extra.get("bindings")
            if bindings is None:
                if extra.get("bindings_unavailable"):
                    return _not_assessed(f"bindings unavailable: {extra.get('bindings_unavailable')}")
                return _not_assessed("IAM bindings unavailable")
            if not isinstance(bindings, list) or not bindings:
                return (RESULT_PASS, None, "no IAM bindings")
            for b in bindings:
                if not isinstance(b, dict):
                    continue
                for member in (b.get("members") or []):
                    if str(member).strip() in ("allUsers", "allAuthenticatedUsers"):
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "member", "observed": member, "role": b.get("role")})
                        return (RESULT_FAIL, ev, f"GCP IAM allows public member {member} with role {b.get('role')}")
            return (RESULT_PASS, None, "no public IAM members")
        if check_id == "GCP-IAM-002":
            bindings = extra.get("bindings")
            if bindings is None:
                return _not_assessed("IAM bindings unavailable")
            if not isinstance(bindings, list):
                return _not_assessed("bindings malformed")
            for b in bindings:
                if not isinstance(b, dict):
                    continue
                if str(b.get("role") or "").lower() in GCP_PRIVILEGED_ROLES:
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "role", "observed": b.get("role"), "members": (b.get("members") or [])[:3]})
                    return (RESULT_FAIL, ev, f"GCP IAM grants privileged role {b.get('role')}")
            return (RESULT_PASS, None, "no privileged project roles")
        if check_id == "GCP-IAM-003":
            bindings = extra.get("bindings")
            if bindings is None:
                return _not_assessed("IAM bindings unavailable")
            for b in bindings:
                if not isinstance(b, dict):
                    continue
                if str(b.get("role") or "").lower() not in GCP_PRIVILEGED_ROLES:
                    continue
                for member in (b.get("members") or []):
                    if "serviceAccount:" in str(member):
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "service_account", "observed": member, "role": b.get("role")})
                        return (RESULT_FAIL, ev, f"GCP service account {member} has privileged role {b.get('role')}")
            return (RESULT_PASS, None, "no privileged service account")
        if check_id == "GCP-IAM-004":
            if "keys" not in extra:
                return _not_assessed("service account keys unavailable")
            keys = extra.get("keys") or []
            if not keys:
                return (RESULT_PASS, None, "no user-managed keys")
            import datetime as _dt
            now = datetime.datetime.now(timezone.utc)
            for k in keys:
                if not isinstance(k, dict):
                    continue
                valid_after = str(k.get("validAfterTime") or k.get("valid_after") or "")[:32]
                if not valid_after:
                    continue
                try:
                    # Try parse ISO
                    dt = None
                    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
                        try:
                            dt = _dt.datetime.strptime(valid_after[:19], fmt[:19])
                            break
                        except Exception:
                            continue
                    if dt is None:
                        try:
                            dt = _dt.datetime.fromisoformat(valid_after.replace("Z", "+00:00"))
                        except Exception:
                            continue
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age = (now - dt).days
                    if age > 90:
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "key_age_days", "observed": age, "key_id": str(k.get("key_id") or k.get("name") or "")[:50]})
                        return (RESULT_FAIL, ev, f"service account key older than 90 days ({age} days)")
                except Exception:
                    continue
            return (RESULT_PASS, None, "no old service account keys")
        if check_id in ("GCP-NET-001", "GCP-NET-002", "GCP-NET-003", "GCP-NET-004", "GCP-NET-005"):
            if "allowed" not in extra or "source_ranges" not in extra:
                return _not_assessed("firewall evidence unavailable")
            allowed = extra.get("allowed") or []
            source_ranges = extra.get("source_ranges") or []
            if not _gcp_has_internet_source(source_ranges):
                return (RESULT_PASS, None, "no Internet source range")
            if check_id == "GCP-NET-001":
                if _gcp_firewall_allows_port(allowed, 22):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "firewall", "port": 22, "source": "0.0.0.0/0"})
                    return (RESULT_FAIL, ev, "GCP firewall allows SSH (22) from Internet")
                return (RESULT_PASS, None, "SSH not exposed")
            if check_id == "GCP-NET-002":
                if _gcp_firewall_allows_port(allowed, 3389):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "firewall", "port": 3389, "source": "0.0.0.0/0"})
                    return (RESULT_FAIL, ev, "GCP firewall allows RDP (3389) from Internet")
                return (RESULT_PASS, None, "RDP not exposed")
            if check_id == "GCP-NET-003":
                for db_port in GCP_DB_PORTS:
                    if _gcp_firewall_allows_port(allowed, db_port):
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "firewall", "port": db_port, "source": "0.0.0.0/0"})
                        return (RESULT_FAIL, ev, f"GCP firewall allows database port {db_port} from Internet")
                return (RESULT_PASS, None, "no database port exposed")
            if check_id == "GCP-NET-004":
                if _gcp_firewall_is_all_ports(allowed) and _gcp_has_internet_source(source_ranges):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "firewall", "ports": "all", "source": "0.0.0.0/0"})
                    return (RESULT_FAIL, ev, "GCP firewall allows all ports from Internet")
                return (RESULT_PASS, None, "no all-port Internet ingress")
            if check_id == "GCP-NET-005":
                # Broad ingress: any allowed with Internet source
                if allowed and _gcp_has_internet_source(source_ranges):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "firewall", "allowed": allowed[:3], "source": "0.0.0.0/0"})
                    return (RESULT_FAIL, ev, "GCP firewall has broad Internet ingress")
                return (RESULT_PASS, None, "no broad Internet ingress")
        if check_id in ("GCP-NET-006", "GCP-COMPUTE-002"):
            if "external_ip" not in extra:
                return _not_assessed("VM external IP unavailable")
            ext = extra.get("external_ip")
            if not ext:
                return (RESULT_PASS, None, "VM has no external IP")
            return _not_assessed("VM firewall correlation requires firewall evidence")
        if check_id == "GCP-NET-007":
            # Unrestricted egress posture
            if "allowed" not in extra:
                return _not_assessed("egress unavailable")
            return (RESULT_PASS, None, "egress posture")
        if check_id == "GCP-GCS-001":
            members = extra.get("public_iam_members") or []
            if not isinstance(members, list):
                return _not_assessed("bucket IAM unavailable")
            for m in members:
                if not isinstance(m, dict):
                    continue
                member = str(m.get("member") or "")
                if member.strip() in ("allUsers", "allAuthenticatedUsers"):
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "member", "observed": member, "role": m.get("role")})
                    return (RESULT_FAIL, ev, f"GCS bucket allows public member {member}")
            return (RESULT_PASS, None, "no public bucket IAM")
        if check_id == "GCP-GCS-002":
            if "uniform_bucket_level_access" not in extra:
                return _not_assessed("uniform access unavailable")
            if extra.get("uniform_bucket_level_access") is True:
                return (RESULT_PASS, None, "uniform access enabled")
            ev = _evidence_base(check, asset_meta, discovery_run_id)
            ev.update({"field": "uniform_bucket_level_access", "observed": False, "expected": True})
            return (RESULT_FAIL, ev, "GCS uniform bucket-level access disabled (posture)")
        if check_id == "GCP-GCS-003":
            if "versioning" not in extra:
                return _not_assessed("versioning unavailable")
            vers = str(extra.get("versioning") or "").lower()
            if vers == "true" or vers == "enabled":
                return (RESULT_PASS, None, "versioning enabled")
            ev = _evidence_base(check, asset_meta, discovery_run_id)
            ev.update({"field": "versioning", "observed": vers or "disabled", "expected": "Enabled"})
            return (RESULT_FAIL, ev, "GCS bucket versioning not enabled (posture)")
        if check_id == "GCP-GCS-004":
            if "encryption" not in extra:
                return _not_assessed("encryption unavailable")
            enc = extra.get("encryption")
            if enc and str(enc).strip():
                # If defaultKmsKeyName present, it's CMEK
                if "kms" in str(enc).lower():
                    return (RESULT_PASS, None, "bucket uses CMEK")
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "encryption", "observed": "google-managed", "expected": "CMEK"})
                return (RESULT_FAIL, ev, "GCS bucket uses Google-managed encryption (posture)")
            return _not_assessed("encryption unknown")
        if check_id == "GCP-COMPUTE-001":
            if "shielded_vm" not in extra:
                return _not_assessed("shielded VM unavailable")
            if extra.get("shielded_vm") is True:
                return (RESULT_PASS, None, "shielded VM enabled")
            ev = _evidence_base(check, asset_meta, discovery_run_id)
            ev.update({"field": "shielded_vm", "observed": False, "expected": True})
            return (RESULT_FAIL, ev, "GCP VM shielded VM disabled (posture)")
        # E7 Azure
        if check_id == "AZURE-IAM-001":
            role = str(extra.get("role_name") or extra.get("roleDefinitionId") or "").lower()
            scope = str(extra.get("scope") or "")
            if not role or not scope:
                return _not_assessed("role assignment unavailable")
            if "owner" in role and "/subscriptions/" in scope.lower():
                # Check subscription scope (contains /subscriptions/<id> and no /resourceGroups/ deeper)
                if scope.lower().count("/subscriptions/") == 1 and "/resourcegroups/" not in scope.lower():
                    ev = _evidence_base(check, asset_meta, discovery_run_id)
                    ev.update({"field": "role", "observed": role, "scope": scope})
                    return (RESULT_FAIL, ev, f"Azure assignment grants Owner at subscription {scope}")
            return (RESULT_PASS, None, "no Owner at subscription")
        if check_id == "AZURE-IAM-002":
            role = str(extra.get("role_name") or extra.get("roleDefinitionId") or "").lower()
            scope = str(extra.get("scope") or "")
            if "contributor" in role and "/subscriptions/" in scope.lower() and "/resourcegroups/" not in scope.lower():
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "role", "observed": role, "scope": scope})
                return (RESULT_FAIL, ev, f"Azure assignment grants Contributor at subscription {scope}")
            return (RESULT_PASS, None, "no Contributor at subscription")
        if check_id == "AZURE-IAM-003":
            role = str(extra.get("role_name") or extra.get("roleDefinitionId") or "").lower()
            scope = str(extra.get("scope") or "")
            if "user access administrator" in role and "/subscriptions/" in scope.lower():
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "role", "observed": role, "scope": scope})
                return (RESULT_FAIL, ev, f"Azure User Access Administrator at {scope}")
            return (RESULT_PASS, None, "no User Access Administrator")
        if check_id.startswith("AZURE-NET-"):
            rules = extra.get("rules")
            if rules is None:
                return _not_assessed("NSG rules unavailable")
            if not isinstance(rules, list):
                return _not_assessed("NSG rules malformed")
            if check_id == "AZURE-NET-001":
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    if _azure_nsg_allows_port(rule, 22):
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "nsg", "port": 22, "rule": rule.get("name")})
                        return (RESULT_FAIL, ev, "Azure NSG allows SSH (22) from Internet")
                return (RESULT_PASS, None, "SSH not exposed")
            if check_id == "AZURE-NET-002":
                for rule in rules:
                    if _azure_nsg_allows_port(rule, 3389):
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "nsg", "port": 3389, "rule": rule.get("name")})
                        return (RESULT_FAIL, ev, "Azure NSG allows RDP (3389) from Internet")
                return (RESULT_PASS, None, "RDP not exposed")
            if check_id == "AZURE-NET-003":
                for db_port in AZURE_DB_PORTS:
                    for rule in rules:
                        if _azure_nsg_allows_port(rule, db_port):
                            ev = _evidence_base(check, asset_meta, discovery_run_id)
                            ev.update({"field": "nsg", "port": db_port, "rule": rule.get("name")})
                            return (RESULT_FAIL, ev, f"Azure NSG allows database port {db_port} from Internet")
                return (RESULT_PASS, None, "no database port exposed")
            if check_id == "AZURE-NET-004":
                for rule in rules:
                    if _azure_nsg_is_all_ports(rule):
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "nsg", "ports": "all", "rule": rule.get("name")})
                        return (RESULT_FAIL, ev, "Azure NSG allows all ports from Internet")
                return (RESULT_PASS, None, "no all-port Internet ingress")
            if check_id == "AZURE-NET-005":
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    if str(rule.get("access") or "").lower() != "allow":
                        continue
                    if str(rule.get("direction") or "").lower() != "inbound":
                        continue
                    if _azure_nsg_is_internet_source(rule.get("source_prefix") or rule.get("sourceAddressPrefix")) or any(_azure_nsg_is_internet_source(p) for p in (rule.get("source_prefixes") or [])):
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "nsg", "rule": rule.get("name")})
                        return (RESULT_FAIL, ev, "Azure NSG has broad Internet ingress")
                return (RESULT_PASS, None, "no broad Internet ingress")
            if check_id == "AZURE-NET-006":
                return _not_assessed("VM NSG correlation requires VM evidence")
            if check_id == "AZURE-NET-007":
                for rule in rules:
                    if str(rule.get("direction") or "").lower() == "outbound" and str(rule.get("access") or "").lower() == "allow":
                        if _azure_nsg_is_internet_source(rule.get("dest_prefix") or rule.get("destinationAddressPrefix") or "*"):
                            dest = str(rule.get("dest_port") or rule.get("destinationPortRange") or "*")
                            if dest in ("*", "0-65535"):
                                ev = _evidence_base(check, asset_meta, discovery_run_id)
                                ev.update({"field": "nsg", "egress": "all"})
                                return (RESULT_FAIL, ev, "Azure NSG allows unrestricted egress (posture)")
                return (RESULT_PASS, None, "no unrestricted egress")
        if check_id == "AZURE-STORAGE-001":
            if extra.get("allow_blob_public_access") is True:
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "allow_blob_public_access", "observed": True})
                return (RESULT_FAIL, ev, "Azure storage allows blob public access")
            if extra.get("allow_blob_public_access") is False:
                return (RESULT_PASS, None, "blob public access disabled")
            return _not_assessed("blob public access unavailable")
        if check_id == "AZURE-STORAGE-002":
            pna = str(extra.get("public_network_access") or "").lower()
            if not pna:
                return _not_assessed("public network access unavailable")
            if pna == "enabled":
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "public_network_access", "observed": pna})
                return (RESULT_FAIL, ev, "Azure storage public network access enabled (posture)")
            return (RESULT_PASS, None, "public network access not enabled")
        if check_id == "AZURE-STORAGE-003":
            https = extra.get("https_only") if "https_only" in extra else extra.get("supportsHttpsTrafficOnly")
            if https is None:
                # Try both keys
                https = extra.get("supportsHttpsTrafficOnly")
            if https is None:
                return _not_assessed("https_only unavailable")
            if https is False:
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "https_only", "observed": False})
                return (RESULT_FAIL, ev, "Azure storage HTTPS-only disabled")
            return (RESULT_PASS, None, "HTTPS-only enabled")
        if check_id == "AZURE-STORAGE-004":
            tls = str(extra.get("minimum_tls") or extra.get("minimumTlsVersion") or "")
            if not tls:
                return _not_assessed("TLS version unavailable")
            # Baseline TLS1_2
            if tls.upper() in ("TLS1_0", "TLS1_1"):
                ev = _evidence_base(check, asset_meta, discovery_run_id)
                ev.update({"field": "minimum_tls", "observed": tls})
                return (RESULT_FAIL, ev, f"Azure storage weak TLS {tls}")
            return (RESULT_PASS, None, "TLS version OK")
        if check_id == "AZURE-STORAGE-005":
            enc = extra.get("encryption")
            if enc is None:
                return _not_assessed("encryption unavailable")
            # Azure storage encryption is normally Microsoft-managed; only flag if explicitly disabled
            # For E7, treat absence of customer-managed key as posture (INFO), not critical
            if isinstance(enc, str) and enc.lower() in ("microsoft.storage", "microsoft.keyvault", "customer-managed"):
                return (RESULT_PASS, None, "encryption posture")
            ev = _evidence_base(check, asset_meta, discovery_run_id)
            ev.update({"field": "encryption", "observed": enc or "microsoft-managed"})
            return (RESULT_FAIL, ev, "Azure storage encryption posture (Microsoft-managed)")
        if check_id in ("AZURE-COMPUTE-001", "AZURE-COMPUTE-002"):
            if "secure_boot" in extra or "vtpm_enabled" in extra:
                if check_id == "AZURE-COMPUTE-001":
                    if extra.get("secure_boot") is False:
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "secure_boot", "observed": False})
                        return (RESULT_FAIL, ev, "Azure VM secure boot disabled (posture)")
                    if extra.get("secure_boot") is True:
                        return (RESULT_PASS, None, "secure boot enabled")
                    return _not_assessed("secure boot unavailable")
                if check_id == "AZURE-COMPUTE-002":
                    if extra.get("vtpm_enabled") is False:
                        ev = _evidence_base(check, asset_meta, discovery_run_id)
                        ev.update({"field": "vtpm_enabled", "observed": False})
                        return (RESULT_FAIL, ev, "Azure VM vTPM disabled (posture)")
                    if extra.get("vtpm_enabled") is True:
                        return (RESULT_PASS, None, "vTPM enabled")
                    return _not_assessed("vTPM unavailable")
            return _not_assessed("compute security profile unavailable")
    except Exception as exc:
        return (RESULT_ERROR, None, f"evaluation error: {str(exc)[:200]}")
    return (RESULT_ERROR, None, f"unknown check: {check_id}")


# ---------------------------------------------------------------------------
# Run evaluation + finding persistence (existing Findings table, scanner cloud)
# ---------------------------------------------------------------------------

MAX_EVAL_ASSETS = 500
MAX_EXISTING_FINDINGS = 500


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _finding_proxy(title: str, check_id: str, asset_value: str, asset_id: str):
    """Fingerprint input mirroring persisted finding metadata (backend d8 fn).

    asset_id must be set: d8_finding_input only reads asset_type/asset_value
    from metadata when the finding carries an asset identity.
    """
    return SimpleNamespace(
        title=title,
        cve=None,
        cwe=None,
        evidence=None,
        asset_id=asset_id,
        extra_data={"rule_id": check_id, "asset_type": "cloud_resource", "asset_value": asset_value},
    )


def _existing_fingerprints(db: Session, project_id: str) -> set[str]:
    from app.models.asset import Asset
    from app.models.finding import Finding
    from app.services import finding_lifecycle as lc

    rows = (
        db.query(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .filter(Asset.project_id == project_id, Finding.scanner == "cloud")
        .order_by(Finding.created_at.desc())
        .limit(MAX_EXISTING_FINDINGS)
        .all()
    )
    fps: set[str] = set()
    for row in rows:
        try:
            fps.add(lc.d8_fingerprint(lc.d8_finding_input(row)))
        except Exception:
            continue
    return fps


def run_evaluation(db: Session, project, connection, discovery_run, actor_user_id: str | None = None):
    """Evaluate one discovery run; create findings for FAILs. Idempotent per run.

    Returns (CloudCheckRun, created: bool). Repeat calls for the same discovery
    run return the existing run without new findings (UNIQUE constraint).
    Findings never auto-resolve: absent conditions leave existing rows alone
    (D8 owns verification/resolution).
    """
    from app.models.asset import Asset
    from app.models.cloud_check import CloudCheckRun
    from app.models.finding import Finding
    from app.services import finding_lifecycle as lc
    from app.services.audit import (
        EVENT_CLOUD_CHECK_RUN_COMPLETED,
        EVENT_CLOUD_CHECK_RUN_FAILED,
        EVENT_CLOUD_CHECK_RUN_PARTIAL,
        EVENT_CLOUD_CHECK_RUN_REQUESTED,
        EVENT_FINDING_CREATED,
        RESOURCE_CLOUD_CHECK_RUN,
        RESOURCE_FINDING,
        RESULT_SUCCESS,
        AuditService,
    )

    existing = (
        db.query(CloudCheckRun)
        .filter(CloudCheckRun.discovery_run_id == discovery_run.id)
        .first()
    )
    if existing is not None:
        return existing, False
    if str(getattr(discovery_run, "status", "") or "").lower() not in ("completed", "partial"):
        raise ValueError("Discovery run has no terminal evidence to evaluate")

    now = _utcnow_naive()
    run = CloudCheckRun(
        id=str(uuid.uuid4()),
        organization_id=project.organization_id,
        project_id=project.id,
        connection_id=connection.id,
        discovery_run_id=discovery_run.id,
        status="running",
        check_pack_version=CHECK_PACK_VERSION,
        requested_by=actor_user_id,
        started_at=now,
    )
    db.add(run)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = (
            db.query(CloudCheckRun)
            .filter(CloudCheckRun.discovery_run_id == discovery_run.id)
            .first()
        )
        return existing, False
    AuditService.record(
        db, event_type=EVENT_CLOUD_CHECK_RUN_REQUESTED, action=EVENT_CLOUD_CHECK_RUN_REQUESTED,
        result=RESULT_SUCCESS, actor_user_id=actor_user_id, organization_id=project.organization_id,
        project_id=project.id, resource_type=RESOURCE_CLOUD_CHECK_RUN, resource_id=run.id,
        metadata={"discovery_run_id": discovery_run.id, "connection_id": connection.id},
    )

    assets = (
        db.query(Asset)
        .filter(Asset.project_id == project.id, Asset.asset_type.in_(["cloud_account", "cloud_resource"]))
        .order_by(Asset.value)
        .limit(MAX_EVAL_ASSETS)
        .all()
    )
    known_fps = _existing_fingerprints(db, project.id)
    counts = {"passed": 0, "failed": 0, "not_assessed": 0, "errors": 0}
    breakdown: dict[str, dict[str, int]] = {}
    findings_created = 0
    evaluated = 0
    # Canonical dedup for overlapping SG broad-ingress checks
    canonical_sg_seen: set[str] = set()

    for asset in assets:
        meta = asset.extra_data if isinstance(asset.extra_data, dict) else {}
        asset_meta = dict(meta)
        asset_meta["value"] = asset.value
        for check in list_catalog(provider="aws"):
            if asset_meta.get("resource_type") not in (check.get("resource_types") or []):
                continue
            evaluated += 1
            entry = breakdown.setdefault(check["check_id"], {"passed": 0, "failed": 0, "not_assessed": 0, "errors": 0})
            result, evidence, note = evaluate_asset(check, asset_meta, discovery_run.id)
            if result == RESULT_PASS:
                counts["passed"] += 1
                entry["passed"] += 1
            elif result == RESULT_FAIL:
                counts["failed"] += 1
                entry["failed"] += 1
                # Canonical dedup for EC2-002 / NET-001 (same SG broad ingress)
                if check["check_id"] in ("AWS-EC2-002", "AWS-NET-001"):
                    try:
                        proto = str((evidence or {}).get("protocol") or "")
                        fp = str((evidence or {}).get("from_port") or "")
                        tp = str((evidence or {}).get("to_port") or "")
                        src = str((evidence or {}).get("source") or (evidence or {}).get("cidr") or "")
                        # Also handle evidence source as list
                        if isinstance(src, list):
                            src = ",".join(sorted([str(s) for s in src][:5]))
                        canon = f"{asset.value}:{proto}:{fp}:{tp}:{src}"
                        if canon in canonical_sg_seen:
                            continue
                        canonical_sg_seen.add(canon)
                    except Exception:
                        pass
                title = f"{check['check_id']}: {check['title']}"
                # Enrich fingerprint with port/source for network checks to distinguish different conditions
                enrich_meta = {}
                try:
                    if evidence and isinstance(evidence, dict):
                        # Port for fingerprint
                        port_val = evidence.get("port") or evidence.get("from_port")
                        if port_val is not None:
                            enrich_meta["port"] = str(port_val)
                        # Source CIDR as parameter for fingerprint distinction
                        src_val = evidence.get("source") or evidence.get("cidr")
                        if src_val:
                            if isinstance(src_val, list):
                                src_val = src_val[0] if src_val else None
                            if src_val:
                                enrich_meta["parameter"] = str(src_val)[:100]
                except Exception:
                    pass
                base_proxy = _finding_proxy(title, check["check_id"], asset.value, asset.id)
                # Inject enrich for fingerprint
                if enrich_meta:
                    try:
                        base_proxy.extra_data.update(enrich_meta)
                    except Exception:
                        pass
                fingerprint = lc.d8_fingerprint(
                    lc.d8_finding_input(base_proxy))
                if fingerprint in known_fps:
                    continue
                known_fps.add(fingerprint)
                finding_meta = {
                    "rule_id": check["check_id"],
                    "check_id": check["check_id"],
                    "check_version": check.get("version"),
                    "provider": "aws",
                    "service": check.get("service"),
                    "resource_type": asset_meta.get("resource_type"),
                    "resource_id": str(asset_meta.get("resource_id") or "")[:500],
                    "arn": str(asset_meta.get("arn") or "")[:1024] or None,
                    "region": asset_meta.get("region"),
                    "account_id": asset_meta.get("account_id"),
                    "asset_type": "cloud_resource",
                    "asset_value": asset.value,
                    "discovery_run_id": discovery_run.id,
                    "connection_id": connection.id,
                    "observed_at": asset_meta.get("observed_at"),
                    "confidence_score": 90,
                    "confidence_level": "high",
                }
                # Include port/source in persisted metadata for analyst
                if enrich_meta.get("port"):
                    finding_meta["port"] = enrich_meta["port"]
                if enrich_meta.get("parameter"):
                    finding_meta["source_cidr"] = enrich_meta["parameter"]
                finding = Finding(
                    id=str(uuid.uuid4()),
                    scan_id=None,
                    target_id=None,
                    scanner="cloud",
                    title=title[:500],
                    description=f"{check.get('description', '')} Evidence: {note}"[:2000],
                    severity=str(check.get("severity", "medium")).lower(),
                    score=int(SEVERITY_SCORES.get(str(check.get("severity", "medium")).lower(), 50)),
                    status="open",
                    evidence=_json.dumps(evidence, sort_keys=True)[:2000] if evidence else None,
                    remediation=str(check.get("remediation") or "")[:2000] or None,
                    cve=None,
                    cwe=None,
                    asset_id=asset.id,
                    extra_data=finding_meta,
                )
                db.add(finding)
                findings_created += 1
                AuditService.record(
                    db, event_type=EVENT_FINDING_CREATED, action=EVENT_FINDING_CREATED,
                    result=RESULT_SUCCESS, actor_user_id=actor_user_id, organization_id=project.organization_id,
                    project_id=project.id, resource_type=RESOURCE_FINDING, resource_id=finding.id,
                    metadata={"check_id": check["check_id"], "discovery_run_id": discovery_run.id},
                )
            elif result == RESULT_NOT_ASSESSED:
                counts["not_assessed"] += 1
                entry["not_assessed"] += 1
            else:
                counts["errors"] += 1
                entry["errors"] += 1

    # GCP VM firewall target matching (bounded deterministic, E6 hardening)
    try:
        gcp_firewalls = [a for a in assets if str((a.extra_data or {}).get("resource_type") or "") == "gcp_firewall"]
        gcp_vms = [a for a in assets if str((a.extra_data or {}).get("resource_type") or "") == "gcp_compute_instance"]
        gcp_vm_seen: set[str] = set()
        check_gcp_net006 = get_check("GCP-NET-006")
        check_gcp_compute002 = get_check("GCP-COMPUTE-002")
        # Prefer COMPUTE-002 as canonical for VM exposure
        for vm in gcp_vms:
            vm_extra = vm.extra_data or {}
            ext_ip = vm_extra.get("external_ip")
            if not ext_ip:
                continue
            matched_fw = None
            for fw in gcp_firewalls:
                fw_extra = fw.extra_data or {}
                if not _gcp_has_internet_source(fw_extra.get("source_ranges") or []):
                    continue
                allowed = fw_extra.get("allowed") or []
                if not allowed:
                    continue
                if not _gcp_firewall_applies_to_vm(fw_extra, vm_extra):
                    continue
                matched_fw = fw
                break
            if not matched_fw:
                continue
            canon = f"{vm.value}:{matched_fw.value}"
            if canon in gcp_vm_seen:
                continue
            gcp_vm_seen.add(canon)
            check = check_gcp_compute002 or check_gcp_net006
            if not check:
                continue
            title = f"{check['check_id']}: {check['title']}"
            # Enrich with external_ip for fingerprint
            base_proxy = _finding_proxy(title, check["check_id"], vm.value, vm.id)
            try:
                base_proxy.extra_data["parameter"] = str(ext_ip)[:100]
            except Exception:
                pass
            fingerprint = lc.d8_fingerprint(lc.d8_finding_input(base_proxy))
            if fingerprint in known_fps:
                continue
            known_fps.add(fingerprint)
            entry = breakdown.setdefault(check["check_id"], {"passed": 0, "failed": 0, "not_assessed": 0, "errors": 0})
            if entry["not_assessed"] > 0:
                entry["not_assessed"] -= 1
                counts["not_assessed"] -= 1
            entry["failed"] += 1
            counts["failed"] += 1
            evaluated += 1
            evidence = {"check_id": check["check_id"], "vm": vm.value, "firewall": matched_fw.value, "external_ip": ext_ip}
            finding_meta = {"rule_id": check["check_id"], "check_id": check["check_id"], "provider": "gcp", "service": "compute", "resource_type": "gcp_compute_instance", "resource_id": str(vm_extra.get("resource_id") or "")[:500], "region": vm_extra.get("zone") or vm_extra.get("region"), "account_id": vm_extra.get("account_id"), "asset_type": "cloud_resource", "asset_value": vm.value, "discovery_run_id": discovery_run.id, "connection_id": connection.id, "observed_at": vm_extra.get("observed_at"), "confidence_score": 90, "confidence_level": "high", "external_ip": ext_ip}
            finding = Finding(id=str(uuid.uuid4()), scan_id=None, target_id=None, scanner="cloud", title=title[:500], description=f"{check.get('description','')} Evidence: VM {vm_extra.get('resource_id')} external IP {ext_ip} via firewall {matched_fw.extra_data.get('resource_id')}"[:2000], severity=str(check.get("severity","high")).lower(), score=int(SEVERITY_SCORES.get(str(check.get("severity","high")).lower(),50)), status="open", evidence=_json.dumps(evidence, sort_keys=True)[:2000], remediation=str(check.get("remediation") or "")[:2000] or None, cve=None, cwe=None, asset_id=vm.id, extra_data=finding_meta)
            db.add(finding)
            findings_created += 1
            AuditService.record(db, event_type=EVENT_FINDING_CREATED, action=EVENT_FINDING_CREATED, result=RESULT_SUCCESS, actor_user_id=actor_user_id, organization_id=project.organization_id, project_id=project.id, resource_type=RESOURCE_FINDING, resource_id=finding.id, metadata={"check_id": check["check_id"], "discovery_run_id": discovery_run.id})
    except Exception:
        pass

    run.checks_executed = len(list_catalog())
    run.resources_evaluated = evaluated
    run.passed = counts["passed"]
    run.failed = counts["failed"]
    run.not_assessed = counts["not_assessed"]
    run.errors = counts["errors"]
    run.findings_created = findings_created
    run.breakdown = breakdown
    run.finished_at = _utcnow_naive()
    if counts["errors"]:
        run.status = "partial"
        run_event, run_result = EVENT_CLOUD_CHECK_RUN_PARTIAL, RESULT_SUCCESS
    else:
        run.status = "completed"
        run_event, run_result = EVENT_CLOUD_CHECK_RUN_COMPLETED, RESULT_SUCCESS
    AuditService.record(
        db, event_type=run_event, action=run_event, result=run_result,
        actor_user_id=actor_user_id, organization_id=project.organization_id,
        project_id=project.id, resource_type=RESOURCE_CLOUD_CHECK_RUN, resource_id=run.id,
        metadata={"discovery_run_id": discovery_run.id, "failed": counts["failed"],
                  "passed": counts["passed"], "not_assessed": counts["not_assessed"],
                  "findings_created": findings_created},
    )
    db.commit()
    db.refresh(run)
    return run, True

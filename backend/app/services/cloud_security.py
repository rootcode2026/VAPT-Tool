"""Cloud Security domain — provider-neutral, extends worker/app/cloud/* foundation.

Reuses canonical assets (cloud_account, cloud_resource), relationships, FindingEngine.
No real credentials, no live SDK.
"""
from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.finding import Finding

# provider-neutral checks — extended from worker/app/cloud/checks.py but safe
PROVIDER_CHECKS = [
    {"check_id": "CLOUD-001", "title": "Cloud resource should have tags", "severity": "low", "provider": "aws", "resource_type": "ec2"},
    {"check_id": "CLOUD-002", "title": "Storage should not be publicly accessible", "severity": "high", "provider": "aws", "resource_type": "s3"},
    {"check_id": "CLOUD-003", "title": "GCP resource should be in allowed region", "severity": "medium", "provider": "gcp", "resource_type": "compute"},
    {"check_id": "CLOUD-004", "title": "Publicly exposed storage bucket", "severity": "critical", "provider": "aws", "resource_type": "s3"},
    {"check_id": "CLOUD-005", "title": "Insecure security group — 0.0.0.0/0 ingress", "severity": "critical", "provider": "aws", "resource_type": "sg"},
    {"check_id": "CLOUD-006", "title": "Encryption disabled for storage", "severity": "high", "provider": "aws", "resource_type": "ebs"},
    {"check_id": "CLOUD-007", "title": "Publicly accessible database", "severity": "critical", "provider": "aws", "resource_type": "rds"},
    {"check_id": "CLOUD-008", "title": "Weak IAM policy — overly permissive", "severity": "high", "provider": "aws", "resource_type": "iam"},
]

def get_cloud_summary(project_id: str, db: Session) -> dict:
    # assets
    account_q = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_account")
    resource_q = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_resource")
    accounts = account_q.scalar() or 0
    resources = resource_q.scalar() or 0

    # provider breakdown via value prefix cloud_account:{provider}:
    provider_counts = {}
    for provider in ("aws", "gcp", "azure"):
        cnt = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.asset_type.in_(["cloud_account", "cloud_resource"]), Asset.value.like(f"%:{provider}:%")).scalar() or 0
        provider_counts[provider] = cnt

    # findings: cloud scanner (asset-scoped so scanless E2 findings count).
    cloud_findings_q = (
        db.query(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .filter(Asset.project_id == project_id, Finding.scanner == "cloud")
    )
    total_findings = cloud_findings_q.count() or 0
    sev = {}
    for s in ("critical", "high", "medium", "low", "info"):
        sev[s] = cloud_findings_q.filter(Finding.severity == s).count() or 0

    # exposure classification via asset exposure helper if available
    exposed = 0
    public_resources = 0
    try:
        assets = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_resource").limit(200).all()
        for a in assets:
            meta = a.extra_data if isinstance(a.extra_data, dict) else {}
            if str(meta.get("public", "")).lower() == "true" or str(meta.get("exposure", "")).upper() == "INTERNET_EXPOSED":
                exposed += 1
            if "public" in str(meta).lower():
                public_resources = exposed
    except Exception:
        pass

    # relationships
    rel_cnt = db.query(func.count(AssetRelationship.id)).filter(AssetRelationship.project_id == project_id).scalar() or 0

    return {
        "project_id": project_id,
        "accounts": accounts,
        "resources": resources,
        "by_provider": provider_counts,
        "findings": {
            "total": total_findings,
            "critical": sev["critical"],
            "high": sev["high"],
            "medium": sev["medium"],
            "low": sev["low"],
            "info": sev["info"],
        },
        "exposure": {
            "exposed_resources": exposed,
            "public_resources": public_resources,
        },
        "relationships": rel_cnt,
        "checks": PROVIDER_CHECKS,
        "providers": ["aws", "gcp", "azure"],
    }

def list_cloud_accounts(project_id: str, db: Session, provider: str | None = None) -> list[dict]:
    q = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_account")
    if provider:
        q = q.filter(Asset.value.like(f"%:{provider}:%"))
    rows = q.limit(100).all()
    out = []
    for a in rows:
        meta = a.extra_data if isinstance(a.extra_data, dict) else {}
        # sanitize: never expose secret fields
        safe_meta = {k: v for k, v in (meta.items() if isinstance(meta, dict) else []) if "secret" not in k.lower() and "private" not in k.lower() and "token" not in k.lower()}
        out.append({"id": a.id, "value": a.value, "asset_type": a.asset_type, "metadata": safe_meta})
    return out

def list_cloud_resources(project_id: str, db: Session, provider: str | None = None, exposed_only: bool = False) -> list[dict]:
    q = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_resource")
    if provider:
        q = q.filter(Asset.value.like(f"%:{provider}:%"))
    rows = q.limit(200).all()
    out = []
    for a in rows:
        meta = a.extra_data if isinstance(a.extra_data, dict) else {}
        is_exposed = str(meta.get("public", "")).lower() == "true" or str(meta.get("exposure", "")).upper() == "INTERNET_EXPOSED"
        if exposed_only and not is_exposed:
            continue
        safe_meta = {k: v for k, v in (meta.items() if isinstance(meta, dict) else []) if "secret" not in k.lower() and "credential" not in k.lower()}
        out.append({"id": a.id, "value": a.value, "asset_type": a.asset_type, "metadata": safe_meta, "exposed": is_exposed})
    return out

def list_cloud_findings(project_id: str, db: Session, page: int = 1, page_size: int = 50, severity: str | None = None) -> dict:
    q = (
        db.query(Finding)
        .join(Asset, Asset.id == Finding.asset_id)
        .filter(Asset.project_id == project_id, Finding.scanner == "cloud")
    )
    if severity:
        q = q.filter(Finding.severity == severity.strip().lower())
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    rows = q.order_by(Finding.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    items = []
    for f in rows:
        meta = f.extra_data if isinstance(f.extra_data, dict) else {}
        # sanitize
        safe_meta = {k: v for k, v in (meta.items() if isinstance(meta, dict) else []) if "secret" not in k.lower()}
        items.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "scanner": f.scanner,
            "asset_id": f.asset_id,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "metadata": safe_meta,
        })
    return {"items": items, "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}

def list_cloud_checks(provider: str | None = None) -> list[dict]:
    if provider:
        provider = provider.strip().lower()
        return [c for c in PROVIDER_CHECKS if c["provider"] == provider]
    return PROVIDER_CHECKS

def cross_domain_relationships(project_id: str, db: Session) -> list[dict]:
    # deterministic relationships: repository->iac_resource, iac_resource->cloud_resource, container_image->cloud_resource, api_endpoint->cloud_resource
    # only return existing relationships where evidence exists (via AssetRelationship)
    rels = db.query(AssetRelationship).filter(AssetRelationship.project_id == project_id).limit(200).all()
    # build map
    assets = {a.id: a for a in db.query(Asset).filter(Asset.project_id == project_id).all()}
    out = []
    for r in rels:
        src = assets.get(r.source_asset_id)
        tgt = assets.get(r.target_asset_id)
        if not src or not tgt:
            continue
        # only include cross-domain: code <-> cloud
        code_types = {"repository", "source_file", "package", "container_image", "iac_resource", "api_endpoint"}
        cloud_types = {"cloud_account", "cloud_resource"}
        if (src.asset_type in code_types and tgt.asset_type in cloud_types) or (src.asset_type in cloud_types and tgt.asset_type in code_types) or (src.asset_type in code_types and tgt.asset_type in code_types):
            out.append({"id": r.id, "source_type": src.asset_type, "target_type": tgt.asset_type, "relationship_type": r.relationship_type, "source_id": src.id, "target_id": tgt.id})
    return out


def list_iam_identities(project_id: str, db: Session) -> list[dict]:
    """E3 IAM identities: roles/users/groups with bounded metadata (no secrets)."""
    iam_types = ("aws_iam_role", "aws_iam_user", "aws_iam_group")
    rows = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_resource").limit(500).all()
    out: list[dict] = []
    for a in rows:
        meta = a.extra_data if isinstance(a.extra_data, dict) else {}
        rtype = str(meta.get("resource_type") or "")
        if rtype not in iam_types:
            continue
        # Sanitize: strip any secret-like keys, limit policies
        safe_meta: dict = {}
        for k in ("resource_type", "resource_id", "arn", "region", "account_id", "name", "path", "created"):
            if k in meta:
                safe_meta[k] = str(meta[k])[:500] if isinstance(meta[k], str) else meta[k]
        # Bounded policy summary (counts only, not full documents for list)
        policies = meta.get("iam_policies") or []
        if isinstance(policies, list):
            safe_meta["policy_count"] = len(policies)
            safe_meta["policies"] = [
                {"type": p.get("type"), "name": str(p.get("name") or p.get("arn") or "")[:200], "is_aws_managed": p.get("is_aws_managed"), "unavailable": bool(p.get("unavailable"))}
                for p in policies[:10] if isinstance(p, dict)
            ]
        if "iam_trust_statements" in meta:
            safe_meta["trust_statement_count"] = len(meta.get("iam_trust_statements") or [])
        if "iam_mfa_device_count" in meta:
            safe_meta["mfa_device_count"] = meta.get("iam_mfa_device_count")
        if "iam_access_keys" in meta:
            safe_meta["access_key_count"] = len(meta.get("iam_access_keys") or [])
        if "iam_password_enabled" in meta:
            safe_meta["password_enabled"] = meta.get("iam_password_enabled")
        out.append({"id": a.id, "value": a.value, "asset_type": a.asset_type, "metadata": safe_meta})
        if len(out) >= 200:
            break
    return out


def get_network_summary(project_id: str, db: Session) -> dict:
    """E4 network posture summary — bounded, deterministic, no secrets."""
    NETWORK_TYPES = {
        "aws_vpc": 0, "aws_subnet": 0, "aws_route_table": 0, "aws_internet_gateway": 0,
        "aws_nat_gateway": 0, "aws_network_acl": 0, "aws_security_group": 0,
        "aws_network_interface": 0, "aws_ec2_instance": 0, "aws_alb": 0, "aws_nlb": 0, "aws_elb": 0,
    }
    rows = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_resource").limit(500).all()
    counts = dict(NETWORK_TYPES)
    public_subnets = 0
    internet_gateways = 0
    exposed_sgs = 0
    # Pre-collect for public subnet detection (exposure, not vulnerability)
    route_tables = [r for r in rows if str((r.extra_data or {}).get("resource_type") or "") == "aws_route_table"]
    igws = [r for r in rows if str((r.extra_data or {}).get("resource_type") or "") == "aws_internet_gateway"]
    def _is_public_subnet(meta: dict) -> bool:
        vpc_id = str(meta.get("vpc_id") or "")
        subnet_id = str(meta.get("resource_id") or meta.get("subnet_id") or "")
        # VPC must have IGW
        has_igw = False
        for igw in igws:
            ig_meta = igw.extra_data or {}
            if str(ig_meta.get("vpc_id") or "") == vpc_id:
                has_igw = True
                break
            for att in (ig_meta.get("attachments") or []):
                if isinstance(att, dict) and str(att.get("vpc_id") or "") == vpc_id:
                    has_igw = True
                    break
        if not has_igw:
            return False
        # Find associated or main route table with IGW route
        candidate_rts = []
        for rt in route_tables:
            rt_meta = rt.extra_data or {}
            if str(rt_meta.get("vpc_id") or "") != vpc_id:
                continue
            for assoc in (rt_meta.get("associations") or []):
                if isinstance(assoc, dict) and str(assoc.get("subnet_id") or "") == subnet_id:
                    candidate_rts.append(rt)
            if not candidate_rts:
                for assoc in (rt_meta.get("associations") or []):
                    if isinstance(assoc, dict) and assoc.get("main"):
                        if rt not in candidate_rts:
                            candidate_rts.append(rt)
        if not candidate_rts:
            candidate_rts = [rt for rt in route_tables if str((rt.extra_data or {}).get("vpc_id") or "") == vpc_id]
        for rt in candidate_rts:
            for route in ((rt.extra_data or {}).get("routes") or []):
                if not isinstance(route, dict):
                    continue
                dest = route.get("destination_cidr") or route.get("destination_ipv6")
                gw = str(route.get("gateway_id") or "")
                if str(dest or "").strip() in ("0.0.0.0/0", "::/0") and gw.startswith("igw-"):
                    return True
        return False
    for a in rows:
        meta = a.extra_data if isinstance(a.extra_data, dict) else {}
        rtype = str(meta.get("resource_type") or "")
        if rtype in counts:
            counts[rtype] += 1
        if rtype == "aws_internet_gateway":
            internet_gateways += 1
        if rtype == "aws_subnet" and _is_public_subnet(meta):
            public_subnets += 1
        if rtype == "aws_security_group":
            for rule in (meta.get("ingress") or []):
                if isinstance(rule, dict):
                    for cidr in (rule.get("cidr_v4") or []) + (rule.get("cidr_v6") or []):
                        if cidr.strip() in ("0.0.0.0/0", "::/0"):
                            exposed_sgs += 1
                            break
                    else:
                        continue
                    break
    # Network findings: scanner cloud + rule_id NET or EC2-002
    net_findings = db.query(Finding).join(Asset, Asset.id == Finding.asset_id).filter(
        Asset.project_id == project_id, Finding.scanner == "cloud",
        Finding.extra_data["rule_id"].astext.in_(["AWS-EC2-002", "AWS-NET-001", "AWS-NET-002", "AWS-NET-003", "AWS-NET-004", "AWS-NET-005", "AWS-NET-006", "AWS-NET-007", "AWS-NET-008", "AWS-NET-009", "AWS-NET-010"])
    ).count() if False else 0
    # Fallback without JSONB intext for sqlite: count via python
    try:
        all_findings = db.query(Finding).join(Asset, Asset.id == Finding.asset_id).filter(Asset.project_id == project_id, Finding.scanner == "cloud").limit(500).all()
        net_ids = {"AWS-EC2-002", "AWS-NET-001", "AWS-NET-002", "AWS-NET-003", "AWS-NET-004", "AWS-NET-005", "AWS-NET-006", "AWS-NET-007", "AWS-NET-008", "AWS-NET-009", "AWS-NET-010"}
        net_findings = sum(1 for f in all_findings if str((f.extra_data or {}).get("rule_id") or "").upper() in net_ids)
    except Exception:
        net_findings = 0
    # NOT_ASSESSED from last check run breakdown
    not_assessed = 0
    try:
        from app.models.cloud_check import CloudCheckRun
        last = db.query(CloudCheckRun).filter(CloudCheckRun.project_id == project_id).order_by(CloudCheckRun.created_at.desc()).first()
        if last and isinstance(last.breakdown, dict):
            for cid, vals in last.breakdown.items():
                if cid.startswith("AWS-NET-") or cid == "AWS-EC2-002":
                    not_assessed += int((vals or {}).get("not_assessed") or 0)
    except Exception:
        pass
    return {
        "project_id": project_id,
        "counts": counts,
        "public_subnets": public_subnets,
        "internet_gateways": internet_gateways,
        "exposed_security_groups": exposed_sgs,
        "network_findings": net_findings,
        "not_assessed": not_assessed,
    }


def get_storage_summary(project_id: str, db: Session) -> dict:
    """E5 storage posture summary — bounded, no secrets, no object enumeration."""
    STORAGE_TYPES = {
        "aws_s3_bucket": 0, "aws_ebs_volume": 0, "aws_ebs_snapshot": 0,
        "aws_efs_filesystem": 0, "aws_rds_instance": 0,
    }
    rows = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_resource").limit(500).all()
    counts = dict(STORAGE_TYPES)
    public_s3 = 0
    unencrypted_ebs = 0
    public_snapshots = 0
    unencrypted_efs = 0
    for a in rows:
        meta = a.extra_data if isinstance(a.extra_data, dict) else {}
        rtype = str(meta.get("resource_type") or "")
        if rtype in counts:
            counts[rtype] += 1
        if rtype == "aws_s3_bucket":
            # Public via policy or ACL
            stmts = meta.get("bucket_policy_statements") or []
            is_public = False
            for stmt in stmts:
                if not isinstance(stmt, dict):
                    continue
                if str(stmt.get("effect") or "").lower() != "allow":
                    continue
                for p in (stmt.get("principals") or []):
                    if str(p).strip() in ("*", "AWS:*"):
                        for act in (stmt.get("actions") or []):
                            if str(act).lower().startswith("s3:"):
                                is_public = True
                                break
                if is_public:
                    break
            if not is_public:
                for grant in (meta.get("acl_grants") or []):
                    if isinstance(grant, dict) and grant.get("public"):
                        is_public = True
                        break
            if is_public:
                public_s3 += 1
        if rtype == "aws_ebs_volume" and meta.get("encrypted") is False:
            unencrypted_ebs += 1
        if rtype == "aws_ebs_snapshot" and meta.get("is_public") is True:
            public_snapshots += 1
        if rtype == "aws_efs_filesystem" and meta.get("encrypted") is False:
            unencrypted_efs += 1
    try:
        all_findings = db.query(Finding).join(Asset, Asset.id == Finding.asset_id).filter(Asset.project_id == project_id, Finding.scanner == "cloud").limit(500).all()
        storage_ids = {"AWS-S3-001", "AWS-S3-002", "AWS-S3-003", "AWS-S3-004", "AWS-S3-005", "AWS-S3-006", "AWS-S3-007", "AWS-S3-008", "AWS-EBS-001", "AWS-EBS-002", "AWS-EFS-001", "AWS-RDS-002"}
        storage_findings = sum(1 for f in all_findings if str((f.extra_data or {}).get("rule_id") or "").upper() in storage_ids)
    except Exception:
        storage_findings = 0
    not_assessed = 0
    try:
        from app.models.cloud_check import CloudCheckRun
        last = db.query(CloudCheckRun).filter(CloudCheckRun.project_id == project_id).order_by(CloudCheckRun.created_at.desc()).first()
        if last and isinstance(last.breakdown, dict):
            for cid, vals in last.breakdown.items():
                if cid.startswith("AWS-S3-") or cid.startswith("AWS-EBS-") or cid.startswith("AWS-EFS-"):
                    not_assessed += int((vals or {}).get("not_assessed") or 0)
    except Exception:
        pass
    return {
        "project_id": project_id,
        "counts": counts,
        "public_s3_buckets": public_s3,
        "unencrypted_ebs_volumes": unencrypted_ebs,
        "public_snapshots": public_snapshots,
        "unencrypted_efs": unencrypted_efs,
        "storage_findings": storage_findings,
        "not_assessed": not_assessed,
    }


def get_gcp_summary(project_id: str, db: Session) -> dict:
    """E6 GCP posture — bounded, no secrets."""
    GCP_TYPES = {
        "gcp_project": 0, "gcp_compute_instance": 0, "gcp_disk": 0, "gcp_vpc": 0, "gcp_subnet": 0,
        "gcp_firewall": 0, "gcp_storage_bucket": 0, "gcp_service_account": 0, "gcp_iam_policy": 0,
    }
    rows = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_resource").limit(500).all()
    counts = dict(GCP_TYPES)
    public_buckets = 0
    public_firewalls = 0
    for a in rows:
        meta = a.extra_data if isinstance(a.extra_data, dict) else {}
        rtype = str(meta.get("resource_type") or "")
        if rtype in counts:
            counts[rtype] += 1
        if rtype == "gcp_storage_bucket":
            for m in (meta.get("public_iam_members") or []):
                if isinstance(m, dict) and str(m.get("member") or "") in ("allUsers", "allAuthenticatedUsers"):
                    public_buckets += 1
                    break
        if rtype == "gcp_firewall":
            for cidr in (meta.get("source_ranges") or []):
                if str(cidr).strip() in ("0.0.0.0/0", "::/0"):
                    public_firewalls += 1
                    break
    try:
        all_findings = db.query(Finding).join(Asset, Asset.id == Finding.asset_id).filter(Asset.project_id == project_id, Finding.scanner == "cloud").limit(500).all()
        gcp_ids = {c["check_id"] for c in __import__("app.services.cloud_checks", fromlist=["AWS_CHECKS"]).AWS_CHECKS if str(c.get("provider") or "").lower() == "gcp"}
        gcp_findings = sum(1 for f in all_findings if str((f.extra_data or {}).get("rule_id") or "").upper() in gcp_ids)
    except Exception:
        gcp_findings = 0
    not_assessed = 0
    try:
        from app.models.cloud_check import CloudCheckRun
        last = db.query(CloudCheckRun).filter(CloudCheckRun.project_id == project_id).order_by(CloudCheckRun.created_at.desc()).first()
        if last and isinstance(last.breakdown, dict):
            for cid, vals in last.breakdown.items():
                if cid.startswith("GCP-"):
                    not_assessed += int((vals or {}).get("not_assessed") or 0)
    except Exception:
        pass
    return {
        "project_id": project_id,
        "counts": counts,
        "public_buckets": public_buckets,
        "public_firewalls": public_firewalls,
        "gcp_findings": gcp_findings,
        "not_assessed": not_assessed,
    }


def get_azure_summary(project_id: str, db: Session) -> dict:
    """E7 Azure posture — bounded, no secrets."""
    AZURE_TYPES = {
        "azure_subscription": 0, "azure_resource_group": 0, "azure_vm": 0, "azure_disk": 0, "azure_vnet": 0, "azure_subnet": 0,
        "azure_nsg": 0, "azure_public_ip": 0, "azure_storage_account": 0, "azure_rbac_assignment": 0,
    }
    rows = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_resource").limit(500).all()
    counts = dict(AZURE_TYPES)
    public_storage = 0
    public_nsg = 0
    for a in rows:
        meta = a.extra_data if isinstance(a.extra_data, dict) else {}
        rtype = str(meta.get("resource_type") or "")
        if rtype in counts:
            counts[rtype] += 1
        if rtype == "azure_storage_account" and meta.get("allow_blob_public_access") is True:
            public_storage += 1
        if rtype == "azure_nsg":
            for rule in (meta.get("rules") or []):
                if isinstance(rule, dict) and str(rule.get("access") or "").lower() == "allow" and str(rule.get("direction") or "").lower() == "inbound":
                    src = str(rule.get("source_prefix") or rule.get("sourceAddressPrefix") or "")
                    if src.strip() in ("*", "0.0.0.0/0", "Internet", "::/0"):
                        dest = str(rule.get("dest_port") or rule.get("destinationPortRange") or "")
                        # Consider any allow from Internet as public
                        public_nsg += 1
                        break
    try:
        all_findings = db.query(Finding).join(Asset, Asset.id == Finding.asset_id).filter(Asset.project_id == project_id, Finding.scanner == "cloud").limit(500).all()
        azure_ids = {c["check_id"] for c in __import__("app.services.cloud_checks", fromlist=["AWS_CHECKS"]).AWS_CHECKS if str(c.get("provider") or "").lower() == "azure"}
        azure_findings = sum(1 for f in all_findings if str((f.extra_data or {}).get("rule_id") or "").upper() in azure_ids)
    except Exception:
        azure_findings = 0
    not_assessed = 0
    try:
        from app.models.cloud_check import CloudCheckRun
        last = db.query(CloudCheckRun).filter(CloudCheckRun.project_id == project_id).order_by(CloudCheckRun.created_at.desc()).first()
        if last and isinstance(last.breakdown, dict):
            for cid, vals in last.breakdown.items():
                if cid.startswith("AZURE-"):
                    not_assessed += int((vals or {}).get("not_assessed") or 0)
    except Exception:
        pass
    return {
        "project_id": project_id,
        "counts": counts,
        "public_storage_accounts": public_storage,
        "public_nsgs": public_nsg,
        "azure_findings": azure_findings,
        "not_assessed": not_assessed,
    }

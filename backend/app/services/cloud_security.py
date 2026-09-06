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
from app.models.scan import Scan
from app.models.target import Target

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

    # findings: cloud scanner
    cloud_findings_q = (
        db.query(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.project_id == project_id, Finding.scanner == "cloud")
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
        .join(Scan, Scan.id == Finding.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.project_id == project_id, Finding.scanner == "cloud")
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

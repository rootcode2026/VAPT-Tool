"""Code Security domain — SAST/SCA/Secrets/Container/IaC/API via existing FindingEngine/Asset model.

Uses existing tables: findings (scanner), assets, targets, scans, relationships.
No new tables, no new scanners, no duplicate finding pipeline.
"""
from __future__ import annotations

import re
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target

CODE_SCANNERS = {"sast", "sca", "secrets", "container", "iac", "api"}
# Map to display
SCANNER_FAMILY = {
    "sast": "SAST",
    "sca": "SCA",
    "secrets": "Secrets",
    "container": "Container",
    "iac": "IaC",
    "api": "API",
}

REDACTED = "[REDACTED]"
_SECRET_RE = re.compile(r"(?i)(password|secret|token|api[_-]?key|aws_secret|private_key)\s*[:=]\s*[^\s]+")

def _sanitize_evidence(text: str | None) -> str | None:
    if not text:
        return text
    # ensure any secret value is redacted
    if any(k in text.lower() for k in ("password", "secret", "token", "private_key", "api_key")):
        return _SECRET_RE.sub(r"\1=" + REDACTED, text)[:2000]
    return text[:2000] if len(text) > 2000 else text

def _finding_query(project_id: str, db: Session):
    return (
        db.query(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.project_id == project_id)
    )

def get_code_security_summary(project_id: str, db: Session) -> dict:
    base = _finding_query(project_id, db).filter(Finding.scanner.in_(list(CODE_SCANNERS)))
    total = base.count() or 0
    # by severity
    sev_counts = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        sev_counts[sev] = base.filter(Finding.severity == sev).count() or 0
    # by status
    open_f = base.filter(Finding.status.in_(["open", "detected", "corroborated", "needs_review", "confirmed"])).count() or 0
    confirmed = base.filter(Finding.status == "confirmed").count() or 0
    false_positive = base.filter(Finding.status == "false_positive").count() or 0
    # by scanner
    by_scanner = {}
    for sc in CODE_SCANNERS:
        by_scanner[sc] = base.filter(Finding.scanner == sc).count() or 0

    # assets
    repo_count = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.asset_type == "repository").scalar() or 0
    source_file_count = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.asset_type == "source_file").scalar() or 0
    package_count = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.asset_type == "package").scalar() or 0
    container_count = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.asset_type == "container_image").scalar() or 0
    iac_count = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.asset_type == "iac_resource").scalar() or 0
    api_count = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.asset_type == "api_endpoint").scalar() or 0

    # recent scans with code profile
    recent_scans = (
        db.query(Scan)
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.project_id == project_id, Scan.profile.in_(["code", "code_full", "sast", "sca", "secrets", "container", "iac", "api"]))
        .order_by(Scan.created_at.desc())
        .limit(5)
        .all()
    )

    return {
        "project_id": project_id,
        "findings": {
            "total": total,
            "open": open_f,
            "confirmed": confirmed,
            "false_positive": false_positive,
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "low": sev_counts["low"],
            "info": sev_counts["info"],
        },
        "by_scanner": by_scanner,
        "by_scanner_display": {SCANNER_FAMILY[k]: v for k, v in by_scanner.items()},
        "assets": {
            "repository": repo_count,
            "source_file": source_file_count,
            "package": package_count,
            "container_image": container_count,
            "iac_resource": iac_count,
            "api_endpoint": api_count,
        },
        "recent_scans": [
            {"id": s.id, "profile": s.profile, "status": s.status, "created_at": s.created_at.isoformat() if s.created_at else None}
            for s in recent_scans
        ],
    }

def list_code_findings(project_id: str, db: Session, page: int = 1, page_size: int = 50, scanner: str | None = None, severity: str | None = None, status: str | None = None, search: str | None = None) -> dict:
    q = _finding_query(project_id, db).filter(Finding.scanner.in_(list(CODE_SCANNERS)))
    if scanner:
        sc = scanner.strip().lower()
        if sc in CODE_SCANNERS:
            q = q.filter(Finding.scanner == sc)
    if severity:
        q = q.filter(Finding.severity == severity.strip().lower())
    if status:
        q = q.filter(Finding.status == status.strip().lower())
    if search and search.strip():
        lookup = search.strip()[:256].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        q = q.filter((Finding.title.ilike(f"%{lookup}%", escape="\\")) | (Finding.description.ilike(f"%{lookup}%", escape="\\")))
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    rows = q.order_by(Finding.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    items = []
    for f in rows:
        # sanitize evidence for secrets
        ev = f.evidence
        if f.scanner == "secrets":
            ev = _sanitize_evidence(ev)
            # also sanitize description/metadata
        meta = f.extra_data if isinstance(f.extra_data, dict) else {}
        # ensure no secret in metadata
        if f.scanner == "secrets" and isinstance(meta, dict):
            for k in list(meta.keys()):
                if isinstance(meta[k], str) and any(s in k.lower() for s in ("secret", "token", "password", "key", "credential")):
                    meta[k] = REDACTED
        items.append({
            "id": f.id,
            "scan_id": f.scan_id,
            "target_id": f.target_id,
            "scanner": f.scanner,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "evidence": ev,
            "asset_id": f.asset_id,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "metadata": meta,
        })
    return {"items": items, "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}

def list_code_targets(project_id: str, db: Session) -> list[dict]:
    targets = db.query(Target).filter(Target.project_id == project_id).all()
    # filter to code-relevant target types where possible
    code_types = {"repository", "source_snapshot", "branch", "commit", "container_image", "iac_directory", "api_spec", "directory", "project", "path"}
    out = []
    for t in targets:
        out.append({
            "id": t.id,
            "value": t.value,
            "target_type": t.target_type,
            "is_code": t.target_type in code_types,
            "project_id": t.project_id,
        })
    return out

def get_asset_relationships(project_id: str, db: Session, asset_type: str | None = None) -> list[dict]:
    q = db.query(AssetRelationship).filter(AssetRelationship.project_id == project_id)
    rows = q.limit(200).all()
    return [
        {"id": r.id, "source_asset_id": r.source_asset_id, "target_asset_id": r.target_asset_id, "relationship_type": r.relationship_type}
        for r in rows
    ]

"""E16 Application Security Intelligence — deterministic aggregation over existing AppSec signals."""
from __future__ import annotations
import re
import uuid
import hashlib
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from sqlalchemy.orm.attributes import flag_modified

from app.models.application import Application, ApplicationAsset, VALID_APP_TYPES, VALID_LIFECYCLES, VALID_STATUSES, VALID_CRITICALITIES, VALID_LINK_TYPES, VALID_CONFIDENCES
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.project import Project

# Bounds
MAX_APPLICATIONS = 500
MAX_FINDINGS = 500
MAX_ASSETS = 500
MAX_CORRELATIONS = 200
MAX_CHANGES = 200

def _sanitize(value: str, max_len: int = 500) -> str:
    if not value:
        return ""
    lower = value.lower()
    if any(k in lower for k in ("secret","private_key","credential","token","password")):
        return "[REDACTED]"
    return value[:max_len]

def _redact_evidence(ev: str | None) -> str | None:
    if not ev:
        return ev
    lower = ev.lower()
    if "secret" in lower or "password" in lower or "token" in lower:
        return "[REDACTED]"
    return ev[:500]

def _normalize_name(name: str) -> str:
    return name.strip()

def _validate_name(name: str):
    if not name or not name.strip():
        raise ValueError("Name required")
    if len(name.strip()) > 200:
        raise ValueError("Name too long (max 200)")
    if len(name.strip()) < 2:
        raise ValueError("Name too short")

def _validate_type(v: str):
    if v not in VALID_APP_TYPES:
        raise ValueError(f"Invalid application_type: {v}")

def _validate_lifecycle(v: str):
    if v not in VALID_LIFECYCLES:
        raise ValueError(f"Invalid lifecycle: {v}")

def _validate_status(v: str):
    if v not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {v}")

# CRUD
def create_application(project_id: str, db: Session, name: str, description: str | None = None, application_type: str = "UNKNOWN", lifecycle: str = "UNKNOWN", criticality: str = "unknown", owner_user_id: str | None = None, primary_domain: str | None = None, organization_id: str | None = None) -> Application:
    _validate_name(name)
    _validate_type(application_type)
    _validate_lifecycle(lifecycle)
    if criticality not in VALID_CRITICALITIES:
        raise ValueError(f"Invalid criticality: {criticality}")
    if lifecycle not in VALID_LIFECYCLES:
        raise ValueError(f"Invalid lifecycle: {lifecycle}")
    proj = db.query(Project).filter(Project.id == project_id).first()
    if not proj:
        raise ValueError("Project not found")
    org_id = organization_id or proj.organization_id
    if org_id != proj.organization_id:
        raise ValueError("Organization mismatch")
    count = db.query(func.count(Application.id)).filter(Application.project_id == project_id).scalar() or 0
    if count >= MAX_APPLICATIONS:
        raise ValueError("Maximum applications reached")
    # duplicate check (case-insensitive)
    existing = db.query(Application).filter(Application.project_id == project_id, func.lower(Application.name) == name.strip().lower()).first()
    if existing:
        raise ValueError("Application already exists")
    # owner validation
    if owner_user_id:
        from app.models.user import User
        u = db.query(User).filter(User.id == owner_user_id, User.organization_id == org_id).first()
        if not u:
            raise ValueError("Owner not found in organization")
    # primary_domain validation simple
    if primary_domain:
        primary_domain = primary_domain.strip().lower()[:255]
        if " " in primary_domain or len(primary_domain) < 3:
            raise ValueError("Invalid primary_domain")
    app = Application(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        project_id=project_id,
        name=_normalize_name(name)[:200],
        description=_sanitize(description or "", 1000) if description else None,
        application_type=application_type,
        lifecycle=lifecycle,
        criticality=criticality,
        owner_user_id=owner_user_id,
        primary_domain=primary_domain,
        status="ACTIVE",
    )
    db.add(app)
    db.commit()
    db.refresh(app)
    return app

def update_application(application_id: str, db: Session, project_id: str, **fields) -> Application | None:
    app = db.query(Application).filter(Application.id == application_id, Application.project_id == project_id).first()
    if not app:
        return None
    if "name" in fields:
        _validate_name(fields["name"])
        # duplicate check
        existing = db.query(Application).filter(Application.project_id == project_id, func.lower(Application.name) == fields["name"].strip().lower(), Application.id != application_id).first()
        if existing:
            raise ValueError("Application already exists")
        app.name = _normalize_name(fields["name"])[:200]
    if "description" in fields:
        app.description = _sanitize(fields["description"] or "", 1000) if fields["description"] else None
    if "application_type" in fields:
        _validate_type(fields["application_type"])
        app.application_type = fields["application_type"]
    if "lifecycle" in fields:
        _validate_lifecycle(fields["lifecycle"])
        app.lifecycle = fields["lifecycle"]
    if "criticality" in fields:
        if fields["criticality"] not in VALID_CRITICALITIES:
            raise ValueError(f"Invalid criticality: {fields['criticality']}")
        app.criticality = fields["criticality"]
    if "status" in fields:
        _validate_status(fields["status"])
        app.status = fields["status"]
    if "owner_user_id" in fields:
        if fields["owner_user_id"]:
            from app.models.user import User
            u = db.query(User).filter(User.id == fields["owner_user_id"]).first()
            if not u:
                raise ValueError("Owner not found")
        app.owner_user_id = fields["owner_user_id"]
    if "primary_domain" in fields:
        if fields["primary_domain"]:
            v = fields["primary_domain"].strip().lower()[:255]
            if " " in v:
                raise ValueError("Invalid primary_domain")
            app.primary_domain = v
        else:
            app.primary_domain = None
    db.commit()
    db.refresh(app)
    return app

def list_applications(project_id: str, db: Session, limit: int = 50, status: str | None = None, lifecycle: str | None = None, criticality: str | None = None) -> list[Application]:
    limit = max(1, min(limit, 100))
    q = db.query(Application).filter(Application.project_id == project_id)
    if status:
        q = q.filter(Application.status == status)
    if lifecycle:
        q = q.filter(Application.lifecycle == lifecycle)
    if criticality:
        q = q.filter(Application.criticality == criticality)
    return q.order_by(Application.created_at.desc()).limit(limit).all()

def get_application(project_id: str, db: Session, application_id: str) -> Application | None:
    return db.query(Application).filter(Application.id == application_id, Application.project_id == project_id).first()

# Asset linking
def link_asset(application_id: str, db: Session, project_id: str, asset_id: str, relationship_type: str = "contains", confidence: str = "MEDIUM", evidence: dict | None = None) -> ApplicationAsset:
    if relationship_type not in VALID_LINK_TYPES:
        raise ValueError(f"Invalid relationship_type: {relationship_type}")
    if confidence not in VALID_CONFIDENCES:
        raise ValueError(f"Invalid confidence: {confidence}")
    app = db.query(Application).filter(Application.id == application_id, Application.project_id == project_id).first()
    if not app:
        raise ValueError("Application not found")
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.project_id == project_id).first()
    if not asset:
        raise ValueError("Asset not found or not in project")
    # evidence sanitization
    if evidence and any("secret" in str(k).lower() for k in evidence.keys()):
        evidence = {"redacted": True}
    count = db.query(func.count(ApplicationAsset.id)).filter(ApplicationAsset.application_id == application_id).scalar() or 0
    if count >= MAX_ASSETS:
        raise ValueError("Maximum linked assets reached")
    existing = db.query(ApplicationAsset).filter(ApplicationAsset.application_id == application_id, ApplicationAsset.asset_id == asset_id).first()
    if existing:
        # update confidence/relationship
        existing.relationship_type = relationship_type
        existing.confidence = confidence
        if evidence:
            existing.evidence = {k: _sanitize(str(v)) for k,v in evidence.items()}
            flag_modified(existing, "evidence")
        db.commit()
        db.refresh(existing)
        return existing
    link = ApplicationAsset(
        id=str(uuid.uuid4()),
        application_id=application_id,
        asset_id=asset_id,
        relationship_type=relationship_type,
        confidence=confidence,
        evidence={k: _sanitize(str(v)) for k,v in (evidence or {}).items()} if evidence else {},
    )
    db.add(link)
    db.commit()
    db.refresh(link)
    return link

def get_application_assets(application_id: str, db: Session, project_id: str, limit: int = 50) -> list[dict]:
    limit = max(1, min(limit, MAX_ASSETS))
    # ensure app belongs to project
    app = db.query(Application).filter(Application.id == application_id, Application.project_id == project_id).first()
    if not app:
        return []
    rows = db.query(ApplicationAsset, Asset).join(Asset, ApplicationAsset.asset_id == Asset.id).filter(ApplicationAsset.application_id == application_id).limit(limit).all()
    result = []
    for link, asset in rows:
        result.append({
            "id": asset.id,
            "asset_type": asset.asset_type,
            "value": asset.value,
            "status": asset.status,
            "criticality": asset.criticality,
            "relationship_type": link.relationship_type,
            "confidence": link.confidence,
            "evidence": link.evidence,
            "extra_data": asset.extra_data,
        })
    return result

def get_application_findings(application_id: str, db: Session, project_id: str, limit: int = 50, severity: str | None = None) -> list[Finding]:
    app = db.query(Application).filter(Application.id == application_id, Application.project_id == project_id).first()
    if not app:
        return []
    # findings via linked assets
    asset_ids = [r[0] for r in db.query(ApplicationAsset.asset_id).filter(ApplicationAsset.application_id == application_id).all()]
    if not asset_ids:
        # also consider findings without asset but linked via project? For E16, if no assets linked, return empty
        return []
    q = db.query(Finding).filter(Finding.asset_id.in_(asset_ids))
    if severity:
        q = q.filter(Finding.severity == severity.lower())
    findings = q.limit(min(limit, MAX_FINDINGS)).all()
    # redact secret evidence
    for f in findings:
        if f.scanner in ("secrets", "gitleaks") or (f.evidence and "secret" in f.evidence.lower()):
            f.evidence = "[REDACTED]"
    return findings

# Correlations reuse E12
def get_application_correlations(application_id: str, db: Session, project_id: str, limit: int = 20) -> list[dict]:
    # Get asset_ids and finding ids for app
    app = db.query(Application).filter(Application.id == application_id, Application.project_id == project_id).first()
    if not app:
        return []
    asset_ids = [r[0] for r in db.query(ApplicationAsset.asset_id).filter(ApplicationAsset.application_id == application_id).all()]
    if not asset_ids:
        return []
    finding_ids = [r[0] for r in db.query(Finding.id).filter(Finding.asset_id.in_(asset_ids)).all()]
    # Use existing E12 correlation: group findings by fingerprint within project, then filter to app's findings
    try:
        from app.services.security_correlation import get_correlations
        all_groups = get_correlations(project_id, db)
        # filter groups that contain at least one finding from this app
        app_groups = [g for g in all_groups if any(fid in finding_ids for fid in [m["finding_id"] for m in g.get("members",[])] )]
        # Map to E16 categories: SAME_APPLICATION etc is already implied
        for g in app_groups:
            g["application_id"] = application_id
            g["confidence_label"] = g.get("confidence","MEDIUM")
        return app_groups[:min(limit, MAX_CORRELATIONS)]
    except Exception:
        return []

# Exposure
def get_application_exposure(application_id: str, db: Session, project_id: str) -> dict:
    app = db.query(Application).filter(Application.id == application_id, Application.project_id == project_id).first()
    if not app:
        return {"internet_facing": False, "external_assets": [], "api_endpoints": [], "cloud_resources": []}
    assets = get_application_assets(application_id, db, project_id, limit=MAX_ASSETS)
    external_assets = []
    api_endpoints = []
    cloud_resources = []
    internet_facing = False
    for a in assets:
        if a["asset_type"] in ("domain","subdomain","url","ip","ipv6"):
            # check externally_reachable via extra_data
            if (a["extra_data"] or {}).get("externally_reachable") or a["asset_type"] in ("url","domain","subdomain"):
                # consider external if linked via exposes relationship or extra flag
                if a["relationship_type"] == "exposes" or (a["extra_data"] or {}).get("externally_reachable"):
                    external_assets.append(a)
                    internet_facing = True
        if a["asset_type"] == "api_endpoint":
            api_endpoints.append(a)
            # if api exposed via external, then internet_facing true if any external
        if a["asset_type"] in ("cloud_resource","cloud_account"):
            cloud_resources.append(a)
    # Also check E15 external assets via primary_domain
    if app.primary_domain:
        # search for external assets with that domain in project
        try:
            ext = db.query(Asset).filter(Asset.project_id == project_id, Asset.value.contains(app.primary_domain)).limit(5).all()
            for e in ext:
                if e.id not in [x["id"] for x in external_assets]:
                    external_assets.append({"id": e.id, "asset_type": e.asset_type, "value": e.value, "relationship_type": "exposes", "confidence": "MEDIUM", "evidence": {}, "extra_data": e.extra_data})
                    if (e.extra_data or {}).get("externally_reachable"):
                        internet_facing = True
        except Exception:
            pass
    return {
        "internet_facing": internet_facing,
        "external_assets": external_assets[:20],
        "api_endpoints": api_endpoints[:20],
        "cloud_resources": cloud_resources[:20],
        "exposure_score": 90 if internet_facing else 20,
    }

# Risk
def calculate_application_risk(application_id: str, db: Session, project_id: str) -> dict:
    app = db.query(Application).filter(Application.id == application_id, Application.project_id == project_id).first()
    if not app:
        return {"score": 0, "tier": "UNKNOWN", "factors": [], "evidence_refs": []}
    findings = get_application_findings(application_id, db, project_id, limit=MAX_FINDINGS)
    exposure = get_application_exposure(application_id, db, project_id)
    # Count findings by severity
    counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        counts[f.severity.lower()] = counts.get(f.severity.lower(),0) + 1
    # Base from highest severity
    highest = "info"
    for sev in ["critical","high","medium","low","info"]:
        if counts[sev] > 0:
            highest = sev
            break
    # Deterministic scoring 0-100
    score = 0
    factors = []
    # highest severity contributes
    sev_scores = {"critical":35,"high":20,"medium":10,"low":3,"info":0}
    base = sev_scores.get(highest,0)
    if base:
        score += base
        factors.append(f"+{base} Highest finding severity {highest.upper()}")
    # number of critical/high
    if counts["critical"]:
        add = min(counts["critical"]*10, 20)
        score += add
        factors.append(f"+{add} Critical findings x{counts['critical']}")
    if counts["high"]:
        add = min(counts["high"]*5, 15)
        score += add
        factors.append(f"+{add} High findings x{counts['high']}")
    # internet exposure
    if exposure["internet_facing"]:
        score += 15
        factors.append("+15 Internet-facing exposure")
    # secret exposure
    secrets = sum(1 for f in findings if f.scanner in ("secrets","gitleaks") or (f.evidence and "secret" in f.evidence.lower()))
    # but evidence is redacted, use scanner
    secrets = sum(1 for f in findings if f.scanner in ("secrets","gitleaks"))
    if secrets:
        add = min(secrets*10, 15)
        score += add
        factors.append(f"+{add} Secret exposure x{secrets}")
    # vulnerable container/package via finding scanners
    container_findings = sum(1 for f in findings if f.scanner == "container")
    if container_findings:
        add = min(container_findings*5, 10)
        score += add
        factors.append(f"+{add} Container findings x{container_findings}")
    # IaC
    iac_findings = sum(1 for f in findings if f.scanner == "iac")
    if iac_findings:
        add = min(iac_findings*3, 10)
        score += add
        factors.append(f"+{add} IaC findings x{iac_findings}")
    # SLA overdue via finding_slas
    try:
        breached = db.query(func.count(text("id"))).select_from(text("finding_slas")).where(text("project_id=:pid AND status='breached'")).params(pid=project_id).scalar()
    except Exception:
        breached = 0
    # fallback count overdue via finding status? Use remediation overdue
    overdue = 0
    try:
        from app.models.finding import FindingSLA
        overdue = db.query(func.count(FindingSLA.id)).filter(FindingSLA.project_id == project_id, FindingSLA.status == "breached").scalar() or 0
        if findings:
            # check if any linked finding SLA breached
            fids = [f.id for f in findings]
            overdue = db.query(func.count(FindingSLA.id)).filter(FindingSLA.finding_id.in_(fids), FindingSLA.status == "breached").scalar() or 0
    except Exception:
        overdue = 0
    if overdue:
        add = min(overdue*5, 10)
        score += add
        factors.append(f"+{add} Overdue remediation x{overdue}")
    # attack path relation via E11 (simplified: if cloud resources + exposure)
    if exposure["cloud_resources"] and exposure["internet_facing"]:
        score += 10
        factors.append("+10 Cloud attack-path potential (internet + cloud)")
    score = max(0, min(100, score))
    tier = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 40 else "LOW" if score >= 20 else "INFO"
    # clamp via criticality
    if app.criticality == "critical" and score < 40:
        score = 40
        tier = "MEDIUM"
    return {
        "score": score,
        "tier": tier,
        "factors": factors,
        "counts": counts,
        "total_findings": len(findings),
        "internet_facing": exposure["internet_facing"],
        "evidence_refs": [f.id for f in findings[:5]],
    }

# Summary
def get_application_summary(application_id: str, db: Session, project_id: str) -> dict:
    app = db.query(Application).filter(Application.id == application_id, Application.project_id == project_id).first()
    if not app:
        return {}
    assets = get_application_assets(application_id, db, project_id, limit=MAX_ASSETS)
    findings = get_application_findings(application_id, db, project_id, limit=MAX_FINDINGS)
    exposure = get_application_exposure(application_id, db, project_id)
    risk = calculate_application_risk(application_id, db, project_id)
    # Changes via asset_change_events filtered to app assets
    asset_ids = [a["id"] for a in assets]
    changes = []
    if asset_ids:
        try:
            from app.models.asset_change_event import AssetChangeEvent
            changes = db.query(AssetChangeEvent).filter(AssetChangeEvent.asset_id.in_(asset_ids)).order_by(AssetChangeEvent.detected_at.desc()).limit(20).all()
            changes = [{"id": c.id, "asset_id": c.asset_id, "change_type": c.change_type, "detected_at": c.detected_at.isoformat() if c.detected_at else None} for c in changes]
        except Exception:
            changes = []
    # Remediation aggregate
    remediation_summary = {"open":0,"blocked":0,"completed":0}
    if findings:
        try:
            from app.models.finding import FindingRemediation
            fids = [f.id for f in findings]
            rows = db.query(FindingRemediation.status, func.count(FindingRemediation.id)).filter(FindingRemediation.finding_id.in_(fids)).group_by(FindingRemediation.status).all()
            for status, cnt in rows:
                remediation_summary[status] = cnt
        except Exception:
            pass
    return {
        "application": {"id": app.id, "name": app.name, "application_type": app.application_type, "lifecycle": app.lifecycle, "criticality": app.criticality, "status": app.status, "owner_user_id": app.owner_user_id, "primary_domain": app.primary_domain, "created_at": app.created_at.isoformat() if app.created_at else None},
        "risk": risk,
        "findings": {"total": len(findings), "by_severity": {k: sum(1 for f in findings if f.severity.lower()==k) for k in ["critical","high","medium","low","info"]}},
        "assets": {"total": len(assets), "by_type": {}},
        "exposure": exposure,
        "changes": changes,
        "remediation": remediation_summary,
    }

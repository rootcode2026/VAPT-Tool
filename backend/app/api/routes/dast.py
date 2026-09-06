from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import uuid
import re
from datetime import datetime, timezone

from app.api.deps import get_current_user, require_project_access, _is_super_admin, _effective_project_role, _effective_org_role
from app.db.database import get_db
from app.models.dast import DASTConfig, DASTEndpoint, DASTParameter
from app.models.user import User
from app.services.audit import AuditService
from app.services.dast_service import get_policy, validate_target_url, validate_target_authorization, detect_endpoints_from_target, detect_parameters, sanitize_headers
from app.services.secret_store import get_secret_store

router = APIRouter(prefix="/api/v1/projects/{project_id}/dast", tags=["DAST"])

def _require_dast_manage(project_id: str, db: Session, user: User):
    if _is_super_admin(user):
        return
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj and _effective_org_role(user, proj.organization_id, db) == "org_admin":
        return
    role = _effective_project_role(user, project_id, db)
    if role not in ("analyst", "project_admin"):
        raise HTTPException(status_code=403, detail="Requires analyst or project_admin")

def _require_active_auth(project_id: str, db: Session, user: User):
    # database_security requires stronger permission
    if _is_super_admin(user):
        return
    role = _effective_project_role(user, project_id, db)
    if role != "project_admin":
        # check org_admin
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        if proj and _effective_org_role(user, proj.organization_id, db) == "org_admin":
            return
        raise HTTPException(status_code=403, detail="Database security requires project_admin")

@router.post("/config", status_code=201)
def create_dast_config(project_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _require_dast_manage(project_id, db, current_user)
    profile = str(payload.get("profile", "web")).strip().lower()
    policy = get_policy(profile)
    # Validate profile exists
    if profile not in ("web", "api", "api_authenticated", "advanced_dast", "database_security", "quick", "full"):
        raise HTTPException(status_code=400, detail="Invalid profile")
    if profile == "database_security":
        _require_active_auth(project_id, db, current_user)
    target_id = payload.get("target_id")
    if target_id:
        validate_target_authorization(str(target_id), db, current_user, project_id)
    openapi_ref = payload.get("openapi_ref")
    if openapi_ref and len(str(openapi_ref)) > 5000:
        raise HTTPException(status_code=400, detail="openapi_ref too large")
    # auth secret reference via SecretStore
    auth_secret = payload.get("auth_secret") or payload.get("credential")
    auth_ref = None
    if auth_secret and isinstance(auth_secret, str) and auth_secret.strip():
        if len(auth_secret) > 8192:
            raise HTTPException(status_code=400, detail="auth_secret too large")
        store = get_secret_store(db)
        auth_ref = store.put_secret(auth_secret.strip())
    allowed_domains = payload.get("allowed_domains") or []
    if not isinstance(allowed_domains, list):
        allowed_domains = []
    allowed_domains = [str(d)[:100] for d in allowed_domains[:10]]
    # Enforce server-side limits
    max_endpoints = min(int(payload.get("max_endpoints", 50)), policy["max_endpoints"])
    max_requests = min(int(payload.get("max_requests", 500)), policy["max_requests"])
    rate_limit = min(int(payload.get("rate_limit", 5)), policy["rate_limit"])
    # Validate allowed_domains not containing traversal
    for dom in allowed_domains:
        if ".." in dom or any(c in dom for c in ";&|$`"):
            raise HTTPException(status_code=400, detail="Invalid domain")
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    cfg = DASTConfig(
        id=str(uuid.uuid4()),
        project_id=project_id,
        organization_id=proj.organization_id if proj else current_user.organization_id,
        profile=profile,
        target_id=str(target_id) if target_id else None,
        openapi_ref=str(openapi_ref)[:5000] if openapi_ref else None,
        auth_secret_reference=auth_ref,
        allowed_domains=allowed_domains,
        max_endpoints=max_endpoints,
        max_requests=max_requests,
        rate_limit=rate_limit,
        active_testing_enabled=str(bool(payload.get("active_testing_enabled", False))).lower(),
        database_testing_enabled=str(bool(payload.get("database_testing_enabled", False))).lower(),
        created_by=current_user.id,
    )
    # If active testing enabled, require project_admin
    if payload.get("active_testing_enabled"):
        _require_active_auth(project_id, db, current_user)
    db.add(cfg)
    try:
        AuditService.record(db, event_type="DAST_CONFIG_CREATED", action="DAST_CONFIG_CREATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=project_id, resource_type="dast_config", resource_id=cfg.id, metadata={"profile": profile})
    except Exception:
        pass
    db.commit()
    db.refresh(cfg)
    return {"id": cfg.id, "profile": cfg.profile, "target_id": cfg.target_id, "allowed_domains": cfg.allowed_domains, "max_endpoints": cfg.max_endpoints}

@router.get("/config")
def get_dast_config(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    cfg = db.query(DASTConfig).filter(DASTConfig.project_id == project_id).order_by(DASTConfig.created_at.desc()).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="DAST config not found")
    return {"id": cfg.id, "profile": cfg.profile, "target_id": cfg.target_id, "openapi_ref": cfg.openapi_ref, "allowed_domains": cfg.allowed_domains, "max_endpoints": cfg.max_endpoints, "max_requests": cfg.max_requests, "rate_limit": cfg.rate_limit, "active_testing_enabled": cfg.active_testing_enabled, "database_testing_enabled": cfg.database_testing_enabled, "auth_configured": bool(cfg.auth_secret_reference), "created_at": cfg.created_at.isoformat() if cfg.created_at else None}

@router.patch("/config/{config_id}")
def update_dast_config(project_id: str, config_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _require_dast_manage(project_id, db, current_user)
    cfg = db.query(DASTConfig).filter(DASTConfig.id == config_id, DASTConfig.project_id == project_id).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Config not found")
    if "profile" in payload and payload["profile"]:
        prof = str(payload["profile"]).strip().lower()
        if prof not in ("web", "api", "advanced_dast", "database_security", "api_authenticated"):
            raise HTTPException(status_code=400, detail="Invalid profile")
        if prof == "database_security":
            _require_active_auth(project_id, db, current_user)
        cfg.profile = prof
    if "allowed_domains" in payload:
        doms = payload["allowed_domains"]
        if isinstance(doms, list):
            cfg.allowed_domains = [str(d)[:100] for d in doms[:10]]
    try:
        AuditService.record(db, event_type="DAST_CONFIG_UPDATED", action="DAST_CONFIG_UPDATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=project_id, resource_type="dast_config", resource_id=cfg.id, metadata={"profile": cfg.profile})
    except Exception:
        pass
    db.commit()
    db.refresh(cfg)
    return {"id": cfg.id, "profile": cfg.profile}

@router.post("/scans", status_code=201)
def create_dast_scan(project_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _require_dast_manage(project_id, db, current_user)
    cfg = db.query(DASTConfig).filter(DASTConfig.project_id == project_id).order_by(DASTConfig.created_at.desc()).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="DAST config not found")
    profile = cfg.profile
    policy = get_policy(profile)
    target_id = cfg.target_id or payload.get("target_id")
    if not target_id:
        raise HTTPException(status_code=400, detail="Target required")
    # Validate target authorization and SSRF
    target = validate_target_authorization(str(target_id), db, current_user, project_id)
    # Validate URL against SSRF and allowed domains
    try:
        validated_url = validate_target_url(target.value if target.value.startswith("http") else f"https://{target.value}", cfg.allowed_domains)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # Check active/database authorization
    if policy["active_allowed"] and cfg.active_testing_enabled != "true":
        # For advanced_dast, need explicit active_testing_enabled
        if profile in ("advanced_dast", "database_security"):
            raise HTTPException(status_code=403, detail="Active testing not authorized for this config")
    if profile == "database_security" and cfg.database_testing_enabled != "true":
        raise HTTPException(status_code=403, detail="Database testing not authorized")
    # Enqueue scan via existing scans route logic? Create Scan row with profile
    from app.models.scan import Scan
    from app.models.target import Target
    scan = Scan(id=str(uuid.uuid4()), target_id=target.id, profile=profile, status="queued")
    db.add(scan)
    try:
        AuditService.record(db, event_type="DAST_SCAN_CREATED", action="DAST_SCAN_CREATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=project_id, resource_type="scan", resource_id=scan.id, metadata={"profile": profile, "target": target.value[:100]})
        if policy["active_allowed"]:
            AuditService.record(db, event_type="DAST_ACTIVE_TEST_AUTHORIZED", action="DAST_ACTIVE_TEST_AUTHORIZED", result="SUCCESS", actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=project_id, resource_type="scan", resource_id=scan.id, metadata={"profile": profile})
        if profile == "database_security":
            AuditService.record(db, event_type="DATABASE_SECURITY_SCAN_AUTHORIZED", action="DATABASE_SECURITY_SCAN_AUTHORIZED", result="SUCCESS", actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=project_id, resource_type="scan", resource_id=scan.id, metadata={"profile": profile})
    except Exception:
        pass
    db.commit()
    # Enqueue via Celery
    try:
        from app.core.celery import celery_app
        celery_app.send_task("app.tasks.execute_scan", args=[scan.id, target.id, target.value, profile])
    except Exception:
        pass
    # Discover endpoints/parameters bounded
    endpoints = detect_endpoints_from_target(target.value)
    for ep in endpoints[:cfg.max_endpoints]:
        existing = db.query(DASTEndpoint).filter(DASTEndpoint.project_id == project_id, DASTEndpoint.url == ep["url"]).first()
        if not existing:
            db.add(DASTEndpoint(id=str(uuid.uuid4()), project_id=project_id, url=ep["url"], method=ep["method"], host=ep["host"], path=ep["path"], discovered_via=ep["discovered_via"]))
    db.commit()
    return {"id": scan.id, "profile": profile, "status": scan.status, "target_id": target.id, "policy": policy}

@router.get("/endpoints")
def list_endpoints(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    rows = db.query(DASTEndpoint).filter(DASTEndpoint.project_id == project_id).limit(100).all()
    return {"project_id": project_id, "count": len(rows), "endpoints": [{"id": r.id, "url": r.url, "method": r.method, "host": r.host, "path": r.path} for r in rows]}

@router.get("/parameters")
def list_parameters(project_id: str, endpoint_id: str | None = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    q = db.query(DASTParameter).filter(DASTParameter.project_id == project_id)
    if endpoint_id:
        q = q.filter(DASTParameter.endpoint_id == endpoint_id)
    rows = q.limit(100).all()
    return {"project_id": project_id, "count": len(rows), "parameters": [{"id": r.id, "name": r.name, "location": r.location, "http_method": r.http_method} for r in rows]}

@router.get("/scans")
def list_dast_scans(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    from app.models.scan import Scan
    from app.models.target import Target
    rows = db.query(Scan).join(Target, Target.id == Scan.target_id).filter(Target.project_id == project_id, Scan.profile.in_(["advanced_dast", "database_security", "api", "api_authenticated"])).order_by(Scan.created_at.desc()).limit(20).all()
    return {"project_id": project_id, "count": len(rows), "scans": [{"id": r.id, "profile": r.profile, "status": r.status, "created_at": r.created_at.isoformat() if r.created_at else None} for r in rows]}

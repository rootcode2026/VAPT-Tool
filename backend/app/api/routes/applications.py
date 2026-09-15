"""E16 Application Security Intelligence API — project-scoped, RLS, RBAC, bounded."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.models.application import VALID_APP_TYPES, VALID_LIFECYCLES, VALID_CRITICALITIES, VALID_STATUSES

router = APIRouter(prefix="/api/v1/projects/{project_id}/applications", tags=["Applications"])

def _set_rls(db: Session, project_id: str, user: User):
    try:
        from app.db.rls import set_tenant_context
        org_id = getattr(user, "organization_id", None)
        if org_id and str(org_id).strip():
            in_tx = False
            try:
                in_tx = bool(db.in_transaction() or db.in_nested_transaction())
            except Exception:
                in_tx = False
            if not in_tx:
                try:
                    db.begin()
                except Exception:
                    pass
            try:
                set_tenant_context(db, organization_id=str(org_id).strip(), project_id=str(project_id).strip(), user_id=str(user.id))
            except Exception:
                try:
                    set_tenant_context(db, organization_id=str(org_id).strip(), user_id=str(user.id))
                except Exception:
                    pass
    except Exception:
        pass

def _require_perm(project_id: str, db: Session, user: User, permission: str):
    from app.api.deps import _effective_project_role, _effective_org_role, _is_super_admin
    from app.core.permissions import ORG_ROLE_PERMISSIONS, PROJECT_ROLE_PERMISSIONS
    if _is_super_admin(user):
        return
    # Strict mode check first
    try:
        from app.core.config import settings
        if getattr(settings, "RBAC_STRICT_MODE", False):
            role = _effective_project_role(user, project_id, db)
            if not role:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            perms = set(PROJECT_ROLE_PERMISSIONS.get(role, set()))
            # supplement org if has membership
            try:
                from app.models.project import Project as _P
                _proj = db.query(_P).filter(_P.id == project_id).first()
                if _proj is not None:
                    _org_role = _effective_org_role(user, _proj.organization_id, db)
                    if _org_role:
                        perms.update(ORG_ROLE_PERMISSIONS.get(_org_role, set()))
            except Exception:
                pass
            if permission not in perms:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return
    except HTTPException:
        raise
    except Exception:
        pass
    perms: set[str] = set()
    from app.api.deps import _effective_project_role as _epr, _effective_org_role as _eor
    role = _epr(user, project_id, db)
    if role:
        perms.update(PROJECT_ROLE_PERMISSIONS.get(role, set()))
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        if proj is not None:
            org_role = _eor(user, proj.organization_id, db)
            if org_role:
                perms.update(ORG_ROLE_PERMISSIONS.get(org_role, set()))
    except Exception:
        pass
    if permission not in perms:
        try:
            from app.services.audit import AuditService
            AuditService.record(db, event_type="AUTHORIZATION_DENIED", action="AUTHORIZATION_DENIED", result="DENIED", actor_user_id=user.id, organization_id=getattr(user,"organization_id",None), project_id=project_id, resource_type="application", resource_id=project_id, metadata={"permission": permission, "role": str(role)[:50]})
            try:
                db.commit()
            except Exception:
                try: db.rollback()
                except: pass
        except: pass
        raise HTTPException(status_code=403, detail="Insufficient permissions")

def _audit(db: Session, project_id: str, user: User, event_type: str, resource_id: str, result: str = "SUCCESS", metadata: dict | None = None):
    try:
        from app.services.audit import AuditService
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type=event_type, action=event_type, result=result, actor_user_id=user.id, organization_id=proj.organization_id if proj else getattr(user,"organization_id",None), project_id=project_id, resource_type="application", resource_id=resource_id, metadata=metadata or {})
        db.commit()
    except Exception:
        try: db.rollback()
        except: pass
        pass

class CreateAppRequest(BaseModel):
    name: str
    description: Optional[str] = None
    application_type: str = "UNKNOWN"
    lifecycle: str = "UNKNOWN"
    criticality: str = "unknown"
    owner_user_id: Optional[str] = None
    primary_domain: Optional[str] = None

class UpdateAppRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    application_type: Optional[str] = None
    lifecycle: Optional[str] = None
    criticality: Optional[str] = None
    status: Optional[str] = None
    owner_user_id: Optional[str] = None
    primary_domain: Optional[str] = None

class LinkAssetRequest(BaseModel):
    asset_id: str
    relationship_type: str = "contains"
    confidence: str = "MEDIUM"
    evidence: Optional[dict] = None

@router.get("")
def list_apps(project_id: str, limit: int = Query(50, ge=1, le=100), status: str | None = Query(None), lifecycle: str | None = Query(None), criticality: str | None = Query(None), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.read")
    from app.services.application_intelligence import list_applications
    apps = list_applications(project_id, db, limit=limit, status=status, lifecycle=lifecycle, criticality=criticality)
    return {"project_id": project_id, "count": len(apps), "applications": [{"id": a.id, "name": a.name, "application_type": a.application_type, "lifecycle": a.lifecycle, "criticality": a.criticality, "status": a.status, "owner_user_id": a.owner_user_id, "primary_domain": a.primary_domain} for a in apps]}

@router.post("")
def create_app(project_id: str, body: CreateAppRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.write")
    from app.services.application_intelligence import create_application
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    try:
        app = create_application(project_id, db, name=body.name, description=body.description, application_type=body.application_type, lifecycle=body.lifecycle, criticality=body.criticality, owner_user_id=body.owner_user_id, primary_domain=body.primary_domain, organization_id=proj.organization_id if proj else None)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(db, project_id, current_user, "APPLICATION_CREATED", app.id, metadata={"name": app.name[:100], "type": app.application_type})
    return {"id": app.id, "name": app.name, "project_id": app.project_id}

@router.get("/{application_id}")
def get_app(project_id: str, application_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.read")
    from app.services.application_intelligence import get_application
    app = get_application(project_id, db, application_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return {"id": app.id, "name": app.name, "description": app.description, "application_type": app.application_type, "lifecycle": app.lifecycle, "criticality": app.criticality, "status": app.status, "owner_user_id": app.owner_user_id, "primary_domain": app.primary_domain, "project_id": app.project_id, "organization_id": app.organization_id, "created_at": app.created_at.isoformat() if app.created_at else None}

@router.patch("/{application_id}")
def update_app(project_id: str, application_id: str, body: UpdateAppRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    # owner change requires owner.write, else write
    perm = "application.owner.write" if body.owner_user_id is not None else "application.write"
    _require_perm(project_id, db, current_user, perm)
    from app.services.application_intelligence import update_application
    fields = {k: v for k,v in body.model_dump().items() if v is not None}
    try:
        app = update_application(application_id, db, project_id, **fields)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    evt = "APPLICATION_OWNER_CHANGED" if "owner_user_id" in fields else "APPLICATION_UPDATED"
    _audit(db, project_id, current_user, evt, application_id, metadata={"fields": ",".join(fields.keys())[:200]})
    return {"id": app.id, "name": app.name, "status": app.status, "owner_user_id": app.owner_user_id}

@router.get("/{application_id}/summary")
def app_summary(project_id: str, application_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.read")
    from app.services.application_intelligence import get_application_summary
    summary = get_application_summary(application_id, db, project_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Application not found")
    return summary

@router.get("/{application_id}/assets")
def app_assets(project_id: str, application_id: str, limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.read")
    from app.services.application_intelligence import get_application_assets
    assets = get_application_assets(application_id, db, project_id, limit=limit)
    # if app not found, assets will be empty but we need 404
    from app.services.application_intelligence import get_application
    if not get_application(project_id, db, application_id):
        raise HTTPException(status_code=404, detail="Application not found")
    return {"application_id": application_id, "count": len(assets), "assets": assets}

@router.post("/{application_id}/assets/link")
def link_asset(project_id: str, application_id: str, body: LinkAssetRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.asset.link")
    from app.services.application_intelligence import link_asset as svc_link
    try:
        link = svc_link(application_id, db, project_id, asset_id=body.asset_id, relationship_type=body.relationship_type, confidence=body.confidence, evidence=body.evidence)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(db, project_id, current_user, "APPLICATION_ASSET_LINKED", application_id, metadata={"asset_id": body.asset_id[:36], "rel": body.relationship_type})
    return {"id": link.id, "asset_id": link.asset_id, "relationship_type": link.relationship_type, "confidence": link.confidence}

@router.get("/{application_id}/findings")
def app_findings(project_id: str, application_id: str, limit: int = Query(50, ge=1, le=100), severity: str | None = Query(None), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.finding.read")
    from app.services.application_intelligence import get_application_findings, get_application
    if not get_application(project_id, db, application_id):
        raise HTTPException(status_code=404, detail="Application not found")
    findings = get_application_findings(application_id, db, project_id, limit=limit, severity=severity)
    return {"application_id": application_id, "count": len(findings), "findings": [{"id": f.id, "scanner": f.scanner, "title": f.title, "severity": f.severity, "cve": f.cve, "cwe": f.cwe, "evidence": (f.evidence[:200] if f.evidence else None)} for f in findings]}

@router.get("/{application_id}/correlations")
def app_correlations(project_id: str, application_id: str, limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.finding.read")
    from app.services.application_intelligence import get_application_correlations, get_application
    if not get_application(project_id, db, application_id):
        raise HTTPException(status_code=404, detail="Application not found")
    corrs = get_application_correlations(application_id, db, project_id, limit=limit)
    return {"application_id": application_id, "count": len(corrs), "correlations": corrs}

@router.get("/{application_id}/exposure")
def app_exposure(project_id: str, application_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.read")
    from app.services.application_intelligence import get_application_exposure, get_application as ga
    if not ga(project_id, db, application_id):
        raise HTTPException(status_code=404, detail="Application not found")
    exp = get_application_exposure(application_id, db, project_id)
    return exp

@router.get("/{application_id}/risk")
def app_risk(project_id: str, application_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.read")
    from app.services.application_intelligence import calculate_application_risk, get_application as ga
    if not ga(project_id, db, application_id):
        raise HTTPException(status_code=404, detail="Application not found")
    risk = calculate_application_risk(application_id, db, project_id)
    return risk

@router.get("/{application_id}/changes")
def app_changes(project_id: str, application_id: str, limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.read")
    from app.services.application_intelligence import get_application_summary, get_application as ga
    if not ga(project_id, db, application_id):
        raise HTTPException(status_code=404, detail="Application not found")
    summary = get_application_summary(application_id, db, project_id)
    return {"application_id": application_id, "changes": summary.get("changes", [])[:limit]}

@router.post("/{application_id}/investigation")
def app_investigation(project_id: str, application_id: str, body: dict = {}, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.investigation.create")
    from app.services.application_intelligence import get_application as ga
    if not ga(project_id, db, application_id):
        raise HTTPException(status_code=404, detail="Application not found")
    # Reuse E13 investigation: subject_type=application or fallback to asset
    try:
        from app.services.security_investigation import create_investigation
        inv = create_investigation(project_id, db, subject_type="application", subject_id=application_id, created_by=current_user.id)
        _audit(db, project_id, current_user, "APPLICATION_INVESTIGATION_CREATED", application_id, metadata={"investigation_id": inv.id[:36]})
        return {"id": inv.id, "subject_type": inv.subject_type, "subject_id": inv.subject_id, "title": inv.title}
    except Exception as e:
        # Fallback: try asset type
        raise HTTPException(status_code=400, detail=str(e)[:300])

@router.get("/{application_id}/investigation")
def list_app_investigations(project_id: str, application_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_perm(project_id, db, current_user, "application.read")
    from app.services.application_intelligence import get_application as ga
    if not ga(project_id, db, application_id):
        raise HTTPException(status_code=404, detail="Application not found")
    try:
        from app.models.security_investigation import SecurityInvestigation
        rows = db.query(SecurityInvestigation).filter(SecurityInvestigation.project_id == project_id, SecurityInvestigation.subject_id == application_id).limit(20).all()
        return {"application_id": application_id, "count": len(rows), "investigations": [{"id": r.id, "title": r.title, "status": r.status, "subject_type": r.subject_type} for r in rows]}
    except Exception:
        return {"application_id": application_id, "count": 0, "investigations": []}

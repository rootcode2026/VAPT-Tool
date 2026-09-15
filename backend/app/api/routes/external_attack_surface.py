"""E15 External Attack Surface API — project-scoped, bounded, safe. E15.1 hardened."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.services.external_attack_surface import (
    create_scope, list_scopes, create_scope_entry, update_scope_entry,
    create_discovery_run, list_assets, get_asset_detail, list_candidates,
    confirm_asset, reject_asset, get_summary, VALID_ENTRY_TYPES, VALID_AUTH, VALID_PROFILES,
)
from app.models.external_scope import ExternalScope, ExternalScopeEntry, ExternalDiscoveryRun

router = APIRouter(prefix="/api/v1/projects/{project_id}/external-attack-surface", tags=["External Attack Surface"])

def _set_rls(db: Session, project_id: str, user: User):
    """Ensure transaction-local RLS context (org+project+user) for defense-in-depth."""
    try:
        from app.db.rls import set_tenant_context
        org_id = getattr(user, "organization_id", None)
        if org_id and str(org_id).strip():
            # Ensure transaction for pool safety (SET LOCAL requires transaction)
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
            # Now set context; validation inside will handle bad UUIDs
            try:
                set_tenant_context(db, organization_id=str(org_id).strip(), project_id=str(project_id).strip(), user_id=str(user.id))
            except Exception:
                # Fallback: try org+user only if project invalid
                try:
                    set_tenant_context(db, organization_id=str(org_id).strip(), user_id=str(user.id))
                except Exception:
                    pass
    except Exception:
        pass

def _require_permission(project_id: str, db: Session, user: User, permission: str):
    """Fine-grained permission check (org+project union). Super_admin bypasses. Strict mode enforces explicit project membership."""
    from app.api.deps import _effective_project_role, _effective_org_role, _is_super_admin
    from app.core.permissions import ORG_ROLE_PERMISSIONS, PROJECT_ROLE_PERMISSIONS
    if _is_super_admin(user):
        return
    # Strict RBAC: explicit project membership required (no org fallback)
    try:
        from app.core.config import settings
        if getattr(settings, "RBAC_STRICT_MODE", False):
            role_strict = _effective_project_role(user, project_id, db)
            if not role_strict:
                # Deny even if org would grant — project isolation under strict mode
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            perms = set(PROJECT_ROLE_PERMISSIONS.get(role_strict, set()))
            # In strict mode, also union org perms only if project role exists (still project membership required)
            # Do not add org perms for missing membership
            if permission not in perms:
                # optionally union org perms for same user if they have project membership? Already have perms from project role alone
                # Check org perms as supplement only when project membership exists
                try:
                    from app.models.project import Project as _P2
                    _proj = db.query(_P2).filter(_P2.id == project_id).first()
                    if _proj is not None:
                        _org_role = _effective_org_role(user, _proj.organization_id, db)
                        if _org_role:
                            perms.update(ORG_ROLE_PERMISSIONS.get(_org_role, set()))
                except Exception:
                    pass
            if permission not in perms:
                try:
                    from app.services.audit import AuditService
                    AuditService.record(db, event_type="AUTHORIZATION_DENIED", action="AUTHORIZATION_DENIED", result="DENIED", actor_user_id=user.id, organization_id=getattr(user, "organization_id", None), project_id=project_id, resource_type="external_attack_surface", resource_id=project_id, metadata={"permission": permission, "role": str(role_strict)[:50]})
                    try:
                        db.commit()
                    except Exception:
                        try:
                            db.rollback()
                        except Exception:
                            pass
                except Exception:
                    pass
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return
    except HTTPException:
        raise
    except Exception:
        pass
    # Transitional (non-strict) — project role + org fallback
    perms: set[str] = set()
    role = _effective_project_role(user, project_id, db)
    if role:
        perms.update(PROJECT_ROLE_PERMISSIONS.get(role, set()))
    # Org role union (covers fallback and explicit org members)
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        if proj is not None:
            org_role = _effective_org_role(user, proj.organization_id, db)
            if org_role:
                perms.update(ORG_ROLE_PERMISSIONS.get(org_role, set()))
    except Exception:
        pass
    if permission not in perms:
        # Audit denied
        try:
            from app.services.audit import AuditService
            AuditService.record(db, event_type="AUTHORIZATION_DENIED", action="AUTHORIZATION_DENIED", result="DENIED", actor_user_id=user.id, organization_id=getattr(user, "organization_id", None), project_id=project_id, resource_type="external_attack_surface", resource_id=project_id, metadata={"permission": permission, "role": str(role)[:50]})
            try:
                db.commit()
            except Exception:
                try:
                    db.rollback()
                except Exception:
                    pass
        except Exception:
            pass
        raise HTTPException(status_code=403, detail="Insufficient permissions")

def _audit(db: Session, project_id: str, user: User, event_type: str, resource_id: str, result: str = "SUCCESS", metadata: dict | None = None):
    try:
        from app.services.audit import AuditService
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type=event_type, action=event_type, result=result, actor_user_id=user.id, organization_id=proj.organization_id if proj else getattr(user, "organization_id", None), project_id=project_id, resource_type="external_attack_surface", resource_id=resource_id, metadata=metadata or {})
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        pass

def _check_rate_limit_or_429(organization_id: str, project_id: str, actor_id: str | None, prefix: str, max_req: int, window: int, audit_db: Session, audit_user: User, audit_project_id: str):
    """Helper to enforce Redis-backed rate limit and raise 429 with safe audit."""
    from app.services.external_attack_surface import _check_external_rate_limit
    allowed, reason = _check_external_rate_limit(prefix, organization_id, project_id, actor_id, max_requests=max_req, window_seconds=window)
    if not allowed:
        # Audit rate limit blocked without exposing redis keys or traces
        try:
            _audit(audit_db, audit_project_id, audit_user, "EXTERNAL_RATE_LIMITED", audit_project_id, result="DENIED", metadata={"operation": prefix, "reason": "rate limit exceeded"})
        except Exception:
            pass
        raise HTTPException(status_code=429, detail="Discovery is temporarily rate limited. Please try again later.")
    return True

# Scopes
class CreateScopeRequest(BaseModel):
    name: str
    description: Optional[str] = None

class CreateEntryRequest(BaseModel):
    entry_type: str
    value: str
    authorization_status: str = "PENDING_REVIEW"

@router.get("")
def get_external_attack_surface(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_asset.read")
    return get_summary(project_id, db)

@router.get("/summary")
def get_eas_summary(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_asset.read")
    return get_summary(project_id, db)

@router.get("/assets")
def list_eas_assets(project_id: str, asset_type: str | None = Query(None, max_length=20), ownership: str | None = Query(None, max_length=20), limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_asset.read")
    assets = list_assets(project_id, db, asset_type=asset_type, ownership=ownership, limit=limit)
    return {"project_id": project_id, "count": len(assets), "assets": [{"id": a.id, "value": a.value, "asset_type": a.asset_type, "extra_data": a.extra_data} for a in assets]}

@router.get("/assets/{asset_id}")
def get_eas_asset(project_id: str, asset_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_asset.read")
    asset = get_asset_detail(project_id, db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"id": asset.id, "value": asset.value, "asset_type": asset.asset_type, "extra_data": asset.extra_data}

@router.get("/assets/{asset_id}/changes")
def get_asset_changes(project_id: str, asset_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_asset.read")
    asset = get_asset_detail(project_id, db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    # D2 compatibility: try real asset_change_events if table exists, else mock empty
    # E15 reuses Asset timestamps, not full D2 asset_change_event for external (partial). Documented as deferred if trivial not already supported.
    try:
        from app.models.asset_change_event import AssetChangeEvent  # type: ignore
        rows = db.query(AssetChangeEvent).filter(AssetChangeEvent.asset_id == asset_id, AssetChangeEvent.project_id == project_id).order_by(AssetChangeEvent.detected_at.desc()).limit(50).all()
        changes = [{"id": r.id, "change_type": getattr(r, "change_type", "UNKNOWN"), "detected_at": r.detected_at.isoformat() if getattr(r, "detected_at", None) else None} for r in rows]
        return {"asset_id": asset_id, "changes": changes}
    except Exception:
        return {"asset_id": asset_id, "changes": []}

@router.get("/candidates")
def list_eas_candidates(project_id: str, limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_asset.read")
    cands = list_candidates(project_id, db, limit=limit)
    return {"project_id": project_id, "count": len(cands), "candidates": [{"id": a.id, "value": a.value, "asset_type": a.asset_type, "extra_data": a.extra_data} for a in cands]}

@router.post("/candidates/{asset_id}/confirm")
def confirm_candidate(project_id: str, asset_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_asset.authorize")
    # Rate limit candidate decisions (10/min)
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    _check_rate_limit_or_429(proj.organization_id if proj else str(getattr(current_user, "organization_id", "")), project_id, current_user.id, "external-candidate-confirm", 10, 60, db, current_user, project_id)
    asset = confirm_asset(asset_id, db, project_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    _audit(db, project_id, current_user, "EXTERNAL_ASSET_CONFIRMED", asset_id, metadata={"ownership_confidence": "CONFIRMED"})
    return {"id": asset.id, "ownership_confidence": asset.extra_data.get("ownership_confidence")}

@router.post("/candidates/{asset_id}/reject")
def reject_candidate(project_id: str, asset_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_asset.reject")
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    _check_rate_limit_or_429(proj.organization_id if proj else str(getattr(current_user, "organization_id", "")), project_id, current_user.id, "external-candidate-reject", 10, 60, db, current_user, project_id)
    asset = reject_asset(asset_id, db, project_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    _audit(db, project_id, current_user, "EXTERNAL_ASSET_REJECTED", asset_id, metadata={"ownership_confidence": "REJECTED"})
    return {"id": asset.id, "ownership_confidence": asset.extra_data.get("ownership_confidence")}

@router.post("/scopes")
def create_eas_scope(project_id: str, body: CreateScopeRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_scope.write")
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    # Rate limit scope creation (10/min)
    _check_rate_limit_or_429(proj.organization_id if proj else str(getattr(current_user, "organization_id", "")), project_id, current_user.id, "external-scope-create", 10, 60, db, current_user, project_id)
    try:
        scope = create_scope(project_id, db, body.name, body.description, created_by=current_user.id, organization_id=proj.organization_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(db, project_id, current_user, "EXTERNAL_SCOPE_CREATED", scope.id, metadata={"name": scope.name[:100]})
    return {"id": scope.id, "name": scope.name, "project_id": scope.project_id}

@router.get("/scopes")
def list_eas_scopes(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_scope.read")
    scopes = list_scopes(project_id, db)
    return {"project_id": project_id, "count": len(scopes), "scopes": [{"id": s.id, "name": s.name, "status": s.status} for s in scopes]}

@router.patch("/scopes/{scope_id}")
def update_eas_scope(project_id: str, scope_id: str, body: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_scope.write")
    scope = db.query(ExternalScope).filter(ExternalScope.id == scope_id, ExternalScope.project_id == project_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    if "name" in body:
        scope.name = str(body["name"])[:200]
    if "status" in body:
        scope.status = str(body["status"])[:20]
    db.commit()
    _audit(db, project_id, current_user, "EXTERNAL_SCOPE_UPDATED", scope_id, metadata={"name": scope.name[:100]})
    return {"id": scope.id, "name": scope.name, "status": scope.status}

@router.post("/scopes/{scope_id}/entries")
def create_eas_entry(project_id: str, scope_id: str, body: CreateEntryRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_scope.entry.write")
    # Verify scope belongs to project
    scope = db.query(ExternalScope).filter(ExternalScope.id == scope_id, ExternalScope.project_id == project_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    _check_rate_limit_or_429(proj.organization_id if proj else str(getattr(current_user, "organization_id", "")), project_id, current_user.id, "external-entry-create", 20, 60, db, current_user, project_id)
    try:
        entry = create_scope_entry(scope_id, db, body.entry_type, body.value, body.authorization_status, source="manual")
    except ValueError as e:
        msg = str(e)
        # Audit SSRF/private blocked without exposing secrets
        if "Private IP" in msg or "Blocked target" in msg or "URL target not allowed" in msg or "CIDR validation" in msg:
            _audit(db, project_id, current_user, "EXTERNAL_SSRF_BLOCKED", scope_id, result="DENIED", metadata={"entry_type": body.entry_type[:20], "reason": msg[:200]})
        raise HTTPException(status_code=400, detail=msg)
    _audit(db, project_id, current_user, "EXTERNAL_SCOPE_ENTRY_CREATED", entry.id, metadata={"entry_type": entry.entry_type, "authorization_status": entry.authorization_status})
    return {"id": entry.id, "value": entry.value, "entry_type": entry.entry_type, "authorization_status": entry.authorization_status}

@router.patch("/entries/{entry_id}")
def update_eas_entry(project_id: str, entry_id: str, body: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_scope.entry.write")
    entry = db.query(ExternalScopeEntry).filter(ExternalScopeEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    # Verify entry's scope belongs to project
    scope = db.query(ExternalScope).filter(ExternalScope.id == entry.external_scope_id, ExternalScope.project_id == project_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Entry not found")
    try:
        updated = update_scope_entry(entry_id, db, authorization_status=body.get("authorization_status"), ownership_confidence=body.get("ownership_confidence"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(db, project_id, current_user, "EXTERNAL_SCOPE_ENTRY_UPDATED", entry_id, metadata={"authorization_status": updated.authorization_status})
    return {"id": updated.id, "authorization_status": updated.authorization_status, "ownership_confidence": updated.ownership_confidence}

class DiscoverRequest(BaseModel):
    external_scope_id: Optional[str] = None
    profile: str = "QUICK"

@router.post("/discover")
def discover_external(project_id: str, body: DiscoverRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_discovery.run")
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    # Pre-check rate limit before service (to audit and return 429)
    _check_rate_limit_or_429(proj.organization_id if proj else str(getattr(current_user, "organization_id", "")), project_id, current_user.id, "external-discovery", 5, 60, db, current_user, project_id)
    try:
        run = create_discovery_run(project_id, db, body.external_scope_id, body.profile, created_by=current_user.id, organization_id=proj.organization_id)
    except ValueError as e:
        msg = str(e)
        if "Rate limit exceeded" in msg:
            _audit(db, project_id, current_user, "EXTERNAL_DISCOVERY_RATE_LIMITED", project_id, result="DENIED", metadata={"reason": "rate limit"})
            raise HTTPException(status_code=429, detail="Discovery is temporarily rate limited. Please try again later.")
        raise HTTPException(status_code=400, detail=msg)
    _audit(db, project_id, current_user, "EXTERNAL_DISCOVERY_STARTED", run.id, metadata={"profile": run.profile, "scope_id": body.external_scope_id})
    return {"id": run.id, "status": run.status, "profile": run.profile}

@router.get("/runs")
def list_runs(project_id: str, limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_discovery.read")
    runs = db.query(ExternalDiscoveryRun).filter(ExternalDiscoveryRun.project_id == project_id).order_by(ExternalDiscoveryRun.created_at.desc()).limit(limit).all()
    return {"project_id": project_id, "count": len(runs), "runs": [{"id": r.id, "status": r.status, "profile": r.profile, "assets_discovered": r.assets_discovered, "created_at": r.created_at.isoformat() if r.created_at else None} for r in runs]}

@router.get("/runs/{run_id}")
def get_run(project_id: str, run_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_permission(project_id, db, current_user, "external_discovery.read")
    run = db.query(ExternalDiscoveryRun).filter(ExternalDiscoveryRun.id == run_id, ExternalDiscoveryRun.project_id == project_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"id": run.id, "status": run.status, "profile": run.profile, "assets_discovered": run.assets_discovered, "assets_new": run.assets_new, "partial": run.partial, "failure_reason": run.failure_reason}

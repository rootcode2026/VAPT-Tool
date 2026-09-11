"""E15 External Attack Surface API — project-scoped, bounded, safe."""

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
    try:
        from app.db.rls import set_tenant_context
        org_id = getattr(user, "organization_id", None)
        if org_id and str(org_id).strip():
            if db.in_transaction():
                set_tenant_context(db, organization_id=str(org_id), project_id=str(project_id), user_id=str(user.id))
    except Exception:
        pass

def _require_role(project_id: str, db: Session, user: User, allowed: list[str]):
    from app.api.deps import _effective_project_role, _is_super_admin
    if _is_super_admin(user):
        return
    role = _effective_project_role(user, project_id, db)
    if role not in allowed:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

def _audit(db: Session, project_id: str, user: User, event_type: str, resource_id: str, result: str = "SUCCESS"):
    try:
        from app.services.audit import AuditService
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type=event_type, action=event_type, result=result, actor_user_id=user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="external_attack_surface", resource_id=resource_id, metadata={})
        db.commit()
    except Exception:
        pass

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
    return get_summary(project_id, db)

@router.get("/summary")
def get_eas_summary(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    return get_summary(project_id, db)

@router.get("/assets")
def list_eas_assets(project_id: str, asset_type: str | None = Query(None, max_length=20), ownership: str | None = Query(None, max_length=20), limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    assets = list_assets(project_id, db, asset_type=asset_type, ownership=ownership, limit=limit)
    return {"project_id": project_id, "count": len(assets), "assets": [{"id": a.id, "value": a.value, "asset_type": a.asset_type, "extra_data": a.extra_data} for a in assets]}

@router.get("/assets/{asset_id}")
def get_eas_asset(project_id: str, asset_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    asset = get_asset_detail(project_id, db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {"id": asset.id, "value": asset.value, "asset_type": asset.asset_type, "extra_data": asset.extra_data}

@router.get("/assets/{asset_id}/changes")
def get_asset_changes(project_id: str, asset_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    asset = get_asset_detail(project_id, db, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    # For E15, return mock changes (reuse asset_change_event if exists)
    return {"asset_id": asset_id, "changes": []}

@router.get("/candidates")
def list_eas_candidates(project_id: str, limit: int = Query(50, ge=1, le=100), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    cands = list_candidates(project_id, db, limit=limit)
    return {"project_id": project_id, "count": len(cands), "candidates": [{"id": a.id, "value": a.value, "asset_type": a.asset_type, "extra_data": a.extra_data} for a in cands]}

@router.post("/candidates/{asset_id}/confirm")
def confirm_candidate(project_id: str, asset_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_role(project_id, db, current_user, ["analyst", "project_admin"])
    asset = confirm_asset(asset_id, db, project_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    _audit(db, project_id, current_user, "EXTERNAL_ASSET_CONFIRMED", asset_id)
    return {"id": asset.id, "ownership_confidence": asset.extra_data.get("ownership_confidence")}

@router.post("/candidates/{asset_id}/reject")
def reject_candidate(project_id: str, asset_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_role(project_id, db, current_user, ["analyst", "project_admin"])
    asset = reject_asset(asset_id, db, project_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    _audit(db, project_id, current_user, "EXTERNAL_ASSET_REJECTED", asset_id)
    return {"id": asset.id, "ownership_confidence": asset.extra_data.get("ownership_confidence")}

@router.post("/scopes")
def create_eas_scope(project_id: str, body: CreateScopeRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_role(project_id, db, current_user, ["project_admin"])
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    try:
        scope = create_scope(project_id, db, body.name, body.description, created_by=current_user.id, organization_id=proj.organization_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(db, project_id, current_user, "EXTERNAL_SCOPE_CREATED", scope.id)
    return {"id": scope.id, "name": scope.name, "project_id": scope.project_id}

@router.get("/scopes")
def list_eas_scopes(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    scopes = list_scopes(project_id, db)
    return {"project_id": project_id, "count": len(scopes), "scopes": [{"id": s.id, "name": s.name, "status": s.status} for s in scopes]}

@router.patch("/scopes/{scope_id}")
def update_eas_scope(project_id: str, scope_id: str, body: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_role(project_id, db, current_user, ["project_admin"])
    scope = db.query(ExternalScope).filter(ExternalScope.id == scope_id, ExternalScope.project_id == project_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    if "name" in body:
        scope.name = str(body["name"])[:200]
    if "status" in body:
        scope.status = str(body["status"])[:20]
    db.commit()
    _audit(db, project_id, current_user, "EXTERNAL_SCOPE_UPDATED", scope_id)
    return {"id": scope.id, "name": scope.name, "status": scope.status}

@router.post("/scopes/{scope_id}/entries")
def create_eas_entry(project_id: str, scope_id: str, body: CreateEntryRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_role(project_id, db, current_user, ["project_admin"])
    # Verify scope belongs to project
    scope = db.query(ExternalScope).filter(ExternalScope.id == scope_id, ExternalScope.project_id == project_id).first()
    if not scope:
        raise HTTPException(status_code=404, detail="Scope not found")
    try:
        entry = create_scope_entry(scope_id, db, body.entry_type, body.value, body.authorization_status, source="manual")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(db, project_id, current_user, "EXTERNAL_SCOPE_ENTRY_CREATED", entry.id)
    return {"id": entry.id, "value": entry.value, "entry_type": entry.entry_type, "authorization_status": entry.authorization_status}

@router.patch("/entries/{entry_id}")
def update_eas_entry(project_id: str, entry_id: str, body: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_role(project_id, db, current_user, ["analyst", "project_admin"])
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
    _audit(db, project_id, current_user, "EXTERNAL_SCOPE_ENTRY_UPDATED", entry_id)
    return {"id": updated.id, "authorization_status": updated.authorization_status, "ownership_confidence": updated.ownership_confidence}

class DiscoverRequest(BaseModel):
    external_scope_id: Optional[str] = None
    profile: str = "QUICK"

@router.post("/discover")
def discover_external(project_id: str, body: DiscoverRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_role(project_id, db, current_user, ["analyst", "project_admin"])
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    try:
        run = create_discovery_run(project_id, db, body.external_scope_id, body.profile, created_by=current_user.id, organization_id=proj.organization_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    _audit(db, project_id, current_user, "EXTERNAL_DISCOVERY_STARTED", run.id)
    return {"id": run.id, "status": run.status, "profile": run.profile}

@router.get("/runs")
def list_runs(project_id: str, limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    runs = db.query(ExternalDiscoveryRun).filter(ExternalDiscoveryRun.project_id == project_id).order_by(ExternalDiscoveryRun.created_at.desc()).limit(limit).all()
    return {"project_id": project_id, "count": len(runs), "runs": [{"id": r.id, "status": r.status, "profile": r.profile, "assets_discovered": r.assets_discovered, "created_at": r.created_at.isoformat() if r.created_at else None} for r in runs]}

@router.get("/runs/{run_id}")
def get_run(project_id: str, run_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    run = db.query(ExternalDiscoveryRun).filter(ExternalDiscoveryRun.id == run_id, ExternalDiscoveryRun.project_id == project_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {"id": run.id, "status": run.status, "profile": run.profile, "assets_discovered": run.assets_discovered, "assets_new": run.assets_new, "partial": run.partial, "failure_reason": run.failure_reason}

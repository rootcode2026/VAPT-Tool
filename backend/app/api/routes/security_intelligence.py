"""F1 Security Intelligence API — deterministic, bounded, tenant-isolated."""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User

router = APIRouter(prefix="/api/v1/projects/{project_id}/security-intelligence", tags=["Security Intelligence"])

def _set_rls(db: Session, project_id: str, user: User):
    try:
        from app.db.rls import set_tenant_context
        org_id = getattr(user, "organization_id", None)
        if org_id and str(org_id).strip():
            in_tx = False
            try:
                in_tx = bool(db.in_transaction() or db.in_nested_transaction())
            except: in_tx = False
            if not in_tx:
                try: db.begin()
                except: pass
            try:
                set_tenant_context(db, organization_id=str(org_id).strip(), project_id=str(project_id).strip(), user_id=str(user.id))
            except:
                try: set_tenant_context(db, organization_id=str(org_id).strip(), user_id=str(user.id))
                except: pass
    except: pass

def _require_read(project_id: str, db: Session, user: User):
    from app.api.deps import _effective_project_role, _effective_org_role, _is_super_admin
    from app.core.permissions import ORG_ROLE_PERMISSIONS, PROJECT_ROLE_PERMISSIONS
    if _is_super_admin(user):
        return
    try:
        from app.core.config import settings
        if getattr(settings, "RBAC_STRICT_MODE", False):
            role = _effective_project_role(user, project_id, db)
            if not role:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            perms = set(PROJECT_ROLE_PERMISSIONS.get(role, set()))
            try:
                from app.models.project import Project as _P
                _proj = db.query(_P).filter(_P.id == project_id).first()
                if _proj:
                    _org_role = _effective_org_role(user, _proj.organization_id, db)
                    if _org_role:
                        perms.update(ORG_ROLE_PERMISSIONS.get(_org_role, set()))
            except: pass
            if "security_intelligence.read" not in perms:
                raise HTTPException(status_code=403, detail="Insufficient permissions")
            return
    except HTTPException: raise
    except: pass
    perms = set()
    from app.api.deps import _effective_project_role as _epr, _effective_org_role as _eor
    role = _epr(user, project_id, db)
    if role:
        perms.update(PROJECT_ROLE_PERMISSIONS.get(role, set()))
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        if proj:
            org_role = _eor(user, proj.organization_id, db)
            if org_role:
                perms.update(ORG_ROLE_PERMISSIONS.get(org_role, set()))
    except: pass
    if "security_intelligence.read" not in perms:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

def _validate_subject(subject_type: str, subject_id: str):
    valid = {"finding","application","asset","cloud_resource","external_asset","attack_path"}
    if subject_type.lower() not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid subject_type: {subject_type}")
    if not subject_id or len(subject_id) > 100:
        raise HTTPException(status_code=400, detail="Invalid subject_id")
    # simple id validation: no injection
    if any(c in subject_id for c in [";", "'", "\"", "--"]):
        raise HTTPException(status_code=400, detail="Invalid subject_id")

@router.get("/context/{subject_type}/{subject_id}")
def get_context(project_id: str, subject_type: str, subject_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    _validate_subject(subject_type, subject_id)
    from app.services.security_intelligence import get_security_context
    ctx = get_security_context(project_id, db, subject_type, subject_id)
    if not ctx:
        raise HTTPException(status_code=404, detail="Subject not found")
    return ctx

@router.get("/blast-radius/{subject_type}/{subject_id}")
def get_blast_radius(project_id: str, subject_type: str, subject_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    _validate_subject(subject_type, subject_id)
    from app.services.security_intelligence import get_blast_radius
    br = get_blast_radius(project_id, db, subject_type, subject_id)
    if not br:
        raise HTTPException(status_code=404, detail="Subject not found")
    return br

@router.get("/exposure-chain/{subject_type}/{subject_id}")
def get_exposure_chain(project_id: str, subject_type: str, subject_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    _validate_subject(subject_type, subject_id)
    from app.services.security_intelligence import get_exposure_chain
    chain = get_exposure_chain(project_id, db, subject_type, subject_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Subject not found")
    return chain

@router.get("/impact/{subject_type}/{subject_id}")
def get_impact(project_id: str, subject_type: str, subject_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    _validate_subject(subject_type, subject_id)
    from app.services.security_intelligence import get_impact
    imp = get_impact(project_id, db, subject_type, subject_id)
    if not imp:
        raise HTTPException(status_code=404, detail="Subject not found")
    return imp

# F2 prioritization endpoints
from fastapi import Query

@router.get("/priorities")
def get_priorities(project_id: str, limit: int = Query(50, ge=1, le=100), severity: str | None = Query(None), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_prioritization import get_prioritized_findings
    findings = get_prioritized_findings(project_id, db, limit=limit)
    if severity:
        findings = [f for f in findings if f["severity"].lower() == severity.lower()]
    # sanitize already done
    return {"project_id": project_id, "count": len(findings[:limit]), "priorities": [{"finding_id": f["finding_id"], "score": f["score"], "tier": f["tier"], "severity": f["severity"], "reasons": f["reasons"][:3], "fingerprint": f["fingerprint"]} for f in findings[:limit]]}

@router.get("/priorities/{subject_type}/{subject_id}")
def get_subject_priority(project_id: str, subject_type: str, subject_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    _validate_subject(subject_type, subject_id)
    if subject_type.lower() == "finding":
        from app.services.security_prioritization import get_finding_priority_detail
        pri = get_finding_priority_detail(project_id, db, subject_id)
        if not pri:
            raise HTTPException(status_code=404, detail="Subject not found")
        return pri
    elif subject_type.lower() == "application":
        from app.services.security_prioritization import get_application_priority_detail
        pri = get_application_priority_detail(project_id, db, subject_id)
        if not pri:
            raise HTTPException(status_code=404, detail="Subject not found")
        return pri
    else:
        # for asset/external etc, return impact as priority
        from app.services.security_intelligence import get_impact
        imp = get_impact(project_id, db, subject_type, subject_id)
        if not imp:
            raise HTTPException(status_code=404, detail="Subject not found")
        # map impact to priority
        return {"subject_type": subject_type, "subject_id": subject_id, "priority": imp.get("priority"), "factors": imp.get("factors"), "score": 0, "tier": imp.get("priority")}

@router.get("/top-risks")
def get_top_risks(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_prioritization import get_top_risks as svc_top
    return svc_top(project_id, db)

@router.get("/priority-summary")
def get_priority_summary(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_prioritization import get_priority_summary as svc_sum
    return svc_sum(project_id, db)

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

# F4 Attack Surface Analytics endpoints
from fastapi import Query
from datetime import datetime, timezone

# --- helpers for F4 ---
def _validate_window(window: str):
    if window not in ("7d", "30d", "90d"):
        raise HTTPException(status_code=400, detail="Invalid window: use 7d|30d|90d")
    return window

def _f4_response(project_id: str, data: dict, data_quality: dict | None = None) -> dict:
    return {
        "project_id": project_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data_quality": data_quality or {"status": "SUFFICIENT", "limitations": []},
        **data,
    }

# F4: attack surface overview
@router.get("/attack-surface")
def get_attack_surface(project_id: str, window: str | None = Query(None), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    if window:
        _validate_window(window)
    from app.services.attack_surface_analytics import get_attack_surface_overview
    overview = get_attack_surface_overview(project_id, db)
    # if window requested, include historical
    if window:
        try:
            from app.services.attack_surface_analytics import get_historical_analytics
            hist = get_historical_analytics(project_id, db, window=window)
            overview["historical"] = hist
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
    return overview

@router.get("/attack-surface/distribution")
def get_attack_distribution(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.attack_surface_analytics import get_exposure_distribution
    dist = get_exposure_distribution(project_id, db)
    return _f4_response(project_id, {"distribution": dist})

@router.get("/attack-surface/hotspots")
def get_attack_hotspots(project_id: str, limit: int = Query(20, ge=1, le=20), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.attack_surface_analytics import get_hotspots
    return get_hotspots(project_id, db, limit=limit)

@router.get("/attack-surface/concentration")
def get_attack_concentration(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.attack_surface_analytics import get_exposure_concentration, get_risk_concentration
    conc = get_exposure_concentration(project_id, db)
    risk = get_risk_concentration(project_id, db)
    return {"project_id": project_id, "generated_at": datetime.now(timezone.utc).isoformat(), "concentration": conc.get("concentration", {}), "risk_concentration": risk, "details": conc.get("details", {})}

@router.get("/attack-surface/coverage")
def get_attack_coverage(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.attack_surface_analytics import get_coverage_gaps
    return get_coverage_gaps(project_id, db)

@router.get("/attack-surface/technology")
def get_attack_technology(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.attack_surface_analytics import get_technology_concentration
    return get_technology_concentration(project_id, db)

@router.get("/attack-surface/cloud")
def get_attack_cloud(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.attack_surface_analytics import get_cloud_exposure_analytics
    return get_cloud_exposure_analytics(project_id, db)

@router.get("/attack-surface/applications")
def get_attack_applications(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.attack_surface_analytics import get_application_exposure_analytics
    return get_application_exposure_analytics(project_id, db)

@router.get("/attack-surface/finding-concentration")
def get_attack_finding_concentration(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.attack_surface_analytics import get_finding_concentration
    return get_finding_concentration(project_id, db)

@router.get("/attack-surface/attack-paths")
def get_attack_paths_analytics(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.attack_surface_analytics import get_attack_path_concentration
    return get_attack_path_concentration(project_id, db)

@router.get("/attack-surface/top")
def get_attack_top(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.attack_surface_analytics import get_top_risk_hotspots
    return get_top_risk_hotspots(project_id, db)

@router.get("/attack-surface/historical")
def get_attack_historical(project_id: str, window: str = Query("7d"), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    _validate_window(window)
    from app.services.attack_surface_analytics import get_historical_analytics
    return get_historical_analytics(project_id, db, window=window)

# F2 prioritization endpoints

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

# F5 Security Exposure Intelligence
@router.get("/exposure-chains")
def get_exposure_chains(project_id: str, limit: int = Query(20, ge=1, le=20), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_exposure_intelligence import get_exposure_chains as svc
    return svc(project_id, db, limit=limit)

@router.get("/exposure-decision")
def get_exposure_decision(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_exposure_intelligence import get_exposure_decision as svc
    return svc(project_id, db)

@router.get("/exposure-concentration")
def get_exposure_concentration_f5(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_exposure_intelligence import get_exposure_concentration_f5 as svc
    return svc(project_id, db)

@router.get("/change-exposure")
def get_change_exposure(project_id: str, limit: int = Query(20, ge=1, le=20), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_exposure_intelligence import get_change_exposure as svc
    return svc(project_id, db, limit=limit)

@router.get("/coverage")
def get_coverage_f5(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_exposure_intelligence import get_security_coverage as svc
    return svc(project_id, db)

@router.get("/root-cause")
def get_root_cause(project_id: str, limit: int = Query(20, ge=1, le=20), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_exposure_intelligence import get_root_cause_context as svc
    return svc(project_id, db, limit=limit)

# F6 Security Decision History
@router.get("/history")
def get_history_f6(project_id: str, window: str = Query("7d", regex="^(7d|30d|90d)$"), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_decision_history import get_exposure_history
    try:
        return get_exposure_history(project_id, db, window=window)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/scorecard")
def get_scorecard_f6(project_id: str, window: str = Query("7d", regex="^(7d|30d|90d)$"), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_decision_history import get_scorecard
    try:
        return get_scorecard(project_id, db, window=window)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/recurring-exposure")
def get_recurring_f6(project_id: str, limit: int = Query(20, ge=1, le=20), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_decision_history import get_recurring_exposure
    return get_recurring_exposure(project_id, db, limit=limit)

@router.get("/remediation-effectiveness")
def get_remediation_f6(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_decision_history import get_remediation_effectiveness
    return get_remediation_effectiveness(project_id, db)

@router.get("/attack-path-history")
def get_attack_history_f6(project_id: str, limit: int = Query(20, ge=1, le=20), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_decision_history import get_attack_path_history_analytics
    return get_attack_path_history_analytics(project_id, db, limit=limit)

@router.get("/subject-history/{subject_type}/{subject_id}")
def get_subject_history_f6(project_id: str, subject_type: str, subject_id: str, window: str = Query("7d", regex="^(7d|30d|90d)$"), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    allowed={"finding","asset","application","attack_path","exposure","investigation"}
    if subject_type.lower() not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid subject_type: {subject_type}")
    if any(c in subject_id for c in [";", "'", "\"", "--"]):
        raise HTTPException(status_code=400, detail="Invalid subject_id")
    from app.services.security_decision_history import get_subject_history
    try:
        res=get_subject_history(project_id, db, subject_type, subject_id, window=window)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not res:
        raise HTTPException(status_code=404, detail="Subject not found")
    return res

@router.get("/risk-acceptance-aging")
def get_acceptance_aging_f6(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_decision_history import get_risk_acceptance_aging
    return get_risk_acceptance_aging(project_id, db)

@router.get("/improvement")
def get_improvement_f6(project_id: str, window: str = Query("7d", regex="^(7d|30d|90d)$"), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_decision_history import get_improvement
    try:
        return get_improvement(project_id, db, window=window)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

# F3 trends
@router.get("/trends")
def get_trends(project_id: str, window: str = Query("7d", regex="^(7d|30d|90d)$"), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_trends import get_trends as svc_trends
    try:
        return svc_trends(project_id, db, window=window)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/trends/summary")
def get_trends_summary(project_id: str, window: str = Query("7d", regex="^(7d|30d|90d)$"), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    from app.services.security_trends import get_trends_summary as svc_sum
    try:
        return svc_sum(project_id, db, window=window)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/trends/{subject_type}/{subject_id}")
def get_subject_trends(project_id: str, subject_type: str, subject_id: str, window: str = Query("7d", regex="^(7d|30d|90d)$"), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_read(project_id, db, current_user)
    _validate_subject(subject_type, subject_id)
    from app.services.security_trends import get_subject_trends as svc_sub
    try:
        res = svc_sub(project_id, db, subject_type, subject_id, window=window)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if not res:
        raise HTTPException(status_code=404, detail="Subject not found")
    return res

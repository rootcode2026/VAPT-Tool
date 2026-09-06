from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access, _is_super_admin, _effective_org_role
from app.db.database import get_db
from app.models.user import User
from app.services.compliance_service import list_frameworks, get_framework, get_controls, get_control_coverage, seed_frameworks

router = APIRouter(prefix="/api/v1/compliance", tags=["Compliance"])

@router.get("/frameworks")
def list_compliance_frameworks(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # All authenticated can list
    frameworks = list_frameworks(db)
    return {"items": [{"id": f.id, "framework": f.framework, "version": f.version, "display_name": f.display_name, "description": f.description} for f in frameworks], "total": len(frameworks)}

@router.get("/frameworks/{framework_id}")
def get_compliance_framework(framework_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    fw = get_framework(db, framework_id)
    if not fw:
        # try by framework name
        from app.models.compliance import ComplianceFramework
        fw = db.query(ComplianceFramework).filter(ComplianceFramework.framework == framework_id).first()
        if not fw:
            raise HTTPException(status_code=404, detail="Framework not found")
    return {"id": fw.id, "framework": fw.framework, "version": fw.version, "display_name": fw.display_name, "description": fw.description}

@router.get("/frameworks/{framework_id}/controls")
def list_controls(framework_id: str, organization_id: str | None = Query(None), project_id: str | None = Query(None), status: str | None = Query(None), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Resolve framework
    from app.models.compliance import ComplianceFramework, ComplianceControl
    fw = get_framework(db, framework_id)
    if not fw:
        fw = db.query(ComplianceFramework).filter(ComplianceFramework.framework == framework_id).first()
        if not fw:
            raise HTTPException(status_code=404, detail="Framework not found")
    # tenant isolation for coverage
    if project_id:
        require_project_access(project_id, db, current_user)
        org_id = db.query(ComplianceFramework).filter(ComplianceFramework.id == fw.id).first()
        # use project org
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        org_for_cov = proj.organization_id if proj else current_user.organization_id
    elif organization_id:
        if not _is_super_admin(current_user):
            role = _effective_org_role(current_user, organization_id, db)
            if not role:
                raise HTTPException(status_code=404, detail="Organization not found")
        org_for_cov = organization_id
    else:
        org_for_cov = current_user.organization_id
    controls = get_controls(db, fw.id)
    if status:
        controls = [c for c in controls if c.status == status.strip().lower()]
    # enrich with mapping coverage
    cov = get_control_coverage(db, fw.id, org_for_cov, project_id)
    return {
        "framework_id": fw.id,
        "framework": fw.framework,
        "display_name": fw.display_name,
        "controls": [{"id": c.id, "control_id": c.control_id, "title": c.title, "description": c.description, "category": c.category, "status": c.status} for c in controls],
        "total": len(controls),
        "coverage": cov,
    }

@router.get("/mappings")
def list_mappings(project_id: str | None = Query(None), framework_id: str | None = Query(None), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    from app.models.compliance import ComplianceMapping
    q = db.query(ComplianceMapping)
    if project_id:
        require_project_access(project_id, db, current_user)
        q = q.filter(ComplianceMapping.project_id == project_id)
    elif not _is_super_admin(current_user):
        q = q.filter(ComplianceMapping.organization_id == current_user.organization_id)
    if framework_id:
        # filter via control
        from app.models.compliance import ComplianceControl
        control_ids = [c.id for c in db.query(ComplianceControl).filter(ComplianceControl.framework_id == framework_id).all()]
        q = q.filter(ComplianceMapping.control_id.in_(control_ids))
    rows = q.limit(100).all()
    return {"items": [{"id": r.id, "control_id": r.control_id, "organization_id": r.organization_id, "project_id": r.project_id, "source_type": r.source_type, "source_id": r.source_id} for r in rows], "total": len(rows)}

@router.post("/reports", status_code=201)
def create_compliance_report(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    framework = str(payload.get("framework", "")).strip().lower()
    if not framework:
        raise HTTPException(status_code=400, detail="framework required")
    # map framework name to id
    from app.models.compliance import ComplianceFramework
    fw = db.query(ComplianceFramework).filter(ComplianceFramework.framework == framework).first()
    if not fw:
        # seed
        seed_frameworks(db)
        fw = db.query(ComplianceFramework).filter(ComplianceFramework.framework == framework).first()
        if not fw:
            raise HTTPException(status_code=404, detail="Framework not found")
    project_id = payload.get("project_id")
    organization_id = payload.get("organization_id") or current_user.organization_id
    if project_id:
        require_project_access(str(project_id), db, current_user)
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == str(project_id)).first()
        organization_id = proj.organization_id if proj else organization_id
    else:
        if not _is_super_admin(current_user):
            role = _effective_org_role(current_user, str(organization_id), db)
            if not role:
                raise HTTPException(status_code=404, detail="Organization not found")
    # Generate compliance report via report service
    from app.services.report_service import collect_metrics, build_report_content
    import uuid
    from datetime import datetime, timezone
    from app.models.report import Report
    from app.services.audit import AuditService
    report = Report(id=str(uuid.uuid4()), organization_id=organization_id, project_id=project_id, report_type="compliance", title=f"Compliance Report — {fw.display_name}", status="completed", generated_by=current_user.id, parameters={"framework": framework, "version": fw.version}, version="1.0", data_as_of=datetime.now(timezone.utc))
    metrics = collect_metrics(db, organization_id, project_id, {})
    from app.services.compliance_service import get_control_coverage
    cov = get_control_coverage(db, fw.id, organization_id, project_id)
    content = {"framework": fw.framework, "display_name": fw.display_name, "version": fw.version, "coverage": cov, "metrics": metrics, "note": "Control coverage via technical evidence, not certification."}
    report.summary = {"coverage": cov, "framework": framework}
    report.content = content
    report.data_snapshot = {"coverage": cov}
    db.add(report)
    db.commit()
    try:
        AuditService.record(db, event_type="COMPLIANCE_REPORT_GENERATED", action="COMPLIANCE_REPORT_GENERATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type="report", resource_id=report.id, metadata={"framework": framework})
        db.commit()
    except Exception:
        pass
    return {"id": report.id, "framework": fw.framework, "display_name": fw.display_name, "status": report.status}

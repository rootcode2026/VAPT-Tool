from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
import uuid
from datetime import datetime, timezone

from app.api.deps import get_current_user, require_project_access, _is_super_admin, _effective_project_role, _effective_org_role
from app.db.database import get_db
from app.models.report import Report, REPORT_TYPES
from app.models.user import User
from app.services.audit import AuditService
from app.services.report_service import collect_metrics, build_report_content, export_csv, export_pdf

router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])

def _resolve_org(project_id: str | None, db: Session, user: User) -> str:
    if project_id:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")
        # tenant check already via require_project_access if project provided
        return proj.organization_id
    return user.organization_id

def _can_generate(user: User, db: Session, organization_id: str, project_id: str | None) -> bool:
    if _is_super_admin(user):
        return True
    if project_id:
        role = _effective_project_role(user, project_id, db)
        if role in ("analyst", "project_admin"):
            return True
        # org_admin via fallback
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        if proj and _effective_org_role(user, proj.organization_id, db) == "org_admin":
            return True
        return False
    else:
        # org report
        role = _effective_org_role(user, organization_id, db)
        return role == "org_admin"

@router.post("", status_code=201)
def create_report(payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    report_type = str(payload.get("report_type", "")).strip().lower()
    if report_type not in REPORT_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid report_type. Allowed: {sorted(REPORT_TYPES)}")
    title = str(payload.get("title", "")).strip()[:255] or f"{report_type} Report"
    project_id = payload.get("project_id")
    if project_id:
        project_id = str(project_id).strip()
        require_project_access(project_id, db, current_user)
        if not _can_generate(current_user, db, "", project_id):
            raise HTTPException(status_code=403, detail="Insufficient permissions to generate report")
        org_id = _resolve_org(project_id, db, current_user)
    else:
        org_id = current_user.organization_id
        if not _can_generate(current_user, db, org_id, None):
            raise HTTPException(status_code=403, detail="Requires org_admin")
    params = payload.get("parameters") or {}
    if not isinstance(params, dict):
        params = {}
    # bounded filters
    for k in list(params.keys()):
        if k not in ("date_from", "date_to", "severity", "finding_status", "asset_type", "scanner", "framework"):
            params.pop(k)
    report = Report(
        id=str(uuid.uuid4()),
        organization_id=org_id,
        project_id=project_id,
        report_type=report_type,
        title=title[:255],
        status="queued",
        generated_by=current_user.id,
        parameters=params,
        version="1.0",
        data_as_of=datetime.now(timezone.utc),
    )
    db.add(report)
    db.flush()
    # audit created
    try:
        AuditService.record(db, event_type="REPORT_CREATED", action="REPORT_CREATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=org_id, project_id=project_id, resource_type="report", resource_id=report.id, metadata={"report_type": report_type, "title": title[:100]})
    except Exception:
        pass
    # Generate synchronously for demo (would be Celery in production)
    report.status = "running"
    db.commit()
    try:
        AuditService.record(db, event_type="REPORT_GENERATION_STARTED", action="REPORT_GENERATION_STARTED", result="SUCCESS", actor_user_id=current_user.id, organization_id=org_id, project_id=project_id, resource_type="report", resource_id=report.id, metadata={"report_type": report_type})
    except Exception:
        pass
    try:
        metrics = collect_metrics(db, org_id, project_id, params)
        content = build_report_content(report_type, metrics, db, org_id, project_id)
        report.summary = metrics
        report.content = content
        report.data_snapshot = {"metrics": metrics, "as_of": report.data_as_of.isoformat() if report.data_as_of else None}
        report.status = "completed"
        report.completed_at = datetime.now(timezone.utc)
        try:
            AuditService.record(db, event_type="REPORT_GENERATION_COMPLETED", action="REPORT_GENERATION_COMPLETED", result="SUCCESS", actor_user_id=current_user.id, organization_id=org_id, project_id=project_id, resource_type="report", resource_id=report.id, metadata={"report_type": report_type})
        except Exception:
            pass
        db.commit()
    except Exception as e:
        report.status = "failed"
        report.error = str(e)[:500]
        report.completed_at = datetime.now(timezone.utc)
        try:
            AuditService.record(db, event_type="REPORT_GENERATION_FAILED", action="REPORT_GENERATION_FAILED", result="FAILURE", actor_user_id=current_user.id, organization_id=org_id, project_id=project_id, resource_type="report", resource_id=report.id, metadata={"error": str(e)[:200]})
        except Exception:
            pass
        db.commit()
        raise HTTPException(status_code=500, detail="Report generation failed")
    db.refresh(report)
    return {"id": report.id, "report_type": report.report_type, "title": report.title, "status": report.status, "organization_id": report.organization_id, "project_id": report.project_id, "created_at": report.created_at.isoformat() if report.created_at else None}

@router.get("")
def list_reports(organization_id: str | None = Query(None), project_id: str | None = Query(None), report_type: str | None = Query(None), page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Tenant isolation: scope to user's org unless super_admin
    if project_id:
        require_project_access(project_id, db, current_user)
        q = db.query(Report).filter(Report.project_id == project_id)
    elif organization_id:
        # verify user belongs to org
        if not _is_super_admin(current_user):
            from app.api.deps import _effective_org_role
            role = _effective_org_role(current_user, organization_id, db)
            if not role:
                raise HTTPException(status_code=404, detail="Organization not found")
        q = db.query(Report).filter(Report.organization_id == organization_id)
    else:
        # default to user's org
        if _is_super_admin(current_user):
            q = db.query(Report)
        else:
            q = db.query(Report).filter(Report.organization_id == current_user.organization_id)
    if report_type:
        if report_type.strip().lower() not in REPORT_TYPES:
            raise HTTPException(status_code=400, detail="Invalid report_type")
        q = q.filter(Report.report_type == report_type.strip().lower())
    total = q.count()
    total_pages = (total + page_size - 1)//page_size if total else 0
    rows = q.order_by(Report.created_at.desc()).offset((page-1)*page_size).limit(page_size).all()
    return {"items": [{"id": r.id, "report_type": r.report_type, "title": r.title, "status": r.status, "organization_id": r.organization_id, "project_id": r.project_id, "created_at": r.created_at.isoformat() if r.created_at else None, "completed_at": r.completed_at.isoformat() if r.completed_at else None} for r in rows], "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}

@router.get("/{report_id}")
def get_report(report_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    # tenant check
    if not _is_super_admin(current_user):
        if r.project_id:
            require_project_access(r.project_id, db, current_user)
        else:
            from app.api.deps import _effective_org_role
            role = _effective_org_role(current_user, r.organization_id, db)
            if not role:
                raise HTTPException(status_code=404, detail="Report not found")
    # audit viewed
    try:
        AuditService.record(db, event_type="REPORT_VIEWED", action="REPORT_VIEWED", result="SUCCESS", actor_user_id=current_user.id, organization_id=r.organization_id, project_id=r.project_id, resource_type="report", resource_id=r.id, metadata={"report_type": r.report_type})
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return {"id": r.id, "report_type": r.report_type, "title": r.title, "status": r.status, "organization_id": r.organization_id, "project_id": r.project_id, "parameters": r.parameters, "summary": r.summary, "content": r.content, "version": r.version, "data_as_of": r.data_as_of.isoformat() if r.data_as_of else None, "created_at": r.created_at.isoformat() if r.created_at else None, "completed_at": r.completed_at.isoformat() if r.completed_at else None}

@router.post("/{report_id}/cancel")
def cancel_report(report_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    if not _is_super_admin(current_user):
        if r.project_id:
            require_project_access(r.project_id, db, current_user)
            # only project_admin can cancel
            from app.api.deps import _effective_project_role
            role = _effective_project_role(current_user, r.project_id, db)
            if role not in ("project_admin", "analyst") and _effective_org_role(current_user, r.organization_id, db) != "org_admin":
                raise HTTPException(status_code=403, detail="Cannot cancel")
        else:
            from app.api.deps import _effective_org_role
            if _effective_org_role(current_user, r.organization_id, db) != "org_admin":
                raise HTTPException(status_code=403, detail="Cannot cancel")
    if r.status in ("completed", "failed", "cancelled"):
        raise HTTPException(status_code=400, detail=f"Cannot cancel report in status {r.status}")
    r.status = "cancelled"
    r.completed_at = datetime.now(timezone.utc)
    try:
        AuditService.record(db, event_type="REPORT_CANCELLED", action="REPORT_CANCELLED", result="SUCCESS", actor_user_id=current_user.id, organization_id=r.organization_id, project_id=r.project_id, resource_type="report", resource_id=r.id)
    except Exception:
        pass
    db.commit()
    return {"id": r.id, "status": r.status}

@router.get("/{report_id}/download/{fmt}")
def download_report(report_id: str, fmt: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    if not _is_super_admin(current_user):
        if r.project_id:
            require_project_access(r.project_id, db, current_user)
        else:
            from app.api.deps import _effective_org_role
            if not _effective_org_role(current_user, r.organization_id, db):
                raise HTTPException(status_code=404, detail="Report not found")
    if r.status != "completed":
        raise HTTPException(status_code=400, detail="Report not completed")
    fmt = fmt.strip().lower()
    if fmt not in ("json", "csv", "pdf"):
        raise HTTPException(status_code=400, detail="Invalid format")
    # audit
    try:
        AuditService.record(db, event_type="REPORT_DOWNLOADED", action="REPORT_DOWNLOADED", result="SUCCESS", actor_user_id=current_user.id, organization_id=r.organization_id, project_id=r.project_id, resource_type="report", resource_id=r.id, metadata={"format": fmt})
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    if fmt == "json":
        return {"id": r.id, "report_type": r.report_type, "title": r.title, "summary": r.summary, "content": r.content, "data_snapshot": r.data_snapshot, "version": r.version}
    elif fmt == "csv":
        # Build findings CSV from content if available
        findings = []
        if r.content and isinstance(r.content, dict) and "findings" in r.content:
            findings = r.content["findings"]
        else:
            # fallback to summary
            findings = [{"id": r.id, "title": r.title, "severity": "info", "status": r.status, "scanner": r.report_type, "asset_id": "", "evidence": ""}]
        csv_bytes = export_csv(findings)
        return Response(content=csv_bytes, media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{r.report_type}-{r.id}.csv"'})
    else:  # pdf
        pdf_bytes = export_pdf({"title": r.title, "report_type": r.report_type, "organization_id": r.organization_id, "project_id": r.project_id, "version": r.version, "data_as_of": r.data_as_of.isoformat() if r.data_as_of else "", "summary": r.summary or {}, "content": r.content or {}})
        return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{r.report_type}-{r.id}.pdf"'})

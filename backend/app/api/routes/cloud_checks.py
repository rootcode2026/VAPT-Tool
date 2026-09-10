"""E2 AWS security-check APIs: catalog, run evaluation, run history.

Evaluation is offline over persisted E1 evidence (no AWS calls, no
credentials). Repeat evaluation of the same discovery run is a deterministic
no-op (UNIQUE constraint). Findings use the existing Findings table with
scanner="cloud" and existing lifecycle states.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access, _is_super_admin, _effective_project_role, _effective_org_role
from app.db.database import get_db
from app.models.cloud_check import CloudCheckRun
from app.models.cloud_discovery import CloudDiscovery
from app.models.connector import CloudConnection
from app.models.project import Project
from app.models.user import User
from app.services import cloud_checks as checks
from app.services.audit import (
    EVENT_CLOUD_CHECK_RUN_FAILED,
    RESOURCE_CLOUD_CHECK_RUN,
    RESULT_FAILURE,
    AuditService,
)

router = APIRouter(prefix="/api/v1/projects/{project_id}/cloud/security-checks", tags=["Cloud Security Checks"])


def _utcnow():
    return datetime.now(timezone.utc)


def _require_run(project_id: str, db: Session, current_user: User) -> None:
    """Run evaluation: analyst or above (mirrors scan/discovery execution)."""
    if _is_super_admin(current_user):
        return
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj and _effective_org_role(current_user, proj.organization_id, db) == "org_admin":
        return
    role = _effective_project_role(current_user, project_id, db)
    if role not in ("analyst", "project_admin"):
        raise HTTPException(status_code=403, detail="Requires analyst or project_admin to run security checks")


def _run_payload(run: CloudCheckRun) -> dict:
    return {
        "id": run.id,
        "connection_id": run.connection_id,
        "discovery_run_id": run.discovery_run_id,
        "project_id": run.project_id,
        "status": run.status,
        "checks_executed": run.checks_executed,
        "resources_evaluated": run.resources_evaluated,
        "passed": run.passed,
        "failed": run.failed,
        "not_assessed": run.not_assessed,
        "errors": run.errors,
        "findings_created": run.findings_created,
        "breakdown": run.breakdown or {},
        "check_pack_version": run.check_pack_version,
        "error": run.error,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


@router.get("/catalog")
def get_catalog(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    return {"provider": "aws", "pack_version": checks.CHECK_PACK_VERSION,
            "count": len(checks.list_catalog(provider="aws")),
            "checks": checks.list_catalog(provider="aws"),
            "deferred": checks.DEFERRED_CHECKS}


@router.post("/run", status_code=201)
def run_security_checks(
    project_id: str,
    payload: dict | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_run(project_id, db, current_user)
    data = payload or {}
    project = db.query(Project).filter(Project.id == project_id).first()
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")

    discovery_run = None
    connection = None
    requested_run_id = str(data.get("discovery_run_id") or "").strip() or None
    requested_conn_id = str(data.get("connection_id") or "").strip() or None
    if requested_run_id:
        discovery_run = db.query(CloudDiscovery).filter(
            CloudDiscovery.id == requested_run_id, CloudDiscovery.project_id == project_id).first()
        if discovery_run is None:
            raise HTTPException(status_code=404, detail="Discovery run not found in this project")
        connection = db.query(CloudConnection).filter(
            CloudConnection.id == discovery_run.connection_id, CloudConnection.project_id == project_id).first()
        if connection is None:
            raise HTTPException(status_code=404, detail="Connection not found in this project")
        if requested_conn_id and requested_conn_id != connection.id:
            raise HTTPException(status_code=400, detail="connection_id does not match the discovery run")
    else:
        q = db.query(CloudDiscovery).filter(CloudDiscovery.project_id == project_id)
        if requested_conn_id:
            connection = db.query(CloudConnection).filter(
                CloudConnection.id == requested_conn_id, CloudConnection.project_id == project_id).first()
            if connection is None:
                raise HTTPException(status_code=404, detail="Connection not found in this project")
            q = q.filter(CloudDiscovery.connection_id == connection.id)
        discovery_run = q.filter(CloudDiscovery.status.in_(["completed", "partial"])) \
            .order_by(CloudDiscovery.created_at.desc()).first()
        if discovery_run is None:
            raise HTTPException(status_code=404, detail="No completed or partial discovery run available")
        connection = connection or db.query(CloudConnection).filter(
            CloudConnection.id == discovery_run.connection_id, CloudConnection.project_id == project_id).first()
        if connection is None:
            raise HTTPException(status_code=404, detail="Connection not found in this project")
    if str(getattr(connection, "status", "active") or "active") != "active":
        raise HTTPException(status_code=400, detail="Connection is disabled")

    try:
        run, created = checks.run_evaluation(db, project, connection, discovery_run, actor_user_id=current_user.id)
    except ValueError as exc:
        try:
            AuditService.record(db, event_type=EVENT_CLOUD_CHECK_RUN_FAILED, action=EVENT_CLOUD_CHECK_RUN_FAILED,
                                result=RESULT_FAILURE, actor_user_id=current_user.id,
                                organization_id=project.organization_id, project_id=project_id,
                                resource_type=RESOURCE_CLOUD_CHECK_RUN, resource_id=None,
                                metadata={"discovery_run_id": discovery_run.id, "reason": str(exc)[:200]})
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        raise HTTPException(status_code=400, detail=str(exc))
    return {**_run_payload(run), "evaluated": created}


@router.get("/runs")
def list_check_runs(
    project_id: str,
    connection_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    try:
        limit = max(1, min(int(limit), 200))
    except Exception:
        limit = 50
    q = db.query(CloudCheckRun).filter(CloudCheckRun.project_id == project_id)
    if connection_id:
        q = q.filter(CloudCheckRun.connection_id == str(connection_id).strip()[:36])
    if status:
        s = str(status).strip().lower()
        if s not in ("running", "completed", "partial", "failed"):
            raise HTTPException(status_code=400, detail="Invalid status")
        q = q.filter(CloudCheckRun.status == s)
    rows = q.order_by(CloudCheckRun.created_at.desc()).limit(limit).all()
    return {"project_id": project_id, "count": len(rows), "runs": [_run_payload(r) for r in rows]}


@router.get("/runs/{run_id}")
def get_check_run(
    project_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    run = db.query(CloudCheckRun).filter(CloudCheckRun.id == run_id, CloudCheckRun.project_id == project_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Check run not found")
    return _run_payload(run)

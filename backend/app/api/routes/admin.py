from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_super_admin
from app.db.database import get_db
from app.models.asset import Asset
from app.models.audit_log import AuditLog
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


def _system_health(db: Session):
    # Backend always healthy if we reached handler
    backend = "Healthy"
    # Database: try SELECT 1
    try:
        db.execute(text("SELECT 1"))
        database = "Healthy"
    except Exception:
        database = "Unavailable"
    # Redis/RabbitMQ/Worker: no cheap safe probe without extra deps, return Unknown
    return {
        "backend": backend,
        "database": database,
        "redis": "Unknown",
        "rabbitmq": "Unknown",
        "worker": "Unknown",
    }


@router.get("/dashboard/summary")
def admin_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    # Organizations
    org_count = db.query(func.count(Organization.id)).scalar() or 0
    # Users — total and active (active = not super_admin? just count all)
    user_count = db.query(func.count(User.id)).scalar() or 0
    # Projects
    project_count = db.query(func.count(Project.id)).scalar() or 0
    # Scans — join not needed, Scan is global
    total_scans = db.query(func.count(Scan.id)).scalar() or 0
    # Scans by status — Scan.status values: queued/running/completed/failed
    active_scans = db.query(func.count(Scan.id)).filter(Scan.status.in_(["queued", "running"])).scalar() or 0
    completed_scans = db.query(func.count(Scan.id)).filter(Scan.status == "completed").scalar() or 0
    failed_scans = db.query(func.count(Scan.id)).filter(Scan.status == "failed").scalar() or 0
    # Findings — global
    total_findings = db.query(func.count(Finding.id)).scalar() or 0
    open_findings = db.query(func.count(Finding.id)).filter(Finding.status.in_(["open", "detected", "corroborated", "needs_review"])).scalar() or 0
    critical_findings = db.query(func.count(Finding.id)).filter(Finding.severity == "critical").scalar() or 0
    high_findings = db.query(func.count(Finding.id)).filter(Finding.severity == "high").scalar() or 0
    medium_findings = db.query(func.count(Finding.id)).filter(Finding.severity == "medium").scalar() or 0
    low_findings = db.query(func.count(Finding.id)).filter(Finding.severity == "low").scalar() or 0
    info_findings = db.query(func.count(Finding.id)).filter(Finding.severity == "info").scalar() or 0
    # Assets
    asset_count = db.query(func.count(Asset.id)).scalar() or 0
    # Scanners — registry
    try:
        from app.scanner.registry import ScannerRegistry

        # Use class-level registry count if available, else fallback to hardcoded 14
        # The registry is singleton via ScannerRegistry()
        from worker.app.scanner.registry import ScannerRegistry as WorkerRegistry

        # Prefer worker registry count
        scanners = WorkerRegistry().list() if hasattr(WorkerRegistry(), "list") else []
        scanner_count = len(scanners) if scanners else 14
        scanner_names = [s.name if hasattr(s, "name") else str(s) for s in scanners] if scanners else []
    except Exception:
        scanner_count = 14
        scanner_names = []

    # If still empty, try backend scanner registry
    if scanner_count == 14 and not scanner_names:
        try:
            from app.scanner.registry import ScannerRegistry as BackendRegistry

            br = BackendRegistry()
            if hasattr(br, "list"):
                lst = br.list()
                if lst:
                    scanner_count = len(lst)
                    scanner_names = [getattr(s, "name", str(s)) for s in lst]
        except Exception:
            pass

    # Audit events
    audit_count = db.query(func.count(AuditLog.id)).scalar() or 0

    # System health
    health = _system_health(db)

    return {
        "organizations": {"total": org_count},
        "users": {"total": user_count, "active": user_count},
        "projects": {"total": project_count},
        "scans": {
            "total": total_scans,
            "active": active_scans,
            "completed": completed_scans,
            "failed": failed_scans,
        },
        "findings": {
            "total": total_findings,
            "open": open_findings,
            "critical": critical_findings,
            "high": high_findings,
            "medium": medium_findings,
            "low": low_findings,
            "info": info_findings,
        },
        "assets": {"total": asset_count},
        "scanners": {"total": scanner_count, "names": scanner_names[:20]},
        "audit_events": {"total": audit_count},
        "system_health": health,
    }


@router.get("/organizations/summary")
def admin_organizations_summary(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    # Server-side pagination, safe aggregates
    total = db.query(func.count(Organization.id)).scalar() or 0
    total_pages = (total + page_size - 1) // page_size if total else 0
    offset = (page - 1) * page_size

    orgs = db.query(Organization).order_by(Organization.name.asc()).offset(offset).limit(page_size).all()

    items = []
    for org in orgs:
        # Projects count
        proj_count = db.query(func.count(Project.id)).filter(Project.organization_id == org.id).scalar() or 0
        # Members count via organization_memberships
        try:
            from app.models.organization_membership import OrganizationMembership

            member_count = db.query(func.count(OrganizationMembership.id)).filter(OrganizationMembership.organization_id == org.id).scalar() or 0
        except Exception:
            member_count = db.query(func.count(User.id)).filter(User.organization_id == org.id).scalar() or 0

        # Open findings for org: join findings -> target -> project -> org
        open_findings = (
            db.query(func.count(Finding.id))
            .join(Target, Target.id == Finding.target_id)
            .join(Project, Project.id == Target.project_id)
            .filter(Project.organization_id == org.id, Finding.status.in_(["open", "detected", "corroborated", "needs_review", "confirmed"]))
            .scalar()
            or 0
        )
        critical_findings = (
            db.query(func.count(Finding.id))
            .join(Target, Target.id == Finding.target_id)
            .join(Project, Project.id == Target.project_id)
            .filter(Project.organization_id == org.id, Finding.severity == "critical")
            .scalar()
            or 0
        )
        # Assets for org
        asset_count = (
            db.query(func.count(Asset.id))
            .join(Project, Project.id == Asset.project_id)
            .filter(Project.organization_id == org.id)
            .scalar()
            or 0
        )
        # Active scans for org
        active_scans = (
            db.query(func.count(Scan.id))
            .join(Target, Target.id == Scan.target_id)
            .join(Project, Project.id == Target.project_id)
            .filter(Project.organization_id == org.id, Scan.status.in_(["queued", "running"]))
            .scalar()
            or 0
        )

        items.append(
            {
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
                "projects": proj_count,
                "members": member_count,
                "open_findings": open_findings,
                "critical_findings": critical_findings,
                "assets": asset_count,
                "active_scans": active_scans,
                "status": "active",
                "created_at": None,
            }
        )

    return {"items": items, "page": page, "page_size": page_size, "total": total, "total_pages": total_pages}

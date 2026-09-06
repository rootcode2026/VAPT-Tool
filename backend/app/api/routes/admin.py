import re
import uuid
from datetime import datetime, timezone

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
from app.schemas.admin import AdminOrganizationCreate, AdminOrganizationUpdate, AdminUserUpdate
from app.services.audit import AuditService

router = APIRouter(prefix="/api/v1/admin", tags=["Admin"])


def _safe_count(query_call, default=0):
    try:
        value = query_call()
        return value if value is not None else default
    except Exception:
        return default


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
    org_count = _safe_count(lambda: db.query(func.count(Organization.id)).scalar())
    # Users — total and active (active = not super_admin? just count all)
    user_count = _safe_count(lambda: db.query(func.count(User.id)).scalar())
    # Projects
    project_count = _safe_count(lambda: db.query(func.count(Project.id)).scalar())
    # Scans — join not needed, Scan is global
    total_scans = _safe_count(lambda: db.query(func.count(Scan.id)).scalar())
    # Scans by status — Scan.status values: queued/running/completed/failed
    active_scans = _safe_count(lambda: db.query(func.count(Scan.id)).filter(Scan.status.in_(["queued", "running"])).scalar())
    completed_scans = _safe_count(lambda: db.query(func.count(Scan.id)).filter(Scan.status == "completed").scalar())
    failed_scans = _safe_count(lambda: db.query(func.count(Scan.id)).filter(Scan.status == "failed").scalar())
    # Findings — global
    total_findings = _safe_count(lambda: db.query(func.count(Finding.id)).scalar())
    open_findings = _safe_count(lambda: db.query(func.count(Finding.id)).filter(Finding.status.in_(["open", "detected", "corroborated", "needs_review"])).scalar())
    critical_findings = _safe_count(lambda: db.query(func.count(Finding.id)).filter(Finding.severity == "critical").scalar())
    high_findings = _safe_count(lambda: db.query(func.count(Finding.id)).filter(Finding.severity == "high").scalar())
    medium_findings = _safe_count(lambda: db.query(func.count(Finding.id)).filter(Finding.severity == "medium").scalar())
    low_findings = _safe_count(lambda: db.query(func.count(Finding.id)).filter(Finding.severity == "low").scalar())
    info_findings = _safe_count(lambda: db.query(func.count(Finding.id)).filter(Finding.severity == "info").scalar())
    # Assets
    asset_count = _safe_count(lambda: db.query(func.count(Asset.id)).scalar())
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
    audit_count = _safe_count(lambda: db.query(func.count(AuditLog.id)).scalar())

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
    total = _safe_count(lambda: db.query(func.count(Organization.id)).scalar())
    total_pages = (total + page_size - 1) // page_size if total else 0
    offset = (page - 1) * page_size

    orgs = db.query(Organization).order_by(Organization.name.asc()).offset(offset).limit(page_size).all()

    items = []
    for org in orgs:
        # Projects count
        proj_count = _safe_count(lambda oid=org.id: db.query(func.count(Project.id)).filter(Project.organization_id == oid).scalar())
        # Members count via organization_memberships
        try:
            from app.models.organization_membership import OrganizationMembership

            member_count = _safe_count(lambda oid=org.id: db.query(func.count(OrganizationMembership.id)).filter(OrganizationMembership.organization_id == oid).scalar())
            if member_count == 0:
                # Fallback still safe
                pass
        except Exception:
            member_count = _safe_count(lambda oid=org.id: db.query(func.count(User.id)).filter(User.organization_id == oid).scalar())

        # Open findings for org: join findings -> target -> project -> org
        def _open_findings(oid=org.id):
            return (
                db.query(func.count(Finding.id))
                .join(Target, Target.id == Finding.target_id)
                .join(Project, Project.id == Target.project_id)
                .filter(Project.organization_id == oid, Finding.status.in_(["open", "detected", "corroborated", "needs_review", "confirmed"]))
                .scalar()
            )

        def _critical_findings(oid=org.id):
            return (
                db.query(func.count(Finding.id))
                .join(Target, Target.id == Finding.target_id)
                .join(Project, Project.id == Target.project_id)
                .filter(Project.organization_id == oid, Finding.severity == "critical")
                .scalar()
            )

        open_findings = _safe_count(_open_findings)
        critical_findings = _safe_count(_critical_findings)
        # Assets for org
        asset_count = _safe_count(
            lambda oid=org.id: db.query(func.count(Asset.id))
            .join(Project, Project.id == Asset.project_id)
            .filter(Project.organization_id == oid)
            .scalar()
        )
        # Active scans for org
        def _active_scans(oid=org.id):
            return (
                db.query(func.count(Scan.id))
                .join(Target, Target.id == Scan.target_id)
                .join(Project, Project.id == Target.project_id)
                .filter(Project.organization_id == oid, Scan.status.in_(["queued", "running"]))
                .scalar()
            )

        active_scans = _safe_count(_active_scans)

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
                "status": getattr(org, "status", "active") or "active",
                "created_at": getattr(org, "created_at", None).isoformat() if getattr(org, "created_at", None) else None,
            }
        )

    return {"items": items, "page": page, "page_size": page_size, "total": total, "total_pages": total_pages}


# -------------------------------------------------------------------
# Organization CRUD — Super Admin only
# -------------------------------------------------------------------

SLUG_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
ORG_STATUSES = {"active", "suspended", "archived"}
USER_STATUSES = {"active", "suspended"}


def _normalize_slug(raw: str) -> str:
    slug = (raw or "").strip().lower()
    slug = re.sub(r"[^a-z0-9-]", "-", slug)
    slug = re.sub(r"-{2,}", "-", slug).strip("-")
    slug = slug[:100]
    return slug


@router.get("/organizations")
def admin_list_organizations(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = Query(None, max_length=100),
    status: str | None = Query(None, max_length=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    q = db.query(Organization)
    if search and search.strip():
        s = f"%{search.strip().replace('%', '').replace('_', '')}%"
        q = q.filter(Organization.name.ilike(s) | Organization.slug.ilike(s))
    if status and status.strip():
        st = status.strip().lower()
        if st not in ORG_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        q = q.filter(Organization.status == st)
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    offset = (page - 1) * page_size
    orgs = q.order_by(Organization.name.asc()).offset(offset).limit(page_size).all()
    items = []
    for org in orgs:
        proj_count = _safe_count(lambda oid=org.id: db.query(func.count(Project.id)).filter(Project.organization_id == oid).scalar())
        try:
            from app.models.organization_membership import OrganizationMembership

            member_count = _safe_count(lambda oid=org.id: db.query(func.count(OrganizationMembership.id)).filter(OrganizationMembership.organization_id == oid).scalar())
        except Exception:
            member_count = _safe_count(lambda oid=org.id: db.query(func.count(User.id)).filter(User.organization_id == oid).scalar())
        items.append(
            {
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
                "status": getattr(org, "status", "active"),
                "created_at": getattr(org, "created_at", None).isoformat() if getattr(org, "created_at", None) else None,
                "projects": proj_count,
                "members": member_count,
            }
        )
    return {"items": items, "page": page, "page_size": page_size, "total": total, "total_pages": total_pages}


@router.post("/organizations", status_code=201)
def admin_create_organization(
    data: AdminOrganizationCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    name = (data.name or "").strip()
    if not name or len(name) > 255:
        raise HTTPException(status_code=400, detail="Invalid name")
    raw_slug = (data.slug or "").strip()
    slug = _normalize_slug(raw_slug)
    if not slug or not SLUG_RE.match(slug):
        raise HTTPException(status_code=400, detail="Invalid slug")
    status_val = (data.status or "active").strip().lower()
    if status_val not in ORG_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status")
    # Uniqueness
    existing = db.query(Organization).filter(Organization.slug == slug).first()
    if existing:
        raise HTTPException(status_code=409, detail="Slug already exists")
    org = Organization(id=str(uuid.uuid4()), name=name, slug=slug)
    # Set status/created_at if column exists
    try:
        org.status = status_val  # type: ignore
    except Exception:
        pass
    db.add(org)
    # Audit ORGANIZATION_CREATED
    try:
        AuditService.record(
            db,
            event_type="ORGANIZATION_CREATED",
            action="ORGANIZATION_CREATED",
            result="SUCCESS",
            actor_user_id=current_user.id,
            organization_id=org.id,
            resource_type="organization",
            resource_id=org.id,
            metadata={"name": name, "slug": slug, "status": status_val},
        )
    except Exception:
        pass
    db.commit()
    db.refresh(org)
    return {"id": org.id, "name": org.name, "slug": org.slug, "status": getattr(org, "status", status_val), "created_at": getattr(org, "created_at", None)}

@router.get("/organizations/{organization_id}")
def admin_get_organization(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    proj_count = _safe_count(lambda: db.query(func.count(Project.id)).filter(Project.organization_id == org.id).scalar())
    try:
        from app.models.organization_membership import OrganizationMembership

        member_count = _safe_count(lambda: db.query(func.count(OrganizationMembership.id)).filter(OrganizationMembership.organization_id == org.id).scalar())
    except Exception:
        member_count = _safe_count(lambda: db.query(func.count(User.id)).filter(User.organization_id == org.id).scalar())

    def _safe_findings_count(statuses=None, severity=None):
        try:
            q = db.query(func.count(Finding.id)).join(Target, Target.id == Finding.target_id).join(Project, Project.id == Target.project_id)
            q = q.filter(Project.organization_id == org.id)
            if statuses is not None:
                q = q.filter(Finding.status.in_(statuses))
            if severity is not None:
                q = q.filter(Finding.severity == severity)
            return q.scalar() or 0
        except Exception:
            return 0

    open_findings = _safe_findings_count(["open", "detected", "corroborated", "needs_review", "confirmed"])
    critical_findings = _safe_findings_count(severity="critical")
    asset_count = _safe_count(lambda: db.query(func.count(Asset.id)).join(Project, Project.id == Asset.project_id).filter(Project.organization_id == org.id).scalar())

    try:
        active_scans = (
            db.query(func.count(Scan.id))
            .join(Target, Target.id == Scan.target_id)
            .join(Project, Project.id == Target.project_id)
            .filter(Project.organization_id == org.id, Scan.status.in_(["queued", "running"]))
            .scalar()
            or 0
        )
    except Exception:
        active_scans = 0
    # Recent audit (last 5)
    recent_audit = (
        db.query(AuditLog).filter(AuditLog.organization_id == org.id).order_by(AuditLog.created_at.desc()).limit(5).all()
    )
    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "status": getattr(org, "status", "active"),
        "created_at": getattr(org, "created_at", None).isoformat() if getattr(org, "created_at", None) else None,
        "projects": proj_count,
        "members": member_count,
        "open_findings": open_findings,
        "critical_findings": critical_findings,
        "assets": asset_count,
        "active_scans": active_scans,
        "recent_audit": [
            {
                "id": a.id,
                "event_type": a.event_type,
                "action": a.action,
                "result": a.result,
                "actor_user_id": a.actor_user_id,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            }
            for a in recent_audit
        ],
    }


@router.patch("/organizations/{organization_id}")
def admin_update_organization(
    organization_id: str,
    data: AdminOrganizationUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    old_name = org.name
    old_slug = org.slug
    old_status = getattr(org, "status", "active")
    changed = False
    if data.name is not None:
        name = data.name.strip()
        if not name or len(name) > 255:
            raise HTTPException(status_code=400, detail="Invalid name")
        if name != org.name:
            org.name = name
            changed = True
    if data.slug is not None:
        raw_slug = data.slug.strip()
        slug = _normalize_slug(raw_slug)
        if not slug or not SLUG_RE.match(slug):
            raise HTTPException(status_code=400, detail="Invalid slug")
        if slug != org.slug:
            existing = db.query(Organization).filter(Organization.slug == slug, Organization.id != organization_id).first()
            if existing:
                raise HTTPException(status_code=409, detail="Slug already exists")
            org.slug = slug
            changed = True
    if data.status is not None:
        st = data.status.strip().lower()
        if st not in ORG_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        if st != getattr(org, "status", "active"):
            try:
                org.status = st  # type: ignore
            except Exception:
                pass
            changed = True
    if not changed:
        return {"id": org.id, "name": org.name, "slug": org.slug, "status": getattr(org, "status", "active")}
    # Audit ORGANIZATION_UPDATED
    try:
        AuditService.record(
            db,
            event_type="ORGANIZATION_UPDATED",
            action="ORGANIZATION_UPDATED",
            result="SUCCESS",
            actor_user_id=current_user.id,
            organization_id=org.id,
            resource_type="organization",
            resource_id=org.id,
            metadata={"old_name": old_name, "new_name": org.name, "old_slug": old_slug, "new_slug": org.slug, "old_status": old_status, "new_status": getattr(org, "status", "active")},
        )
    except Exception:
        pass
    db.commit()
    db.refresh(org)
    return {"id": org.id, "name": org.name, "slug": org.slug, "status": getattr(org, "status", "active"), "created_at": getattr(org, "created_at", None)}


# -------------------------------------------------------------------
# User Management — Super Admin only
# -------------------------------------------------------------------

@router.get("/users")
def admin_list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    organization_id: str | None = Query(None),
    role: str | None = Query(None, max_length=50),
    status: str | None = Query(None, max_length=20),
    search: str | None = Query(None, max_length=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    q = db.query(User)
    if organization_id and organization_id.strip():
        q = q.filter(User.organization_id == organization_id.strip())
    if role and role.strip():
        q = q.filter(User.role == role.strip())
    if status and status.strip():
        st = status.strip().lower()
        if st not in USER_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        q = q.filter(User.status == st)
    if search and search.strip():
        s = f"%{search.strip().replace('%', '').replace('_', '')}%"
        q = q.filter(User.email.ilike(s))
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    offset = (page - 1) * page_size
    users = q.order_by(User.email.asc()).offset(offset).limit(page_size).all()
    items = []
    for u in users:
        items.append(
            {
                "id": u.id,
                "email": u.email,
                "organization_id": u.organization_id,
                "role": u.role,
                "status": getattr(u, "status", "active"),
                "created_at": getattr(u, "created_at", None).isoformat() if getattr(u, "created_at", None) else None,
            }
        )
    return {"items": items, "page": page, "page_size": page_size, "total": total, "total_pages": total_pages}


@router.get("/users/{user_id}")
def admin_get_user(
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    # Membership info
    try:
        from app.models.organization_membership import OrganizationMembership
        from app.models.project_membership import ProjectMembership

        org_memberships = db.query(OrganizationMembership).filter(OrganizationMembership.user_id == u.id).all()
        proj_memberships = db.query(ProjectMembership).filter(ProjectMembership.user_id == u.id).all()
    except Exception:
        org_memberships = []
        proj_memberships = []
    return {
        "id": u.id,
        "email": u.email,
        "organization_id": u.organization_id,
        "role": u.role,
        "status": getattr(u, "status", "active"),
        "created_at": getattr(u, "created_at", None).isoformat() if getattr(u, "created_at", None) else None,
        "organization_memberships": [
            {"organization_id": m.organization_id, "role": m.role, "status": m.status} for m in org_memberships
        ],
        "project_memberships": [
            {"project_id": m.project_id, "role": m.role, "status": m.status} for m in proj_memberships
        ],
    }


@router.patch("/users/{user_id}")
def admin_update_user(
    user_id: str,
    data: AdminUserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if data.status is not None:
        st = data.status.strip().lower()
        if st not in USER_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        old_status = getattr(u, "status", "active")
        if st != old_status:
            try:
                u.status = st  # type: ignore
            except Exception:
                pass
            # Audit status change
            try:
                AuditService.record(
                    db,
                    event_type="SECURITY_CONFIGURATION_CHANGED",
                    action="SECURITY_CONFIGURATION_CHANGED",
                    result="SUCCESS",
                    actor_user_id=current_user.id,
                    organization_id=u.organization_id,
                    resource_type="user",
                    resource_id=u.id,
                    metadata={"old_status": old_status, "new_status": st},
                )
            except Exception:
                pass
    db.commit()
    db.refresh(u)
    return {"id": u.id, "email": u.email, "organization_id": u.organization_id, "role": u.role, "status": getattr(u, "status", "active"), "created_at": getattr(u, "created_at", None)}

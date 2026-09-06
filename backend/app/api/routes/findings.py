import re
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import (
    _effective_project_role,
    _is_super_admin,
    get_current_user,
    require_project_access,
)
from app.db.database import get_db
from app.models.asset import Asset
from app.models.finding import Finding, FindingComment, FindingHistory, FindingTag
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.schemas.finding import FindingResponse
from app.schemas.finding_workflow import FindingCommentCreate, FindingUpdate
from app.services.audit import (
    EVENT_FINDING_STATUS_CHANGED,
    EVENT_FINDING_TRIAGED,
    EVENT_FINDING_UPDATED,
    RESOURCE_FINDING,
    RESULT_SUCCESS,
    AuditService,
)

router = APIRouter(
    prefix="/api/v1/findings",
    tags=["Findings"],
)

WORKFLOW_STATUSES = {"open", "triaged", "in_progress", "resolved", "false_positive", "accepted_risk", "reopened"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}
TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def _ensure_finding_workflow_columns(db: Session) -> None:
    """Backward compat for isolated SQLite test DBs that define their own findings table."""
    try:
        from sqlalchemy import text as _text

        for ddl in (
            "ALTER TABLE findings ADD COLUMN assigned_to TEXT",
            "ALTER TABLE findings ADD COLUMN owner_user_id TEXT",
            "ALTER TABLE findings ADD COLUMN severity_override TEXT",
            "ALTER TABLE findings ADD COLUMN updated_at DATETIME",
        ):
            try:
                db.execute(_text(ddl))
            except Exception:
                pass
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
    except Exception:
        pass


def _finding_context(finding: Finding, db: Session):
    scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
    target = db.query(Target).filter(Target.id == scan.target_id).first() if scan else None
    project = db.query(Project).filter(Project.id == target.project_id).first() if target else None
    asset = db.query(Asset).filter(Asset.id == finding.asset_id).first() if finding.asset_id else None
    return scan, target, project, asset


def _require_finding_access(finding_id: str, db: Session, current_user: User):
    try:
        finding = db.query(Finding).filter(Finding.id == finding_id).first()
    except Exception as exc:
        if "no such column" in str(exc).lower() and "findings." in str(exc).lower():
            try:
                db.rollback()
            except Exception:
                pass
            _ensure_finding_workflow_columns(db)
            finding = db.query(Finding).filter(Finding.id == finding_id).first()
        else:
            raise
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    scan, target, project, asset = _finding_context(finding, db)
    if target:
        require_project_access(target.project_id, db, current_user)
        return finding, scan, target, project, asset
    if asset:
        require_project_access(asset.project_id, db, current_user)
        return finding, scan, target, project, asset
    # No tenant context — deny safely
    raise HTTPException(status_code=404, detail="Finding not found")


def _require_finding_manage(project_id: str, db: Session, current_user: User):
    if _is_super_admin(current_user):
        return
    # Org admin can manage all findings in org
    from app.api.deps import _effective_org_role

    # project_id must be provided; check org role via project
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj:
        org_role = _effective_org_role(current_user, proj.organization_id, db)
        if org_role == "org_admin":
            return
    role = _effective_project_role(current_user, project_id, db)
    if role not in ("analyst", "project_admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires analyst or project_admin to triage findings")


def _normalize_tags(raw: list[str] | None) -> list[str]:
    if raw is None:
        return None  # type: ignore
    seen: list[str] = []
    for t in raw[:10]:
        s = str(t).strip().lower()[:30]
        if not s:
            continue
        if not TAG_RE.match(s):
            raise HTTPException(status_code=400, detail=f"Invalid tag: {t[:30]}")
        if s not in seen:
            seen.append(s)
    return seen


def _validate_user_in_org(user_id: str, organization_id: str, db: Session) -> User:
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="Assignee not found")
    # Must belong to same org (via primary org or membership)
    if u.organization_id == organization_id:
        pass
    else:
        try:
            from app.models.organization_membership import OrganizationMembership

            m = (
                db.query(OrganizationMembership)
                .filter(
                    OrganizationMembership.user_id == u.id,
                    OrganizationMembership.organization_id == organization_id,
                    OrganizationMembership.status == "active",
                )
                .first()
            )
            if not m:
                raise HTTPException(status_code=403, detail="Assignee is not in the finding organization")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=403, detail="Assignee is not in the finding organization")
    if getattr(u, "status", "active") != "active":
        raise HTTPException(status_code=403, detail="Assignee is not active")
    return u


def _finding_detail_payload(finding: Finding, db: Session) -> dict:
    scan, target, project, asset = _finding_context(finding, db)
    meta = finding.extra_data or {}
    effective_severity = getattr(finding, "severity_override", None) or finding.severity
    try:
        comments = (
            db.query(FindingComment)
            .filter(FindingComment.finding_id == finding.id)
            .order_by(FindingComment.created_at.asc())
            .all()
        )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        comments = []
    try:
        tags = db.query(FindingTag).filter(FindingTag.finding_id == finding.id).order_by(FindingTag.tag.asc()).all()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        tags = []
    try:
        history = (
            db.query(FindingHistory)
            .filter(FindingHistory.finding_id == finding.id)
            .order_by(FindingHistory.created_at.desc())
            .limit(50)
            .all()
        )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        history = []
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "target_id": finding.target_id,
        "project_id": target.project_id if target else (asset.project_id if asset else None),
        "organization_id": project.organization_id if project else None,
        "scanner": finding.scanner,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "severity_override": getattr(finding, "severity_override", None),
        "effective_severity": effective_severity,
        "score": finding.score,
        "status": finding.status,
        "validation_state": meta.get("validation_state") or meta.get("state"),
        "confidence_score": meta.get("confidence_score"),
        "confidence_level": meta.get("confidence_level"),
        "cve": finding.cve,
        "cwe": finding.cwe,
        "asset_id": finding.asset_id,
        "asset": {"id": asset.id, "asset_type": asset.asset_type, "value": asset.value} if asset else None,
        "target": {"id": target.id, "value": target.value, "target_type": target.target_type} if target else None,
        "evidence": finding.evidence,
        "remediation": finding.remediation,
        "assigned_to": getattr(finding, "assigned_to", None),
        "owner_user_id": getattr(finding, "owner_user_id", None),
        "tags": [t.tag for t in tags],
        "comments": [
            {
                "id": c.id,
                "finding_id": c.finding_id,
                "author_user_id": c.author_user_id,
                "body": c.body,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in comments
        ],
        "history": [
            {
                "id": h.id,
                "action": h.action,
                "actor_user_id": h.actor_user_id,
                "old_value": h.old_value,
                "new_value": h.new_value,
                "reason": h.reason,
                "created_at": h.created_at.isoformat() if h.created_at else None,
            }
            for h in history
        ],
        "metadata": meta,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
        "updated_at": getattr(finding, "updated_at", None).isoformat() if getattr(finding, "updated_at", None) else None,
    }


@router.get(
    "",
    response_model=None,
)
def get_findings(
    scan_id: str | None = None,
    severity: str | None = None,
    effective_severity: str | None = Query(default=None, description="Filter by effective severity"),
    scanner: str | None = None,
    status: str | None = Query(default=None, description="Filter by status"),
    asset_id: str | None = Query(default=None, description="Filter by asset"),
    project_id: str | None = Query(default=None, description="Filter by project"),
    project: str | None = Query(default=None, description="Filter by project alias"),
    assigned_to: str | None = Query(default=None, description="Filter by assignee"),
    tag: str | None = Query(default=None, description="Filter by tag"),
    search: str | None = Query(default=None, description="Search title/description"),
    page: int | None = Query(default=None, ge=1, description="Page number (paginated mode)"),
    page_size: int | None = Query(default=None, ge=1, le=100, description="Page size (paginated mode)"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_finding_workflow_columns(db)
    query = db.query(Finding)

    selected_project = (project_id or project or "").strip() or None
    if selected_project:
        require_project_access(selected_project, db, current_user)
        query = query.join(Scan, Scan.id == Finding.scan_id).join(
            Target, Target.id == Scan.target_id
        ).filter(Target.project_id == selected_project)
    else:
        if _is_super_admin(current_user):
            pass  # platform-wide
        else:
            query = query.join(Scan, Scan.id == Finding.scan_id).join(
                Target, Target.id == Scan.target_id
            ).join(Project, Project.id == Target.project_id).filter(
                Project.organization_id == current_user.organization_id
            )

    if scan_id:
        query = query.filter(Finding.scan_id == scan_id.strip())
    if severity:
        query = query.filter(Finding.severity == severity.strip().lower())
    if effective_severity:
        es = effective_severity.strip().lower()
        if es not in SEVERITIES:
            raise HTTPException(status_code=400, detail="Invalid effective_severity")
        query = query.filter(func.coalesce(Finding.severity_override, Finding.severity) == es)
    if scanner:
        query = query.filter(Finding.scanner == scanner.strip().lower())
    if status:
        query = query.filter(Finding.status == status.strip().lower())
    if asset_id:
        query = query.filter(Finding.asset_id == asset_id.strip())
    if assigned_to:
        query = query.filter(Finding.assigned_to == assigned_to.strip())
    if tag:
        t = tag.strip().lower()[:30]
        query = query.join(FindingTag, FindingTag.finding_id == Finding.id).filter(FindingTag.tag == t)

    if search:
        lookup = search.strip()[:256].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(
            (Finding.title.ilike(f"%{lookup}%", escape="\\"))
            | (Finding.description.ilike(f"%{lookup}%", escape="\\"))
        )

    query = query.order_by(Finding.created_at.desc())

    if page is not None or page_size is not None:
        p = page or 1
        ps = page_size or limit
        if ps > 100:
            ps = 100
        total = query.count()
        import math

        total_pages = math.ceil(total / ps) if total > 0 else 0
        offset = (p - 1) * ps
        items = query.offset(offset).limit(ps).all()
        return {
            "items": [FindingResponse.model_validate(i).model_dump() for i in items],
            "total": total,
            "page": p,
            "page_size": ps,
            "total_pages": total_pages,
        }

    return query.limit(limit).all()


@router.get(
    "/{finding_id}",
    response_model=None,
)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, scan, target, project, asset = _require_finding_access(finding_id, db, current_user)
    return _finding_detail_payload(finding, db)


@router.patch(
    "/{finding_id}",
    response_model=None,
)
def update_finding(
    finding_id: str,
    data: FindingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, scan, target, project, asset = _require_finding_access(finding_id, db, current_user)
    project_id = target.project_id if target else (asset.project_id if asset else None)
    if not project_id or not project:
        raise HTTPException(status_code=404, detail="Finding not found")
    _require_finding_manage(project_id, db, current_user)
    organization_id = project.organization_id

    # Validate status
    new_status = None
    if data.status is not None:
        new_status = data.status.strip().lower()
        if new_status not in WORKFLOW_STATUSES:
            raise HTTPException(status_code=400, detail=f"Invalid status. Allowed: {sorted(WORKFLOW_STATUSES)}")
        # Reopen only from terminal states
        if new_status == "reopened" and finding.status not in ("resolved", "false_positive", "accepted_risk", "remediated", "closed"):
            raise HTTPException(status_code=400, detail="Can only reopen from resolved/false_positive/accepted_risk")
        # Reason required for false_positive/accepted_risk
        if new_status in ("false_positive", "accepted_risk") and not (data.reason and data.reason.strip()):
            raise HTTPException(status_code=400, detail="Reason is required for false_positive/accepted_risk")

    # Validate severity override (None clears)
    new_override = None
    override_changed = False
    if "severity_override" in data.model_fields_set:
        if data.severity_override is None:
            new_override = None
            override_changed = getattr(finding, "severity_override", None) is not None
        else:
            so = data.severity_override.strip().lower()
            if so not in SEVERITIES:
                raise HTTPException(status_code=400, detail="Invalid severity_override")
            new_override = so
            override_changed = getattr(finding, "severity_override", None) != so

    # Validate assignee/owner (None clears)
    new_assignee = None
    assignee_changed = False
    if "assigned_to" in data.model_fields_set:
        if data.assigned_to is None:
            new_assignee = None
            assignee_changed = getattr(finding, "assigned_to", None) is not None
        else:
            auid = data.assigned_to.strip()
            if not auid:
                raise HTTPException(status_code=400, detail="Invalid assigned_to")
            _validate_user_in_org(auid, organization_id, db)
            new_assignee = auid
            assignee_changed = getattr(finding, "assigned_to", None) != auid

    new_owner = None
    owner_changed = False
    if "owner_user_id" in data.model_fields_set:
        if data.owner_user_id is None:
            new_owner = None
            owner_changed = getattr(finding, "owner_user_id", None) is not None
        else:
            ouid = data.owner_user_id.strip()
            if not ouid:
                raise HTTPException(status_code=400, detail="Invalid owner_user_id")
            _validate_user_in_org(ouid, organization_id, db)
            new_owner = ouid
            owner_changed = getattr(finding, "owner_user_id", None) != ouid

    # Validate tags
    new_tags = None
    tags_changed = False
    if data.tags is not None:
        new_tags = _normalize_tags(data.tags)
        existing_tags = sorted([t.tag for t in db.query(FindingTag).filter(FindingTag.finding_id == finding.id).all()])
        tags_changed = sorted(new_tags) != existing_tags

    status_changed = new_status is not None and new_status != finding.status

    if not status_changed and not override_changed and not assignee_changed and not owner_changed and not tags_changed:
        # No-op — return detail without audit
        return _finding_detail_payload(finding, db)

    reason = (data.reason.strip()[:1000] if data.reason else None)

    old_status = finding.status
    old_override = getattr(finding, "severity_override", None)
    old_assignee = getattr(finding, "assigned_to", None)
    old_owner = getattr(finding, "owner_user_id", None)

    if status_changed:
        finding.status = new_status
    if override_changed:
        finding.severity_override = new_override
    if assignee_changed:
        finding.assigned_to = new_assignee
    if owner_changed:
        finding.owner_user_id = new_owner
    try:
        finding.updated_at = datetime.utcnow()
    except Exception:
        pass

    # Tags: replace set
    if tags_changed and new_tags is not None:
        db.query(FindingTag).filter(FindingTag.finding_id == finding.id).delete()
        for t in new_tags:
            db.add(FindingTag(id=str(uuid.uuid4()), finding_id=finding.id, tag=t))

    # History rows (one per changed field)
    hid = str(uuid.uuid4())
    if status_changed:
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="status_changed", old_value=old_status, new_value=new_status, reason=reason))
    if override_changed:
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="severity_override", old_value=old_override, new_value=new_override, reason=reason))
    if assignee_changed:
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="assigned", old_value=old_assignee, new_value=new_assignee, reason=reason))
    if owner_changed:
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="owner_changed", old_value=old_owner, new_value=new_owner, reason=reason))
    if tags_changed:
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="tags_changed", old_value=None, new_value=",".join(new_tags or []), reason=reason))

    # Audit — one event per PATCH (no duplicates)
    if status_changed and new_status == "triaged":
        evt = EVENT_FINDING_TRIAGED
    elif status_changed:
        evt = EVENT_FINDING_STATUS_CHANGED
    else:
        evt = EVENT_FINDING_UPDATED
    meta: dict = {}
    if status_changed:
        meta["old_status"] = old_status
        meta["new_status"] = new_status
    if override_changed:
        meta["old_severity"] = old_override
        meta["new_severity"] = new_override
    if assignee_changed:
        meta["old_assignee"] = old_assignee
        meta["new_assignee"] = new_assignee
    AuditService.record(
        db,
        event_type=evt,
        action=evt,
        result=RESULT_SUCCESS,
        actor_user_id=current_user.id,
        organization_id=organization_id,
        project_id=project_id,
        resource_type=RESOURCE_FINDING,
        resource_id=finding.id,
        metadata=meta or {"finding_id": finding.id},
    )
    db.commit()
    db.refresh(finding)
    return _finding_detail_payload(finding, db)


@router.get("/{finding_id}/comments")
def list_finding_comments(
    finding_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, scan, target, project, asset = _require_finding_access(finding_id, db, current_user)
    q = db.query(FindingComment).filter(FindingComment.finding_id == finding.id).order_by(FindingComment.created_at.asc())
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    offset = (page - 1) * page_size
    rows = q.offset(offset).limit(page_size).all()
    return {
        "items": [
            {
                "id": c.id,
                "finding_id": c.finding_id,
                "author_user_id": c.author_user_id,
                "body": c.body,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


@router.post("/{finding_id}/comments", status_code=201)
def create_finding_comment(
    finding_id: str,
    data: FindingCommentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, scan, target, project, asset = _require_finding_access(finding_id, db, current_user)
    project_id = target.project_id if target else (asset.project_id if asset else None)
    if not project_id or not project:
        raise HTTPException(status_code=404, detail="Finding not found")
    _require_finding_manage(project_id, db, current_user)
    body = (data.body or "").strip()
    if not body:
        raise HTTPException(status_code=400, detail="Comment body is required")
    body = body[:2000]
    comment = FindingComment(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        author_user_id=current_user.id,
        body=body,
    )
    db.add(comment)
    db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="comment_added", old_value=None, new_value=body[:500], reason=None))
    AuditService.record(
        db,
        event_type=EVENT_FINDING_UPDATED,
        action=EVENT_FINDING_UPDATED,
        result=RESULT_SUCCESS,
        actor_user_id=current_user.id,
        organization_id=project.organization_id,
        project_id=project_id,
        resource_type=RESOURCE_FINDING,
        resource_id=finding.id,
        metadata={"comment_added": True},
    )
    db.commit()
    db.refresh(comment)
    return {
        "id": comment.id,
        "finding_id": comment.finding_id,
        "author_user_id": comment.author_user_id,
        "body": comment.body,
        "created_at": comment.created_at.isoformat() if comment.created_at else None,
    }


@router.get("/{finding_id}/history")
def list_finding_history(
    finding_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, scan, target, project, asset = _require_finding_access(finding_id, db, current_user)
    q = db.query(FindingHistory).filter(FindingHistory.finding_id == finding.id).order_by(FindingHistory.created_at.desc())
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    offset = (page - 1) * page_size
    rows = q.offset(offset).limit(page_size).all()
    return {
        "items": [
            {
                "id": h.id,
                "action": h.action,
                "actor_user_id": h.actor_user_id,
                "old_value": h.old_value,
                "new_value": h.new_value,
                "reason": h.reason,
                "created_at": h.created_at.isoformat() if h.created_at else None,
            }
            for h in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }

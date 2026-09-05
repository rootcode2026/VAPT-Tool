import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import _effective_org_role, _effective_project_role, _is_super_admin, get_current_user, require_project_access
from app.core.permissions import PROJECT_ROLES
from app.db.database import get_db
from app.models.project_membership import ProjectMembership
from app.models.user import User
from app.schemas.membership import ProjectMemberCreate, ProjectMemberResponse, ProjectMemberUpdate
from app.services.audit import (
    EVENT_PROJECT_MEMBER_ADDED,
    EVENT_PROJECT_MEMBER_REMOVED,
    EVENT_PROJECT_MEMBER_UPDATED,
    RESOURCE_PROJECT_MEMBERSHIP,
    RESULT_SUCCESS,
    AuditService,
)

router = APIRouter(prefix="/api/v1/projects", tags=["Project Members"])


def _require_project_manage(project_id: str, db: Session, current_user: User):
    if _is_super_admin(current_user):
        return
    # Check org_admin first (can manage any project in org)
    from app.models.project import Project

    proj = db.query(Project).filter(Project.id == project_id).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    org_role = _effective_org_role(current_user, proj.organization_id, db)
    if org_role == "org_admin":
        return
    role = _effective_project_role(current_user, project_id, db)
    if role != "project_admin":
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires project_admin or org_admin")


def _validate_project_role(role: str | None):
    if role is not None and role not in PROJECT_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid project role: {role}. Allowed: {sorted(PROJECT_ROLES)}")
    if role == "super_admin":
        raise HTTPException(status_code=403, detail="Cannot assign platform super_admin via project membership")


@router.get("/{project_id}/members", response_model=list[ProjectMemberResponse])
def list_project_members(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    # Only project_admin or org_admin can list members (consistent with manage permission)
    # But for now allow any project member to list? Task says project_admin or authorized org_admin
    # We enforce manage permission: require project_admin/org_admin
    _require_project_manage(project_id, db, current_user)
    memberships = db.query(ProjectMembership).filter(ProjectMembership.project_id == project_id).all()
    result = []
    for m in memberships:
        user = db.query(User).filter(User.id == m.user_id).first()
        result.append(
            ProjectMemberResponse(
                id=m.id,
                project_id=m.project_id,
                user_id=m.user_id,
                email=user.email if user else None,
                role=m.role,
                status=m.status,
                created_at=m.created_at,
                updated_at=m.updated_at,
            )
        )
    return result


@router.post("/{project_id}/members", response_model=ProjectMemberResponse, status_code=201)
def add_project_member(
    project_id: str,
    data: ProjectMemberCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_project_manage(project_id, db, current_user)
    _validate_project_role(data.role)
    if data.status and data.status not in ("active", "suspended", "pending"):
        raise HTTPException(status_code=400, detail="Invalid status")

    from app.models.project import Project

    proj = db.query(Project).filter(Project.id == project_id).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")

    target_user = db.query(User).filter(User.id == data.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Cross-organization protection: target user must be member of project's organization
    # unless actor is super_admin
    if not _is_super_admin(current_user):
        # Check if target user is member of project's organization
        target_org_role = _effective_org_role(target_user, proj.organization_id, db)
        # Also check if target user has any org membership or fallback
        # For existing users without explicit membership, fallback via User.organization_id
        # If target user is not in org, deny
        if target_org_role is None:
            # Also check direct fallback: target_user.organization_id == proj.organization_id
            # _effective_org_role already handles fallback, so None means not member
            raise HTTPException(status_code=403, detail="Target user is not a member of the project's organization")

    existing = (
        db.query(ProjectMembership)
        .filter(ProjectMembership.project_id == project_id, ProjectMembership.user_id == data.user_id)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Membership already exists")

    # Role assignment security: viewer/analyst cannot grant project_admin
    if not _is_super_admin(current_user):
        caller_role = _effective_project_role(current_user, project_id, db)
        caller_org_role = _effective_org_role(current_user, proj.organization_id, db)
        # If caller is org_admin, they can assign any project role
        if caller_org_role == "org_admin":
            pass
        elif caller_role == "project_admin":
            # project_admin can assign any project role
            pass
        elif caller_role in ("viewer", "analyst"):
            # viewer/analyst cannot grant project_admin
            if data.role == "project_admin":
                raise HTTPException(status_code=403, detail="Insufficient permissions to assign project_admin")
        else:
            raise HTTPException(status_code=403, detail="Insufficient permissions")

    # Self-escalation protection
    if data.user_id == current_user.id:
        # User trying to add themselves — check if they are escalating
        # Already handled via role assignment security above

        # Prevent self-creation into project_admin if they were not already
        # If they were viewer/analyst, they cannot self-promote to project_admin
        pass

    membership = ProjectMembership(
        id=str(uuid.uuid4()),
        project_id=project_id,
        user_id=data.user_id,
        role=data.role,
        status=data.status or "active",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(membership)
    # Audit — organization_id derived from project's actual owning org (server-controlled)
    AuditService.record(
        db,
        event_type=EVENT_PROJECT_MEMBER_ADDED,
        action=EVENT_PROJECT_MEMBER_ADDED,
        result=RESULT_SUCCESS,
        actor_user_id=current_user.id,
        organization_id=proj.organization_id,
        project_id=project_id,
        target_user_id=data.user_id,
        resource_type=RESOURCE_PROJECT_MEMBERSHIP,
        resource_id=membership.id,
        metadata={"role": data.role, "status": data.status or "active"},
    )
    db.commit()
    db.refresh(membership)
    user = db.query(User).filter(User.id == membership.user_id).first()
    return ProjectMemberResponse(
        id=membership.id,
        project_id=membership.project_id,
        user_id=membership.user_id,
        email=user.email if user else None,
        role=membership.role,
        status=membership.status,
        created_at=membership.created_at,
        updated_at=membership.updated_at,
    )


@router.patch("/{project_id}/members/{user_id}", response_model=ProjectMemberResponse)
def update_project_member(
    project_id: str,
    user_id: str,
    data: ProjectMemberUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_project_manage(project_id, db, current_user)
    if data.role is not None:
        _validate_project_role(data.role)
    if data.status is not None and data.status not in ("active", "suspended", "pending"):
        raise HTTPException(status_code=400, detail="Invalid status")

    membership = (
        db.query(ProjectMembership)
        .filter(ProjectMembership.project_id == project_id, ProjectMembership.user_id == user_id)
        .first()
    )
    if not membership:
        raise HTTPException(status_code=404, detail="Membership not found")

    # Role assignment security: check caller can assign new role
    if data.role is not None and data.role != membership.role:
        if not _is_super_admin(current_user):
            from app.models.project import Project

            proj = db.query(Project).filter(Project.id == project_id).first()
            caller_org_role = _effective_org_role(current_user, proj.organization_id, db) if proj else None
            caller_role = _effective_project_role(current_user, project_id, db)
            if caller_org_role == "org_admin" or caller_role == "project_admin":
                pass
            else:
                raise HTTPException(status_code=403, detail="Insufficient permissions to change role")

    # Self-escalation: user cannot elevate own role
    if user_id == current_user.id and data.role is not None and data.role != membership.role:
        # If user is viewer/analyst, they cannot self-promote to project_admin — already blocked above
        pass

    # Last admin protection: for project, we do NOT enforce strict last project_admin because org_admin can manage
    # Documented as not required. So we allow demotion/removal even if last project_admin.

    old_role = membership.role
    old_status = membership.status
    if data.role is not None:
        membership.role = data.role
    if data.status is not None:
        membership.status = data.status
    membership.updated_at = datetime.utcnow()
    # Resolve owning org for tenant isolation
    from app.models.project import Project as _Proj

    _proj = db.query(_Proj).filter(_Proj.id == project_id).first()
    _org_id = _proj.organization_id if _proj else None
    meta: dict = {}
    if data.role is not None and data.role != old_role:
        meta["old_role"] = old_role
        meta["new_role"] = membership.role
    if data.status is not None and data.status != old_status:
        meta["old_status"] = old_status
        meta["new_status"] = membership.status
    if not meta:
        meta = {"role": membership.role, "status": membership.status}
    AuditService.record(
        db,
        event_type=EVENT_PROJECT_MEMBER_UPDATED,
        action=EVENT_PROJECT_MEMBER_UPDATED,
        result=RESULT_SUCCESS,
        actor_user_id=current_user.id,
        organization_id=_org_id,
        project_id=project_id,
        target_user_id=user_id,
        resource_type=RESOURCE_PROJECT_MEMBERSHIP,
        resource_id=membership.id,
        metadata=meta,
    )
    db.commit()
    db.refresh(membership)
    user = db.query(User).filter(User.id == membership.user_id).first()
    return ProjectMemberResponse(
        id=membership.id,
        project_id=membership.project_id,
        user_id=membership.user_id,
        email=user.email if user else None,
        role=membership.role,
        status=membership.status,
        created_at=membership.created_at,
        updated_at=membership.updated_at,
    )


@router.delete("/{project_id}/members/{user_id}", status_code=204)
def remove_project_member(
    project_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_project_manage(project_id, db, current_user)
    membership = (
        db.query(ProjectMembership)
        .filter(ProjectMembership.project_id == project_id, ProjectMembership.user_id == user_id)
        .first()
    )
    if not membership:
        raise HTTPException(status_code=404, detail="Membership not found")

    # No last admin protection for project (org_admin fallback ensures manageability)
    # Audit before deletion — server-controlled tenant context
    from app.models.project import Project as _Proj2

    _proj2 = db.query(_Proj2).filter(_Proj2.id == project_id).first()
    _org_id2 = _proj2.organization_id if _proj2 else None
    AuditService.record(
        db,
        event_type=EVENT_PROJECT_MEMBER_REMOVED,
        action=EVENT_PROJECT_MEMBER_REMOVED,
        result=RESULT_SUCCESS,
        actor_user_id=current_user.id,
        organization_id=_org_id2,
        project_id=project_id,
        target_user_id=user_id,
        resource_type=RESOURCE_PROJECT_MEMBERSHIP,
        resource_id=membership.id,
        metadata={"role": membership.role, "status": membership.status},
    )
    db.delete(membership)
    db.commit()
    return None

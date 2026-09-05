import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import _effective_org_role, _is_super_admin, get_current_user
from app.core.permissions import ORG_ROLES
from app.db.database import get_db
from app.models.organization_membership import OrganizationMembership
from app.models.user import User
from app.schemas.membership import (
    OrganizationMemberCreate,
    OrganizationMemberResponse,
    OrganizationMemberUpdate,
)
from app.services.audit import (
    EVENT_AUTHZ_DENIED,
    EVENT_ORG_MEMBER_ADDED,
    EVENT_ORG_MEMBER_REMOVED,
    EVENT_ORG_MEMBER_UPDATED,
    RESOURCE_ORG_MEMBERSHIP,
    RESULT_DENIED,
    RESULT_SUCCESS,
    AuditService,
)

router = APIRouter(prefix="/api/v1/organizations", tags=["Organization Members"])


def _require_org_admin(organization_id: str, db: Session, current_user: User):
    if _is_super_admin(current_user):
        return
    role = _effective_org_role(current_user, organization_id, db)
    if role != "org_admin":
        try:
            AuditService.record(
                db,
                event_type=EVENT_AUTHZ_DENIED,
                action=EVENT_AUTHZ_DENIED,
                result=RESULT_DENIED,
                actor_user_id=current_user.id,
                organization_id=str(organization_id)[:36],
                resource_type="organization",
                resource_id=str(organization_id)[:100],
                metadata={"reason": "insufficient_permissions", "actual_role": str(role)[:50]},
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires org_admin")


def _validate_org_role(role: str | None):
    if role is not None and role not in ORG_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid organization role: {role}. Allowed: {sorted(ORG_ROLES)}")
    if role == "super_admin":
        raise HTTPException(status_code=403, detail="Cannot assign platform super_admin via organization membership")


@router.get("/{organization_id}/members", response_model=list[OrganizationMemberResponse])
def list_organization_members(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_org_admin(organization_id, db, current_user)
    # Verify organization exists (via membership check already, but ensure 404 for unknown)
    from app.models.organization import Organization

    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    memberships = (
        db.query(OrganizationMembership).filter(OrganizationMembership.organization_id == organization_id).all()
    )
    # Enrich with email
    result = []
    for m in memberships:
        user = db.query(User).filter(User.id == m.user_id).first()
        result.append(
            OrganizationMemberResponse(
                id=m.id,
                organization_id=m.organization_id,
                user_id=m.user_id,
                email=user.email if user else None,
                role=m.role,
                status=m.status,
                created_at=m.created_at,
                updated_at=m.updated_at,
            )
        )
    return result


@router.post("/{organization_id}/members", response_model=OrganizationMemberResponse, status_code=201)
def add_organization_member(
    organization_id: str,
    data: OrganizationMemberCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_org_admin(organization_id, db, current_user)
    _validate_org_role(data.role)
    if data.status and data.status not in ("active", "suspended", "pending"):
        raise HTTPException(status_code=400, detail="Invalid status")

    from app.models.organization import Organization

    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    # Verify target user exists (do not leak other org users via 404)
    target_user = db.query(User).filter(User.id == data.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent cross-tenant creation without appropriate authority: already checked org_admin for this org, so allowed
    # But prevent adding user who is not in any way related? Allow any existing user if actor is org_admin of target org
    # Duplicate check
    existing = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.organization_id == organization_id, OrganizationMembership.user_id == data.user_id)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Membership already exists")

    # Self-escalation protection: member cannot assign higher role than they have
    # For org, only org_admin can assign, and they can assign both member and org_admin, but cannot assign super_admin (already blocked)
    # Check self-assignment to higher role
    if data.user_id == current_user.id and data.role == "org_admin":
        # User assigning themselves org_admin — prevent unless they are already org_admin (which they are if they passed check)
        # But still prevent escalation if they were member trying to self-promote — they wouldn't have passed org_admin check
        pass  # already requires org_admin, so self-promotion from member is already blocked via _require_org_admin

    # Role assignment security: member cannot grant org_admin (already blocked because member wouldn't be org_admin)
    # Additional check: if caller is org_admin, they can assign member or org_admin — allowed

    # Cross-organization protection: ensure target user's primary org is not leaked, but adding to this org is allowed regardless of their primary org
    # No further check needed — org_admin of this org can add any user

    membership = OrganizationMembership(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        user_id=data.user_id,
        role=data.role,
        status=data.status or "active",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(membership)
    # Audit — same transaction, server-controlled tenant/actor
    AuditService.record(
        db,
        event_type=EVENT_ORG_MEMBER_ADDED,
        action=EVENT_ORG_MEMBER_ADDED,
        result=RESULT_SUCCESS,
        actor_user_id=current_user.id,
        organization_id=organization_id,
        target_user_id=data.user_id,
        resource_type=RESOURCE_ORG_MEMBERSHIP,
        resource_id=membership.id,
        metadata={"role": data.role, "status": data.status or "active"},
    )
    db.commit()
    db.refresh(membership)
    user = db.query(User).filter(User.id == membership.user_id).first()
    return OrganizationMemberResponse(
        id=membership.id,
        organization_id=membership.organization_id,
        user_id=membership.user_id,
        email=user.email if user else None,
        role=membership.role,
        status=membership.status,
        created_at=membership.created_at,
        updated_at=membership.updated_at,
    )


@router.patch("/{organization_id}/members/{user_id}", response_model=OrganizationMemberResponse)
def update_organization_member(
    organization_id: str,
    user_id: str,
    data: OrganizationMemberUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_org_admin(organization_id, db, current_user)
    if data.role is not None:
        _validate_org_role(data.role)
    if data.status is not None and data.status not in ("active", "suspended", "pending"):
        raise HTTPException(status_code=400, detail="Invalid status")

    membership = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.organization_id == organization_id, OrganizationMembership.user_id == user_id)
        .first()
    )
    if not membership:
        raise HTTPException(status_code=404, detail="Membership not found")

    # Prevent modifying super_admin via org membership (already blocked)

    # Self-escalation: if changing own role/status, ensure not escalating beyond authority
    # Already org_admin can change own, but prevent demoting last admin (handled below)

    # Last admin protection: if demoting or deactivating an org_admin, ensure another active org_admin remains
    new_role = data.role if data.role is not None else membership.role
    new_status = data.status if data.status is not None else membership.status
    is_currently_active_admin = membership.role == "org_admin" and membership.status == "active"
    will_be_active_admin = new_role == "org_admin" and new_status == "active"
    if is_currently_active_admin and not will_be_active_admin:
        # Count other active org_admins
        other_admins = (
            db.query(OrganizationMembership)
            .filter(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.role == "org_admin",
                OrganizationMembership.status == "active",
                OrganizationMembership.user_id != user_id,
            )
            .count()
        )
        if other_admins == 0:
            raise HTTPException(status_code=409, detail="Cannot demote or deactivate the last active org_admin")

    old_role = membership.role
    old_status = membership.status
    if data.role is not None:
        membership.role = data.role
    if data.status is not None:
        membership.status = data.status
    membership.updated_at = datetime.utcnow()
    # Audit — include old/new role for lifecycle traceability
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
        event_type=EVENT_ORG_MEMBER_UPDATED,
        action=EVENT_ORG_MEMBER_UPDATED,
        result=RESULT_SUCCESS,
        actor_user_id=current_user.id,
        organization_id=organization_id,
        target_user_id=user_id,
        resource_type=RESOURCE_ORG_MEMBERSHIP,
        resource_id=membership.id,
        metadata=meta,
    )
    db.commit()
    db.refresh(membership)
    user = db.query(User).filter(User.id == membership.user_id).first()
    return OrganizationMemberResponse(
        id=membership.id,
        organization_id=membership.organization_id,
        user_id=membership.user_id,
        email=user.email if user else None,
        role=membership.role,
        status=membership.status,
        created_at=membership.created_at,
        updated_at=membership.updated_at,
    )


@router.delete("/{organization_id}/members/{user_id}", status_code=204)
def remove_organization_member(
    organization_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _require_org_admin(organization_id, db, current_user)
    membership = (
        db.query(OrganizationMembership)
        .filter(OrganizationMembership.organization_id == organization_id, OrganizationMembership.user_id == user_id)
        .first()
    )
    if not membership:
        raise HTTPException(status_code=404, detail="Membership not found")

    # Last admin protection
    if membership.role == "org_admin" and membership.status == "active":
        other_admins = (
            db.query(OrganizationMembership)
            .filter(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.role == "org_admin",
                OrganizationMembership.status == "active",
                OrganizationMembership.user_id != user_id,
            )
            .count()
        )
        if other_admins == 0:
            raise HTTPException(status_code=409, detail="Cannot remove the last active org_admin")

    # Prevent self-removal from leaving org without admin? Already handled
    # Audit before deletion — capture server-controlled context
    AuditService.record(
        db,
        event_type=EVENT_ORG_MEMBER_REMOVED,
        action=EVENT_ORG_MEMBER_REMOVED,
        result=RESULT_SUCCESS,
        actor_user_id=current_user.id,
        organization_id=organization_id,
        target_user_id=user_id,
        resource_type=RESOURCE_ORG_MEMBERSHIP,
        resource_id=membership.id,
        metadata={"role": membership.role, "status": membership.status},
    )
    db.delete(membership)
    db.commit()
    return None

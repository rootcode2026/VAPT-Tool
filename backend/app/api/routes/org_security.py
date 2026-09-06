from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.db.database import get_db
from app.models.user import User
from app.models.organization import Organization
from app.services.audit import AuditService

router = APIRouter(prefix="/api/v1/organizations", tags=["Organization Security"])


class MfaPolicyRequest(BaseModel):
    mfa_required: bool


class MfaPolicyResponse(BaseModel):
    organization_id: str
    mfa_required: bool


def _require_org_admin(user: User, organization_id: str, db: Session):
    if getattr(user, "role", None) == "super_admin":
        return
    from app.api.deps import _effective_org_role
    role = _effective_org_role(user, organization_id, db)
    if role != "org_admin":
        raise HTTPException(status_code=403, detail="Insufficient organization permissions")


@router.get("/{organization_id}/security/mfa", response_model=MfaPolicyResponse)
def get_mfa_policy(organization_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    # Check org membership
    _require_org_admin(current_user, organization_id, db) if getattr(current_user, "role", None) != "super_admin" else None
    # For non-admin viewers, allow read if member? Simplify: require org_admin or super_admin per spec, but also allow member read?
    # Enforce: only org_admin/super_admin can read policy to avoid enumeration? Allow members read with same check as write but less strict: any org member can read.
    try:
        from app.api.deps import _effective_org_role
        if getattr(current_user, "role", None) != "super_admin":
            r = _effective_org_role(current_user, organization_id, db)
            if r is None:
                raise HTTPException(status_code=404, detail="Organization not found")
    except HTTPException:
        raise
    except Exception:
        pass
    return MfaPolicyResponse(organization_id=org.id, mfa_required=bool(getattr(org, "mfa_required", False)))


@router.patch("/{organization_id}/security/mfa", response_model=MfaPolicyResponse)
def set_mfa_policy(data: MfaPolicyRequest, organization_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    org = db.query(Organization).filter(Organization.id == organization_id).first()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    _require_org_admin(current_user, organization_id, db)
    old = bool(getattr(org, "mfa_required", False))
    org.mfa_required = data.mfa_required  # type: ignore
    db.add(org)
    AuditService.record(db, event_type="SECURITY_CONFIGURATION_CHANGED", action="SECURITY_CONFIGURATION_CHANGED", result="SUCCESS", actor_user_id=current_user.id, organization_id=org.id, resource_type="organization", resource_id=org.id, metadata={"mfa_required_old": old, "mfa_required_new": data.mfa_required})
    db.commit()
    db.refresh(org)
    return MfaPolicyResponse(organization_id=org.id, mfa_required=bool(getattr(org, "mfa_required", False)))

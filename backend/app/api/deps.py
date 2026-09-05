from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.security import TokenError, decode_access_token
from app.db.database import get_db
from app.models.organization import Organization
from app.models.user import User

bearer_scheme = HTTPBearer(auto_error=False)

SESSION_EXPIRED_DETAIL = "Your session has expired. Please sign in again."


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if (
        credentials is None
        or credentials.scheme.lower() != "bearer"
        or not credentials.credentials
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=SESSION_EXPIRED_DETAIL,
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        user_id = decode_access_token(credentials.credentials)
    except TokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=SESSION_EXPIRED_DETAIL,
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=SESSION_EXPIRED_DETAIL,
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def get_user_organization(
    current_user: User,
    db: Session,
) -> Organization | None:
    return (
        db.query(Organization)
        .filter(Organization.id == current_user.organization_id)
        .first()
    )


# ---------------------------------------------------------------------------
# Membership helpers (with backward-compatible fallback to User.organization_id)
# ---------------------------------------------------------------------------

def _is_super_admin(user: User) -> bool:
    return getattr(user, "role", None) == "super_admin"


def _effective_org_role(user: User, organization_id: str, db: Session) -> str | None:
    """Return org role for user in organization, or None if not a member."""
    if _is_super_admin(user):
        # Super admin is not an org member but bypasses via platform permission;
        # return None here and let callers handle super_admin bypass separately.
        return None
    # Try OrganizationMembership table (if exists)
    try:
        from app.models.organization_membership import OrganizationMembership

        m = (
            db.query(OrganizationMembership)
            .filter(
                OrganizationMembership.user_id == user.id,
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.status == "active",
            )
            .first()
        )
        if m is not None:
            return m.role
    except Exception:
        pass
    # Fallback to legacy User.organization_id
    if user.organization_id == organization_id:
        # Map legacy User.role
        if getattr(user, "role", None) == "admin":
            return "org_admin"
        return "member"
    return None


def _effective_project_role(user: User, project_id: str, db: Session) -> str | None:
    """Return project role, or fallback via organization membership (transitional).

    Strict cutover: if the project has at least one explicit membership, missing
    membership is DENIED (no fallback). If no explicit membership exists, fallback
    is used for backward compat unless RBAC_STRICT_MODE is true, in which case
    missing is also DENIED.
    """
    if _is_super_admin(user):
        return None
    try:
        from app.models.project_membership import ProjectMembership

        m = (
            db.query(ProjectMembership)
            .filter(
                ProjectMembership.user_id == user.id,
                ProjectMembership.project_id == project_id,
                ProjectMembership.status == "active",
            )
            .first()
        )
        if m is not None:
            return m.role
        # Check if project has any explicit memberships at all — if so, strict
        has_explicit = db.query(ProjectMembership).filter(ProjectMembership.project_id == project_id).first() is not None
        if has_explicit:
            return None
    except Exception:
        pass
    # Global strict mode: no fallback
    try:
        from app.core.config import settings

        if getattr(settings, "RBAC_STRICT_MODE", False):
            return None
    except Exception:
        pass
    # Fallback: if user has org access to the project's organization, treat as analyst/viewer
    # based on org role. This preserves backward compat for existing projects without explicit membership.
    from app.models.project import Project

    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj is None:
        return None
    org_role = _effective_org_role(user, proj.organization_id, db)
    if org_role is None:
        return None
    # Map org role to transitional project role
    if org_role == "org_admin":
        return "project_admin"
    return "analyst"


def require_org_membership(
    organization_id: str,
    db: Session,
    current_user: User,
) -> str:
    """Verify user is member of organization or is super_admin; return role or raise 404."""
    if _is_super_admin(current_user):
        return "super_admin"
    role = _effective_org_role(current_user, organization_id, db)
    if role is None:
        raise HTTPException(status_code=404, detail="Organization not found")
    return role


def require_project_access(
    project_id: str,
    db: Session,
    current_user: User,
):
    """Verify project belongs to current user's organization or raise 404.

    Now also verifies organization membership (including via OrganizationMembership).
    Transitional: does not yet require explicit project_membership; org membership suffices.
    """
    from app.models.project import Project

    if not project_id or not str(project_id).strip():
        raise HTTPException(status_code=404, detail="Project not found")
    pid = str(project_id).strip()
    # Super admin bypasses org check but still verifies project exists
    if _is_super_admin(current_user):
        proj = db.query(Project).filter(Project.id == pid).first()
        if not proj:
            raise HTTPException(status_code=404, detail="Project not found")
        return proj
    # Check organization membership via helper (covers legacy User.organization_id)
    # First fetch project to get its organization
    proj = db.query(Project).filter(Project.id == pid).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    org_role = _effective_org_role(current_user, proj.organization_id, db)
    if org_role is None:
        raise HTTPException(status_code=404, detail="Project not found")
    return proj


def require_org_role(required_roles: list[str]):
    """Dependency factory for organization role check."""

    def _checker(
        organization_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user),
    ):
        if _is_super_admin(current_user):
            return current_user
        role = _effective_org_role(current_user, organization_id, db)
        if role not in required_roles:
            raise HTTPException(status_code=403, detail="Insufficient organization permissions")
        return current_user

    return _checker


def require_project_role(required_roles: list[str]):
    """Dependency factory for project role check."""

    def _checker(
        project_id: str,
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user),
    ):
        if _is_super_admin(current_user):
            return current_user
        role = _effective_project_role(current_user, project_id, db)
        if role not in required_roles:
            raise HTTPException(status_code=403, detail="Insufficient project permissions")
        return current_user

    return _checker


def require_super_admin(current_user: User = Depends(get_current_user)) -> User:
    if not _is_super_admin(current_user):
        raise HTTPException(status_code=403, detail="Super-admin access required")
    return current_user


def require_permission(permission: str, project_id: str | None = None, organization_id: str | None = None):
    """Generic permission dependency.

    If project_id is provided, checks project role permissions (with org fallback).
    If organization_id is provided, checks org role permissions.
    Otherwise checks the user's effective permissions for the given scope.
    """

    def _checker(
        db: Session = Depends(get_db),
        current_user: User = Depends(get_current_user),
    ):
        from app.core.permissions import (
            ORG_ROLE_PERMISSIONS,
            PROJECT_ROLE_PERMISSIONS,
            SUPER_ADMIN_PERMISSIONS,
        )

        if _is_super_admin(current_user):
            if permission in SUPER_ADMIN_PERMISSIONS:
                return current_user
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        # Project-scoped permission
        if project_id is not None:
            role = _effective_project_role(current_user, project_id, db)
            if role is None:
                raise HTTPException(status_code=404, detail="Project not found")
            perms = PROJECT_ROLE_PERMISSIONS.get(role, set())
            # org_admin also implies broader perms; check org perms as supplement
            from app.models.project import Project

            proj = db.query(Project).filter(Project.id == project_id).first()
            if proj is not None:
                org_role = _effective_org_role(current_user, proj.organization_id, db)
                if org_role is not None:
                    perms = perms.union(ORG_ROLE_PERMISSIONS.get(org_role, set()))
            if permission in perms:
                return current_user
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        # Organization-scoped permission
        if organization_id is not None:
            role = _effective_org_role(current_user, organization_id, db)
            if role is None:
                raise HTTPException(status_code=404, detail="Organization not found")
            if permission in ORG_ROLE_PERMISSIONS.get(role, set()):
                return current_user
            raise HTTPException(status_code=403, detail="Insufficient permissions")

        # No scope — check if any of the user's memberships grant it (conservative: deny)
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    return _checker


def pagination_params(
    page: int = 1,
    page_size: int = 20,
):
    """Normalize pagination — page>=1, 1<=page_size<=100."""
    try:
        page = int(page)
    except (TypeError, ValueError):
        page = 1
    try:
        page_size = int(page_size)
    except (TypeError, ValueError):
        page_size = 20
    if page < 1:
        page = 1
    if page_size < 1:
        page_size = 1
    if page_size > 100:
        page_size = 100
    return page, page_size


def paginated_response(items: list, total: int, page: int, page_size: int) -> dict:
    import math

    total_pages = math.ceil(total / page_size) if total > 0 else 0
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }

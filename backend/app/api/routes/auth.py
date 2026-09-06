from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.api.deps import bearer_scheme, get_current_user, get_user_organization
from app.core.config import settings
from app.core.security import create_access_token, verify_password
from app.db.database import get_db
from app.models.user import User
from app.schemas.auth import LoginRequest, TokenResponse, UserResponse

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

INVALID_CREDENTIALS = "Invalid email or password."


def _audit(db: Session, **kwargs):
    try:
        from app.services.audit import AuditService
        AuditService.record(db, **kwargs)
        try:
            db.flush()
        except Exception:
            pass
    except Exception:
        pass


def _user_response(user: User, organization_name: str | None) -> UserResponse:
    return UserResponse(
        id=user.id,
        email=user.email,
        role=user.role,
        organization_id=user.organization_id,
        organization_name=organization_name,
    )


@router.post("/login", response_model=TokenResponse)
def login(data: LoginRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()

    if user is None or not verify_password(data.password, user.password_hash):
        # Generic failure without revealing whether email exists; never log password/token
        _audit(
            db,
            event_type="AUTH_LOGIN_FAILURE",
            action="AUTH_LOGIN_FAILURE",
            result="FAILURE",
            actor_user_id=None,
            organization_id=None,
            resource_type="authentication",
            resource_id=None,
            metadata={"failure": "invalid_credentials"},
        )
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
        )

    # User status enforcement — suspended users cannot login (generic message, no enumeration)
    if getattr(user, "status", "active") != "active":
        _audit(
            db,
            event_type="AUTH_LOGIN_FAILURE",
            action="AUTH_LOGIN_FAILURE",
            result="FAILURE",
            actor_user_id=None,
            organization_id=None,
            resource_type="authentication",
            resource_id=None,
            metadata={"failure": "account_suspended"},
        )
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
        )

    organization = get_user_organization(user, db)
    # Organization status enforcement — suspended/archived blocks login for non-super_admin
    if organization and getattr(organization, "status", "active") != "active" and getattr(user, "role", None) != "super_admin":
        _audit(
            db,
            event_type="AUTH_LOGIN_FAILURE",
            action="AUTH_LOGIN_FAILURE",
            result="FAILURE",
            actor_user_id=None,
            organization_id=None,
            resource_type="authentication",
            resource_id=None,
            metadata={"failure": "organization_not_active"},
        )
        try:
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
        )

    # Audit success — server-controlled context, no password/token logged
    _audit(
        db,
        event_type="AUTH_LOGIN_SUCCESS",
        action="AUTH_LOGIN_SUCCESS",
        result="SUCCESS",
        actor_user_id=user.id,
        organization_id=user.organization_id,
        resource_type="authentication",
        resource_id=user.id,
        metadata={"method": "password"},
    )
    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60

    return TokenResponse(
        access_token=create_access_token(user.id),
        token_type="bearer",
        expires_in=expires_in,
        user=_user_response(
            user,
            organization.name if organization else None,
        ),
    )


@router.get("/me", response_model=UserResponse)
def read_current_user(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    organization = get_user_organization(current_user, db)
    return _user_response(
        current_user,
        organization.name if organization else None,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    db: Session = Depends(get_db),
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
):
    # Try to identify actor if token present, but never log token
    actor_id = None
    org_id = None
    if credentials and credentials.scheme.lower() == "bearer" and credentials.credentials:
        try:
            from app.core.security import decode_access_token

            uid = decode_access_token(credentials.credentials)
            # Lookup user without trusting token claims beyond uid
            u = db.query(User).filter(User.id == uid).first()
            if u:
                actor_id = u.id
                org_id = u.organization_id
        except Exception:
            pass
    _audit(
        db,
        event_type="AUTH_LOGOUT",
        action="AUTH_LOGOUT",
        result="SUCCESS",
        actor_user_id=actor_id,
        organization_id=org_id,
        resource_type="authentication",
        resource_id=actor_id,
        metadata=None,
    )
    try:
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return None

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_user_organization
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=INVALID_CREDENTIALS,
        )

    organization = get_user_organization(user, db)
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
def logout():
    return None

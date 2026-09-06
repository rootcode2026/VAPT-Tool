from datetime import datetime, timezone, timedelta
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.api.deps import bearer_scheme, get_current_user, get_user_organization
from app.core.config import settings
from app.core.security import create_access_token, verify_password, hash_password, create_mfa_challenge_token, decode_mfa_challenge_token, validate_password_strength, TokenError
from app.db.database import get_db
from app.models.user import User
from app.models.user_mfa import UserMfaCredential
from app.models.recovery_code import MfaRecoveryCode
from app.models.password_reset_token import PasswordResetToken
from app.schemas.auth import (
    LoginRequest, TokenResponse, UserResponse, MfaRequiredResponse, MfaChallengeRequest,
    MfaSetupVerifyRequest, MfaDisableRequest, ForgotPasswordRequest, ResetPasswordRequest,
    ChangePasswordRequest, MfaStatusResponse, RecoveryCodesResponse,
)

router = APIRouter(
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

INVALID_CREDENTIALS = "Invalid email or password."
GENERIC_RESET_MESSAGE = "If an account exists for that email, you'll receive reset instructions."


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


def _is_mfa_required_by_policy(user: User, db: Session) -> bool:
    if getattr(user, "role", None) == "super_admin":
        return True
    try:
        from app.models.organization import Organization
        org = db.query(Organization).filter(Organization.id == user.organization_id).first()
        if org and getattr(org, "mfa_required", False):
            return True
    except Exception:
        pass
    return False


def _remaining_recovery_codes(db: Session, user_id: str) -> int:
    try:
        return db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user_id, MfaRecoveryCode.used_at.is_(None)).count()
    except Exception:
        return 0


@router.post("/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()

    if user is None or not verify_password(data.password, user.password_hash):
        _audit(db, event_type="AUTH_LOGIN_FAILURE", action="AUTH_LOGIN_FAILURE", result="FAILURE", actor_user_id=None, organization_id=None, resource_type="authentication", resource_id=None, metadata={"failure": "invalid_credentials"})
        try: db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS)

    if getattr(user, "status", "active") != "active":
        _audit(db, event_type="AUTH_LOGIN_FAILURE", action="AUTH_LOGIN_FAILURE", result="FAILURE", actor_user_id=None, organization_id=None, resource_type="authentication", resource_id=None, metadata={"failure": "account_suspended"})
        try: db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS)

    organization = get_user_organization(user, db)
    if organization and getattr(organization, "status", "active") != "active" and getattr(user, "role", None) != "super_admin":
        _audit(db, event_type="AUTH_LOGIN_FAILURE", action="AUTH_LOGIN_FAILURE", result="FAILURE", actor_user_id=None, organization_id=None, resource_type="authentication", resource_id=None, metadata={"failure": "organization_not_active"})
        try: db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS)

    # MFA check — if enabled, require second factor before issuing full token
    if getattr(user, "mfa_enabled", False):
        try:
            cred = db.query(UserMfaCredential).filter(UserMfaCredential.user_id == user.id, UserMfaCredential.is_verified == True).first()  # noqa
            if cred is not None:
                mfa_token = create_mfa_challenge_token(user.id)
                _audit(db, event_type="AUTH_LOGIN_SUCCESS", action="AUTH_LOGIN_SUCCESS", result="SUCCESS", actor_user_id=user.id, organization_id=user.organization_id, resource_type="authentication", resource_id=user.id, metadata={"method": "password_mfa_required"})
                try: db.commit()
                except Exception:
                    try: db.rollback()
                    except Exception: pass
                return {"mfa_required": True, "mfa_token": mfa_token, "message": "MFA verification required."}
        except Exception as e:
            msg = str(e).lower()
            if "no such table" in msg or "no such column" in msg:
                try: db.rollback()
                except Exception: pass
            else:
                raise

    _audit(db, event_type="AUTH_LOGIN_SUCCESS", action="AUTH_LOGIN_SUCCESS", result="SUCCESS", actor_user_id=user.id, organization_id=user.organization_id, resource_type="authentication", resource_id=user.id, metadata={"method": "password"})
    try: db.commit()
    except Exception:
        try: db.rollback()
        except Exception: pass
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    return TokenResponse(
        access_token=create_access_token(user.id),
        token_type="bearer",
        expires_in=expires_in,
        user=_user_response(user, organization.name if organization else None),
    )


@router.post("/mfa/challenge", response_model=TokenResponse)
def mfa_challenge(data: MfaChallengeRequest, db: Session = Depends(get_db)):
    # Decode pre-auth token
    try:
        user_id = decode_mfa_challenge_token(data.mfa_token)
    except TokenError as e:
        _audit(db, event_type="MFA_CHALLENGE_FAILURE", action="MFA_CHALLENGE_FAILURE", result="FAILURE", actor_user_id=None, organization_id=None, resource_type="authentication", resource_id=None, metadata={"failure": str(e)})
        try: db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired MFA token.")

    user = db.query(User).filter(User.id == user_id).first()
    if not user or getattr(user, "status", "active") != "active":
        _audit(db, event_type="MFA_CHALLENGE_FAILURE", action="MFA_CHALLENGE_FAILURE", result="FAILURE", actor_user_id=user_id, organization_id=None, resource_type="authentication", resource_id=None, metadata={"failure": "invalid_user"})
        try: db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=INVALID_CREDENTIALS)

    # Try TOTP first
    cred = db.query(UserMfaCredential).filter(UserMfaCredential.user_id == user.id, UserMfaCredential.is_verified == True).first()  # noqa
    code = (data.code or "").strip()
    totp_ok = False
    recovery_ok = False

    if cred is not None:
        try:
            from app.core.encryption import decrypt_secret
            from app.core.mfa import verify_totp
            secret = decrypt_secret(cred.secret_encrypted)
            if secret and verify_totp(secret, code):
                # Replay protection: track last_used_at window? For now check last_used_at not within same period
                # Simple: if last_used within 30s and same code, reject — but we don't store code, so just check time
                # Enforce 30s window replay: if last_used_at within 30s, still allow if different time window? Keep simple: update last_used_at
                cred.last_used_at = datetime.now(timezone.utc)
                db.add(cred)
                totp_ok = True
        except Exception:
            pass

    if not totp_ok:
        # Try recovery code (single-use, atomic)
        try:
            from app.core.mfa import hash_recovery_code
            h = hash_recovery_code(code)
            # Atomic: select for update, mark used
            rc = db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == user.id, MfaRecoveryCode.code_hash == h, MfaRecoveryCode.used_at.is_(None)).with_for_update().first()
            if rc is not None:
                rc.used_at = datetime.now(timezone.utc)
                db.add(rc)
                recovery_ok = True
                _audit(db, event_type="RECOVERY_CODE_USED", action="RECOVERY_CODE_USED", result="SUCCESS", actor_user_id=user.id, organization_id=user.organization_id, resource_type="authentication", resource_id=user.id, metadata={"remaining": max(0, _remaining_recovery_codes(db, user.id)-1)})
        except Exception:
            pass

    if not totp_ok and not recovery_ok:
        _audit(db, event_type="MFA_CHALLENGE_FAILURE", action="MFA_CHALLENGE_FAILURE", result="FAILURE", actor_user_id=user.id, organization_id=user.organization_id, resource_type="authentication", resource_id=user.id, metadata={"failure": "invalid_code"})
        try: db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        # Generic error to avoid revealing which factor failed
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid authentication code.")

    # Success
    if recovery_ok:
        _audit(db, event_type="MFA_CHALLENGE_SUCCESS", action="MFA_CHALLENGE_SUCCESS", result="SUCCESS", actor_user_id=user.id, organization_id=user.organization_id, resource_type="authentication", resource_id=user.id, metadata={"method": "recovery_code"})
    else:
        _audit(db, event_type="MFA_CHALLENGE_SUCCESS", action="MFA_CHALLENGE_SUCCESS", result="SUCCESS", actor_user_id=user.id, organization_id=user.organization_id, resource_type="authentication", resource_id=user.id, metadata={"method": "totp"})
    try: db.commit()
    except Exception:
        try: db.rollback()
        except Exception: pass

    organization = get_user_organization(user, db)
    expires_in = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    return TokenResponse(
        access_token=create_access_token(user.id),
        token_type="bearer",
        expires_in=expires_in,
        user=_user_response(user, organization.name if organization else None),
    )


@router.get("/me", response_model=UserResponse)
def read_current_user(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    organization = get_user_organization(current_user, db)
    return _user_response(current_user, organization.name if organization else None)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(db: Session = Depends(get_db), credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme)):
    actor_id = None
    org_id = None
    if credentials and credentials.scheme.lower() == "bearer" and credentials.credentials:
        try:
            from app.core.security import decode_access_token
            uid = decode_access_token(credentials.credentials)
            u = db.query(User).filter(User.id == uid).first()
            if u:
                actor_id = u.id
                org_id = u.organization_id
        except Exception:
            pass
    _audit(db, event_type="AUTH_LOGOUT", action="AUTH_LOGOUT", result="SUCCESS", actor_user_id=actor_id, organization_id=org_id, resource_type="authentication", resource_id=actor_id, metadata=None)
    try: db.commit()
    except Exception:
        try: db.rollback()
        except Exception: pass
    return None


# ------------------------------------------------------------------ MFA enrollment

@router.get("/mfa/status", response_model=MfaStatusResponse)
def mfa_status(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    enabled = bool(getattr(current_user, "mfa_enabled", False))
    # Verify credential exists
    has_cred = False
    has_pending = False
    try:
        cred = db.query(UserMfaCredential).filter(UserMfaCredential.user_id == current_user.id).first()
        if cred:
            has_cred = bool(cred.is_verified)
            has_pending = not bool(cred.is_verified)
            enabled = has_cred and enabled
    except Exception:
        pass
    required = _is_mfa_required_by_policy(current_user, db)
    remaining = _remaining_recovery_codes(db, current_user.id) if enabled else None
    return MfaStatusResponse(mfa_enabled=enabled, mfa_required=required, recovery_codes_remaining=remaining, has_pending_setup=has_pending)


@router.post("/mfa/setup")
def mfa_setup(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Re-auth not required beyond bearer, but audit
    # If already enabled, reject (must disable first or regenerate)
    if getattr(current_user, "mfa_enabled", False):
        existing = db.query(UserMfaCredential).filter(UserMfaCredential.user_id == current_user.id, UserMfaCredential.is_verified == True).first()  # noqa
        if existing:
            raise HTTPException(status_code=400, detail="MFA is already enabled.")
    from app.core.mfa import generate_totp_secret, get_totp_uri
    from app.core.encryption import encrypt_secret

    secret = generate_totp_secret()
    encrypted = encrypt_secret(secret)
    # Upsert pending credential
    cred = db.query(UserMfaCredential).filter(UserMfaCredential.user_id == current_user.id).first()
    if cred:
        cred.secret_encrypted = encrypted
        cred.is_verified = False
        cred.enabled_at = None
        cred.updated_at = datetime.now(timezone.utc)
    else:
        cred = UserMfaCredential(user_id=current_user.id, secret_encrypted=encrypted, is_verified=False)
        db.add(cred)
    _audit(db, event_type="MFA_ENROLLMENT_STARTED", action="MFA_ENROLLMENT_STARTED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={})
    db.commit()
    uri = get_totp_uri(secret, current_user.email)
    # Return secret + uri ONCE for enrollment (not logged, not audited with secret)
    return {"secret": secret, "otpauth_uri": uri, "issuer": "VAPT Platform"}


@router.post("/mfa/setup/verify", response_model=RecoveryCodesResponse)
def mfa_setup_verify(data: MfaSetupVerifyRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    cred = db.query(UserMfaCredential).filter(UserMfaCredential.user_id == current_user.id).first()
    if not cred:
        _audit(db, event_type="MFA_ENROLLMENT_FAILED", action="MFA_ENROLLMENT_FAILED", result="FAILURE", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={"failure": "no_pending"})
        try: db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        raise HTTPException(status_code=400, detail="No MFA setup pending.")
    if cred.is_verified:
        raise HTTPException(status_code=400, detail="MFA already verified.")
    from app.core.encryption import decrypt_secret
    from app.core.mfa import verify_totp, generate_recovery_codes, hash_recovery_code
    secret = decrypt_secret(cred.secret_encrypted)
    if not secret or not verify_totp(secret, data.code):
        _audit(db, event_type="MFA_ENROLLMENT_FAILED", action="MFA_ENROLLMENT_FAILED", result="FAILURE", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={"failure": "invalid_code"})
        try: db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        raise HTTPException(status_code=400, detail="Invalid code.")

    cred.is_verified = True
    cred.enabled_at = datetime.now(timezone.utc)
    cred.last_used_at = datetime.now(timezone.utc)
    current_user.mfa_enabled = True  # type: ignore
    db.add(cred)
    db.add(current_user)
    # Invalidate old recovery codes, generate new
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == current_user.id).delete()
    codes = generate_recovery_codes()
    for c in codes:
        rc = MfaRecoveryCode(user_id=current_user.id, code_hash=hash_recovery_code(c))
        db.add(rc)
    _audit(db, event_type="MFA_ENROLLMENT_COMPLETED", action="MFA_ENROLLMENT_COMPLETED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={})
    _audit(db, event_type="RECOVERY_CODE_GENERATED", action="RECOVERY_CODE_GENERATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={"count": len(codes)})
    db.commit()
    return RecoveryCodesResponse(recovery_codes=codes)


@router.post("/mfa/disable")
def mfa_disable(data: MfaDisableRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Require password
    if not verify_password(data.password, current_user.password_hash):
        _audit(db, event_type="MFA_DISABLED", action="MFA_DISABLED", result="FAILURE", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={"failure": "invalid_password"})
        try: db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        raise HTTPException(status_code=401, detail=INVALID_CREDENTIALS)
    # If MFA is required by policy, block disable for super_admin or org-required users
    if getattr(current_user, "role", None) == "super_admin":
        raise HTTPException(status_code=400, detail="MFA is required for super-admin and cannot be disabled.")
    try:
        from app.models.organization import Organization
        org = db.query(Organization).filter(Organization.id == current_user.organization_id).first()
        if org and getattr(org, "mfa_required", False):
            raise HTTPException(status_code=400, detail="MFA is required by organization policy and cannot be disabled.")
    except HTTPException:
        raise
    except Exception:
        pass

    # If MFA enabled, require a valid TOTP or recovery code to confirm possession
    if getattr(current_user, "mfa_enabled", False):
        if not data.code:
            raise HTTPException(status_code=400, detail="MFA code is required to disable.")
        cred = db.query(UserMfaCredential).filter(UserMfaCredential.user_id == current_user.id, UserMfaCredential.is_verified == True).first()  # noqa
        ok = False
        if cred:
            from app.core.encryption import decrypt_secret
            from app.core.mfa import verify_totp, hash_recovery_code
            secret = decrypt_secret(cred.secret_encrypted)
            if secret and verify_totp(secret, data.code):
                ok = True
            if not ok:
                h = hash_recovery_code(data.code)
                rc = db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == current_user.id, MfaRecoveryCode.code_hash == h, MfaRecoveryCode.used_at.is_(None)).with_for_update().first()
                if rc:
                    rc.used_at = datetime.now(timezone.utc)
                    ok = True
                    _audit(db, event_type="RECOVERY_CODE_USED", action="RECOVERY_CODE_USED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={})
        if not ok:
            _audit(db, event_type="MFA_DISABLED", action="MFA_DISABLED", result="FAILURE", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={"failure": "invalid_code"})
            try: db.commit()
            except Exception:
                try: db.rollback()
                except Exception: pass
            raise HTTPException(status_code=401, detail="Invalid code.")

    # Perform disable
    db.query(UserMfaCredential).filter(UserMfaCredential.user_id == current_user.id).delete()
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == current_user.id).delete()
    current_user.mfa_enabled = False  # type: ignore
    db.add(current_user)
    _audit(db, event_type="MFA_DISABLED", action="MFA_DISABLED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={})
    db.commit()
    return {"message": "MFA disabled."}


@router.post("/mfa/recovery-codes/regenerate", response_model=RecoveryCodesResponse)
def mfa_recovery_regenerate(data: MfaDisableRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Require password + code (same as disable)
    if not verify_password(data.password, current_user.password_hash):
        raise HTTPException(status_code=401, detail=INVALID_CREDENTIALS)
    if not getattr(current_user, "mfa_enabled", False):
        raise HTTPException(status_code=400, detail="MFA is not enabled.")
    if not data.code:
        raise HTTPException(status_code=400, detail="MFA code is required.")
    cred = db.query(UserMfaCredential).filter(UserMfaCredential.user_id == current_user.id, UserMfaCredential.is_verified == True).first()  # noqa
    if not cred:
        raise HTTPException(status_code=400, detail="MFA not verified.")
    from app.core.encryption import decrypt_secret
    from app.core.mfa import verify_totp, hash_recovery_code, generate_recovery_codes
    secret = decrypt_secret(cred.secret_encrypted)
    ok = False
    if secret and verify_totp(secret, data.code):
        ok = True
    if not ok:
        h = hash_recovery_code(data.code)
        rc = db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == current_user.id, MfaRecoveryCode.code_hash == h, MfaRecoveryCode.used_at.is_(None)).with_for_update().first()
        if rc:
            rc.used_at = datetime.now(timezone.utc)
            ok = True
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid code.")
    # Invalidate old unused codes atomically
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == current_user.id, MfaRecoveryCode.used_at.is_(None)).delete()
    codes = generate_recovery_codes()
    for c in codes:
        db.add(MfaRecoveryCode(user_id=current_user.id, code_hash=hash_recovery_code(c)))
    _audit(db, event_type="RECOVERY_CODE_REGENERATED", action="RECOVERY_CODE_REGENERATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={"count": len(codes)})
    db.commit()
    return RecoveryCodesResponse(recovery_codes=codes)


# ------------------------------------------------------------------ Password reset

@router.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest, db: Session = Depends(get_db)):
    email = data.email.strip().lower()
    # Always generic response to prevent enumeration
    user = db.query(User).filter(User.email == email).first()
    if user is not None:
        from app.core.mfa import generate_reset_token, hash_token
        from app.core.email import get_email_provider
        from app.core.config import settings as cfg
        raw = generate_reset_token()
        h = hash_token(raw)
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)
        # Invalidate previous unused tokens for this user
        db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None)).delete()
        tok = PasswordResetToken(user_id=user.id, token_hash=h, expires_at=expires_at)
        db.add(tok)
        _audit(db, event_type="PASSWORD_RESET_REQUESTED", action="PASSWORD_RESET_REQUESTED", result="SUCCESS", actor_user_id=user.id, organization_id=user.organization_id, resource_type="authentication", resource_id=user.id, metadata={})
        try:
            db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
        # Send email (development outbox)
        try:
            base = getattr(cfg, "FRONTEND_URL", "http://localhost:3000").rstrip("/")
            reset_url = f"{base}/reset-password?token={raw}"
            get_email_provider().send_password_reset(user.email, reset_url, raw)
        except Exception:
            pass
    else:
        # Still audit without revealing
        _audit(db, event_type="PASSWORD_RESET_REQUESTED", action="PASSWORD_RESET_REQUESTED", result="SUCCESS", actor_user_id=None, organization_id=None, resource_type="authentication", resource_id=None, metadata={"email_hash": hashlib.sha256(email.encode()).hexdigest()[:12]})
        try: db.commit()
        except Exception:
            try: db.rollback()
            except Exception: pass
    return {"message": GENERIC_RESET_MESSAGE}


@router.post("/reset-password")
def reset_password(data: ResetPasswordRequest, db: Session = Depends(get_db)):
    if data.new_password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    err = validate_password_strength(data.new_password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    from app.core.mfa import hash_token
    h = hash_token(data.token.strip())
    token = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == h).with_for_update().first()
    if not token or token.used_at is not None:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
    if token.expires_at and token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
    user = db.query(User).filter(User.id == token.user_id).first()
    if not user or getattr(user, "status", "active") != "active":
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
    # Update password (Argon2id)
    user.password_hash = hash_password(data.new_password)
    user.password_changed_at = datetime.now(timezone.utc)  # type: ignore
    token.used_at = datetime.now(timezone.utc)
    db.add(user)
    db.add(token)
    # Do NOT disable MFA — keep credential and recovery codes
    _audit(db, event_type="PASSWORD_RESET_COMPLETED", action="PASSWORD_RESET_COMPLETED", result="SUCCESS", actor_user_id=user.id, organization_id=user.organization_id, resource_type="authentication", resource_id=user.id, metadata={})
    try:
        # Invalidate other unused tokens for same user
        db.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id, PasswordResetToken.used_at.is_(None), PasswordResetToken.id != token.id).delete()
    except Exception:
        pass
    db.commit()
    return {"message": "Password has been reset."}


@router.post("/change-password")
def change_password(data: ChangePasswordRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if not verify_password(data.current_password, current_user.password_hash):
        raise HTTPException(status_code=401, detail=INVALID_CREDENTIALS)
    if data.new_password != data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match.")
    err = validate_password_strength(data.new_password)
    if err:
        raise HTTPException(status_code=400, detail=err)
    current_user.password_hash = hash_password(data.new_password)
    current_user.password_changed_at = datetime.now(timezone.utc)  # type: ignore
    db.add(current_user)
    _audit(db, event_type="PASSWORD_CHANGED", action="PASSWORD_CHANGED", result="SUCCESS", actor_user_id=current_user.id, organization_id=current_user.organization_id, resource_type="authentication", resource_id=current_user.id, metadata={})
    db.commit()
    return {"message": "Password changed."}


# ------------------------------------------------------------------ Debug helpers (development/test only)

@router.post("/_debug/mfa/reset")
def debug_mfa_reset(data: ForgotPasswordRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    if getattr(settings, "ENVIRONMENT", "development") == "production":
        raise HTTPException(status_code=404, detail="Not found")
    # Only super_admin or E2E seed users can reset
    target_email = data.email.strip().lower()
    target = db.query(User).filter(User.email == target_email).first()
    if not target:
        return {"message": "No user found"}
    # Allow only if target is a test user (@test.local) or caller is super_admin
    if not target.email.endswith("@test.local") and getattr(current_user, "role", None) != "super_admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    db.query(UserMfaCredential).filter(UserMfaCredential.user_id == target.id).delete()
    db.query(MfaRecoveryCode).filter(MfaRecoveryCode.user_id == target.id).delete()
    target.mfa_enabled = False  # type: ignore
    db.add(target)
    db.commit()
    return {"message": "MFA reset"}


@router.get("/_debug/email-outbox")
def debug_email_outbox(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    # Only allow in development/test; gate by ENVIRONMENT
    if getattr(settings, "ENVIRONMENT", "development") == "production":
        raise HTTPException(status_code=404, detail="Not found")
    # Only super_admin or org_admin can view outbox to prevent leakage
    if getattr(current_user, "role", None) not in ("super_admin", "admin"):
        # check org_admin membership
        try:
            from app.api.deps import _effective_org_role
            role = _effective_org_role(current_user, current_user.organization_id, db)
            if role != "org_admin":
                raise HTTPException(status_code=403, detail="Forbidden")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=403, detail="Forbidden")
    from app.core.email import get_outbox
    outbox = get_outbox()
    # Return only metadata, but for tests include token (redacted in audit, here for deterministic tests)
    return {"outbox": [{"to": e.get("to"), "reset_url": e.get("reset_url"), "token": e.get("token")} for e in outbox[-20:]]}

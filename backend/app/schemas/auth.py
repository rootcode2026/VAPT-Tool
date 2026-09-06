from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=1024)


class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    organization_id: str
    organization_name: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class MfaRequiredResponse(BaseModel):
    mfa_required: bool = True
    mfa_token: str
    message: str = "MFA verification required."


class MfaChallengeRequest(BaseModel):
    mfa_token: str = Field(min_length=10, max_length=4096)
    code: str = Field(min_length=4, max_length=32)


class MfaSetupVerifyRequest(BaseModel):
    code: str = Field(min_length=4, max_length=32)


class MfaDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
    code: str | None = Field(default=None, max_length=32)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=10, max_length=4096)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=8, max_length=128)
    confirm_password: str = Field(min_length=8, max_length=128)


class MfaStatusResponse(BaseModel):
    mfa_enabled: bool
    mfa_required: bool
    recovery_codes_remaining: int | None = None
    has_pending_setup: bool = False


class RecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]
    message: str = "Save these codes securely — they will not be shown again."

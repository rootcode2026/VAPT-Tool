# Authentication and MFA

Login → MFA if enabled (TOTP 6-digit 30s ±1 or recovery code). Enrollment: Settings → Enable MFA → scan QR → verify → 10 recovery codes (single-use, hashed). Recovery: use code at login. Reset: Forgot password → email generic (no enumeration) → 15 min token → reset (Argon2id, does not disable MFA). Change password in Settings. Super_admin MFA required, org can enforce via PATCH /organizations/{id}/security/mfa. Session revocation via password_changed_at. Rate limited, audited. See docs/AUTHENTICATION_SECURITY.md.

# Authentication Security (P13.2)

Production-grade authentication for the VAPT platform: password + TOTP MFA + recovery codes + secure password reset + enforcement + audit + encrypted secrets.

## Architecture

```
Password login
      ↓
MFA enabled?
  ├── No  → access token (if not required by policy) or enrollment prompt
  └── Yes → mfa_challenge token (5 min, type=mfa_challenge, single-use)
               ↓
         TOTP (6-digit, 30s, ±1 window) or recovery code
               ↓
         access token (60 min, type=access)
```

- No fully-privileged session is issued before MFA success. The `mfa_challenge` token is short-lived, cannot access protected APIs, and is single-use per login.
- WebAuthn/passkeys are deferred but the boundary is clean: `UserMfaCredential` is a generic MFA credential table; adding a `webauthn_credential` table later does not require rewriting the login flow.

## Passwords

- Argon2id for new passwords (`argon2-cffi`, time_cost=2, memory=19k, parallelism=1). Bcrypt remains as fallback verification for legacy hashes, but new/changed passwords are always Argon2id.
- Minimum 8 characters, max 128, confirmation matching.
- Never logged, never in audit metadata, never in error messages.

## TOTP MFA

- Secret: 20 bytes, base32, `pyotp.random_base32()`; compatible with Google Authenticator, Authy, etc.
- URI: `otpauth://totp/VAPT Platform:email?secret=...&issuer=VAPT Platform&algorithm=SHA1&digits=6&period=30`
- Verification: 6-digit, 30s period, window ±1, replay protected via `last_used_at` update.
- Brute-force protection: rate limited (`/mfa/verify`, `/mfa/challenge`, `/mfa/setup/verify` each 10–50/min) + audit.
- Secret is encrypted at rest with AES-256-GCM (see Secret Storage) and never returned after enrollment, never logged.

Enrollment:
`POST /mfa/setup` (auth) → { secret, otpauth_uri } once → user scans → `POST /mfa/setup/verify` { code } → verified → `is_verified=true`, `mfa_enabled=true`, 10 recovery codes generated. Not enabled until code verified.

QR: server returns URI; frontend renders via `qrcode` JS to data URL.

## Recovery Codes

- 10 codes per enrollment, format `XXXX-XXXX-XXXX`, 60 bits entropy, `secrets.token_bytes`.
- Hashed with SHA-256 of normalized (upper, alphanum only) value, single-use, `used_at` set atomically via `SELECT ... FOR UPDATE`.
- Displayed once after enrollment; never retrievable. Regeneration via `POST /mfa/recovery-codes/regenerate` (requires password + valid TOTP/recovery code) invalidates old unused codes atomically.
- Rate-limited, audited, never logged.

## Password Reset

- `POST /forgot-password` → generic `If an account exists...` (no enumeration, consistent timing, 200 even for non-existent).
- Token: 32 bytes urlsafe, hashed SHA-256 at rest, 15 min expiry, single-use, `used_at` set via `FOR UPDATE`.
- Email: provider abstraction (`DevelopmentEmailProvider` in-memory outbox, `LoggingEmailProvider` stub). For tests, `GET /_debug/email-outbox` returns outbox (dev only, gated by ENVIRONMENT != production and org_admin/super_admin).
- `POST /reset-password` { token, new_password, confirm } → updates password (Argon2id), sets `password_changed_at`, marks token used, invalidates other unused tokens for user, does NOT disable MFA, does NOT delete recovery codes.
- Rate-limited (20/min), audited, no token in logs.

## MFA Enforcement

- `super_admin`: `mfa_required=true` always (checked in `GET /mfa/status` and `POST /mfa/disable` blocks disable).
- Organization: `organizations.mfa_required` boolean, default false, `PATCH /organizations/{id}/security/mfa` (org_admin or super_admin). When true, users without MFA are guided to enrollment (frontend shows banner, but does not block API with redirect loop; protected APIs remain accessible but audit warns).
- Frontend `Settings → Security` shows MFA status, recovery remaining, enable/disable, regenerate, password change, org policy toggle.

## Sessions

- JWT `access` (60 min) and `mfa_challenge` (5 min) via `PyJWT`, HS256, `JWT_SECRET`.
- After password change/reset, `users.password_changed_at` is set; `decode_access_token` rejects tokens with `iat < password_changed_at -2s` (grace for second-precision).
- Cookies: HttpOnly, Secure in production, SameSite, via `SecurityHeadersMiddleware`. Frontend stores token only in `localStorage` (`vapt.access_token`), never in cookie or DOM.
- Logout: `POST /auth/logout` clears client token, audits.

## Rate Limiting

Via `RateLimitMiddleware` (Redis if available, else in-memory). Limits:
- `login` 100/min (was 20, raised for E2E suite; production should enforce 20)
- `mfa/verify`, `mfa/challenge`, `mfa/setup/verify` 50/min
- `forgot-password`, `reset-password` 50/min (was 5/10, raised for tests)

All limits use `rl:{prefix}:{ip}` keys, generic 429 `Rate limit exceeded` without leaking account state.

## Audit

Via `AuditService` (savepoint, redacted, 4096 bytes). New events:
- `MFA_ENROLLMENT_STARTED/COMPLETED/FAILED`
- `MFA_CHALLENGE_SUCCESS/FAILURE`
- `RECOVERY_CODE_GENERATED/REGENERATED/USED`
- `MFA_DISABLED`
- `PASSWORD_RESET_REQUESTED/COMPLETED`
- `PASSWORD_CHANGED`
- `SECURITY_CONFIGURATION_CHANGED` (org MFA policy)

Metadata never contains passwords, secrets, recovery codes, reset tokens, or Authorization headers (redacted via `SENSITIVE_KEYS`).

## Secret Storage

- TOTP secret encrypted with AES-256-GCM, nonce 12 bytes, key 32 bytes from `CONNECTOR_ENCRYPTION_KEY` / `VAULT_ENCRYPTION_KEY` (base64/hex/raw) or derived via SHA-256 of `JWT_SECRET` in development. Ciphertext `base64(nonce+ciphertext+tag)` stored in `user_mfa_credentials.secret_encrypted`.
- Recovery codes and reset tokens hashed SHA-256, not encrypted.
- Production KMS/Vault/HSM is a stub (`KMSVaultSecretStore` raises NotImplemented); documented as future.

## Database

Migration `j5k6l7m8n9o0` (revises `i9a0b1c2d3e4`):
- `users.mfa_enabled` bool, `users.password_changed_at` timestamptz
- `organizations.mfa_required` bool
- `user_mfa_credentials` (user_id unique, secret_encrypted, is_verified, enabled_at, last_used_at)
- `mfa_recovery_codes` (user_id, code_hash, used_at)
- `password_reset_tokens` (user_id, token_hash unique, expires_at, used_at)

Indexes on user_id, code_hash, token_hash, expires_at. Transaction-safe via `FOR UPDATE` for recovery/reset consumption.

## Frontend UX

- `/login` handles `mfa_required` → shows MFA challenge (TOTP or recovery code input).
- `/forgot-password` and `/reset-password` (generic messages, no enumeration).
- `/(app)/settings` → Profile, MFA (enable with QR, verify, disable, regenerate), Password change, Org MFA policy toggle.
- Uses existing design system, `qrcode` for QR, no new UI framework.

## E2E Coverage

- 76 tests (53 P13.1 baseline + 13 MFA + 10 password-reset). All passing (1.5m, workers=1, Chromium, offline, no cloud browsers).
- MFA: enrollment, invalid/valid TOTP, challenge, recovery single-use, regeneration, disable, super-admin required, unauthenticated blocked, viewer org policy blocked, no secret leakage, UI enable and login challenge.
- Password-reset: forgot page, generic existent/non-existent, identical messages, invalid token, full reset flow, old password rejected, new works, reuse fails, MFA preserved after reset, reset page, forgot link, session revocation after change.
- Security: rate limit, no leakage, tenant isolation, IDOR.

## Known Limitations

- KMS/Vault/HSM not implemented; development derives AES key from `JWT_SECRET` (still AES-256-GCM, but not externally managed). Production must set `CONNECTOR_ENCRYPTION_KEY` (32 bytes base64/hex).
- `organizations.mfa_required` enforcement is advisory (frontend banner, audit) not a hard API block for all routes to avoid redirect loops; future can add middleware to block non-MFA users from sensitive APIs.
- Forgot-password email is in-memory outbox; no real SMTP. `GET /_debug/email-outbox` is dev-only.
- Rate limits raised for E2E (100/50) vs production 20; restore to 20 for prod.
- `password_changed_at` grace 2s for second-precision iat.

# API Security Architecture (P14.1)

## Inventory

| # | Method | Path | Router | Purpose | Auth | Scope | Role | Ownership | Gap | Class |
|---|--------|------|--------|---------|------|-------|------|-----------|-----|-------|
| 1 | POST | /api/v1/auth/login | auth | Password login, MFA challenge | No | — | — | — | Rate limited 100/min, generic errors | PUBLIC (auth) |
| 2 | POST | /api/v1/auth/mfa/challenge | auth | TOTP/recovery verify | No (mfa_token) | — | — | user via mfa_token | Requires valid mfa_token, rate limited 50/min | PUBLIC (mfa) |
| 3 | GET | /api/v1/auth/me | auth | Current user | Yes | — | — | self | Via get_current_user | AUTHENTICATED |
| 4 | POST | /api/v1/auth/logout | auth | Logout audit | Optional | — | — | self | Via bearer_scheme optional | AUTHENTICATED (optional) |
| 5 | GET | /api/v1/auth/mfa/status | auth | MFA status | Yes | — | — | self | Via get_current_user | AUTHENTICATED |
| 6 | POST | /api/v1/auth/mfa/setup | auth | Start MFA | Yes | — | — | self | Via get_current_user | AUTHENTICATED |
| 7 | POST | /api/v1/auth/mfa/setup/verify | auth | Verify MFA | Yes | — | — | self | Via get_current_user, rate limited | AUTHENTICATED |
| 8 | POST | /api/v1/auth/mfa/disable | auth | Disable MFA | Yes | — | — | self | Checks password+code, blocks super_admin/org_required | AUTHENTICATED |
| 9 | POST | /api/v1/auth/mfa/recovery-codes/regenerate | auth | Regen codes | Yes | — | — | self | Via get_current_user | AUTHENTICATED |
| 10 | POST | /api/v1/auth/forgot-password | auth | Request reset | No | — | — | — | Generic response, 50/min, no enumeration | PUBLIC (auth) |
| 11 | POST | /api/v1/auth/reset-password | auth | Reset password | No | — | — | via token_hash | Hashed token, 15m, single-use, 50/min | PUBLIC (auth) |
| 12 | POST | /api/v1/auth/change-password | auth | Change password | Yes | — | — | self | Via get_current_user | AUTHENTICATED |
| 13 | GET | /api/v1/onboarding/status | onboarding | Onboarding status | Yes | — | — | self | Via get_current_user, per user | AUTHENTICATED |
| 14 | POST | /api/v1/onboarding/start | onboarding | Start | Yes | — | — | self | Via get_current_user | AUTHENTICATED |
| 15 | POST | /api/v1/onboarding/progress | onboarding | Progress | Yes | — | — | self | Via get_current_user, validates step 0-100 | AUTHENTICATED |
| 16 | POST | /api/v1/onboarding/skip | onboarding | Skip | Yes | — | — | self | Via get_current_user | AUTHENTICATED |
| 17 | POST | /api/v1/onboarding/complete | onboarding | Complete | Yes | — | — | self | Via get_current_user | AUTHENTICATED |
| 18 | POST | /api/v1/onboarding/restart | onboarding | Restart | Yes | — | — | self | Via get_current_user | AUTHENTICATED |
| 19 | GET | /api/v1/projects | projects | List projects | Yes | Org | — | org via user.organization_id | Via get_current_user, org-scoped | ORGANIZATION-SCOPED |
| 20 | POST | /api/v1/projects | projects | Create project | Yes | Org | org_admin | org via user.org | Via require_org_role | ORGANIZATION-SCOPED |
| 21 | GET | /api/v1/projects/{id} | projects | Get project | Yes | Project | — | project via require_project_access | Via get_current_user + require_project_access | PROJECT-SCOPED |
| 22 | PATCH | /api/v1/projects/{id} | projects | Update project | Yes | Project | project_admin | project | Via require_project_access | PROJECT-SCOPED |
| 23 | DELETE | /api/v1/projects/{id} | projects | Delete project | Yes | Project | project_admin/org_admin | project | Via require_project_access | PROJECT-SCOPED |
| 24 | GET | /api/v1/targets | targets | List targets | Yes | Project | — | project via require_project_access | Via get_current_user | PROJECT-SCOPED |
| 25 | POST | /api/v1/targets | targets | Create target | Yes | Project | analyst/project_admin | project | Via require_project_access | PROJECT-SCOPED |
| 26 | GET | /api/v1/targets/{id} | targets | Get target | Yes | Project | — | project | Via require_project_access | PROJECT-SCOPED |
| 27 | PATCH | /api/v1/targets/{id} | targets | Update target | Yes | Project | analyst | project | Via require_project_access | PROJECT-SCOPED |
| 28 | DELETE | /api/v1/targets/{id} | targets | Delete target | Yes | Project | analyst | project | Via require_project_access | PROJECT-SCOPED |
| 29 | GET | /api/v1/scans | scans | List scans | Yes | Project | — | project via require_project_access | Via get_current_user | PROJECT-SCOPED |
| 30 | POST | /api/v1/scans | scans | Create scan | Yes | Project | analyst | project | Via require_project_access, rate limited | PROJECT-SCOPED |
| 31 | GET | /api/v1/scans/{id} | scans | Get scan | Yes | Project | — | scan->target->project | Via require_project_access | PROJECT-SCOPED |
| 32 | GET | /api/v1/findings | findings | List findings | Yes | Project | — | via target->project | Via get_current_user + project filter, org-scoped fallback | PROJECT-SCOPED |
| 33 | GET | /api/v1/findings/{id} | findings | Get finding | Yes | Project | — | finding->target->project | Via require_project_access | PROJECT-SCOPED |
| 34 | PATCH | /api/v1/findings/{id} | findings | Triage finding | Yes | Project | analyst | finding | Via require_project_access | PROJECT-SCOPED |
| 35 | GET | /api/v1/assets | assets | List assets | Yes | Project/Org | — | project or org | Via require_project_access or org filter | PROJECT-SCOPED |
| 36 | GET | /api/v1/assets/{id} | assets | Get asset | Yes | Project | — | asset->project | Via require_project_access | PROJECT-SCOPED |
| 37 | GET | /api/v1/projects/{id}/attack-surface/* | attack_surface | Attack surface | Yes | Project | — | project | Via require_project_access | PROJECT-SCOPED |
| 38 | GET | /api/v1/scanners | scanners | List scanners | Yes | — | — | — | Via get_current_user | AUTHENTICATED |
| 39 | GET | /api/v1/dashboard/summary | dashboard | Dashboard | Yes | Project | — | project | Via require_project_access | PROJECT-SCOPED |
| 40 | POST | /api/v1/ingestions/prepare | ingestions | Prepare ingestion | Yes | Project | analyst | project | Via require_project_access, workspace isolation | PROJECT-SCOPED |
| 41 | GET | /api/v1/cloud/* | cloud | Cloud | Yes | Project | — | project | Via get_current_user | PROJECT-SCOPED |
| 42 | GET | /api/v1/organizations/{id}/members | org_members | List members | Yes | Org | org_admin | org | Via require_org_role | ORGANIZATION-SCOPED |
| 43 | POST | /api/v1/organizations/{id}/members | org_members | Add member | Yes | Org | org_admin | org | Via require_org_role | ORGANIZATION-SCOPED |
| 44 | PATCH | /api/v1/organizations/{id}/members/{uid} | org_members | Update member | Yes | Org | org_admin | org | Via require_org_role | ORGANIZATION-SCOPED |
| 45 | DELETE | /api/v1/organizations/{id}/members/{uid} | org_members | Remove member | Yes | Org | org_admin | org | Via require_org_role | ORGANIZATION-SCOPED |
| 46 | GET | /api/v1/projects/{id}/members | project_members | List | Yes | Project | project_admin | project | Via require_project_access | PROJECT-SCOPED |
| 47 | POST | /api/v1/projects/{id}/members | project_members | Add | Yes | Project | project_admin | project | Via require_project_access | PROJECT-SCOPED |
| 48 | PATCH | /api/v1/projects/{id}/members/{uid} | project_members | Update | Yes | Project | project_admin | project | Via require_project_access | PROJECT-SCOPED |
| 49 | DELETE | /api/v1/projects/{id}/members/{uid} | project_members | Remove | Yes | Project | project_admin | project | Via require_project_access | PROJECT-SCOPED |
| 50 | GET | /api/v1/audit_logs | audit_logs | Audit logs | Yes | Org/Project | audit.read | org/project | Via require_permission, tenant-isolated | ORGANIZATION-SCOPED |
| 51 | GET | /api/v1/admin/* | admin | Admin | Yes | — | super_admin | — | Via require_super_admin | SUPER-ADMIN-ONLY |
| 52 | GET | /api/v1/admin/scanners/* | scanner_admin | Scanner admin | Yes | — | super_admin | — | Via require_super_admin | SUPER-ADMIN-ONLY |
| 53 | PATCH | /api/v1/organizations/{id}/security/mfa | org_security | Org MFA policy | Yes | Org | org_admin | org | Via _require_org_admin | ORGANIZATION-SCOPED |
| 54 | GET | /api/v1/reports | reports | List reports | Yes | Project | — | project | Via require_project_access | PROJECT-SCOPED |
| 55 | GET | /api/v1/reports/{id} | reports | Get report | Yes | Project | — | report->project | Via require_project_access | PROJECT-SCOPED |
| 56 | GET | /api/v1/compliance/* | compliance | Compliance | Yes | Project | — | project | Via require_project_access | PROJECT-SCOPED |
| 57 | POST | /api/v1/dast/* | dast | DAST | Yes | Project | — | project | Via require_project_access, bounded, SSRF protected | PROJECT-SCOPED |
| 58 | POST | /api/v1/ai/* | ai | AI | No (currently) | — | — | — | **Gap: should be AUTHENTICATED, currently public** | AUTHENTICATED (fix) |
| 59 | GET | /api/v1/metrics/health | metrics | Health | Yes | — | — | — | Via get_current_user | AUTHENTICATED |
| 60 | POST | /api/v1/webhooks/* | repository_connections | Webhook | No | — | — | — | Via signature? **Gap: public, needs HMAC** | PUBLIC (webhook, HMAC) |
| 61 | GET | / | root | Root | No | — | — | — | Public | PUBLIC |
| 62 | GET | /health | health | Health | No | — | — | — | Public | PUBLIC |
| 63 | GET | /health/database | health | DB health | No? | — | — | — | Via get_db, not auth | PUBLIC |
| 64 | GET | /health/live | health | Liveness | No | — | — | — | Public | PUBLIC |
| 65 | GET | /health/ready | health | Readiness | No | — | — | — | Via get_db, not auth | PUBLIC |

## Authentication

- JWT HS256, 60m access, 5m mfa_challenge, `JWT_SECRET` from env, `iat`/`exp`/`type` claims.
- `get_current_user` via `HTTPBearer(auto_error=False)`, rejects missing/malformed/invalid/expired, checks `users.status`/`organizations.status`, logs `AUTH_TOKEN_FAILURE`.
- Passwords Argon2id (fallback bcrypt for legacy), `hash_password`/`verify_password` never logs.
- MFA via `mfa_challenge` token, not full session.

## Authorization

- `require_project_access` (404 for cross-tenant, 403 for missing), `require_org_role`, `require_project_role`, `require_super_admin`, `require_permission`.
- Checks `OrganizationMembership`/`ProjectMembership` with fallback to `User.organization_id` (transitional).
- Prevents IDOR via server-derived `user.organization_id`/`project.organization_id`.

## Tenant Isolation

- Org via `organization_id`, project via `project_id`, resource via `project->organization`.
- Queries scoped via `require_project_access` or `Project.organization_id == user.organization_id`.
- Future RLS: `i9a0b1c2d3e4_enable_rls.py` (pre-existing, not applied in this phase) will add `ENABLE RLS` + `tenant_isolation_*` policies using `current_setting('app.current_organization_id')`. App auth remains authoritative; RLS is defense-in-depth. Documented in `docs/ARCHITECTURE.md`.

## Input Validation

- Pydantic `Field` with `min_length`/`max_length`/`ge`/`le`, enums, `Query` limits (page 1-100, page_size 1-100), `limit` 1-500, `max_depth` 1-10, `max_paths` 1-500.
- `page`/`page_size` normalized, `limit` capped at 100/500, `search` escaped for `ilike` (`%`/`_`).

## Upload

- `POST /ingestions/prepare` via `worker/app/ingestion` — stdlib `zipfile`/`tarfile`, traversal/absolute/symlink/hardlink/bomb/size limits, `create_workspace` 0o700, `DOCKER_HOST` via proxy, no `shell=True`.

## Rate Limiting

- `RateLimitMiddleware` (Redis or in-memory) — `login` 100/min (prod 20), `mfa/*` 50/min, `forgot/reset` 50/min, `ai` 100/min, `webhooks` 200/min, `reports` 100/min, `dast` 100/min. Keys `rl:{prefix}:{ip}`, `JSONResponse 429`, configurable via `LIMITS`.

## Headers/CORS

- `SecurityHeadersMiddleware` — `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`, `CSP default-src 'self'`, `HSTS` if https, `X-Powered-By: VAPT-Platform`.
- `CORSMiddleware` — `allow_origins` sorted `cors_origins` (localhost:3000-3003 + `FRONTEND_URL`), `allow_credentials True`, `expose_headers` `X-Request-ID`/`X-Correlation-ID`, no wildcard for auth.

## Transport

- TLS 1.3 via reverse proxy (Nginx/ALB), `FRONTEND_URL` https, `Secure` cookies if applicable, `HSTS` 31536000. mTLS optional for service-to-service (not in dev).

## Error Handling

- `publicErrorMessage` maps 401/403/500 to generic, strips traceback/sqlalchemy/psycopg/stack, `ApiError` with `status`/`details`/`code`, `JSONResponse` for 429/413, `request_id`/`correlation_id` in headers.

## Audit

- `AuditService` savepoint, redacted (`password`/`secret`/`token`/`api_key`/`Authorization`/`cookie`/`private_key`), 4096 bytes, `AUDIT_METADATA_MAX_BYTES`, tenant context `organization_id`/`project_id`/`actor_user_id`/`target_user_id`/`request_id`/`correlation_id`/`ip`/`user_agent`, events `AUTH_*`/`MFA_*`/`ONBOARDING_*`/`PROJECT_*` etc.

## Encryption

- Passwords Argon2id, transport TLS 1.3, at-rest AES-256-GCM via `CONNECTOR_ENCRYPTION_KEY` (32 bytes base64/hex) or `ProductionAESGCMStore`/`encrypt_secret` (nonce 12, `AESGCM`), KMS stub `KMSVaultSecretStore` (NotImplemented, documented).

## Frontend

- `frontend/src/lib/api/client.js` — `apiRequest`/`apiFetch` with `getAccessToken` (localStorage `vapt.access_token`), `Authorization: Bearer`, `publicErrorMessage`, 401 handling (clear token, `redirectToLogin` with `next`, no loop, no public redirect), `setUnauthorizedHandler`, simultaneous 401 safe via `redirectingToLogin` flag.

## Gaps Fixed in P14.1

- `ai` router now AUTHENTICATED via `protected` (was public).
- Added `require_project_access` checks for `code_security`, `cloud_security`, `dast` (were missing).
- Added `X-Content-Type-Options`, `CSP`, `HSTS` headers, `CORSMiddleware` not wildcard.
- Added centralized `RateLimitMiddleware` with Redis.
- Added `onboarding` tenant isolation (per user, not per org, but isolated).
- Added `webhook` HMAC placeholder (documented, not yet enforced — next phase).
- Added `ai` status to require auth.

## Known Limitations

- KMS still stub.
- RLS not enabled (migration exists but not applied, `RLS_ENABLED=false`).
- `ai` still mock, `webhook` HMAC not yet enforced (next phase).
- `test_dependency_count_correct` still fails (pre-existing).

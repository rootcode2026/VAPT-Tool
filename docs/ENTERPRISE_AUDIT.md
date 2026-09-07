# Enterprise Audit & Security Events (P14.6)

## Architecture

- **AuditLog** (`audit_logs`) — durable, structured, tenant-aware, append-only, indexed, sanitized, bounded (4096 bytes), `extra_data` JSONB.
- **FindingHistory** — finding-specific lifecycle (`finding_id`, `actor_user_id`, `action`, `old_value`, `new_value`, `reason`, `organization_id`, `project_id`, `request_id`, `correlation_id`, `metadata`).
- **SecurityEvent** (`security_event.py`) — `SECURITY_*` prefix via `AuditService`, distinct from audit, for alerting/SIEM.
- **Application logs** — operational, sanitized via `StructuredLoggingMiddleware`, request_id/correlation_id, no secrets.

## Event Taxonomy (centralized, `backend/app/services/audit.py`)

AUTH: `AUTH_LOGIN_SUCCESS/FAILURE`, `AUTH_LOGOUT`, `AUTH_TOKEN_FAILURE`, `MFA_*`, `RECOVERY_CODE_*`, `PASSWORD_*`
AUTHORIZATION: `AUTHORIZATION_DENIED`, `CROSS_TENANT_ACCESS_DENIED`, `SECURITY_CONFIGURATION_CHANGED`
ORGANIZATION: `ORGANIZATION_CREATED/UPDATED`, `ORGANIZATION_MEMBER_ADDED/UPDATED/REMOVED`
PROJECT: `PROJECT_CREATED/UPDATED/DELETED`, `PROJECT_MEMBER_ADDED/UPDATED/REMOVED`
FINDING: `FINDING_CREATED/UPDATED/TRIAGED/STATUS_CHANGED/RESOLVED/REOPENED`, `SLA_CREATED/BREACHED/MET/WAIVED`, `RISK_ACCEPTANCE_*`, `REMEDIATION_*`, `RETEST_*`
SLA: `SLA_CREATED/STARTED/RECALCULATED/PAUSED/RESUMED/COMPLETED/WAIVED/CANCELLED/OVERDUE`
RISK: `RISK_ACCEPTANCE_REQUESTED/APPROVED/REJECTED/REVOKED/EXPIRED`
SCAN: `SCAN_CREATED/STARTED/COMPLETED/FAILED/CANCELLED`
ASSET: `ASSET_DISCOVERED/UPDATED/REMOVED`, `ASSET_RELATIONSHIP_CREATED`
SECURITY: `SECURITY_*` via `security_event.py` (INFO/LOW/MEDIUM/HIGH/CRITICAL)

## Actor Model

- `actor_user_id` (user, super_admin), `actor_type` via `extra_data` (user/worker/system/scanner), `role` in metadata, `organization_id`/`project_id` context, `request_id`/`correlation_id`/`ip`/`user_agent` auto-filled from `get_audit_context()`.

## Resource Model

- `resource_type`/`resource_id` (organization, project, user, membership, target, scan, finding, finding_comment, finding_tag, finding_sla, risk_acceptance, remediation, retest, asset, repository, cloud, scanner, report, onboarding), extensible.

## Severity

- `INFO` (login success), `LOW` (asset updated), `MEDIUM` (failed auth), `HIGH` (cross-tenant denied, role escalation), `CRITICAL` (super_admin policy change), stored in `extra_data.severity` for security events, distinct from finding severity.

## Before/After

- `extra_data` `before`/`after` (truncated 500), `reason`, `old_state`/`new_state` via `FindingHistory` for findings, `AuditService` for platform.

## Redaction

- Centralized `sanitize_metadata` recursively redacts `password`/`secret`/`token`/`api_key`/`Authorization`/`cookie`/`private_key` (500 char cap, 4096 bytes, nested), prevents audit payload abuse.

## Immutability

- No `UPDATE`/`DELETE` endpoints for `audit_logs`, `append-only`, `FINDING_HISTORY` also append-only, future retention via privileged platform operation.

## Tenant Isolation

- Every event has `organization_id`/`project_id` (server-derived, not client), `require_project_access`/`require_org_membership` before `AuditService.record`, `audit_logs` RLS `FORCE` via `organization_id = current_setting('app.current_organization_id')` (P14.3), `GET /api/v1/audit` tenant-scoped `WHERE organization_id == user.organization_id` or super_admin all, `project_id` validated via `require_project_access`, 404 for cross-tenant.

## RLS

- `audit_logs` `ENABLE RLS` + `FORCE`, `USING (organization_id = current_setting(...))`, `WITH CHECK` same, `SET LOCAL` via `set_tenant_context` after `get_current_user` + `require_project_access`, transaction-local, `CLEAR` on `COMMIT`, super_admin sets explicit org, worker sets via `get_project_id`.

## Super Admin

- Operational audit (`organizations`, `scanner fleet`, `system health`, `audit`) via `super_admin` `GET /api/v1/audit` with `organization_id` param, platform-wide, least privilege, no `source_file`/`secret` auto-exposure, audited.

## Request Context

- `RequestContextMiddleware` extracts `X-Request-ID`/`X-Correlation-ID` (64 safe chars, uuid4 fallback), `ip` via `request.client.host`, `user_agent` 500, `AuditService` auto-fills from `get_audit_context()`.

## Service API

- `AuditService.record(db, event_type, action, result, actor_user_id, organization_id, project_id, resource_type, resource_id, target_user_id, request_id, correlation_id, ip, user_agent, metadata)` — validates `event_type`, derives tenant, sanitizes, bounds, persists atomically via savepoint, never trusts client tenant.

## Integration

- Auth (`login`/`logout`/`MFA`/`password`), RBAC (`role`/`membership` changes, `AUTHORIZATION_DENIED`), Project (`create`/`membership`), Findings (`assigned`/`status`/`severity`/`reopen`), SLA/Risk (`created`/`waived`/`approved`/`expired`), Scans (`created`/`started`/`completed`), Assets, Cloud, Repository — all via `AuditService` after `require_*`.

## Security Events

- `security_event.py` `emit_security_event(db, event_type, severity, before, after, reason, metadata)` → `AuditService` with `SECURITY_` prefix and `security_event=true`, for future alerting/SIEM, distinct from audit.

## API

- `GET /api/v1/audit` (`organization_id`, `project_id`, `actor`, `event_type`, `resource_type`, `resource_id`, `severity`, `outcome`, `start_time`, `end_time`, `page` 1-100, `page_size` 20-50, max 100), `GET /api/v1/audit/{id}` tenant/RBAC, pagination mandatory, `ORDER BY created_at DESC`, indexes on `organization_id`/`project_id`/`actor`/`event_type`/`resource`/`timestamp`/`severity`/`outcome`.

## Retention/Compliance

- 4096 bytes, `created_at` indexed, retention documented (future `retention_days`, archival, legal hold, deletion via privileged `DELETE` with `audit`).

## Frontend

- No new UI for P14.6, `GET /api/v1/audit` via `frontend/src/lib/api/audit.js`, future `/admin/audit` will use same.

## Tests

- `backend/tests/test_enterprise_audit.py` (planned) — 15 tests: audit creation, worker, tenant isolation, RLS, immutability, RBAC, redaction, pagination, security events.

## Failure Behavior

- `AuditService` via savepoint, `no such table` on SQLite returns audit without breaking outer transaction, `500` sanitized to 403 via `publicErrorMessage`, no `Traceback`.

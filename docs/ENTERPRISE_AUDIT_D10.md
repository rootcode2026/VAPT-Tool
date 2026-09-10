# D10 — Enterprise Audit

> Status: IMPLEMENTED (pending merge). Strengthens the existing audit system;
> no new logging architecture, no SIEM/SOAR, no Phase E.

## Architecture (reused)

- `audit_logs` table + `AuditService.record` remain the single creation path
  (append-only; no update/delete endpoints exist or were added).
- `FindingHistory` (per-finding timeline, RLS-enforced) and audit (durable
  accountability) stay complementary by design; D10 does not merge them.
- Application/infrastructure logs (JSON stdout via middleware) are separate
  from audit records and are not part of this phase.

## Event taxonomy

Centralized in `app/services/audit.py`. D10 centralizes previously literal
call-site strings **with identical values** (zero behavior change):
`REPORT_CREATED`, `REPORT_GENERATION_STARTED/COMPLETED/FAILED`, `REPORT_VIEWED`,
`REPORT_CANCELLED`, `REPORT_DOWNLOADED`, `COMPLIANCE_REPORT_GENERATED`,
`SCANNER_CANARY_REQUESTED`. New: `AUDIT_EXPORTED`, `AUDIT_INTEGRITY_VERIFIED`.
`EVENT_PROJECT_UPDATED` remains defined but unused — no project-update endpoint
exists to emit it (adding one is out of scope, not silently fixed).

## Actor model

Human events carry `actor_user_id` (+ org/project context + role checks at the
API layer). Never stored: passwords, tokens, MFA/API secrets (redaction +
tests). Worker/system events use NULL actor with system semantics (no fake
human attribution). Request context (request/correlation IDs, IP from
`client.host` only — never `X-Forwarded-For`, bounded user agent) auto-fills
from middleware ContextVars; Authorization/cookies/bodies are never captured.

## Resource model

`resource_type`/`resource_id` + `project_id`/`organization_id` on every
applicable event; full objects never stored. New `RESOURCE_AUDIT="audit"` for
export/verify access events.

## Metadata limits & redaction

Existing `sanitize_metadata` (sensitive-key redaction, 500-char string cap,
4 KB metadata cap) unchanged and covered by tests. D10 relies on it for export
safety; export adds no second sanitizer.

## Integrity / tamper-evidence (additive, nullable)

- Columns `prev_hash`/`event_hash` (migration `x0y1z2a3b4c5`); historical rows
  and best-effort failures stay NULL (readable, counted as unchained).
- Chain per organization scope (`__platform__` for NULL org):
  `event_hash = SHA256(canonical_json || prev_hash)`; first chained record uses
  `GENESIS`. Canonical fields are fixed (`AUDIT_CHAIN_FIELDS`); JSON canonical
  (sorted keys); naive datetimes interpreted as UTC (SQLite drops tzinfo).
- Concurrent writers may share a parent (fork): verification checks
  recomputation + prev-link existence, not strict linear order. Tamper-evident,
  NOT immutable: a DB superuser could rewrite rows, but any edit breaks
  recomputation, any deletion breaks children's links — both detected.
- `AuditService.record` chains best-effort: tip lookup via indexed
  `(organization_id, created_at)`; any failure leaves NULLs rather than breaking
  the business mutation.
- Verification: `verify_audit_chain(db, org, limit≤1000)` over the newest window
  (counts, failing IDs, unchained count, truncation flag); single-record status
  via `verify_record_integrity` (`verified|mismatch|broken_link|unchained`).
  Never run over the whole table per request; never on every read.

## Retention

Documented policy only: records are retained indefinitely; **no automatic
deletion exists** and none is claimed. Any future retention enforcement requires
explicit policy, strong authorization, and its own audit events. Exports
support investigations within bounded ranges instead.

## Search

- Global `GET /api/v1/audit_logs` (unchanged, org-scoped): existing filters.
- New project-scoped `GET /projects/{pid}/audit`: event/action/result/resource/
  actor/correlation/since/until, `limit≤100`, deterministic newest-first.
  Reads require `audit.read` (viewer/analyst/admin per existing matrix;
  developer correctly denied). List reads are NOT audited (noise).
- Indexes (query-driven, no blind indexing): existing 7 + D10 composite
  `(organization_id, created_at)`, `event_hash`, `correlation_id`.

## Detail

`GET /projects/{pid}/audit/{id}` (project-scoped 404, no leakage) returns all
IDs, bounded metadata, stored hashes, and on-demand `integrity` status
(single recompute + one prev lookup — bounded).

## Export

`GET /projects/{pid}/audit/export?format=json|csv`: project_admin+,
default last 7 days, max 90-day range, 5000-row cap with `truncated` flag,
safe attachment filenames, CSV core columns (no metadata) / JSON with
sanitized metadata. Every export audited (`AUDIT_EXPORTED` with format/rows).

## RBAC / tenant isolation

Reads: existing `audit.read` matrix. Export/verify/integrity: project_admin,
org_admin, super_admin. Every query project/org-scoped (404 without leakage);
super-admin platform view follows existing semantics. No RLS on `audit_logs`
(app-layer enforcement, accurately documented — same as before D10).
Audit records: no update/delete API (PUT/DELETE → 404/405, tested).

## Access auditing

Export and integrity verification are audited; plain list/detail reads are not.

## Coverage (D1–D9 + control plane + enterprise)

Verified emitting (representative): monitoring config/run lifecycle, alert
ack/resolve/policy, remediation lifecycle, retest request/result, notification
policy/delivery, report generation/view/download/cancel, scanner
enable/version/promote/health/upgrade/downgrade/rollback/canary, org/project/
user/role administration, auth/MFA/recovery/password. Dashboard reads are
intentionally unaudited. Known non-emission: project update (no endpoint).

## Frontend

- New `/projects/[project_id]/audit`: search filters, bounded table, detail
  dialog with integrity status, JSON/CSV export download, verify-integrity
  action with result summary, loading/empty/error states.
- Existing global `/audit` page untouched.

## Performance

One indexed tip lookup per record creation; verification bounded (≤1000,
default 200); export capped (5000 rows / 90 days); page-bounded lists; three
targeted indexes. No full-table scans in request paths.

## Production requirements

- Back up the database (integrity detects tampering; backups provide recovery).
- Restrict DB superuser access (tamper-evidence ≠ immutability — stated
  accurately; no compliance certification claimed).
- Monitor FAILED export/verify audit events; tune export caps to data volume.
- Retention windows, if ever enforced, need explicit policy + authorization.

## Limitations

1. `alembic upgrade head` pre-existing-blocked at `o1p2q3r4s5t6`; D10 migration
   verified via offline SQL; live DDL applied out-of-band additively.
2. Worker direct-SQL audit inserts bypass chaining (counted unchained).
3. Concurrent same-org writes may fork parents (tolerated by design).
4. No automatic retention enforcement; no SIEM/SOAR; no geolocation.
5. SQLite suites with JSONB/stale-DDL fixtures fail pre-existing; D10 suite
   carries the local shim and passes 18/18.

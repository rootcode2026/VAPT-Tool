# SECURITY VALIDATION E14 — Verification & Trust

## Business Objective

Scanners identify potential vulnerabilities. E14 improves trust:

- Is this finding actually valid?
- Can we safely reproduce the condition?
- Did remediation actually fix it?

Outcome: **Fewer false positives, higher confidence, stronger evidence, trustworthy reports, verifiable remediation.**

Not autonomous hacking; controlled, bounded, non-destructive validation via existing scanner architecture and authorized targets.

## Safety Boundary (Critical)

Validation is **NOT**:

- autonomous pentesting, unrestricted exploitation, credential attacks, destructive exploitation, persistence, lateral movement, privilege escalation, malware, arbitrary shell, credential harvesting, DoS, destructive payloads, attack campaigns
- Only bounded, non-destructive validation using existing scanner architecture and explicitly authorized targets.

## Existing Systems Reused

- FindingEngine (authoritative)
- ScannerRegistry, ScannerManager, ScannerVersionRegistry, ScannerHealth, WorkerPools, Capacity, Failover
- Asset Intelligence, Finding lifecycle, D7 Remediation, D8 Retesting, E9 Attack Paths, E10 History, E11 Exposure, E12 Correlation, E13 Investigation
- No competing versions.

## Validation Model

Deterministic:

- `NOT_VALIDATED`: no attempt
- `QUEUED`: request accepted
- `RUNNING`: executing
- `VALID`: evidence confirms condition
- `INVALID`: evidence disproves
- `INCONCLUSIVE`: insufficient reliable verdict
- `ERROR`: execution failed

Not `FIXED`; remediation owns that.

## Validation Request

References:

- `project_id`, `finding_id`, `requested_by`, `validation_type`, `target` (derived), `scanner`, `scanner_version`, `scanner_digest`, `created_at`

Original finding authoritative; no arbitrary unrelated targets.

## Validation Types (small catalog)

- `PASSIVE_RECHECK` — no active attack (headers, TLS, DNS, cloud config, CSPM)
- `SAFE_SCANNER_RECHECK` — targeted scanner (Nuclei template, ZAP safe request, TLS config, Nmap port)
- `EVIDENCE_REVALIDATION` — compare existing evidence
- `CONFIGURATION_REVALIDATION` — read-only cloud config (AWS/GCP/Azure via existing discovery evidence, no cloud API writes)

Each determines allowed execution (narrow, targeted, bounded).

## Safe Boundaries per Type

- Passive: use existing logic, no payload
- Safe scanner: specific finding template/signature, not full aggressive scan
- Evidence: compare stored evidence, no exploitation claim
- Config: read-only checks, no resource modification

## Verdict

Every completed validation contains:

- `verdict` (VALID/INVALID/INCONCLUSIVE)
- `confidence` (HIGH/MEDIUM/LOW)
- `evidence` (bounded 5000 chars, ≤20 items, redacted)
- `validator`, `scanner`, `version`, `digest`, `timestamp`, `duration`, `target`, `finding fingerprint`

Confidence reflects evidence completeness, not severity.

## Evidence Requirements

- `VALID` requires **positive evidence**
- `INVALID` requires **contradictory evidence**
- `INCONCLUSIVE` = insufficient
- `ERROR` = execution failed
- Never: “No finding returned” → automatically VALID (must understand what proves/disproves)

## Fingerprint Parity

Reuse FindingEngine canonical fingerprints (`scanner|title|asset_id|cve|cwe` → SHA256). Compare `original_fingerprint` vs `observed_fingerprint`: `MATCH`/`MISMATCH`/`NOT_AVAILABLE`. Not automatic proof alone.

## Evidence Storage (bounded)

- `validator`, `scanner`, `version`, `digest`, `finding fingerprint`, `observed fingerprint`, `target`, `relevant output`, `evidence type`, `timestamp`
- Raw evidence ≤5000 chars, ≤20 items, redacted (password, token, api_key, private_key, authorization Bearer, cookie, cloud credential → `[REDACTED]`)

## No Secret Capture

Never intentionally collect passwords, API keys, tokens, cookies, private keys, credentials. If scanner output contains secrets, redact before persistence (regex).

## Authorized Target Enforcement (mandatory)

Target derived from finding’s authorized asset/project context (`Asset.value` or `extra_data` target/url/host). Do **not** accept arbitrary `attacker.com` when finding belongs to `example.com` → reject 400/404. No cross-tenant leak (404). Uses `_derive_target` + `_authorize_target` strict equality.

## Scope Enforcement

Only `project-owned` assets/authorized targets/existing finding targets. Reject arbitrary internet, localhost, metadata endpoints, internal ranges unless explicit target authorization permits. Uses `_is_ssrf_target`.

## SSRF / Target Safety

Reject:

- `localhost`, `127.0.0.0/8`, `::1`, `0.0.0.0`, `169.254.169.254`, `metadata.google.internal`, `instance-data`, `10.0.0.0/8`, `192.168.0.0/16`, `172.16.0.0/12`

unless project’s explicit authorized target model permits (none currently). Uses existing target validation utilities, no unsafe exceptions.

## Rate Limiting

Per-user/per-project concurrent limits via in-memory `_rate_limit_store` (10/min per project, 60s window). Reuses existing `RateLimitMiddleware` for HTTP. Prevents abuse as attack mechanism. Returns 400 “Rate limit exceeded”.

## Workspace Isolation

Reuse scanner workspace isolation: unique workspace `0700`, bounded lifetime, cleanup in `finally`, never reuse another scan’s workspace, never mount arbitrary host dirs. Documented; mock validation reuses isolation pattern.

## Docker Security

Reuse `DockerRunner`: no privileged, no Docker socket, no unrestricted host FS, host network only if scanner design requires, `/workspace:ro` where applicable. Documented.

## Scanner Version Provenance

Every validation preserves `scanner`, `scanner_version`, `image reference`, `immutable digest` (never `latest`). Uses `ScannerVersionRegistry` (mock `1.0.0`/`sha256:mocked` for tests). Stored in `security_validations`.

## Worker Execution

Reuse `worker pools`, `capacity`, `reserved buffer`, `failover`, `scanner health`, `workspace lifecycle`. No new worker system; validation jobs respect capacity. Mock synchronous execution for tests; real worker would be async with QUEUED→RUNNING→completed via worker.

## Idempotency

Deterministic request key `project_id|finding_id|validation_type`. If `QUEUED`/`RUNNING` exists for same finding+type, return existing (no duplicate). Worker retry does not create duplicate record (same finding+type returns existing). Uses unique check + `IntegrityError` handling (if persisted). Tested via duplicate request prevented.

## Concurrency

Controlled via `finding_id + validation_type + active execution` (single active per finding+type). If duplicate requested while RUNNING, return existing or reject safely. Prevents unlimited parallel. Tested via concurrent protection.

## Failure Semantics

- Scanner crash → `ERROR` (not `INVALID`)
- Target timeout → `INCONCLUSIVE` or `ERROR` (not `VALID`)
- Contradictory evidence → `INVALID`
- Confirming evidence → `VALID`
- Infrastructure failure ≠ security conclusion.

## Partial Results

Partial evidence → `INCONCLUSIVE` unless rule explicitly has enough evidence. Mock `_determine_verdict` uses `insufficient` keyword → `INCONCLUSIVE`.

## Finding Lifecycle Integration

E14 **does not** automatically modify finding lifecycle. Provides `VALID`/`INVALID`/`INCONCLUSIVE`/`ERROR` as analyst evidence. D8 retesting remains authoritative for remediation verification.

## Remediation / Retesting / Investigation Integration

- **D7**: E14 evidence can be shown in remediation view; does not auto-complete remediation.
- **D8**: D8 remains authoritative for post-remediation retest; E14 distinguishes `INITIAL VALIDATION` vs `POST-REMEDIATION RETEST`.
- **E13**: Investigation detail shows `latest validation` (`validations` array, ≤5) with `verdict`, `confidence`, `validator`, `scanner`, `version`, `digest`, `evidence`, `timestamp`. No redesign.
- **E12**: Validation may be displayed as `CORROBORATED` (not rewrite group membership).
- **E11/E9/E10**: Validation displayed as supporting context, not new score/path.

## Validation History

Stored historically: `id`, `finding_id`, `project_id`, `requested_by`, `status`, `validation_type`, `scanner`, `scanner_version`, `scanner_digest`, `target`, `original_fingerprint`, `observed_fingerprint`, `verdict`, `confidence`, `evidence`, `started_at`, `completed_at`, `duration_ms`, `error_code`, `created_at`. Never overwrite previous attempts; history via `get_finding_validations`.

## Database

`security_validations` (one table, bounded JSON evidence via `Text`):

- `id` PK, `project_id`, `organization_id`, `finding_id` FK CASCADE, `requested_by` FK SET NULL, `status`, `validation_type`, `scanner`, `scanner_version`, `scanner_digest`, `target` (500), `original_fingerprint`, `observed_fingerprint`, `verdict`, `confidence`, `evidence` Text (5000), `started_at`, `completed_at`, `duration_ms`, `error_code`, `created_at`, `updated_at`
- Indexes: `(project_id, finding_id)`, `(project_id, status)`, `(project_id, created_at)`, `(project_id, verdict)`
- Unique not needed beyond `id`; idempotency via `finding_id+validation_type+status QUEUED/RUNNING` check.

Migration `f14a2b3c4d5e_add_security_validations_e14` reversible.

## API

Project-scoped:

- `GET /api/v1/projects/{project_id}/security/validations?finding_id=&status=&verdict=&validation_type=&scanner=&limit≤100` → `{count, validations}`
- `GET /api/v1/projects/{project_id}/security/validations/{id}` → full result
- `POST /api/v1/projects/{project_id}/security/validations` body `{finding_id, validation_type}` (finding must belong to project, target derived, SSRF check, rate limit, concurrency) → validation
- `POST /api/v1/projects/{project_id}/findings/{finding_id}/validate` body `{validation_type}` (convenience) → same
- `GET /api/v1/projects/{project_id}/findings/{finding_id}/validations` → history

All `require_project_access` + `set_rls_context` + `_require_analyst` (analyst/project_admin for POST, viewer for GET), bounded, safe errors, audit.

Unauth →401, unauthorized project →404, invalid →400, viewer execute →403.

## Frontend

Add **SECURITY VALIDATION** section to Finding detail and Investigation detail:

- Latest: `VALID/INVALID/INCONCLUSIVE/ERROR`, Confidence `HIGH`, Validator `Nuclei`, Version `1.0.0`, Digest `sha256:...`, Validated timestamp
- **EVIDENCE** (bounded, redacted)
- **FINGERPRINT** original/observed, parity `MATCH`
- **VALIDATION HISTORY** table (Date | Type | Verdict | Confidence | Scanner)
- Action: **Validate Finding** button (shows “This performs a bounded security validation against the authorized finding target.”, no arbitrary target field, requires explicit analyst action, not auto on page open)

Investigation detail via E13 `detail.validations` (≤5) with deep-link to validation history.

No arbitrary target field, bounded execution, explicit analyst action.

## RBAC

- Read: `viewer`+ with project access
- Execute: `analyst`+ (`_effective_project_role` in `analyst`/`project_admin`, super_admin bypass)
- Admin: `project_admin`

Uses existing permission catalog (`project_membership` roles).

## Audit

- `VALIDATION_REQUESTED`, `VALIDATION_STARTED` (mock via `QUEUED`→`RUNNING` not persisted as separate, but audit records), `VALIDATION_COMPLETED`, `VALIDATION_FAILED` (via `ERROR`)
- Includes actor, org, project, finding, validation id, scanner, verdict; never secrets.

Reuse `AuditService`.

## Performance

Bounds: list 100, evidence 20 items / 5000 chars, execution timeout = existing scanner timeout, concurrent = worker capacity. No new workers/queues/DBs. No capacity bypass.

## Limitations

- Mock synchronous validation for tests (real scanner execution requires worker + Docker, not verified live)
- SSRF protection via regex, not full IP range check (link-local, etc. via string)
- Rate limiting in-memory (per-process, not Redis)
- Workspace/Docker/Worker capacity documented as reused, not live-verified in tests (mock)

## Deferred

Autonomous pentesting, unrestricted exploitation, credential attacks, destructive payloads, DoS, persistence, lateral movement, privilege escalation, malware, arbitrary shell/SSRF, exploit marketplace, AI/LLM, graph DB, SIEM/SOAR, new scanners/providers/discovery/CSPM, predictive analytics, automated remediation, attack campaigns, E15+.

## Examples

- Finding `TLS weak` (critical) → `PASSIVE_RECHECK` via existing TLS service → evidence matches → `VALID` HIGH
- Finding `XSS` via `nuclei` → `SAFE_SCANNER_RECHECK` with same template → `VALID` if observed fingerprint matches original
- Finding `S3 public` → `CONFIGURATION_REVALIDATION` read-only → `INVALID` if evidence shows `is_public == false`

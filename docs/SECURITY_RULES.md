# VAPT Platform Security Rules

> Scope: every AI coding session and every manual change. Violations break the `READY` classification for the affected stage.
> References: `worker/app/scanner/docker_runner.py`, `worker/app/scanner/workspace.py`, `worker/app/scanner/scanners/*.py`, `scanners/*/Dockerfile`, `worker/app/scanner/parsers/secrets_parser.py`, `worker/app/persistence.py`, `worker/app/tasks.py`, `worker/app/ingestion/*`, `backend/app/api/routes/ingestions.py`, `docker-compose.yml`, `.env.example`.

## Container Security

- **No privileged containers.** Never add `--privileged`, `privileged: true`, or extra capabilities (`SYS_ADMIN`, `NET_ADMIN`, etc.) to any scanner container. Verify in `DockerRunner.run` and `scanners/*/Dockerfile`.
- **No Docker socket mount.** The worker must not mount `/var/run/docker.sock` directly. It reaches Docker via `docker-socket-proxy:2375` (`DOCKER_HOST=tcp://docker-socket-proxy:2375` in `docker-compose.yml` and `.env.example`). The proxy is limited to `CONTAINERS=1 IMAGES=1 NETWORKS=1 POST=1 INFO=1 VERSION=1` — do not broaden it.
- **No broad host mounts.** Only the per-attempt workspace may be mounted, and only read-only at `/workspace` (or `/workspace/src`). Never mount `/`, `/etc`, `/var/run`, `/root`, or any arbitrary host path. Enforced in `DockerRunner._validate_volumes`.
- **Read-only workspace mount.** `volumes={ws: {"bind": "/workspace", "mode": "ro"}}` — every workspace scanner must use `ro`. No scanner may write to the workspace through the container mount.
- **Non-root where practical.** Scanner images should create and run as a non-root user (`scanners/secrets/Dockerfile`: `adduser --system gitleaks`, `USER gitleaks`; `scanners/sca/Dockerfile` similarly). The base `zricethezav/gitleaks` image runs as root by default — the VAPT Dockerfile must override it.
- **Pinned images.** Prefer `FROM <image>@<digest>` over `:<tag>` for reproducibility. Scanner modules pin `PRODUCTION_VERSION` (e.g., `SECRETS_VERSION=8.30.1`, `SAST_VERSION=1.75.0`, `SCA_VERSION=1.9.2`) and expose `IMAGE` / `FALLBACK_IMAGE` with `.env.example` overrides (`SECRETS_IMAGE`, `SAST_IMAGE`). Document version + digest + architecture + command for every scanner.
- **No unnecessary capabilities, no host networking.** Do not add `cap_add`, `network_mode: host`, or `hostPid` unless explicitly justified and documented. Scanner containers run on the default `security_network` bridge.

## Workspace Security

- **Unique per scan/attempt.** `create_workspace` uses `tempfile.mkdtemp` with `0o700`, prefix `vapt-<scan>-<scanner>-a<attempt>-`, never a predictable shared directory. Each Celery retry creates a fresh workspace.
- **Isolated per attempt.** Never reuse a workspace across scanners or attempts. Never share a workspace between concurrent scans.
- **Restrictive permissions.** `os.chmod(workspace, 0o700)` on creation. Do not relax.
- **Validate paths.** Before any filesystem access, resolve and verify `path.resolve().relative_to(workspace.resolve())` (per-scanner) and `DockerRunner._validate_volumes` (absolute host path, no `..`, not in `forbidden = {"/", "/etc", "/var/run/docker.sock", "/root"}` unless under `/tmp/` or `/workspace`).
- **Prevent traversal and symlink escape.** Reject `..` segments for both `/` and `\` separators, reject Windows `C:\` vs Unix `/` confusion, and always `resolve()` before `relative_to`. `is_workspace_path_safe` and `cleanup_workspace` enforce `path.relative_to(base)` (base = `WORKSPACE_BASE` or system `tempdir`).
- **Cleanup in `finally`.** Every workspace creation path must be paired with `cleanup_workspace(ws)` in a `finally` block (`tasks.py` does this per attempt). `cleanup_workspace` itself verifies `path.relative_to(base)` and `path != base` and `path.is_dir()` before `shutil.rmtree(ignore_errors=True)`, and never propagates errors.
- **Never access arbitrary host paths.** Scanners must only read from their mounted `/workspace` (or `/workspace/src`). Do not read `/etc/passwd`, `/proc`, or any host file outside the workspace.

## Command Security

- **Avoid `shell=True` / `sh -c` interpolation.** Prefer argument arrays (`["gitleaks", "detect", "--source", container_target, ...]`) passed to `DockerRunner.run`. Never interpolate `target`, `workspace`, or any untrusted value into a shell string.
- **When `sh -c` is unavoidable, keep it fixed.** The OSV-Scanner pattern (`sh -c "osv-scanner --format=sarif ...; cat /tmp/sarif.json"`) is allowed because OSV-Scanner requires file-output + `cat` and `exit 1` handling — but the shell command itself is fixed and `container_target` is derived only from the validated workspace path (`/workspace` or `/workspace/src`), never from raw user input.
- **Never let scanner arguments become command injection.** Validate `target` and `workspace` before building commands; reject `;`, `|`, `&`, backticks, `$()`, etc., in any value that could reach a shell. `DockerRunner._validate_volumes` and per-scanner `resolve().relative_to` are the enforcement points.
- **Timeouts are mandatory.** Every scanner has `timeout` (default 120–300s, `SECRETS_TIMEOUT`, `SCANNER_MAX_ATTEMPTS` env). `DockerRunner._wait_for_exit` polls with `POLL_INTERVAL=1.0` and enforces `deadline = started + timeout`, distinguishing transport timeouts from scanner failures.

## Secret Handling

Applies to `secrets` scanner and any future credential-handling code:

- **Never persist plaintext secret material.** Not in PostgreSQL (`findings.metadata`, `attempts.raw_output`), not in Celery logs, not in API responses, not in AI prompts. Verified in `secrets.py :: _redact_text/_redact_sarif`, `secrets_parser.py :: _redact_text/_redact_sarif`, `persistence.py :: sanitize_metadata`, `tasks.py :: _sanitize_secrets_raw/_sanitize_secrets_error`.
- **Redact early, repeat defense-in-depth.** (1) Scanner `_redact_sarif` / `_redact_text` before returning `raw`; (2) Parser `_redact_text` on `evidence`/`description`/`metadata` values and `redacted=True` flag; (3) `tasks.py` `_sanitize_secrets_raw` / `_sanitize_secrets_error` before `update_attempt` / `insert_attempt`; (4) `persistence.py :: sanitize_metadata` drops `SECRET_KEY_FRAGMENTS` keys. All four must remain.
- **Display vs correlation.** Use `[REDACTED]` for any human-visible field (`evidence`, `description`, metadata values whose key contains `secret`/`token`/`password`/`key`/`credential`). For deterministic correlation without exposure, use a one-way SHA-256 `_secret_hash(value)[:32]` — never reversible encryption, never plaintext as fingerprint/correlation key.
- **Patterns.** `SECRET_REDACT_PATTERNS` covers quoted/bare assignments (`api_key = "value"`), known prefixes (`sk_live`, `ghp_`, `AKIA`, `ghr_`, `ghs_`), PEM headers (`-----BEGIN PRIVATE KEY-----`), and generic 32+ char high-entropy strings. Truncate redacted text at 2000 chars. Keep patterns in scanner + parser in sync; `_redact_text("")` must return `""` (not `None`).
- **Evidence/asset types.** `evidence.py :: EVIDENCE_TYPES` includes `secret`; secrets findings map to `evidence_type="secret"` and `asset_type="source_file"`. Do not use plaintext secret values in `fingerprint`, `evidence_text`, or `normalizer` inputs.
- **Never log the raw SARIF before redaction.** `raw_redacted = _redact_sarif(raw) if "runs" in raw else _redact_text(raw)` must happen before any `print`/`logger`/`persist` of `raw`.
- **`BLOCKED_METADATA_KEYS` and `SECRET_KEY_FRAGMENTS`.** `persistence.py` blocks `raw_output`, `logs`, `command`, `credentials`, `env`, `environment` entirely, and drops any key whose lowercased name contains `password`/`secret`/`token`/`api_key`/`private_key`/`access_key`/`jwt`/`cookie`/`authorization`. Do not bypass this for any scanner.

## Network Security

- **Prefer offline.** AppSec scanners run offline by design: Semgrep `p/security-audit --metrics off --timeout 60`, OSV-Scanner `--offline`, Gitleaks `--no-git --redact --config /config/gitleaks.toml` (bundled rules, no network). Do not remove offline flags without justification.
- **No unnecessary external API calls.** Scanners must not phone home, upload code, or fetch remote configs at runtime. Vulnerability DB/rules are baked into the Docker images at build time; updates happen via image rebuilds, not runtime fetches.
- **No mandatory third-party data upload.** Never require sending workspace contents to an external service for scanning. Fallback engines (`*_FALLBACK_ENABLED=false` by default) are disabled for exactly this reason — they would run a local analyzer but are explicitly opt-in for dev/test only.
- **Do not require API keys unless genuinely needed.** `NVD_API_KEY`, `SHODAN_API_KEY`, `CENSYS_API_*` in `.env.example` are optional enrichment keys, not required for core scanning.

## Configuration

- **Secrets only in environment / secret management.** Never hard-code credentials in code, Dockerfiles, or configs. `.env` is ignored (`.gitignore`); `.env.example` contains placeholders only (`change-this-in-production`, empty keys for optional APIs, `SECRETS_IMAGE=vapt-secrets:latest`).
- **Fallback flags default to `false`.** `SECRETS_FALLBACK_ENABLED`, `SAST_FALLBACK_ENABLED`, `SCA_FALLBACK_ENABLED` must all default to `"false"` (checked via `os.getenv(..., "false").lower() in ("1","true","yes","on")`). Fallback is a disabled-by-default degradation path that returns empty or local-analyzer results with `execution_engine=secrets_fallback` / `sast_analyzer` and `execution_mode=fallback` — it must never be enabled in production.
- **Pin scanner versions in code and env.** Each scanner module defines `PRODUCTION_VERSION` and `PRODUCTION_ENGINE` / `FALLBACK_ENGINE` / `IMAGE` / `FALLBACK_IMAGE`; `.env.example` exposes `SECRETS_IMAGE`, `SAST_IMAGE`, `SECRETS_TIMEOUT`, etc. Keep them consistent and documented.

## Database Security

- **Project isolation.** Every query that touches tenant data must filter `WHERE project_id = :project_id` (see `persistence.py :: upsert_assets`, `upsert_relationships`, `_load_target_assets_pre_mutation`, `tasks.py :: get_project_id`). Never leak cross-project assets/findings/relationships.
- **Parameterized queries / ORM.** Use `sqlalchemy.text` with bound parameters (`:project_id`, `:asset_type`, `:value`), never string-interpolated SQL. Validate `target_id` ownership via `get_project_id(db, target_id)` before any scan.
- **Safe metadata.** `sanitize_metadata` / `_sanitize_value` enforce `MAX_METADATA_BYTES=16384`, string cap 4000 chars, list cap 100 items, and `BLOCKED_METADATA_KEYS` / `SECRET_KEY_FRAGMENTS` filtering. Do not write unsanitized `finding["metadata"]` to `findings.metadata` JSONB.
- **No plaintext secrets in JSONB.** Even if `sanitize_metadata` would already drop a secret-bearing key, the secrets scanner must have redacted before reaching persistence. Treat persistence sanitization as a second barrier, not the first.

### Row-Level Security Foundation (Defense-in-Depth, Disabled — Preparation Only)

> **Foundation implemented** — `backend/app/db/rls.py` + `RLS_ENABLED=false`.
> **Enforcement NOT enabled** — no `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`, no `CREATE POLICY`, no migration.
> Application authorization remains authoritative.

- **Helpers only.** `backend/app/db/rls.py` exposes `is_rls_enabled()`, `validate_context_value()`,
  `set_tenant_context(db, organization_id, project_id?, user_id?)`, `clear_tenant_context()`,
  `get_current_tenant_context()`. No global wiring in this phase.
- **Transaction-local, never session-scoped.** Uses `SELECT set_config(:k, :v, true)` (`is_local=true`,
  equivalent to `SET LOCAL`). GUCs `app.current_organization_id` / `app.current_project_id` /
  `app.current_user_id`. Must be called inside `with db.begin():` — otherwise raises `RuntimeError`
  on PostgreSQL. `COMMIT`/`ROLLBACK` clears context, so `QueuePool` reuse cannot inherit Company A context.
- **Never interpolate tenant values.** Keys are trusted constants; values are bound parameters (`:k`, `:v`).
  Never `f"SET LOCAL ... = '{org_id}'"`.
- **Validate before setting.** `validate_context_value` enforces UUID v4 strict (`uuid.UUID(..., version=4)`);
  rejects empty, non-UUID, and injection strings (`'; SET LOCAL ... --`). Do not accept raw
  `organization_id`/`project_id` from query/body — authoritative source is `get_current_user` +
  `require_project_access` verified membership.
- **Dialect-safe.** No-op on non-PostgreSQL (SQLite in tests) after validation; `RLS_ENABLED=false` is no-op everywhere.
- **Future policies (deferred).** Will enforce `USING (organization_id = current_setting('app.current_organization_id', true)::uuid)`
  or `USING (project_id = current_setting('app.current_project_id', true)::uuid)` with `WITH CHECK` mirrors,
  `FORCE RLS` where needed. Never `USING (true)` — that bypasses isolation. Policies remain **not created** this phase.

## RBAC & Tenancy Security (Enterprise Foundation)

> **Foundation implemented** — membership tables + permission model, transitional enforcement. See `docs/RBAC_MODEL.md`.

- **Organization membership is authoritative.** `organization_memberships` (`unique(organization_id, user_id)`, `role` member/org_admin) is the source for org access; fallback `User.organization_id` only for backward compat with existing data. `require_project_access` now verifies via `_effective_org_role`.
- **Project membership is authoritative (transitional fallback).** `project_memberships` (`unique(project_id, user_id)`, `role` viewer/analyst/project_admin) is the source for project access; fallback `org_member → analyst`, `org_admin → project_admin` preserves existing projects without explicit rows. Future will require explicit membership (no fallback).
- **Platform super_admin is separate.** `User.role == 'super_admin'` bypasses org/project checks via `_is_super_admin`; never grant via org/project membership. `require_super_admin` exists but no route currently requires it. No dashboard built yet; super_admin actions must be auditable (future).
- **Permissions are centralized.** `backend/app/core/permissions.py` defines `ALL_PERMISSIONS` and `ORG_ROLE_PERMISSIONS`/`PROJECT_ROLE_PERMISSIONS`; `backend/app/api/deps.py` exports `_effective_org_role`, `_effective_project_role`, `require_permission`, `require_org_role`, `require_project_role`, `require_super_admin`. Do not scatter `if user.role == ...` checks in handlers.
- **Never trust client tenant IDs.** `organization_id`/`project_id` from body/query is validated via `require_project_access` (checks `Project.organization_id == current_user.org` via membership) before permission check. Client cannot change own role or assign higher role — no membership API exists yet.
- **Project creation is org_admin only.** `POST /projects` now checks `_effective_org_role == 'org_admin'` (member → 403). Transitional mapping `User.role admin → org_admin` preserves existing admin users.
- **Destructive & expensive ops are role-gated.** `DELETE /projects` → `org_admin`, `POST /targets`/`POST /scans` → `analyst`/`project_admin`, `DELETE /targets` → `analyst`/`project_admin` (future will be `project_admin` only). Other reads still via `require_project_access` fallback (viewer can read).
- **Cross-tenant is 404, not 403.** Use 404 for not-found vs cross-tenant to avoid enumeration; 403 for insufficient permissions within same tenant.
- **Future RLS will be defense-in-depth.** Helper `backend/app/db/rls.py` remains `RLS_ENABLED=false`; future `BEGIN → set_tenant_context(org, project, user) → RLS USING (...)` after verified membership.

- **Membership management is privileged.** `POST /organizations/{id}/members` and `/projects/{id}/members` require `org_admin` or `project_admin`/`org_admin` respectively; validate target user exists, duplicate 409, role assignment security (cannot grant higher than own, cannot grant `super_admin`, self-escalation blocked), cross-org 403, last-active-org_admin protection (409). No membership API can modify `User.role` platform `super_admin`.
- **Strict RBAC cutover:** `RBAC_STRICT_MODE=false` (transitional). Per-project strict when explicit `project_membership` exists (`missing → DENIED`), otherwise fallback `org→project` for backward compat. `RBAC_STRICT_MODE=true` enforces strict for all. Backfill `project_backfill.py` is dry-run by default, idempotent, never fabricates. Inactive `status != active` memberships are denied.

## Audit Logging (Foundation + Membership/Project Lifecycle)

- **Model:** `audit_logs` append-only, `SET NULL` on user/org/project delete so history survives (project deletion retains deletion audit via `SET NULL`), no `UPDATE`/`DELETE` API, indexed for tenant/time/event queries, `metadata` JSONB bounded to `AUDIT_METADATA_MAX_BYTES=4096` (configurable, truncation).
- **Service:** `backend/app/services/audit.py` — centralized `AuditService.record` with server-controlled `actor_user_id`/`organization_id`/`project_id`, sanitizes `metadata` (redacts `password`, `secret`, `token`, `api_key`, `authorization`, `cookie`, `private_key`, `client_secret`, `credential` nested, size-bounded), never stores passwords/JWTs/API keys/cloud credentials/private keys/cookies/source code/file contents/scanner stdout/stderr/bodies/connection strings. `request_id`/`correlation_id`/`ip_address`/`user_agent` captured where available, same DB transaction as business mutation for consistency (`db.flush()` via savepoint; outer rollback rolls back audit; savepoint isolates missing-table in ephemeral test DBs). No audit on failed authz (403/404) — only `SUCCESS` after mutation succeeds.
- **Taxonomies:** Centralized `EVENT_*` (auth, org/project/member, target, scan, finding, ingestion, cloud, authz denied), `RESULT_*` (`SUCCESS`/`FAILURE`/`DENIED`/`PARTIAL`), `RESOURCE_*` — not scattered. **6B wired:** `ORGANIZATION_MEMBER_ADDED/UPDATED/REMOVED` (`organization_membership`, `old_role`/`new_role`), `PROJECT_MEMBER_ADDED/UPDATED/REMOVED` (`project_membership`, `old_role`/`new_role`), `PROJECT_CREATED`/`PROJECT_DELETED` (`project`, `name`). Target/scan/finding/ingestion/cloud/auth remain **DEFERRED**.
- **Tenant isolation:** Every audit carries `organization_id`/`project_id` from authorized resource (org members: path `organization_id`; project members: `project.organization_id`; project lifecycle: `project.organization_id`); never client-provided. Cross-tenant requests remain `403`/`404` and create no `SUCCESS` audit.
- **Target/Scan (6C):** `TARGET_CREATED/DELETED` (`target_type` only, no raw `value` value logged as customer content unless safe), `SCAN_CREATED` (`profile`/`target_type`), `SCAN_STARTED` (`profile`, `actor NULL` for worker), `SCAN_COMPLETED` (`scanners`/`finding_count`/`risk_score`, no `stdout/stderr`), `SCAN_FAILED` (`error` sanitized via `_sanitize_audit_metadata` + existing `_sanitize_secrets_error`, no `raw_output`, no `command`, no Docker env, no exception dump with credentials), intermediate retry never emits terminal `SCAN_FAILED`, terminal emitted once. Tenant derived `scan->target->project->org`, never task payload `organization_id`. Same DB transaction as status (commit together, rollback together).
- **Finding/Ingestion/Cloud (6D):** `FINDING_CREATED` (`severity`/`scanner`/`status` only, no evidence/source/tokens, `actor NULL` system, tenant `finding->target->project->org`, one audit per canonical finding row, not per observation). `FINDING_UPDATED`/`TRIAGED`/`STATUS_CHANGED` deferred — no `PATCH /findings/{id}` lifecycle exists. `INGESTION_CREATED` (`source_type`/`file_count`/`recommended_scanners`, no file contents, `actor_user_id` from API user, tenant `project.organization_id`, same tx) and `INGESTION_FAILED` (`error` sanitized 500, `FAILURE`, no upload source/credentials). Cloud `CLOUD_ACCOUNT_ADDED/UPDATED/REMOVED` deferred — no `POST/PATCH/DELETE /cloud/accounts` CRUD (read-only `GET /cloud/*`), `CLOUD_OPERATION` deferred — no callable cloud operation. All use `_sanitize_audit_metadata` (4096 cap) and savepoint isolation; failed mutations never create SUCCESS.
- **Auth/Authorization (6E):** AUTH_LOGIN_SUCCESS/FAILURE (password never logged, generic invalid_credentials), AUTH_LOGOUT (no token), AUTH_TOKEN_FAILURE (no Authorization header/JWT), AUTHORIZATION_DENIED/CROSS_TENANT_ACCESS_DENIED (conservative, ctor_organization_id+
equested_id, no resource contents, same 401/403/404), all savepoint-isolated, never break auth, tenant server-controlled, no enumeration.
- **Request Context + Read API (6F):** `X-Request-ID`/`X-Correlation-ID` bounded 64 safe chars `^[A-Za-z0-9._-]+$`, `uuid4().hex` fallback, not sequential, returned in response, CORS exposed, IP via `request.client.host` (not `X-Forwarded-For`, documented trusted proxy limitation), User-Agent bounded 500, never `Authorization`/`Cookie`/`body`. `GET /api/v1/audit_logs` requires `audit.read` (org_admin/super_admin), tenant `WHERE organization_id` else super_admin all, `project_id` validated `require_project_access` cannot bypass, actor/resource filters ANDed with tenant, pagination bounded, sorting fixed `created_at DESC` no SQL injection, response sanitized (metadata already `[REDACTED]`).
- **Worker Correlation + Integrity (6G):** `X-Correlation-ID` bounded 64 safe `^[A-Za-z0-9._-]+$`, `uuid4` fallback, not sequential, propagated `HTTP -> Celery` via `kwargs` (only `correlation_id`+`scan_id`/`target_id`/`profile` hint, never `Authorization`/`Cookie`/`JWT`/`body`, validated, tenant `scan->target->project->org` not payload), worker `request_id` NULL (`correlation_id` preserved, separate concepts), transaction `business+audit+commit` same outer tx (savepoint, outer rollback rolls back audit), duplicate guard `_scan_audit_exists` prevents duplicate `SCAN_*` on retry/redeliver, `FINDING_CREATED` one per `finding_id`, immutability `GET /api/v1/audit_logs` only (405 for others), no `UPDATE`/`DELETE` for audit, read tenant-enforced, metadata `[REDACTED]`, no `password/JWT/token/cookie` in worker audit.
- **Future:** Retention, RLS, etc. ID middleware, audit read API, remaining events (auth/authz-denied), retention (Phase 6E+). `SCAN_CANCELLED` exists but not wired — no cancellation implementation found.

## API Security

Current conventions (verified in `backend/app/api/`):

- JWT auth via `backend/app/api/deps.py` (`JWT_SECRET`, `JWT_ALGORITHM=HS256`, `ACCESS_TOKEN_EXPIRE_MINUTES=60`); optional bootstrap `AUTH_BOOTSTRAP_EMAIL`/`PASSWORD` only for local dev.
- All routes are project-scoped; `project_id` is taken from the authenticated user's project membership, not from untrusted query params alone.
- Use `pydantic` schemas (`backend/app/schemas/`) to validate inputs; do not trust raw `target` strings beyond scanner `target_types` checks (`ScannerManager.run` validates `target_type in scanner.target_types`).
- Do not return raw scanner output, logs, or secret material in API responses. Findings endpoints return standardized findings (`title`, `description`, `severity`, `evidence` already redacted where applicable).

## Logging

- **No secrets, no sensitive credentials.** `DockerRunner._safe_message`, `execution.py :: sanitize_error_message`, `tasks.py :: _sanitize_secrets_error` all redact `password=`, `secret=`, `token=`, `api_key`, `authorization:` patterns to `Scanner execution failed. See scanner logs for details.` Never log `raw_output` for secrets without redaction.
- **Sanitized errors, useful observability.** Log `scanner`, `target` (via `safe_target` which strips query strings), `phase` (`starting`/`waiting`/`log collection`/`execution`/`parsing`/`persistence`/`analysis`), `elapsed`, `error_type`, `retryable`, `attempt`, `findings_count`, `assets_count`. Truncate diagnostics at `DIAGNOSTIC_LIMIT=4000` and error messages at 4000 chars.
- **No sensitive payloads.** Do not log workspace file contents, manifest contents, or SARIF `message.text` before redaction.

## AI Security

Future AI components (analyst, triage, remediation suggestions) must never receive:

- Plaintext credentials or secret values — only `[REDACTED]` evidence and `_secret_hash` hashes.
- Unnecessary sensitive data — scope AI context to `title`, `severity`, `file`, `line`, `rule_id`, `cve`/`cwe`, and redacted `evidence` (≤500 chars), not full file contents or raw SARIF.
- Secrets scanner output containing real credentials — the AI input must be the redacted finding, not `raw_output`. `EVIDENCE_TYPES=secret` findings are explicitly excluded from LLM prompts unless double-redacted.

## Dependency Security

- **Pin security-sensitive tool versions.** Document and pin: Semgrep `1.75.0`, OSV-Scanner `1.9.2`, Gitleaks `8.30.1` (with digest `sha256:c00b6bd0...`). Update via Dockerfile + scanner `PRODUCTION_VERSION` + `.env.example` together.
- **Avoid unnecessary dependencies.** Do not add new Python/JS packages for scanner-adjacent code without checking existing `backend/requirements.txt` and `worker/requirements.txt`. Prefer stdlib (`re`, `hashlib`, `json`, `pathlib`) for redaction/hashing.
- **Scanner Dockerfiles must be minimal.** Do not install extra tools, do not `pip install` unverified packages in scanner images, and do not add `curl`/`wget` runtime fetches where the tool already bundles rules.

## Ingestion Security (P11.1)

Ingestion handles **untrusted** repository/archive contents. Never execute them:

- **No automatic execution:** Never run `package.json` scripts, `Makefile`, `build.sh`, `Dockerfile` `RUN`, CI YAML, hooks, binaries, or any repository code during ingestion. Files may be *detected* and *scanned* later, but not executed. `IngestionService` only validates and extracts; it does not `import` or `exec` repository files.
- **Archive validation before extraction:** Inspect every entry's `filename`/`linkname` before writing. Reject `../` traversal, absolute Unix (`/etc/passwd`), Windows drive (`C:\`), UNC (`\\server`), `//`, and null bytes. Use `_validate_entry_name` for ZIP/TAR. For TAR, also reject `..` in `linkname`.
- **Symlink/hardlink escape:** `zip` symlinks via `external_attr` + `linkname` content; `tar` `issym()`/`islnk()` — validate `linkname` is not absolute, not `..` traversal, and `resolve().relative_to(workspace)` stays inside. Create symlinks only after validation; hard links only if target exists within workspace. Count symlinks/hardlinks toward `MAX_FILE_COUNT`.
- **Workspace containment:** `create_workspace` (`0o700`, `WORKSPACE_BASE`) + `resolve().relative_to(workspace)` for every extracted file **before and after** write. `_ensure_workspace_containment` verifies `workspace` is inside `WORKSPACE_BASE`. `cleanup_workspace` verifies `relative_to(base)` and `path != base` before `shutil.rmtree`.
- **Resource limits (env-overridable, safe defaults):** `MAX_ARCHIVE_SIZE` 100 MB, `MAX_EXTRACTED_SIZE` 500 MB, `MAX_FILE_COUNT` 10k, `MAX_FILE_SIZE` 50 MB, `MAX_ARCHIVE_BOMB_RATIO` 100. Enforce in **two passes**: first validate `file_size`/`file_count`/`total_size` without writing, then stream extraction with `remaining` check. Reject with `IngestionError` category (`archive_too_large`, `extracted_too_large`, `too_many_files`, `file_too_large`).
- **Malformed archives:** `zipfile.BadZipFile`/`tarfile.TarError` → `IngestionError` `malformed_archive`/`unsupported_format`, not crash, not log raw content. `detect_archive_type` checks filename + magic (`PK\x03\x04`, `\x1f\x8b`, `ustar` at 257) and fallback try.
- **No secrets in logs:** `IngestionResult.to_safe_dict()` truncates `error_message` 500, `warnings` 20×200, `source_name` 100, never logs `archive_bytes` or file contents. `IngestionError` messages are bounded and sanitized; backend `prepare_ingestion` returns `detail` without raw. Never store `SECRET_VALUE_FAKE` etc. in metadata (test_24 verifies).
- **Project isolation:** `IngestionService.prepare_from_archive(archive_bytes, filename, project_id)` requires `project_id` (validated, not empty), creates workspace with `project_id` prefix (`vapt-<ingest>-ingestion-<project>`), `IngestionResult.project_id` preserved, `require_project_access` in API ensures `project_id` belongs to `current_user.organization_id`. No cross-project workspace reuse.
- **No execution of build scripts:** `artifact_detection` only `rglob` and `read_text[:2000]` for `openapi`/`swagger` marker, never `subprocess` or `eval` on repository files.
- **Cleanup:** `IngestionService.cleanup(workspace)` → `cleanup_workspace` (idempotent, verifies `relative_to`), called in service `except` (failed ingestion cleans workspace, returns `workspace_path=""`) and in API `shutil.rmtree` + `finally`. Failed ingestion never leaves workspace.

## Cloud Security (P12.1)

Cloud foundation must be read-only, non-destructive, and credential-safe:

- **Provider-neutral:** `CloudProvider` registry, `is_supported_provider` check, `MockCloudDiscoveryAdapter` for tests, no live SDK calls in unit tests, no `aws`/`gcloud`/`az` CLI `subprocess`
- **No destructive actions:** `discover()` is read-only, never `delete`/`update`/`create` cloud resources, never modify cloud state, never trust resource names as commands
- **No shell interpolation:** Never interpolate `resource_id`/`resource.name`/`tags` into shell commands (`;|&$` etc. would be rejected by `_validate_image_ref`-style validation if ever used) — use controlled APIs, not `subprocess` with `shell=True`
- **Credential reference only:** `CloudAccount.credential_reference` is opaque string (100 chars), never plaintext `AWS_SECRET`/`GCP private key`/`Azure secret` in `Asset`/`Finding`/`logs`; `to_safe_dict()` strips `secret`/`token`/`key`/`private` from `metadata`/`tags`; `test_20`/`test_21` verify, future vault deferred
- **Project isolation:** Every `CloudAccount`/`CloudResource` has `project_id`, `canonical_value` is `cloud_account:{provider}:{account}:{region}` / `cloud_resource:{provider}:{account}:{region}:{type}:{id}` (deterministic, hash if >1024), `Asset` persistence is `(project_id, asset_type, value)` — same value different `project_id` → different rows, `GET /api/v1/cloud/accounts?project_id=` etc. require `require_project_access` and `WHERE project_id`
- **No secrets in logs:** `CloudDiscoveryResult.to_safe_dict()` sanitizes `error_message` 500, no raw API responses, `sanitize_cloud_metadata` strips `secret`/`token`
- **Read-only discovery:** Default, never perform destructive operations, never execute arbitrary resource-provided commands
- **No external calls in tests:** `MockCloudDiscoveryAdapter` with deterministic `provider-resource-{i}` and `contains`/`uses` relationships, no network, no credentials required

## Change Safety

Future agents must:

1. **Inspect first** — `Read` the exact files being changed; prefer `Grep`/`Glob` to broad dumps.
2. **Make minimal scoped changes** — touch only the files required for the requested stage; avoid large refactors.
3. **Add regression tests** — for any new parser branch, redaction pattern, or execution path, add a focused test (see `worker/tests/test_secrets_*.py` as reference) and run `python -m pytest <focused> -q` + full `python -m pytest` regression.
4. **Verify security-sensitive behavior** — for any change to `docker_runner`, `workspace`, `secrets` redaction, or `persistence` sanitization, re-run Docker image builds, pinned-version checks, vulnerable-fixture vs clean-fixture scans, and DB/log leakage inspection before claiming `READY`.
5. **Avoid breaking existing scanners** — preserve `scan(target)` backward compat, keep parser output shape stable, and keep `FindingEngine` generic. Run the full scanner contract tests (`tests/test_*_scanner.py`, `tests/test_*_parser.py`) on every change.

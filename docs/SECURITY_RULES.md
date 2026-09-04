# VAPT Platform Security Rules

> Scope: every AI coding session and every manual change. Violations break the `READY` classification for the affected stage.
> References: `worker/app/scanner/docker_runner.py`, `worker/app/scanner/workspace.py`, `worker/app/scanner/scanners/*.py`, `scanners/*/Dockerfile`, `worker/app/scanner/parsers/secrets_parser.py`, `worker/app/persistence.py`, `worker/app/tasks.py`, `docker-compose.yml`, `.env.example`.

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

## Change Safety

Future agents must:

1. **Inspect first** — `Read` the exact files being changed; prefer `Grep`/`Glob` to broad dumps.
2. **Make minimal scoped changes** — touch only the files required for the requested stage; avoid large refactors.
3. **Add regression tests** — for any new parser branch, redaction pattern, or execution path, add a focused test (see `worker/tests/test_secrets_*.py` as reference) and run `python -m pytest <focused> -q` + full `python -m pytest` regression.
4. **Verify security-sensitive behavior** — for any change to `docker_runner`, `workspace`, `secrets` redaction, or `persistence` sanitization, re-run Docker image builds, pinned-version checks, vulnerable-fixture vs clean-fixture scans, and DB/log leakage inspection before claiming `READY`.
5. **Avoid breaking existing scanners** — preserve `scan(target)` backward compat, keep parser output shape stable, and keep `FindingEngine` generic. Run the full scanner contract tests (`tests/test_*_scanner.py`, `tests/test_*_parser.py`) on every change.

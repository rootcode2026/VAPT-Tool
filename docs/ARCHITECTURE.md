# VAPT Platform Architecture

> Verified against: `worker/app/scanner/*`, `worker/app/finding_engine/`, `worker/app/services/*`, `worker/app/asset_intel/`, `worker/app/risk_engine/`, `worker/app/tasks.py`, `worker/app/persistence.py`, `backend/app/api/routes/*`, `frontend/src/app/(app)/*`, `docker-compose.yml`, `scanners/*/Dockerfile`.
> Labels: COMPLETE / IN PROGRESS / PLANNED / DEFERRED refer to code + test + verification evidence, not file existence alone.

## System Overview

```
                    Next.js SOC Frontend (port 3000)
                              |
                    FastAPI Backend (port 8000)
                     /      |       \
              PostgreSQL  Celery  Redis/RabbitMQ
              (16-alpine)  Worker  (7-alpine / 3-management)
                           |
                    docker-socket-proxy:2375
                           |
              Scanner Containers (per-attempt, isolated)
                           |
              PostgreSQL (findings, assets, relationships, attempts)
```

- **Frontend** (`frontend/`) — Next.js SOC workspace, project-scoped navigation (`dashboard`, `projects`, `targets`, `scans`, `findings`, `assets`, `attack-surface`, `settings`), `NEXT_PUBLIC_API_URL=http://localhost:8000`.
- **Backend API** (`backend/`) — FastAPI, JWT auth (`backend/app/api/deps.py`, `routes/auth.py`), project-scoped CRUD (`projects`, `targets`, `scans`, `findings`, `assets`, `scanners`, `dashboard`), Alembic migrations (10 versions), `backend/app/services/` for domain logic.
- **Celery Worker** (`worker/`) — `worker/app/celery_app.py` + `worker/app/tasks.py :: execute_scan`, `worker/app/persistence.py`, `worker/app/scanner/*`, `worker/app/finding_engine/`, `worker/app/services/*`, `worker/app/asset_intel/`, `worker/app/risk_engine/`.
- **Data Plane** — PostgreSQL (`security_saas`), Redis (Celery results), RabbitMQ (Celery broker), Docker runtime via `docker-socket-proxy`.
- **Scanner Plane** — Per-family Docker images in `scanners/` (nmap, nuclei, zap, nikto, tls, dns, subdomain, sast, sca, secrets), invoked via `DockerRunner`.

## High-Level Components

| Component | Code | Responsibility |
|---|---|---|
| Frontend | `frontend/src/app/` | Project/target/scan/findings/assets dashboards, scan orchestration UI, risk views |
| Backend API | `backend/app/api/routes/` | REST endpoints, auth, project isolation, scan dispatch (enqueue Celery), finding/asset queries |
| Celery Worker | `worker/app/celery_app.py`, `worker/app/tasks.py` | Async scan execution, workspace lifecycle, pipeline orchestration, risk calculation, persistence |
| PostgreSQL | `docker-compose.yml :: postgres` | Scans, targets, assets, relationships, findings, attempts, migrations |
| Redis | `docker-compose.yml :: redis` | Celery result backend |
| RabbitMQ | `docker-compose.yml :: rabbitmq` | Celery broker |
| Docker Runtime | `worker/app/scanner/docker_runner.py` + `docker-socket-proxy` | Container lifecycle, volume validation, timeout polling, log collection |
| Scanner Images | `scanners/*/Dockerfile` | Per-tool images, pinned versions/digests where practical, non-root where practical |

## Scanner Architecture

### Base Abstractions

- **`BaseScanner`** (`worker/app/scanner/base.py`) — ABC with identity (`name`, `category`, `family`, `description`), target/input (`target_types`, `input_type`, `requires_workspace`, `supported_profiles`), output (`output_format`), capabilities, timeout. Two entry points: `scan(target: str) -> str` (legacy, required) and `scan_with_context(ScanContext) -> str` (AppSec, defaults to `scan(context.target)`).
- **`ScanContext`** (`worker/app/scanner/base.py`) — `@dataclass` with `target`, `target_type`, `project_id`, `scan_id`, `workspace`, `metadata`. Added for AppSec without breaking legacy scanners.
- **`ScannerRegistry`** (`worker/app/scanner/registry.py`) — Registers 11 built-in scanners (`nmap`, `nuclei`, `http_fingerprint`, `zap`, `nikto`, `tls`, `dns`, `subdomain`, `sca`, `sast`, `secrets`), exposes `get(name)` / `list()` / `register()`.
- **`ScannerManager`** (`worker/app/scanner/manager.py`) — Thin dispatcher: `run(scanner, target)` → `scanner.scan(target)` with `target_type` validation; `run_with_context(scanner, ScanContext|str)` → `scanner.scan_with_context(context)` (or `scan(target)` fallback).
- **`ScannerPipeline`** (`worker/app/scanner/pipeline.py`) — Three stages: `manager.run` → `parser_registry.get(scanner).parse(raw)` → `finding_engine.analyze(parsed)`. Two entry points `run(scanner, target)` / `run_with_context(scanner, context)`, plus `run_many` with `run_with_retries` per scanner.
- **`DockerRunner`** (`worker/app/scanner/docker_runner.py`) — `run(image, command, timeout, scanner, target, volumes, workspace) -> str` and `run_detailed(...) -> DockerRunResult`. Validates volumes, injects workspace mount, polls `container.reload()` / `container.status` (not streaming `wait()`), handles timeouts vs transport errors (`ChunkedEncodingError`, `ProtocolError`), collects `stdout`/`stderr` separately, enforces `DIAGNOSTIC_LIMIT=4000` and `_safe_message` redaction.

### Workspace vs Non-Workspace Paths

- **Legacy (non-workspace):** `tasks.py` calls `run_with_retries(pipeline.run, scanner, target)` directly; scanner receives raw target string (URL, IP, hostname).
- **AppSec (workspace):** `tasks.py` detects `scanner_instance.requires_workspace`, then per attempt: `ws = create_workspace(scan_id, scanner, project_id)` → `ctx = ScanContext(target=ws, workspace=ws, ...)` → `run_with_retries(_execute_with_workspace, scanner, target)` where `_execute_with_workspace` calls `pipeline.run_with_context(scanner, ctx)` inside `try/finally: cleanup_workspace(ws)`. Each retry gets a fresh workspace.

## Workspace Architecture

`worker/app/scanner/workspace.py` — COMPLETE:

- `create_workspace(scan_id?, scanner?, attempt?, project_id?) -> str` — `tempfile.mkdtemp(prefix="vapt-<scan>-<scanner>-a<attempt>-", dir=_base_dir())`, `os.chmod 0o700`, base is `WORKSPACE_BASE` env or system `tempdir`.
- `cleanup_workspace(workspace?)` — Resolves path, verifies `path.relative_to(base)`, refuses to delete `base` itself or non-directories, `shutil.rmtree(ignore_errors=True)`, never propagates errors (does not hide scanner error).
- `is_workspace_path_safe(workspace?) -> bool` — Verifies inside base, not base itself, no `..` segment, exists and is directory.
- Docker mount: `DockerRunner._validate_volumes` + `tasks.py` workspace injection mounts `{ws: {"bind": "/workspace", "mode": "ro"}}` (read-only). Scanners resolve `ws/src` vs `ws` and `p.resolve().relative_to(ws.resolve())` to prevent traversal/symlink escape.

Invariants: one workspace per scan/attempt, never shared, never predictable shared directory, always cleaned in `finally`, retry creates a new one.

## Scanner Execution

Sequence per scanner in `tasks.py :: execute_scan`:

```
for scanner_name in get_scanners_for_profile(profile):
    insert_attempt(scan_id, scanner_name, pending)
    on_attempt_start -> update_attempt(running)
    on_attempt_failure -> update_attempt(failed)

    if requires_workspace:
        ws = create_workspace(...)
        ctx = ScanContext(target=ws, workspace=ws, ...)
        outcome = run_with_retries(_execute_with_workspace, scanner_name, target)
        finally: cleanup_workspace(ws)
    else:
        outcome = run_with_retries(pipeline.run, scanner_name, target)

    if is_scanner_success(outcome):
        correlated = correlate_parsed_bundle(scanner, assets, findings)
        persisted_assets = persist_parsed_bundle(db, project_id, scan_id, scanner, assets, findings)
        _persist_findings(db, scan_id, target_id, scanner_name, findings, persisted_assets)
        update_attempt(completed, findings_count, assets_count)
    else:
        update_attempt(failed, error_type, retryable)

    _refresh_progress(scan_id, statuses)
    scanner_summary(outcomes) -> overall_scan_status -> risk_engine.calculate(all_findings) -> UPDATE scans (risk_score/grade/level)
```

`worker/app/scanner/execution.py` — `get_max_attempts` (default 2, `SCANNER_MAX_ATTEMPTS` env), `duration_ms`, `utc_now`, `calculate_progress`, `overall_scan_status`, `scanner_summary`, `sanitize_error_message`, `classify_failure` (maps `ScannerTimeoutError` → `timeout`, `ScannerFailureError` → `container_failure`, transport errors → `docker_transport`, etc., with `RETRYABLE_ERROR_TYPES` = timeout/transport/provider errors), `failed_scanner_result`, `run_with_retries` (calls `on_attempt_start`/`on_attempt_failure`, respects `retryable` flag).

## Parser Architecture

- **`BaseParser`** (`worker/app/scanner/parsers/base.py`) — `parse(raw: str) -> dict` returning `{scanner, assets, findings, errors, metadata}`.
- **`ParserRegistry`** (`worker/app/scanner/parsers/registry.py`) — Maps scanner name → parser instance; `get(scanner)`.
- **`SarifParser`** (`worker/app/scanner/parsers/sarif_parser.py`) — Generic SARIF 2.1.0 parser for AppSec families (sast, sca, secrets). Extracts `runs[0].results[]` → findings, `runs[0].artifacts[]` / `results[].locations[]` → `source_file`/`package` assets, preserves `ruleId`, `level`, `message`, `locations`, `partialFingerprints`.
- **Per-scanner parsers:** `nmap_parser`, `nuclei_parser`, `zap_parser`, `nikto_parser`, `tls_parser`, `dns_parser`, `subdomain_parser`, `http_fingerprint_parser`, `sast_parser` (SARIF → typed findings), `sca_parser` (SARIF → dependency vulns), `secrets_parser` (SARIF/legacy → `secret` findings, `source_file` assets, mandatory redaction).

## Finding Architecture

```
scanner raw output (SARIF/JSON/text)
  -> Parser.parse(raw) -> {scanner, assets, findings, errors, metadata}
  -> FindingEngine.analyze(parsed) -> list[standardized findings]
```

`worker/app/finding_engine/engine.py :: FindingEngine` — COMPLETE, generic (no `if scanner == ...` branches):

- `analyze(scan_result)` validates `scanner`, iterates `scan_result.findings`, calls `_standardize_finding`.
- `_standardize_finding(scanner, finding)` normalizes `severity` → `score` (`critical:90 high:75 medium:50 low:25 info:5`), ensures `metadata: dict`, returns `{scanner, title, description, severity, score, status, evidence, remediation, cve, cwe, metadata}`.

## Correlation

`worker/app/services/finding_correlation/` — COMPLETE, deterministic, bounded:

- **`normalizer.py`** — `normalize_finding(finding) -> {url, hostname, ip, port, parameter, file, line, rule_id, cve, cwe, ecosystem, package_name, evidence, asset_type, ...}`; extracts canonical keys for fingerprinting regardless of scanner.
- **`correlator.py`** — `correlate_findings(findings) -> {groups, fingerprint -> {findings, scanners, contexts}}`; groups by `fingerprint = hash(normalized fields)` (file+line+rule_id for SAST, package+ecosystem+installed_version for SCA, file+rule_id for secrets), bounded, no DB/network.
- **`validation.py`** — `validate_correlated(correlated) -> {state, confidence_score, confidence_level, signals, reasons}`; states: `detected`, `corroborated` (multi-scanner), `needs_review`, `confirmed`, `false_positive`, `accepted_risk`, `remediated`, `reopened` (lifecycle states are persisted but validation itself is deterministic).
- **`evidence.py`** — `build_evidence_provenance(correlated) -> {evidence_items, evidence_count, independent_scanner_count, evidence_types, coverage, provenance_quality_score, provenance_quality_level}`; `EVIDENCE_TYPES` includes `secret`, `container_layer`, `iac_resource`, `api_endpoint`; `enrich_finding_confidence(validation, provenance)` adds +5 if `provenance_quality_score>=70` and +5 if `evidence_count>=2 && independent>=2`.

Correlation never uses plaintext secret values as keys — for secrets, fingerprint is `file + rule_id` (and `_secret_hash` is kept separate, not as fingerprint input).

## Validation

See `worker/app/services/finding_correlation/validation.py` — deterministic, project-scoped, bounded:

| State | Meaning |
|---|---|
| `detected` | Single-scanner, no corroboration |
| `corroborated` | Same fingerprint seen by ≥2 scanners/contexts |
| `needs_review` | Ambiguous or low confidence |
| `confirmed` | Manual confirmation (persisted) |
| `false_positive` | Manual triage (persisted) |
| `accepted_risk` | Risk accepted (persisted) |
| `remediated` | Fix verified (persisted) |
| `reopened` | Previously closed finding seen again (change detection) |

Signals: `scanner_count`, `evidence_count`, `has_url/hostname/ip/port/parameter/file/cve/cwe/rule_id`, `provenance_quality_score`. Confidence `0–100` mapped to `low <40 medium <70 high <90 very_high`.

## Evidence / Provenance

`worker/app/services/finding_correlation/evidence.py` — `build_evidence_provenance` input is a correlated finding (`finding_count`, `scanners`, `evidence: [{scanner, evidence, fingerprint}]`, `file`, `rule_id`, etc.). Output: `evidence_items: [{scanner, evidence_type, fingerprint, file, line, ...}]` (≤50 items, deduped by `scanner:fingerprint:evidence`), `evidence_types` (sorted, ≤20), `cves`/`cwes`/`rule_ids` (sorted, ≤20), `coverage` flags (`has_asset`, `has_location`, `has_url`, `has_file`, ...), `provenance_quality_score` 0–100, `provenance_quality_level`.

AppSec evidence type mapping (`_classify_evidence_type`):
- `secrets` / `gitleaks` → `secret`
- `sca` or `ecosystem`/`package_name` → `dependency`
- `file` present → `source_code`
- `container`/`trivy` → `container_layer`, `iac`/`checkov` → `iac_resource`, `api` → `api_endpoint`

Asset types: `source_file` (file paths, verified in `secrets_parser` assets), `package`, `container_image`, `repository` (future).

## Risk

Two layers (both deterministic, no external calls):

1. **`worker/app/risk_engine/engine.py :: RiskAssessmentEngine`** — Scan-level risk: `score = max(0, 100 - Σ SEVERITY_WEIGHTS)` where `critical:35 high:20 medium:10 low:3 info:0`, `grade: A≥90 B≥75 C≥50 D<50`, `risk_level: critical/high/medium/low/informational`. Called in `tasks.py` after all scanners succeed.

2. **`worker/app/services/risk_intelligence/`** — Finding/path-level enrichment:
   - `enricher.py` — per-finding `risk_score` / `risk_level` from severity + confidence + provenance.
   - `asset_context.py` — `asset_risk_modifier` (-10…+15) and `is_externally_exposed` from asset type/value/relationships (public IP, URL, `exposes`/`resolves_to`/`serves`).
   - `attack_paths.py` — `discover_attack_paths(assets, relationships, findings)` builds asset graph → paths (`nodes`, `relationships`, `finding_ids`, `path_length`).
   - `prioritizer.py :: prioritize_attack_paths` — `priority_score 0–100` = `severity_contrib` (35/20/10/3/0) + `confidence_contrib` (0–15) + `corroboration` (0/10/15) + `provenance` (0–10) + `exposure` (0/10) + `asset_modifier` (-10…+15) + `completeness` (0/5) + `length` (0–3), clamped, prioritized descending.

## Asset Intelligence

`worker/app/asset_intel/` — COMPLETE:

- **`normalize.py`** — `normalize_url`, `normalize_hostname`, `normalize_ip`, `infer_asset_type`, `infer_asset_value` — canonical, project-scoped determinism.
- **`types.py`** — `ASSET_TYPES` (`ip`, `ipv6`, `hostname`, `domain`, `subdomain`, `url`, `port`, `service`, `technology`, `package`, `source_file`, `tls_endpoint`, ...), `RELATIONSHIP_TYPES` (`resolves_to`, `exposes`, `serves`, `hosts`, `depends_on`, ...).
- **`correlate.py`** — `correlate_parsed_bundle(scanner, assets, findings) -> {assets, relationships}` — dedupes by `(asset_type, value)`, merges metadata, infers relationships deterministically.
- **`provenance.py`** — `validate_relationship`, `merge_relationship_metadata` — enforces allowed `(source_type, relationship_type, target_type)` triples.
- **`change_detection.py`** — `detect_asset_changes` / `persist_change_events` — compares current vs previous assets/relationships (loaded single-query via `_load_target_assets_pre_mutation`), emits `created`/`updated`/`disappeared` events, `compute_asset_lifecycle_status` (active/stale).
- **`classification.py` / `enrich.py`** — Asset classification and metadata enrichment.

## Persistence

`worker/app/persistence.py` + `worker/app/scanner/result_store.py` → PostgreSQL:

- **`sanitize_metadata`** — Strips `BLOCKED_METADATA_KEYS` (`raw_output`, `logs`, `command`, `credentials`, `env`, `environment`), drops keys containing `SECRET_KEY_FRAGMENTS` (`password`, `secret`, `token`, `api_key`, `private_key`, ...), caps at `MAX_METADATA_BYTES=16384`, truncates strings at 4000 chars, lists at 100 items.
- **`persist_parsed_bundle(db, project_id, scan_id, scanner, assets, findings)`** — `correlate_parsed_bundle` → `detect_asset_changes` → `upsert_assets` (ON CONFLICT `(project_id, asset_type, value)` DO UPDATE, merges metadata, updates `first_seen_at`/`last_seen_at`/`last_seen_scan_id` via `observation_timestamps`) → `upsert_relationships` (ON CONFLICT `(project_id, source, target, relationship_type)`).
- **`_persist_findings`** (`tasks.py`) — Inserts `findings` rows with `match_asset_id` (exact → scanner-preferred → partial matching via `SCANNER_ASSET_PREFERENCE`, `finding_needles` from `metadata.uri/url/host/ip/evidence`).
- **`result_store.py`** — `insert_attempt`, `update_attempt`, `update_scan_progress` — per-scanner attempt rows with `status`, `raw_output` (sanitized for secrets), `error_type`, `retryable`, `duration_ms`, `findings_count`, `assets_count`.
- **`tasks.py` defense-in-depth for secrets:** `_sanitize_secrets_raw` / `_sanitize_secrets_error` redact via `secrets._redact_text` before any `raw_output`/`error_message` persistence or logging.

Scan-level persistence: `scans` rows store `status` (`pending`/`running`/`completed`/`failed`), `phase` (e.g., `nmap_running`, `sast_completed`, `analyzing`), `progress` 0–100, `risk_score`/`risk_grade`/`risk_level`.

## Execution Observability

`worker/app/scanner/execution.py` — COMPLETE:

- **Statuses:** `pending`, `running`, `completed`, `failed`, `skipped`; `FINISHED_STATUSES = {completed, failed, skipped}`.
- **Error types:** `timeout`, `docker_transport`, `docker_api`, `container_failure`, `invalid_target`, `scanner_failure`, `parser_failure`, `persistence_failure`, `unknown`, plus SCA provider errors (`provider_timeout`, `provider_transport`, `provider_rate_limit`, `provider_error`).
- **Retryability:** `RETRYABLE_ERROR_TYPES = {timeout, docker_transport, docker_api, provider_*}` — `run_with_retries` retries only those, up to `SCANNER_MAX_ATTEMPTS` (default 2).
- **Observability:** `ScannerOutcome` (`scanner`, `status`, `attempt`, `max_attempts`, `started_at`, `completed_at`, `duration_ms`, `findings_count`, `assets_count`, `error_type`, `retryable`, `raw_output`, `parsed_result`, `findings`), `FailureInfo`, `scanner_summary(outcomes)`, `overall_scan_status(outcomes)`, `calculate_progress(statuses, total)`, `log_scanner_start/success/failure`.

## Frontend Architecture

Next.js SOC workspace — COMPLETE (verified routes):

- **`/(app)/dashboard`** — Risk score/grade, severity distribution, asset type summary, recent scans.
- **`/(app)/projects`** — Project CRUD, project-scoped target/scan navigation.
- **`/(app)/targets`** — Target CRUD (domain/IP/URL), active/inactive, project filter.
- **`/(app)/scans`** — Scan list, scan detail (`/scans/[scan_id]`), phase/progress/attempts, scanner summary.
- **`/(app)/findings`** — Findings list, finding detail (`/findings/[finding_id]`), severity/status, evidence, remediation, CVE/CWE, asset linkage.
- **`/(app)/assets`** — Asset inventory, asset detail (`/assets/[assetId]`), type/value, relationships, lifecycle status.
- **`/(app)/attack-surface`** — Attack surface / attack paths view.
- **`/(app)/settings`** — Project settings.
- **`lib/`** — `api/` clients (`assets.js`, `findings.js`, `scans.js`, ...), `dashboard/loadDashboard.js`, auth helpers.
- **`components/`** — `layout/AppShell`, `Sidebar`, `TopBar`, `dashboard/*`, `projects/*`, `ui/DataTable`, etc.

Backend routes serving the frontend: `backend/app/api/routes/` — `auth`, `projects`, `targets`, `scans`, `scanners`, `findings`, `assets`, `dashboard` (all project-scoped, JWT-gated via `deps.py`).

## Security Boundaries

- **Scanner container isolation:** No `--privileged`, no `docker.sock` mount (worker uses `docker-socket-proxy:2375`), only per-attempt workspace mounted read-only at `/workspace` (or `/workspace/src`), no host networking, no broad host mounts, pinned images (`FROM <image>@<digest>` where practical, `PRODUCTION_VERSION` in scanner modules, `.env.example` overrides).
- **Workspace isolation:** `tempfile.mkdtemp` (0o700) per scan/attempt, `Path.resolve().relative_to(workspace)` checks in every workspace scanner, `DockerRunner._validate_volumes` rejects `..` traversal, `/`, `/etc`, `/var/run/docker.sock`, validates absolute host paths, `cleanup_workspace` in `finally` (retry gets a fresh workspace).
- **Command injection:** Argument arrays (`["gitleaks","detect","--source", container_target, ...]`), never `shell=True` interpolation of untrusted values; only `sh -c` where the tool requires it (OSV-Scanner `cat` pattern) with fixed, non-interpolated shell.
- **Path safety:** `workspace.py` + `docker_runner.py` + per-scanner `resolve().relative_to(workspace)` prevent traversal/symlink escape; `is_workspace_path_safe` guards cleanup.
- **Secret handling:** See `SECURITY_RULES.md` — early redaction in scanner, repeated at persistence/tasks, `[REDACTED]` + `_secret_hash` (SHA-256 32 hex), never plaintext in DB/logs/API/AI.
- **Network:** AppSec scanners run offline (`semgrep p/security-audit --metrics off`, `osv-scanner --offline`, `gitleaks --no-git --config` bundled rules); no mandatory external API calls, no third-party data upload.
- **Project isolation:** All persistence queries are `WHERE project_id = :project_id`; `get_project_id` validates `target_id` ownership; findings/assets/relationships are project-scoped.

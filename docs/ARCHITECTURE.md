# VAPT Platform Architecture

> Verified against: `worker/app/scanner/*`, `worker/app/ingestion/*`, `worker/app/finding_engine/`, `worker/app/services/*`, `worker/app/asset_intel/`, `worker/app/risk_engine/`, `worker/app/tasks.py`, `worker/app/persistence.py`, `backend/app/api/routes/*`, `frontend/src/app/(app)/*`, `docker-compose.yml`, `scanners/*/Dockerfile`.
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
- **Scanner Plane** — Per-family Docker images in `scanners/` (nmap, nuclei, zap, nikto, tls, dns, subdomain, sast, sca, secrets, container, iac, api), invoked via `DockerRunner`.
- **Ingestion Plane** — `worker/app/ingestion/` (`service.py`, `archive.py`, `artifact_detection.py`, `scanner_routing.py`, `limits.py`) + `backend/app/api/routes/ingestions.py` — secure archive extraction (ZIP/TAR/TGZ) into isolated workspace, artifact detection, scanner routing, then `ScanContext` → `ScannerPipeline`.

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
| Ingestion Service | `worker/app/ingestion/` + `backend/app/api/routes/ingestions.py` | Archive validation, secure extraction (zip/tar), artifact detection (languages, manifests, IaC, API, secrets), scanner routing, project-scoped workspace preparation |
| Scanner Images | `scanners/*/Dockerfile` | Per-tool images, pinned versions/digests where practical, non-root where practical |

## Scanner Architecture

### Base Abstractions

- **`BaseScanner`** (`worker/app/scanner/base.py`) — ABC with identity (`name`, `category`, `family`, `description`), target/input (`target_types`, `input_type`, `requires_workspace`, `supported_profiles`), output (`output_format`), capabilities, timeout. Two entry points: `scan(target: str) -> str` (legacy, required) and `scan_with_context(ScanContext) -> str` (AppSec, defaults to `scan(context.target)`).
- **`ScanContext`** (`worker/app/scanner/base.py`) — `@dataclass` with `target`, `target_type`, `project_id`, `scan_id`, `workspace`, `metadata`. Added for AppSec without breaking legacy scanners.
- **`ScannerRegistry`** (`worker/app/scanner/registry.py`) — Registers 14 built-in scanners (`nmap`, `nuclei`, `http_fingerprint`, `zap`, `nikto`, `tls`, `dns`, `subdomain`, `sca`, `sast`, `secrets`, `container`, `iac`, `api`), exposes `get(name)` / `list()` / `register()`.
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

## Ingestion Architecture (P11.1)

`worker/app/ingestion/` — COMPLETE (foundation):

- **Service:** `IngestionService` (`service.py`) with `IngestionResult` dataclass (`ingestion_id`, `project_id`, `source_type`/`source_name`, `workspace_path`, `file_count`/`total_size`, `detected_languages`, `detected_artifact_types`, `artifact_details`, `recommended_scanners`/`scan_reasons`, `status`/`duration_ms`/`error_category`/`error_message`). Methods: `prepare_from_archive(archive_bytes, filename, project_id)` and `prepare_from_directory(source_path, project_id)` — both create isolated workspace via `create_workspace` (project_id prefix, 0o700), validate, extract, detect, route, return result, and guarantee `cleanup_workspace` on failure via `finally`/`shutil.rmtree` in caller. **Does not execute** package scripts, Makefiles, Dockerfiles, CI, hooks, binaries — only scans later.
- **Archive:** `archive.py` — `safe_extract_zip`/`safe_extract_tar`/`detect_archive_type` with Python stdlib (`zipfile`, `tarfile`). Two-pass validation: first validate every entry (`_validate_entry_name` rejects `../`, absolute `/`, Windows `C:\`/`\\`, `//`, null bytes), then symlink/hardlink checks (`_check_symlink_target` rejects absolute/`..` escape via `resolve().relative_to(workspace)`), then size/count limits (`MAX_ARCHIVE_SIZE` 100 MB, `MAX_EXTRACTED_SIZE` 500 MB, `MAX_FILE_COUNT` 10k, `MAX_FILE_SIZE` 50 MB, `MAX_ARCHIVE_BOMB_RATIO` 100, env-overridable), then extraction with streaming and post-extract `resolve().relative_to(workspace)` containment. `IngestionError` with safe `category` (`traversal`, `absolute_path`, `windows_path`, `symlink_escape`, `archive_too_large`, etc.) and bounded message (no raw content).
- **Detection:** `artifact_detection.py` — `detect_artifacts(workspace)` walks `rglob`, skips `ignored_dirs` (`.git` still counted for repo metadata), checks `LANGUAGE_MAP` (11 languages), `DEPENDENCY_MANIFESTS` (14 manifests), `SECRETS_CANDIDATES` (`.env`, `config`/`credential`, `.pem`/`.key`), `IAC_EXTENSIONS`/`IAC_FILENAMES` (`.tf`, `Dockerfile`, `k8s` yaml), `API_SPEC_NAMES` (openapi/swagger via name + content `openapi`/`swagger` in first 2KB), `REPO_METADATA` (`.git`, `.github`, `Jenkinsfile`), returns sorted deterministic counts (`total_files`, `source_files`, etc.) and `summarize_artifact_types`.
- **Routing:** `scanner_routing.py` — `recommend_scanners(detection, has_container_image=False)` maps `languages`→`sast`, `manifests`→`sca`, `secrets`→`secrets`, `iac_files`→`iac`, `api_specs`→`api`, flag `has_container_image`→`container`; returns `{recommended: sorted, reasons: {scanner: reason}, all_scanners}` without blindly executing. `web`/`full` profiles unchanged (8 web only).
- **Limits:** `limits.py` — safe defaults, `os.getenv` overridable, used in both two-pass validation and streaming extraction.
- **Backend API:** `backend/app/api/routes/ingestions.py` — `POST /api/v1/ingestions/prepare` (`project_id` Form + `file` UploadFile, `require_project_access`, `MAX_ARCHIVE_SIZE` check, `detect_archive_type`, same `archive.py` validation duplicated for backend (no worker import), `rglob` detection, `recommend_scanners`, `shutil.rmtree` cleanup, returns safe IngestionResult; no secrets in logs, error 400 with sanitized `detail`.
- **Flow:** `Repository/Artifact (ZIP/TAR/TGZ bytes + filename, project_id) → IngestionService → Input Validation (project_id, archive size/type) → Secure Extraction (validate every entry, enforce limits, handle symlinks) → Isolated Workspace (create_workspace, 0o700, project_id, resolve containment) → Artifact Detection → Scanner Routing → IngestionResult (file_count, total_size, languages, artifact_types, recommended_scanners) → ScanContext(workspace) → Existing ScannerPipeline` — no second pipeline.

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
- **Per-scanner parsers:** `nmap_parser`, `nuclei_parser`, `zap_parser`, `nikto_parser`, `tls_parser`, `dns_parser`, `subdomain_parser`, `http_fingerprint_parser`, `sast_parser` (SARIF → typed findings), `sca_parser` (SARIF → dependency vulns), `secrets_parser` (SARIF/legacy → `secret` findings, `source_file` assets, mandatory redaction), `container_parser` (SARIF → `container_image`/`container_layer`), `iac_parser` (Checkov JSON/SARIF → `iac_resource`), `api_parser` (SARIF → `api_endpoint`).

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
- **`change_detection.py`** — `detect_asset_changes` / `persist_change_events` — compares current vs previous assets/relationships (loaded single-query via `_load_target_assets_pre_mutation`), emits `created`/`updated`/`disappeared` events, `compute_asset_lifecycle_status` (active/stale). Contract: `persist_parsed_bundle` (persistence.py) must upsert `assets` (and relationships) BEFORE writing `asset_change_events`, because `asset_change_events.asset_id` is a FK to `assets.id` — writing events for brand-new assets first aborts the transaction (masked later as `InFailedSqlTransaction`). `persist_change_events` isolates each event insert in a SQLAlchemy savepoint (`begin_nested()`) so a single failed event cannot abort the surrounding persistence transaction.
- **`classification.py` / `enrich.py`** — Asset classification and metadata enrichment.

## Cloud Foundation (P12.1)

`worker/app/cloud/` — FOUNDATION (provider-neutral, no live SDK):

- **Provider:** `provider.py` (`SUPPORTED_PROVIDERS` `aws`/`gcp`/`azure`, `CloudProvider` + `CloudProviderCapabilities` (8 capabilities), `get_provider`/`list_providers`/`is_supported_provider`, `register_provider`, sample `regions`/`supported_services` per provider)
- **Models:** `models.py` (`CloudAccount` with `aws_account_id`/`gcp_project_id`/`azure_subscription_id`+`resource_group`/`region`/`credential_reference` opaque + `canonical_value()` → `cloud_account:{provider}:{account}:{region}`, `CloudResource` with `provider`/`resource_type`/`resource_id`/`region`/`service`/`name`/`account_id`/`tags`/`metadata` + `canonical_value()` → `cloud_resource:{provider}:{account}:{region}:{type}:{id}` with hash if >1024, `CloudDiscoveryResult`, `CloudRegion`, `CloudSecurityCheck`/`CloudCheckResult` (`to_finding_dict()` → `Finding` for `FindingEngine`))
- **Normalization:** `normalization.py` (`normalize_account_value`, `normalize_resource_value`, `sanitize_cloud_metadata` strips `secret`/`token`/`key`, `validate_provider`)
- **Discovery:** `discovery.py` (`CloudDiscoveryAdapter` abstract `discover(account) -> CloudDiscoveryResult`, `MockCloudDiscoveryAdapter` deterministic `provider-resource-{i}`, `contains` + `uses` relationships, `MockAWS/GCP/AzureAdapter` wrappers, no SDK, no network, `unsupported_provider` handling)
- **Checks:** `checks.py` (`CloudSecurityCheck` `check_id`/`title`/`provider`/`resource_type`/`severity`, `CloudCheckResult` `to_finding_dict()` → `Finding`, `DEFAULT_CHECKS` 3, `get_checks_for_provider`/`run_checks_for_resource`)
- **Asset:** `asset.py` (`cloud_account_to_asset`, `cloud_resource_to_asset` → `cloud_account`/`cloud_resource` canonical, `build_cloud_relationships` via `contains`/`uses`)
- **Reuse:** `Asset`/`AssetRelationship`/`Finding`/`Evidence`/`Risk`/`Asset.normalize`/`correlate`/`persistence` — no new cloud table, project-scoped `(project_id, asset_type, value)`, `cloud_account`/`cloud_resource` added to `CANONICAL_ASSET_TYPES`
- **No destructive actions:** No `delete`/`update`/`create` on cloud, no `subprocess` for `aws`/`gcloud`/`az` CLI, no shell interpolation of resource names, read-only discovery only

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

## Row-Level Security Foundation (Defense-in-Depth, Disabled — Preparation Only)

> Status: **FOUNDATION IMPLEMENTED** — `backend/app/db/rls.py` helper + `RLS_ENABLED=false` config.
> Enforcement: **NOT ENABLED** — no table has `ENABLE ROW LEVEL SECURITY`, no policies created, no migration.
> Application authorization (`get_current_user` + `require_project_access`) remains authoritative.

### Purpose

Provide a safe, reusable PostgreSQL-level defense-in-depth for organization/project
tenant isolation that can later complement (not replace) application-layer checks.

### Layers

```
Application authorization:  user -> organization -> project -> resource
        (get_current_user, require_project_access, WHERE project_id / organization_id)
                                |
RLS defense-in-depth (future):  authenticated/authorized request
                                -> verified tenant context (UUID-validated)
                                -> transaction: BEGIN
                                -> SELECT set_config('app.current_organization_id', :oid, true)
                                   SELECT set_config('app.current_project_id', :pid, true)
                                -> queries (policies use current_setting('app.current_organization_id', true))
                                -> COMMIT/ROLLBACK (context disappears)
                                -> database rows
```

### Helper

- **Location:** `backend/app/db/rls.py` — `is_rls_enabled()`, `validate_context_value()`,
  `set_tenant_context(db, organization_id, project_id?, user_id?)`, `clear_tenant_context()`,
  `get_current_tenant_context()`.
- **Mechanism:** `SELECT set_config(:k, :v, true)` with `is_local=true` (transaction-local,
  equivalent to `SET LOCAL`). GUCs: `app.current_organization_id`, `app.current_project_id`,
  `app.current_user_id`. Keys are trusted constants; values are bound parameters — never
  string-interpolated.
- **Validation:** UUID v4 strict via `uuid.UUID(..., version=4)`; rejects empty, non-UUID,
  and injection strings like `'; SET LOCAL ... --`.
- **Pool safety:** Requires explicit transaction (`with db.begin(): set_tenant_context(...)`);
  otherwise raises `RuntimeError` on PostgreSQL. `COMMIT`/`ROLLBACK` clears context, so
  `QueuePool` reuse cannot leak Company A context to the next request. No `SET` (session-scoped).
- **Dialect-safe:** No-op on non-PostgreSQL (SQLite in tests) after validation; `RLS_ENABLED=false`
  makes it a no-op everywhere.

### Future scope (not yet protected)

When enforcement is wired (deferred to RBAC phase), RLS will eventually protect tenant-owned
resources: **projects, scans, assets, findings, evidence, repositories, cloud accounts,
integrations, reports, jobs, audit logs**. No claim is made that these tables are RLS-protected yet.

### Policy design (deferred, not created)

Future policies must enforce `USING (organization_id = current_setting('app.current_organization_id', true)::uuid)`
or `USING (project_id = current_setting('app.current_project_id', true)::uuid)` with
`WITH CHECK` mirrors, role-aware where required, and `FORCE RLS` for table owners. Never
`USING (true)` (bypasses isolation). Policies remain **not created** in this phase.

## Enterprise Multi-Tenancy + RBAC Foundation (Transitional)

> **Status:** Membership tables + permission model implemented; enforcement is transitional (org fallback preserves existing access). Full strict enforcement is **TARGET**, not yet current.

### Tenancy Model

- **Organizations:** `organizations` (id, name, slug)
- **Users:** `users` (id, `organization_id` legacy primary org, `email`, `role` platform `super_admin`/`admin`/`member`)
- **OrganizationMemberships:** `organization_memberships` (`unique(organization_id, user_id)`, `role` ∈ {`member`, `org_admin`}, `status`, timestamps, FK CASCADE, indexes)
- **Projects:** `projects` (`organization_id` FK)
- **ProjectMemberships:** `project_memberships` (`unique(project_id, user_id)`, `role` ∈ {`viewer`, `analyst`, `project_admin`}, `status`, timestamps, FK CASCADE, indexes)

Migration `9f8e7d6c5b4a` creates both tables and populates `organization_memberships` from existing `users` (`admin`→`org_admin`, else `member`); `project_memberships` not auto-populated (creator not stored) — fallback preserves access (org member → `analyst`, org_admin → `project_admin` on existing projects).

### Strict Cutover (Per-Project Strict + RBAC_STRICT_MODE)

- `backend/app/core/config.py:RBAC_STRICT_MODE=false` (default transitional). `backend/app/api/deps.py::_effective_project_role` now per-project strict: if project has any explicit `project_membership` rows, missing membership → `None` (DENIED) without fallback; if project has zero explicit rows, fallback `org→project` is used unless `RBAC_STRICT_MODE=true` (global strict). New projects get explicit `project_admin` for creator and are immediately strict.
- Backfill: `backend/app/services/project_backfill.py` (`backfill_project_memberships(dry_run=True)`) classifies `ALREADY_BACKFILLED` / `SAFE_TO_BACKFILL` (0, no creator) / `AMBIGUOUS` (has activity) / `NO_EVIDENCE`, idempotent, supports `--dry-run`/`--apply`, reports for manual assignment. No fabrication for existing projects.

### Roles & Permissions

- **Platform:** `super_admin` (via `users.role`, bypass, future platform visibility with audit)
- **Organization:** `member` (read), `org_admin` (manage + all member perms + project.create/delete)
- **Project:** `viewer` (read), `analyst` (viewer + target.create, scan.execute, ingestion.create), `project_admin` (analyst + target.delete, project.delete/manage)

Centralized in `backend/app/core/permissions.py` (`ORG_ROLE_PERMISSIONS`, `PROJECT_ROLE_PERMISSIONS`, `SUPER_ADMIN_PERMISSIONS`).

### Authorization Flow

```
JWT → get_current_user → _is_super_admin? → bypass
  → _effective_org_role (OrganizationMembership or fallback User.organization_id)
  → _effective_project_role (ProjectMembership or fallback org→project mapping)
  → Permission check (role's permission set contains required permission) → 403 or allow
  → require_project_access (Project.organization_id == user.org via membership) → 404
  → WHERE project_id / organization_id predicate
```

`backend/app/api/deps.py` now exports `_is_super_admin`, `_effective_org_role`, `_effective_project_role`, `require_org_membership`, `require_project_role`, `require_permission`, `require_super_admin` plus legacy `require_project_access` updated to use membership fallback.

Transitional enforcement:
- `POST /projects` and `DELETE /projects/{id}` require `org_admin`
- `POST /targets` and `POST /scans` require `analyst`/`project_admin`
- Other reads still via `require_project_access` fallback (viewer can read)

### Future RLS Wiring (not yet)

```
JWT → authenticated user → org membership → project membership → permission → verified tenant context (UUID) → BEGIN → set_tenant_context(db, org, project, user) → RLS USING (...) → rows
```

Helper `backend/app/db/rls.py` remains `RLS_ENABLED=false` and not wired; will be called after `require_project_access` inside `with db.begin()` in enforcement phase.

### Audit Logging Foundation (Enterprise, Append-Only)

- **Model:** `audit_logs` (`id` UUID PK, `organization_id`/`project_id`/`actor_user_id`/`target_user_id` nullable FK `SET NULL` (survives user deletion/project deletion), `event_type`/`action`/`resource_type`/`resource_id`/`result`, `request_id`/`correlation_id`, `ip_address`/`user_agent`, `metadata` JSONB, `created_at`, indexes on `organization_id`, `project_id`, `actor_user_id`, `target_user_id`, `event_type`, `resource_type+resource_id`, `created_at`)
- **Service:** `backend/app/services/audit.py` — `AuditService.record(db, event_type, action, result, actor_user_id, organization_id, project_id, resource_type, resource_id, target_user_id, request_id, correlation_id, ip_address, user_agent, metadata)` — server-controlled context, sanitizes `metadata` via `sanitize_metadata` (redacts `password`, `secret`, `token`, etc., nested, size-bounded to `AUDIT_METADATA_MAX_BYTES=4096` from `config.py`), append-only (no update/delete API), uses same DB transaction as business mutation for consistency (`db.flush()` via savepoint; if outer rolls back audit rolls back; savepoint isolates missing-table in ephemeral test DBs, not production).
- **Taxonomies:** Centralized `EVENT_*` (auth, org/project/member, target, scan, finding, ingestion, cloud, authz denied), `RESULT_*` (`SUCCESS`/`FAILURE`/`DENIED`/`PARTIAL`), `RESOURCE_*` (organization, project, target, scan, etc.) — not scattered.
- **Tenant context:** Every audit carries `organization_id`/`project_id` derived from authorized resource, not client input; platform events may have `NULL` for pre-tenant failures. `RLS_ENABLED=false` still.
- **6B Wiring (COMPLETE):** `organization_members.py` `POST/PATCH/DELETE` → `ORGANIZATION_MEMBER_ADDED/UPDATED/REMOVED` (`organization_membership`, `organization_id` from path, `target_user_id`, `old_role`/`new_role`), `project_members.py` `POST/PATCH/DELETE` → `PROJECT_MEMBER_ADDED/UPDATED/REMOVED` (`project_membership`, `organization_id` from `project.organization_id`, `project_id`), `projects.py` `POST` → `PROJECT_CREATED` (`project`, `organization_id` from `current_user.organization_id`), `DELETE` → `PROJECT_DELETED` (captures `organization_id`/`project_id` before delete, survives via `SET NULL`). No audit on 403/404/409; same transaction as mutation; no new migration.
- **6C Wiring (COMPLETE):** `targets.py` `POST` → `TARGET_CREATED` (`target`, `metadata{target_type}`, tenant `project.organization_id`), `DELETE` → `TARGET_DELETED` (before `db.delete`, survives, `metadata{target_type}`); `scans.py` `POST` → `SCAN_CREATED` (`scan`, `metadata{profile,target_type}`, tenant `target->project->org`, same tx, `actor_user_id` from API user, mocked `celery_app.send_task` in tests); `worker/app/tasks.py` `execute_scan` → `SCAN_STARTED` (after `UPDATE scans status=running`, `actor NULL` system, tenant `scan->target->project->org`, `metadata{profile}`, same tx via savepoint), `SCAN_COMPLETED` (after `UPDATE scans status=completed` + `risk_engine.calculate`, `metadata{profile,scanners,finding_count,risk_score}`, `SUCCESS`), `SCAN_FAILED` (after terminal `status=failed` when `overall_scan_status != completed` or `except` fallback, `result=FAILURE`, `metadata{profile,scanners,error}` sanitized, intermediate per-scanner retry via `run_with_retries` does NOT emit terminal), `SCAN_CANCELLED` taxonomy exists but no cancellation code path found — not wired. Worker `_audit_scan_event` uses `db.begin_nested()` savepoint, `CAST(:meta AS JSONB)` on Postgres else plain text on SQLite, `NOW()`/`CURRENT_TIMESTAMP` dialect-aware, `get_project_id` + `SELECT organization_id` for tenant, metadata `_sanitize_audit_metadata` (redacts `password`/`secret`/`token` etc., 4096 cap). All scans `scan->target` ensures cross-tenant IDs never write other org's audit.
- **Future wiring:** Finding, ingestion, cloud, auth routes and additional background tasks remain **DEFERRED** (Phase 6D+). Read API and request/correlation ID middleware are **DEFERRED**.

### Membership Management APIs (Strict-ish Enforcement)

- **Organization members:** `backend/app/api/routes/organization_members.py` (`GET/POST/PATCH/DELETE /organizations/{org_id}/members`) — requires `org_admin`, validates user exists, duplicate 409, role assignment security (cannot grant `super_admin`, member cannot grant `org_admin`), cross-org 403, last-active-org_admin protection (409 if last), `backend/app/schemas/membership.py`.
- **Project members:** `backend/app/api/routes/project_members.py` (`GET/POST/PATCH/DELETE /projects/{project_id}/members`) — requires `project_admin` or `org_admin` (`_require_project_manage`), validates target user in same org, viewer/analyst cannot grant `project_admin`, cross-org 403, duplicate 409, no strict last project_admin (org_admin fallback ensures manageability).
- **Ingestion gap fixed:** `POST /ingestions/prepare` now requires `analyst`/`project_admin` (viewer → 403) after `require_project_access`.

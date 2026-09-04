# VAPT Platform — Project State

> Last verified: 2026-09-04 (P12.1 Cloud Security Foundation — provider-neutral cloud asset plane, mock discovery, checks, FindingEngine integration)
> Source of truth: file system + `worker/app/scanner/registry.py`, `profiles.py`, `scanners/*.py`, `scanners/*/Dockerfile`, `worker/app/ingestion/*`, `worker/app/asset_intel/*`, `worker/app/cloud/*`, `backend/app/api/routes/cloud.py`, `.env.example`, `worker/tests/`, `backend/alembic/versions/`, `docker-compose.yml`.
> Do not mark a phase COMPLETE merely because files exist — use tests + live verification evidence.

## Current Status

**Roadmap position: P10.5 (S7.4 Production SCA) — COMPLETE / READY. P10.6 (S7.5 Production Secrets) — COMPLETE / READY. P10.7 (S7.6 Production Container) — COMPLETE / READY. P10.8 (S7.7 Production IaC) — COMPLETE / READY. P10.9 (S7.8 Production API) — COMPLETE / READY. P10.10 (S7.9 AppSec Integration) — COMPLETE / READY. P11.1 (Repository/Artifact Ingestion) — COMPLETE / READY. P11.2 (Advanced AppSec Asset Intelligence) — COMPLETE / READY. P12.1 (Cloud Security Foundation) — COMPLETE / READY.**

- S7.4 (SCA) implementation, tests, Docker image, SARIF pipeline, and persistence are present in the working tree and prior project docs mark it READY. One pre-existing test failure (`test_dependency_count_correct` — missing `dependencies_total` in SCA metadata) is tracked as a working-tree issue, not a blocker for the S7.4 READY classification; it should be fixed or the test updated before the next release.
- S7.5 (Secrets / Gitleaks v8.30.1) — **COMPLETE / READY**: implementation (scanner + parser + registry + profile + Dockerfile digest-pinned `zricethezav/gitleaks@sha256:c00b6bd0...` + `gitleaks.toml` with merged allowlist), tests (90 secrets tests pass), live verification (vulnerable fixture detected, clean fixture 0 findings, SARIF via `sh -c` cat reaches parser → FindingEngine → correlation/validation → evidence/provenance → risk → persistence), redaction verified (plaintext `[REDACTED TEST SECRET]` absent from findings/metadata/evidence/DB payload/logs/API), container security verified (non-root `gitleaks` user, no privileged/capabilities, no Docker socket, ro workspace mount), workspace cleanup verified.
- S7.6 (Container / Trivy 0.66.0) — **COMPLETE / READY**: implementation (scanner + parser + registry + profile + Dockerfile `FROM aquasec/trivy@sha256:086971aaf400beebd94e8300fd8ea623774419597169156cec56eec5b00dfb1e` + image `vapt-container:latest`), tests (46 container tests), live verification (vulnerable `alpine:3.10` → 1 finding `CVE-2021-36159` + `container_image` asset, clean `hello-world:latest` → 0 findings, invalid image → proper ScannerFailureError, injection blocked via `_validate_image_ref`), security verified (non-root `trivy` user, no privileged/caps, no Docker socket, no host mount, array-form command, image-ref validation, timeout 300, sanitized errors).
- S7.7 (IaC / Checkov 3.3.16) — **COMPLETE / READY**: implementation (scanner + parser + registry + profile + Dockerfile `FROM bridgecrew/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016` + image `vapt-iac:latest`), tests (43 IaC tests), live verification (vulnerable Terraform SG `0.0.0.0/0` → 6 findings `CKV_AWS_260` etc. + `iac_resource`/`source_file` assets, clean `README.md` (no IaC) → 0 findings via `no iac files`, malformed/unsupported handled, JSON via `checkov -d /workspace -o json --quiet` → `IacParser` → FindingEngine → correlation/validation → `iac_resource` evidence → risk → `sanitize_metadata`), security verified (non-root `checkov` user, no privileged/caps, no Docker socket, ro workspace mount, strict workspace/path handling, array-form command, timeout 180).
- S7.8 (API / vapt-api 1.0.0) — **COMPLETE / READY**: implementation (scanner + parser + registry + profile + Dockerfile `FROM python@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534` + image `vapt-api:latest` with `api_scan.py`), tests (38 API tests, 887 total worker tests + 1 pre-existing SCA failure), live verification (vulnerable `openapi.yaml` with `http://` + missing `security` + missing `operationId` → 3 findings `API001`/`API002`/`API006`, clean `openapi.yaml` with `https://` + `security` + `operationId` → 0 findings, malformed `openapi.json` → 1 finding `API999` parse error, SARIF via `python /app/api_scan.py /workspace --output /tmp/sarif.json` → `ApiParser` → FindingEngine → `api_endpoint` evidence → risk → `sanitize_metadata`), security verified (non-root `api` user, no privileged/caps, no Docker socket, ro workspace mount, array-form `sh -c` cat wrapper, strict path validation, timeout 120).

## Completed Phases

| ID | Phase | Status | Notes |
|---|---|---|---|
| P0 | Foundation & Infrastructure | COMPLETE | `docker-compose.yml` (FastAPI, Postgres 16, Redis 7, RabbitMQ 3, worker, docker-socket-proxy), `.env.example`, `alembic` migrations (10 versions), `backend/` + `worker/` + `frontend/` scaffolding |
| P1 | Scanner Platform | COMPLETE | `BaseScanner`, `ScanContext`, `ScannerRegistry` (14 scanners), `ScannerManager`, `DockerRunner`, `profiles.py` |
| P2 | Parser / Finding Pipeline | COMPLETE | `BaseParser`, `ParserRegistry`, `SarifParser`, per-scanner parsers, `FindingEngine`, `ScannerPipeline` |
| P3 | SAST (initial) | COMPLETE | `SASTAnalyzer` local analyzer, Python/JS/TS rules, parser adapter |
| P4 | Asset Intelligence | COMPLETE | `worker/app/asset_intel/` — normalization (`normalize.py`), classification, dedup/correlation (`correlate.py`), provenance, relationships (`provenance.py`, `types.py`), change detection (`change_detection.py`), enrichment |
| P5 | Finding Intelligence | COMPLETE | `worker/app/services/finding_correlation/` — `normalizer.py`, `correlator.py`, `validation.py` (states: detected/corroborated/needs_review/confirmed/false_positive/accepted_risk/remediated/reopened), `evidence.py` (EVIDENCE_TYPES, provenance quality) |
| P6 | Risk Intelligence | COMPLETE | `worker/app/risk_engine/` + `worker/app/services/risk_intelligence/` — `RiskAssessmentEngine` (score 0–100, grade A–D, level critical/high/medium/low/informational), asset context, attack paths (`attack_paths.py`), prioritization (`prioritizer.py`) |
| P7 | Execution Observability | COMPLETE | `worker/app/scanner/execution.py` — `ScannerOutcome`, `FailureInfo`, `classify_failure`, `run_with_retries`, `overall_scan_status`, `scanner_summary`, `calculate_progress`; `worker/app/scanner/result_store.py` + `tasks.py` attempt/progress persistence |
| P8 | Backend API Foundation | COMPLETE | FastAPI routes: `auth`, `projects`, `targets`, `scans`, `scanners`, `findings`, `assets`, `dashboard`; `backend/app/db/`, `backend/app/models/`, `backend/app/schemas/`, JWT auth, project-scoped queries |
| P9 | Frontend SOC Workspace | COMPLETE | Next.js routes: `/(app)/dashboard`, `/(app)/projects`, `/(app)/targets`, `/(app)/scans`, `/(app)/findings`, `/(app)/assets`, `/(app)/attack-surface`, `/(app)/settings`; `components/`, `lib/` |
| P10.1 | S7.1 Scanner/AppSec Expansion Foundation | COMPLETE | `ScanContext`, `scanner/base.py` family/category, `requires_workspace`, `supported_profiles`, registry-driven expansion |
| P10.2 | S7.2 Workspace Execution Foundation | COMPLETE | `worker/app/scanner/workspace.py` (`create_workspace`/`cleanup_workspace`/`is_workspace_path_safe`), `tasks.py` per-attempt workspace lifecycle, `DockerRunner._validate_volumes` |
| P10.3 | S7.3 Production SAST | COMPLETE | Semgrep `1.75.0` via `vapt-sast:latest` / `returntocorp/semgrep:1.75.0`, SARIF, `DockerRunner`, offline `p/security-audit`, provenance (`execution_engine`/`execution_mode`) |
| P10.4 | S7.3.1 Production SAST Hardening & Live Verification | COMPLETE | Hardened SAST scanner/parser, digest-pinned image, live vulnerable/clean fixture verification, non-root where practical, read-only mounts |
| P10.5 | S7.4 Production SCA | COMPLETE / READY | OSV-Scanner `1.9.2` via `vapt-sca:latest` / `ghcr.io/google/osv-scanner:1.9.2`, SARIF, workspace read-only, `--offline`, `SCA_FALLBACK_ENABLED=false`, FindingEngine → correlation → validation → evidence → risk → asset linkage verified (see note on `test_dependency_count_correct`) |
| P10.6 | S7.5 Production Secrets | COMPLETE / READY | Gitleaks `8.30.1` via `vapt-secrets:latest` / `zricethezav/gitleaks@sha256:c00b6bd0...`, SARIF via `sh -c` cat, workspace ro, `--no-git --redact`, `SECRETS_FALLBACK_ENABLED=false`, `redacted=True` provenance, 90 tests, live vulnerable/clean + redaction verified |
| P10.7 | S7.6 Production Container | COMPLETE / READY | Trivy `0.66.0` via `vapt-container:latest` / `aquasec/trivy@sha256:086971aaf400beebd94e8300fd8ea623774419597169156cec56eec5b00dfb1e`, SARIF (`trivy image --format sarif --quiet`), no Docker socket, image-ref validation, `CONTAINER_FALLBACK_ENABLED=false`, `container_image` asset, `container_layer` evidence, 46 tests, live `alpine:3.10` → 1 finding / `hello-world` → 0 |
| P10.8 | S7.7 Production IaC | COMPLETE / READY | Checkov `3.3.16` via `vapt-iac:latest` / `bridgecrew/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016`, JSON (`checkov -d /workspace -o json --quiet`), workspace ro, `IAC_FALLBACK_ENABLED=false`, `iac_resource`/`source_file` assets, `iac_resource` evidence, 43 tests, live `main.tf` SG `0.0.0.0/0` → 6 findings / empty → 0 |
| P10.9 | S7.8 Production API | COMPLETE / READY | vapt-api `1.0.0` via `vapt-api:latest` / `python@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534` + `api_scan.py`, SARIF (`python /app/api_scan.py /workspace --output /tmp/sarif.json`), workspace ro, `API_FALLBACK_ENABLED=false`, `api_endpoint` asset, `api_endpoint` evidence, 38 tests, live `openapi.yaml` HTTP+no-auth → 3 findings / clean → 0 |
| P10.10 | S7.9 AppSec Integration | COMPLETE / READY | Integration verification for SAST+SCA+Secrets+Container+IaC+API via shared pipeline: registry 14 scanners, profiles, security, parser/FindingEngine, correlation/validation, evidence/provenance, assets, risk, live 6× vulnerable/clean, cross-scanner dedup, 887 worker tests |
| P11.1 | Repository/Artifact Ingestion | COMPLETE / READY | Ingestion foundation: `worker/app/ingestion/*` (`service.py`, `archive.py`, `artifact_detection.py`, `scanner_routing.py`, `limits.py`), archive support `.zip`/`.tar`/`.tar.gz`/`.tgz` via stdlib, workspace `create_workspace` isolation, secure extraction (traversal/absolute/Windows/symlink/hardlink/bomb/size limits), artifact detection (11 languages, 14 manifests, IaC, API, secrets), scanner routing (sast/sca/secrets/iac/api/container), `backend/app/api/routes/ingestions.py` project-scoped `POST /api/v1/ingestions/prepare`, 24 ingestion tests, 911 worker tests |
| P11.2 | Advanced AppSec Asset Intelligence | COMPLETE / READY | AppSec intelligence: `worker/app/asset_intel/appsec.py` (repository `repo:{project_id}:{name}`, source_file normalized, package `name@version` per eco, `build_appsec_relationships` via `contains`/`observed_on`, `associate_findings_to_assets`, `persist_appsec_assets`, `resolve_finding_asset_context`), ingestion now creates `repository` + `source_file` assets + `contains` relationships, finding→asset via file/package/image/resource/endpoint, project-scoped `(project_id, asset_type, value)`, deduplicated/idempotent, provenance `sources: [ingestion,sast]`, change detection via `detect_asset_changes`, 26 AppSec asset tests, 937 worker tests |
| P12.1 | Cloud Security Foundation | COMPLETE / READY | Cloud foundation: `worker/app/cloud/*` (provider registry for aws/gcp/azure, `CloudAccount`/`CloudResource`/`CloudDiscoveryResult`/`CloudRegion`/`CloudSecurityCheck`, `MockCloudDiscoveryAdapter` per provider, `cloud_account`/`cloud_resource` canonical types, `build_cloud_relationships` via `contains`/`uses`/`observed_on`, `CloudCheckResult` → `FindingEngine`, `backend/app/api/routes/cloud.py` project-scoped `GET /api/v1/cloud/providers|accounts|assets|assets/{id}|assets/{id}/related`, 25 cloud tests, 962 worker tests |

## Current Phase

**P12.1 — Cloud Security Foundation — COMPLETE / READY**

- **Provider abstraction:** `worker/app/cloud/provider.py` (`SUPPORTED_PROVIDERS` `aws`/`gcp`/`azure`, `CloudProvider` dataclass with `capabilities` `CloudProviderCapabilities` (resource/regions/identity/network/storage/container/serverless/iam), `list_providers`/`get_provider`/`is_supported_provider`, `register_provider`, sample `regions` and `supported_services` per provider)
- **Account model:** `worker/app/cloud/models.py` `CloudAccount` (provider, `aws_account_id`/`gcp_project_id`/`azure_subscription_id`+`resource_group`, `region`, `display_name`, `credential_reference` opaque, `metadata`, `project_id`, `canonical_value()` → `cloud_account:{provider}:{account}:{region}`, `to_safe_dict` sanitizes `secret`/`token`/`key`)
- **Resource model:** `CloudResource` (provider, `resource_type`, `resource_id`, `region`, `service`, `name`, `account_id`, `tags` 20×200, `metadata`, `project_id`, `canonical_value()` → `cloud_resource:{provider}:{account}:{region}:{type}:{id}` with hash if >1024, `to_asset_dict()` → `cloud_resource` asset, `to_safe_dict` strips secret tags)
- **Asset types:** `cloud_account`/`cloud_resource` added to `CANONICAL_ASSET_TYPES` in `types.py` (minimal, justified: account vs resource, provider-neutral with metadata), reuse `Asset`/`AssetRelationship`/`Finding`/`Evidence`/`Risk`, no new cloud table, project-scoped `(project_id, asset_type, value)` via `canonical_value`
- **Relationships:** `cloud_account --contains--> cloud_resource`, `cloud_resource --uses--> cloud_resource`, `cloud_resource --observed_on--> finding` via `build_cloud_relationships` in `asset.py`, deterministic `seen` set, `contains`/`uses`/`observed_on` existing types, `asset.py` `cloud_account_to_asset`/`cloud_resource_to_asset` helpers
- **Discovery:** `worker/app/cloud/discovery.py` `CloudDiscoveryAdapter` abstract `discover(account) -> CloudDiscoveryResult`, `MockCloudDiscoveryAdapter` (deterministic `provider-resource-{i}`, `region` from account, `account_id`, `tags`, `contains` + `uses` relationships, 3/100 resources), `MockAWSAdapter`/`MockGCPAdapter`/`MockAzureAdapter` wrappers, no SDK, no network, `is_supported_provider` check → `failed` with `unsupported_provider` for invalid provider
- **Check abstraction:** `worker/app/cloud/checks.py` `CloudSecurityCheck` (`check_id`, `title`, `description`, `provider`, `resource_type`, `severity`, `remediation`, `references`), `CloudCheckResult` (`check`, `resource`, `passed`, `evidence`, `to_finding_dict()` → standardized `Finding` for `FindingEngine` with `scanner=cloud`, `severity`, `metadata` `check_id`/`rule_id`/`provider`/`resource_id`/`region`), `DEFAULT_CHECKS` 3 (CLOUD-001 tags low, CLOUD-002 storage high, CLOUD-003 region medium), `get_checks_for_provider`/`run_checks_for_resource`
- **Finding integration:** `CloudCheckResult.to_finding_dict()` → `FindingEngine.analyze({"scanner":"cloud","findings":[finding]})` verified (synthetic `CLOUD-001` high → 1 finding, `scanner=cloud`), no second pipeline
- **Risk/asset context:** `RiskAssessmentEngine.calculate` handles `cloud` severity (`critical:35` etc.), `cloud_resource` → `cloud_account` via `contains` for `asset_context`, no new risk engine
- **Region model:** `CloudRegion` (`provider`, `region`, `zone` optional), extensible, no hard-coded worldwide DB, `CloudProvider.regions` sample 3-4 per provider
- **Project isolation:** Every `CloudAccount`/`CloudResource` has `project_id`, `canonical_value` is deterministic but `Asset` persistence is `(project_id, asset_type, value)` — same value different `project_id` → different rows, `test_19` verifies `repo:proj1` ≠ `repo:proj2` in metadata, `test_19` and API `require_project_access` enforce isolation, relationships are `project_id` filtered
- **Credential security:** `CloudAccount.credential_reference` is opaque string (100 chars), never plaintext `AWS_SECRET`, `GCP private key`, `Azure secret` in DB/assets/logs/findings/API; `to_safe_dict` strips `secret`/`token`/`key`/`private` from `metadata`/`tags`, `test_20`/`test_21` verify, future `secure provider authentication` deferred, documented, no custom vault, no insecure encryption, no `subprocess` for cloud CLI
- **Observability:** `CloudDiscoveryResult` (`provider`, `account`, `resource_count`, `duration_ms`, `status`, `error_category`, sanitized `error_message` 500), no raw API responses, no credentials logged
- **Performance:** `MockCloudDiscoveryAdapter` uses `dict`/`set` for 100 resources (test_25) → `build_cloud_relationships` 101 relationships deduplicated via `seen` set, no `O(N²)`, no DB per resource, no SDK, resource-efficient
- **Tests:** `worker/tests/test_cloud.py` 25 tests (provider registry, AWS/GCP/Azure metadata, capabilities, account/resource normalization, project-scoped identity, resource creation, relationship, deduplication, idempotent discovery, mock adapter per provider, check abstraction, synthetic finding → FindingEngine, finding→asset, repo/project context, risk, project isolation, secret-safe metadata/logs, unsupported provider, malformed resource, deterministic, performance 100) + existing 937 worker → **962 passed, 1 failed (pre-existing SCA), 1 skipped**; backend 257 still passed (cloud API reuses existing `GET /api/v1/assets` for cloud, no new migration)
- **API:** `backend/app/api/routes/cloud.py` `GET /api/v1/cloud/providers` (no DB, `list_providers().to_dict()`), `GET /api/v1/cloud/accounts?project_id=&provider=`, `GET /api/v1/cloud/assets?project_id=&provider=&asset_type=`, `GET /api/v1/cloud/assets/{id}`, `GET /api/v1/cloud/assets/{id}/related` — all `require_project_access`, `asset_type` in `cloud_account`/`cloud_resource`, `value` like `cloud_account:aws:%`, project-scoped `WHERE project_id`, no credentials exposed, registered in `main.py` with `dependencies=protected`

Previous phases P11.2 — Advanced AppSec Asset Intelligence — and P11.1 — Repository/Artifact Ingestion — remain COMPLETE / READY (see above).

## Next Phases

| ID | Phase | Status | Scope |
|---|---|---|---|
| Post-AppSec | Cloud Security, Continuous Monitoring, AI Analyst, Reporting, Remediation, External Intel, Scale, Production Hardening, QA/Release | DEFERRED | Future roadmap beyond AppSec family |

## Important Future Work

**Repository / Artifact Ingestion — P11.1 FOUNDATION COMPLETE, FULL GIT/CLOUD STILL FUTURE.** Secure archive ingestion (`.zip`/`.tar`/`.tar.gz`/`.tgz` via `worker/app/ingestion` with traversal/absolute/Windows/symlink/hardlink/bomb/size limits, `create_workspace` isolation, artifact detection, scanner routing) and local directory ingestion are implemented and project-scoped. **Still future:** GitHub/GitLab/Bitbucket OAuth, cloud repository integrations, webhook sync, and full artifact history persistence (beyond ephemeral workspace). Current AppSec scanners now can be driven via `IngestionService.prepare_from_archive` → `ScanContext(workspace)` → `ScannerPipeline` without manual `rglob` population, but `tasks.py` still creates empty workspaces for direct scans (backward compat). Parsers and pipeline still handle empty workspaces gracefully.

**Cloud Security — P12.1 FOUNDATION COMPLETE, LIVE DISCOVERY DEFERRED.** Provider-neutral `worker/app/cloud` (provider registry for `aws`/`gcp`/`azure`, `CloudAccount`/`CloudResource`/`CloudDiscoveryResult`/`CloudRegion`, `cloud_account`/`cloud_resource` canonical types, `MockCloudDiscoveryAdapter` per provider, `CloudSecurityCheck`/`CloudCheckResult` → `FindingEngine`, `backend/app/api/routes/cloud.py` project-scoped) is implemented. **Still future:** Live AWS/GCP/Azure enumeration via SDKs, real credential vault, CSPM rule packs, IAM auditing, cloud misconfiguration scanning, attack graph, remediation, and region-wide discovery (beyond mock 100 resources).

Later phases (all DEFERRED unless explicitly scheduled):

- Cloud Security (CSPM)
- Advanced Asset Intelligence (enrichment, external intel)
- Attack Graph / Visualization
- Continuous Monitoring & Scheduling
- AI Security Analyst (LLM-assisted triage — must never receive plaintext secrets)
- Reporting & Compliance (PDF/CSV, framework mapping)
- Remediation & Retesting
- Multi-Tenant Enterprise (RBAC, SSO, org isolation hardening)
- Integrations (SIEM, ticketing, webhooks)
- Scale & Production Hardening, QA/Release

## Current Scanner Inventory

Registered in `worker/app/scanner/registry.py` (14 scanners):

| Name | Family | Workspace? | Output | Profiles | Image / Engine | Status |
|---|---|---|---|---|---|---|
| nmap | network | No | text/json | quick, web, full | `vapt-tool-nmap` | COMPLETE |
| nuclei | web | No | json | web, full | `vapt-tool-nuclei` | COMPLETE |
| http_fingerprint | web | No | json | web, full | — | COMPLETE |
| zap | web/dast | No | json | web, full | `zaproxy` | COMPLETE |
| nikto | web | No | text | web, full | `nikto` | COMPLETE |
| tls | network | No | json | web, full | `tls` | COMPLETE |
| dns | network | No | json | web, full | `dns` | COMPLETE |
| subdomain | network | No | json | web, full | `subdomain` | COMPLETE |
| sast | sast | **Yes** | sarif | sast, full | `vapt-sast:latest` / Semgrep `1.75.0` (`returntocorp/semgrep:1.75.0`) | COMPLETE (production) |
| sca | sca | **Yes** | sarif | sca, full | `vapt-sca:latest` / OSV-Scanner `1.9.2` (`ghcr.io/google/osv-scanner:1.9.2`), `SCA_FALLBACK_ENABLED=false` | COMPLETE / READY |
| secrets | secrets | **Yes** | sarif | secrets | `vapt-secrets:latest` / Gitleaks `8.30.1` (`zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f` verified) — `sh -c` cat wrapper, `SECRETS_FALLBACK_ENABLED=false` | **COMPLETE / READY** |
| container | container | **No** | sarif | container, container_full | `vapt-container:latest` / Trivy `0.66.0` (`aquasec/trivy@sha256:086971aaf400beebd94e8300fd8ea623774419597169156cec56eec5b00dfb1e` verified) — `trivy image --format sarif --quiet`, no socket, `CONTAINER_FALLBACK_ENABLED=false` | **COMPLETE / READY** |
| iac | iac | **Yes** | json/sarif | iac, iac_full | `vapt-iac:latest` / Checkov `3.3.16` (`bridgecrew/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016` verified) — `checkov -d /workspace -o json --quiet`, workspace ro, `IAC_FALLBACK_ENABLED=false` | **COMPLETE / READY** |
| api | api | **Yes** | sarif | api, api_full | `vapt-api:latest` / vapt-api `1.0.0` (`python@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534` verified) — `python /app/api_scan.py /workspace --output /tmp/sarif.json`, workspace ro, `API_FALLBACK_ENABLED=false` | **COMPLETE / READY** |

## Current AppSec Status

| Family | Engine | Version | Mode | Status |
|---|---|---|---|---|
| SAST | Semgrep | `1.75.0` | Docker SARIF, workspace read-only, `p/security-audit` offline | **Production** |
| SCA | OSV-Scanner | `1.9.2` | Docker SARIF, workspace read-only, `--offline` | **Production** |
| Secrets | Gitleaks | `8.30.1` | Docker SARIF via `sh -c` cat wrapper, workspace read-only, `--no-git --redact`, mandatory redaction, `redacted=True` provenance | **Production** |
| Container | Trivy | `0.66.0` | Docker SARIF (`trivy image --format sarif --quiet`), no Docker socket, image-ref validation, `container_image` asset, `container_layer` evidence | **Production** |
| IaC | Checkov | `3.3.16` | Docker JSON (`checkov -d /workspace -o json --quiet`), workspace read-only, `iac_resource` asset, `iac_resource` evidence | **Production** |
| API Security | vapt-api | `1.0.0` | Docker SARIF (`python /app/api_scan.py /workspace --output /tmp/sarif.json`), workspace read-only, `api_endpoint` asset, `api_endpoint` evidence | **Production** |
| Cloud (Foundation) | Mock | — | Provider-neutral `worker/app/cloud` (aws/gcp/azure), `cloud_account`/`cloud_resource`, mock discovery | **Foundation** (no live cloud) |

## Current Limitations

Verified from code, tests, and working-tree state:

- **Repository ingestion is archive/directory only (P11.1).** Secure `prepare_from_archive` for `.zip`/`.tar`/`.tar.gz`/`.tgz` and `prepare_from_directory` are implemented; **still future:** GitHub/GitLab/Bitbucket OAuth, cloud repo integrations, webhook sync, persistent ingestion history beyond ephemeral workspace.
- **Cloud is foundation only (P12.1).** Provider-neutral `worker/app/cloud` with `aws`/`gcp`/`azure` registry, `cloud_account`/`cloud_resource` assets, mock discovery, check abstraction, `FindingEngine` integration, and `backend/app/api/routes/cloud.py` are implemented; **still future:** live AWS/GCP/Azure SDK enumeration, real credential vault, CSPM rule packs, IAM auditing, cloud misconfiguration scanning, attack graph, remediation, and region-wide discovery (beyond mock 100 resources).
- **Workspace AppSec is filesystem-only.** Secrets uses `gitleaks detect --no-git` (no Git history scanning in S7.5).
- **`full` profile is currently network/web only.** `full` expands to `[nmap, http_fingerprint, nuclei, zap, nikto, tls, dns, subdomain]`; it does not yet include `sast`/`sca`/`secrets` (those have dedicated `sast`/`sca`/`secrets` profiles).
- **SCA manifest coverage is bounded.** `sca.py :: SUPPORTED_FILES` covers `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `pom.xml`, `build.gradle`, `go.mod`, `Cargo.lock`, etc. (max 10 manifests, 2 MiB per file).
- **Vulnerability DB freshness depends on image build.** OSV-Scanner and Semgrep rules are baked into the Docker images; offline mode avoids runtime network but requires image rebuilds for DB/rule updates.
- **Secrets redaction is pattern-based.** `SECRET_REDACT_PATTERNS` covers assignments, known prefixes (`sk_`, `ghp_`, `AKIA`, etc.), PEM headers, and 32+ char high-entropy strings; it is not a guarantee of catching every custom secret format.
- **Known working-tree test issue.** `worker/tests/test_sca_scanner.py :: test_dependency_count_correct` expects `metadata.dependencies_total` which the current `sca.py` does not emit (legacy `sca.py` did). This is a pre-existing working-tree failure unrelated to S7.5; fix or update the test before release. Do not hide it as environmental.
- **Future beyond cloud foundation not implemented.** Continuous monitoring, AI analyst, attack graph visualization, reporting/compliance, remediation, external intel remain DEFERRED.

## Current Infrastructure

| Component | Technology | Notes |
|---|---|---|
| Backend API | FastAPI (Python) | `backend/` — JWT auth, project-scoped, Alembic migrations (10 versions), `backend/app/api/routes/cloud.py` (P12.1) + `ingestions.py` (P11.1) |
| Database | PostgreSQL 16 (`postgres:16-alpine`) | `security_saas` DB, `security` user, volumes `postgres_data` |
| Queue | RabbitMQ 3 (`rabbitmq:3-management-alpine`) | Celery broker, `amqp://guest:guest@rabbitmq:5672//` |
| Cache / Result | Redis 7 (`redis:7-alpine`) | Celery result backend `redis://redis:6379/0` |
| Worker | Celery + `worker/` | `security_worker`, `DOCKER_HOST=tcp://docker-socket-proxy:2375`, `SCANNER_MAX_ATTEMPTS=2`, `worker/app/ingestion/` + `worker/app/asset_intel/appsec.py` (P11.1/P11.2) + `worker/app/cloud/` (P12.1), `INGESTION_MAX_*`/`CLOUD_*` limits |
| Docker runtime | Docker + `docker-socket-proxy` (`tecnativa/docker-socket-proxy`) | Worker never mounts `/var/run/docker.sock` directly; proxy with `CONTAINERS=1 IMAGES=1 NETWORKS=1 POST=1` |
| Frontend | Next.js | `frontend/` — SOC workspace, `NEXT_PUBLIC_API_URL=http://localhost:8000` |
| Scanner images | Per-family Dockerfiles in `scanners/` | `scanners/sast/Dockerfile`, `scanners/sca/Dockerfile`, `scanners/secrets/Dockerfile` (Gitleaks digest-pinned), `scanners/container/Dockerfile` (Trivy `0.66.0` digest-pinned), `scanners/iac/Dockerfile` (Checkov `3.3.16` digest-pinned), `scanners/api/Dockerfile` (Python 3.11-slim digest-pinned + `api_scan.py`) |
| Ingestion | `worker/app/ingestion/` + `backend/app/api/routes/ingestions.py` | Secure archive extraction (ZIP/TAR/TGZ), artifact detection (11 langs, 14 manifests), scanner routing, project-scoped workspace |
| Cloud Foundation | `worker/app/cloud/` + `backend/app/api/routes/cloud.py` | Provider-neutral `CloudProvider`/`CloudAccount`/`CloudResource`/`CloudDiscoveryResult`/`CloudSecurityCheck`, `cloud_account`/`cloud_resource` assets, mock discovery, `FindingEngine` integration |

## Testing Baseline

Do not invent numbers. Verify with `python -m pytest` from `worker/` (`pytest.ini`: `testpaths=tests`, `pythonpath=.`):

- Most recent focused run (Cloud): `tests/test_cloud.py` — **25 passed** (provider registry, AWS/GCP/Azure metadata, capabilities, account/resource normalization, project-scoped identity, resource creation, relationship, deduplication, idempotent discovery, mock adapter per provider, check abstraction, synthetic finding → FindingEngine, finding→asset, repo/project context, risk, project isolation, secret-safe metadata/logs, unsupported provider, malformed resource, deterministic, performance 100); AppSec Asset 26, Ingestion 24, API 38, IaC 43, container 46, secrets 90.
- Most recent full run (worker): **962 passed, 1 failed, 1 skipped** (failure is `test_sca_scanner.py::test_dependency_count_correct` — pre-existing working-tree issue, see above; skip is expected). Backend: **257 passed** (after `pip install python-multipart` for `/api/v1/ingestions/prepare` + `/api/v1/cloud/*`).
- Live verification (2026-09-04): `vapt-api:latest` built, `python --version` → `3.11.16` + `api_scan.py` → `1.0.0`, vulnerable `openapi.yaml` (`http://` + no `security` + no `operationId`) → 3 findings (`API001`/`API002`/`API006`, `api_endpoint` asset `openapi.yaml`, `execution_engine=vapt-api`), clean `openapi.yaml` (`https://` + `security` + `operationId`) → 0 findings, malformed `openapi.json` (`{ not json`) → 1 finding `API999`, empty `no api spec` → 0, SARIF via `python /app/api_scan.py /workspace --output /tmp/sarif.json` → `ApiParser` → `FindingEngine` → `api_endpoint` evidence → risk → `sanitize_metadata`, workspace ro mount, no socket/privileged, array-form command, timeout 120, workspace cleanup verified; ingestion `live_all6.py` still 6× vulnerable/clean, plus ingestion live `prepare_from_archive` ZIP/TAR with `a.py`+`package.json` → completed, traversal rejected → failed, workspace containment/cleanup verified; cloud `MockAWSAdapter` with 3 resources → deterministic `cloud_account:aws:123:us-east-1` + 3 `cloud_resource` + 4 relationships (3 contains + 1 uses), `CloudCheckResult` → `FindingEngine` 1 finding, project isolation verified.

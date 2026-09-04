# VAPT Platform — Project State

> Last verified: 2026-09-04 (live verification + regression — IaC Checkov 3.3.16, Terraform/Dockerfile, workspace ro, SARIF/JSON pipeline)
> Source of truth: file system + `worker/app/scanner/registry.py`, `profiles.py`, `scanners/*.py`, `scanners/*/Dockerfile`, `.env.example`, `worker/tests/`, `backend/alembic/versions/`, `docker-compose.yml`.
> Do not mark a phase COMPLETE merely because files exist — use tests + live verification evidence.

## Current Status

**Roadmap position: P10.5 (S7.4 Production SCA) — COMPLETE / READY. P10.6 (S7.5 Production Secrets) — COMPLETE / READY. P10.7 (S7.6 Production Container) — COMPLETE / READY. P10.8 (S7.7 Production IaC) — COMPLETE / READY.**

- S7.4 (SCA) implementation, tests, Docker image, SARIF pipeline, and persistence are present in the working tree and prior project docs mark it READY. One pre-existing test failure (`test_dependency_count_correct` — missing `dependencies_total` in SCA metadata) is tracked as a working-tree issue, not a blocker for the S7.4 READY classification; it should be fixed or the test updated before the next release.
- S7.5 (Secrets / Gitleaks v8.30.1) — **COMPLETE / READY**: implementation (scanner + parser + registry + profile + Dockerfile digest-pinned `zricethezav/gitleaks@sha256:c00b6bd0...` + `gitleaks.toml` with merged allowlist), tests (90 secrets tests pass), live verification (vulnerable fixture detected, clean fixture 0 findings, SARIF via `sh -c` cat reaches parser → FindingEngine → correlation/validation → evidence/provenance → risk → persistence), redaction verified (plaintext `[REDACTED TEST SECRET]` absent from findings/metadata/evidence/DB payload/logs/API), container security verified (non-root `gitleaks` user, no privileged/capabilities, no Docker socket, ro workspace mount), workspace cleanup verified.
- S7.6 (Container / Trivy 0.66.0) — **COMPLETE / READY**: implementation (scanner + parser + registry + profile + Dockerfile `FROM aquasec/trivy@sha256:086971aaf400beebd94e8300fd8ea623774419597169156cec56eec5b00dfb1e` + image `vapt-container:latest`), tests (46 container tests), live verification (vulnerable `alpine:3.10` → 1 finding `CVE-2021-36159` + `container_image` asset, clean `hello-world:latest` → 0 findings, invalid image → proper ScannerFailureError, injection blocked via `_validate_image_ref`), security verified (non-root `trivy` user, no privileged/caps, no Docker socket, no host mount, array-form command, image-ref validation, timeout 300, sanitized errors).
- S7.7 (IaC / Checkov 3.3.16) — **COMPLETE / READY**: implementation (scanner + parser + registry + profile + Dockerfile `FROM bridgecrew/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016` + image `vapt-iac:latest`), tests (43 IaC tests, 849 total worker tests + 1 pre-existing SCA failure), live verification (vulnerable Terraform SG `0.0.0.0/0` → 6 findings `CKV_AWS_260` etc. + `iac_resource`/`source_file` assets, clean `README.md` (no IaC) → 0 findings via `no iac files`, malformed/unsupported handled, JSON via `checkov -d /workspace -o json --quiet` → `IacParser` → FindingEngine → correlation/validation → `iac_resource` evidence → risk → `sanitize_metadata`), security verified (non-root `checkov` user, no privileged/caps, no Docker socket, ro workspace mount, strict workspace/path handling, array-form command, timeout 180).

## Completed Phases

| ID | Phase | Status | Notes |
|---|---|---|---|
| P0 | Foundation & Infrastructure | COMPLETE | `docker-compose.yml` (FastAPI, Postgres 16, Redis 7, RabbitMQ 3, worker, docker-socket-proxy), `.env.example`, `alembic` migrations (10 versions), `backend/` + `worker/` + `frontend/` scaffolding |
| P1 | Scanner Platform | COMPLETE | `BaseScanner`, `ScanContext`, `ScannerRegistry` (11 scanners), `ScannerManager`, `DockerRunner`, `profiles.py` |
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

## Current Phase

**P10.8 — S7.7 Production IaC — COMPLETE / READY**

- Engine: Checkov `3.3.16`, image `vapt-iac:latest` (Dockerfile `FROM bridgecrew/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016` / `3.3.16` verified via `checkov --version` at build), fallback `bridgecrew/checkov@sha256:7407699a91a556849ae66e05c3753f58cf0ce922aa6ddfac7839aad4f390c016` (digest-pinned, `USER checkov`, `ENTRYPOINT []`).
- Scanner: `worker/app/scanner/scanners/iac.py` — `IacScanner`, `requires_workspace=True`, `target_types={"repository","project","directory"}`, `supported_profiles={"iac","iac_full"}`, array-form `checkov -d /workspace --framework all -o json --quiet` (no shell, ro mount `/workspace`, strict `resolve().relative_to` + ignored dirs `{.git, node_modules, venv, ...}`), `IAC_EXTENSIONS={.tf,.yaml,.yml,.json}` + `IAC_FILENAMES={Dockerfile, docker-compose.*}`, fallback `IAC_FALLBACK_ENABLED=false`, provenance `execution_engine=checkov`, timeout 180.
- Parser: `worker/app/scanner/parsers/iac_parser.py` — handles Checkov JSON (`results.failed_checks` → findings) and SARIF fallback via `SarifParser`; sets `evidence_type="iac_resource"`, preserves `check_id`/`rule_id`, `file`/`line`, `resource`, `framework`, `severity`, creates `iac_resource` + `source_file` assets, `iac_resource` asset type now canonical in `types.py`.
- Registry/profile: `ScannerRegistry` registers `IacScanner` (now 13 scanners); `ParserRegistry` registers `IacParser`; `profiles.py` has `iac: ["iac"]`, `iac_full: ["iac"]`.
- Persistence/assets: `iac_resource` asset type (added to `CANONICAL_ASSET_TYPES`), `iac_resource` evidence type (existing), `sanitize_metadata` preserves IaC fields, project isolation via `persist_parsed_bundle`.
- Tests: `worker/tests/test_iac_scanner.py` (21), `test_iac_parser.py` (13), `test_iac_pipeline.py` (9) — **43 IaC tests pass**; container 46, secrets 90, total **849 passed, 1 failed (pre-existing SCA), 1 skipped**; backend 257.
- **Verification:** Docker image builds (`3.3.16` verified, `USER checkov`), live vulnerable Terraform `aws_security_group` `0.0.0.0/0` → 6 findings (`CKV_AWS_260` etc., `iac_resource`/`source_file` assets, `execution_engine=checkov`, `iac_resource` evidence, FindingEngine → correlation/validation → risk), clean `README.md` (no IaC) → 0 findings via `no iac files`, malformed/unsupported handled, JSON via `checkov -d /workspace -o json --quiet` correctly parsed, workspace ro mount, no socket/privileged, strict path handling, `checkov` timeout/failure via `ScannerFailureError`, workspace cleanup verified.

Previous phases P10.7 — S7.6 Container — and P10.6 — S7.5 Secrets — remain COMPLETE / READY (see above).

## Next Phases

| ID | Phase | Status | Scope |
|---|---|---|---|
| P10.9 | S7.8 API Security / Advanced DAST | PLANNED | OpenAPI/endpoint discovery, authenticated scans, expanded ZAP/Nuclei coverage |
| P10.10 | S7.9 AppSec Integration Verification | PLANNED | Cross-family pipeline verification, full-profile orchestration, unified reporting |

## Important Future Work

**Repository / Artifact Ingestion — FUTURE, NOT YET IMPLEMENTED.** No GitHub/GitLab/arbitrary-Git cloning, no artifact upload, no webhooks, no automatic sync exists. Current workspace scanners (sast, sca, secrets) operate on **manually populated workspaces**: the orchestrator (`tasks.py`) creates an empty isolated `tempfile.mkdtemp` (0o700) per scan/attempt, and the caller/test harness populates it. Parsers and the pipeline handle empty workspaces gracefully (empty findings with `execution_engine`/`execution_mode` provenance, not a failure). Do not implement ingestion during S7.5–S7.8.

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

Registered in `worker/app/scanner/registry.py` (13 scanners):

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

API scanner is not registered yet (`profiles.py` has empty `api` entry — PLANNED).

## Current AppSec Status

| Family | Engine | Version | Mode | Status |
|---|---|---|---|---|
| SAST | Semgrep | `1.75.0` | Docker SARIF, workspace read-only, `p/security-audit` offline | **Production** |
| SCA | OSV-Scanner | `1.9.2` | Docker SARIF, workspace read-only, `--offline` | **Production** |
| Secrets | Gitleaks | `8.30.1` | Docker SARIF via `sh -c` cat wrapper, workspace read-only, `--no-git --redact`, mandatory redaction, `redacted=True` provenance | **Production** |
| Container | Trivy | `0.66.0` | Docker SARIF (`trivy image --format sarif --quiet`), no Docker socket, image-ref validation, `container_image` asset, `container_layer` evidence | **Production** |
| IaC | Checkov | `3.3.16` | Docker JSON (`checkov -d /workspace -o json --quiet`), workspace read-only, `iac_resource` asset, `iac_resource` evidence | **Production** |
| API Security | — | — | — | PLANNED (current ZAP/Nuclei cover basic DAST) |

## Current Limitations

Verified from code, tests, and working-tree state:

- **No repository/artifact ingestion.** Workspaces are empty by default; population is manual/test-harness only. Do not add cloning now.
- **Workspace AppSec is filesystem-only.** Secrets uses `gitleaks detect --no-git` (no Git history scanning in S7.5).
- **`full` profile is currently network/web only.** `full` expands to `[nmap, http_fingerprint, nuclei, zap, nikto, tls, dns, subdomain]`; it does not yet include `sast`/`sca`/`secrets` (those have dedicated `sast`/`sca`/`secrets` profiles).
- **SCA manifest coverage is bounded.** `sca.py :: SUPPORTED_FILES` covers `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `pom.xml`, `build.gradle`, `go.mod`, `Cargo.lock`, etc. (max 10 manifests, 2 MiB per file).
- **Vulnerability DB freshness depends on image build.** OSV-Scanner and Semgrep rules are baked into the Docker images; offline mode avoids runtime network but requires image rebuilds for DB/rule updates.
- **Secrets redaction is pattern-based.** `SECRET_REDACT_PATTERNS` covers assignments, known prefixes (`sk_`, `ghp_`, `AKIA`, etc.), PEM headers, and 32+ char high-entropy strings; it is not a guarantee of catching every custom secret format.
- **Known working-tree test issue.** `worker/tests/test_sca_scanner.py :: test_dependency_count_correct` expects `metadata.dependencies_total` which the current `sca.py` does not emit (legacy `sca.py` did). This is a pre-existing working-tree failure unrelated to S7.5; fix or update the test before release. Do not hide it as environmental.
- **Future AppSec families not implemented.** Container, IaC, API, cloud security, continuous monitoring, AI analyst, reporting/compliance remain DEFERRED.

## Current Infrastructure

| Component | Technology | Notes |
|---|---|---|
| Backend API | FastAPI (Python) | `backend/` — JWT auth, project-scoped, Alembic migrations (10 versions) |
| Database | PostgreSQL 16 (`postgres:16-alpine`) | `security_saas` DB, `security` user, volumes `postgres_data` |
| Queue | RabbitMQ 3 (`rabbitmq:3-management-alpine`) | Celery broker, `amqp://guest:guest@rabbitmq:5672//` |
| Cache / Result | Redis 7 (`redis:7-alpine`) | Celery result backend `redis://redis:6379/0` |
| Worker | Celery + `worker/` | `security_worker`, `DOCKER_HOST=tcp://docker-socket-proxy:2375`, `SCANNER_MAX_ATTEMPTS=2` |
| Docker runtime | Docker + `docker-socket-proxy` (`tecnativa/docker-socket-proxy`) | Worker never mounts `/var/run/docker.sock` directly; proxy with `CONTAINERS=1 IMAGES=1 NETWORKS=1 POST=1` |
| Frontend | Next.js | `frontend/` — SOC workspace, `NEXT_PUBLIC_API_URL=http://localhost:8000` |
| Scanner images | Per-family Dockerfiles in `scanners/` | `scanners/sast/Dockerfile`, `scanners/sca/Dockerfile`, `scanners/secrets/Dockerfile` (Gitleaks digest-pinned), `scanners/container/Dockerfile` (Trivy `0.66.0` digest-pinned), `scanners/iac/Dockerfile` (Checkov `3.3.16` digest-pinned) |

## Testing Baseline

Do not invent numbers. Verify with `python -m pytest` from `worker/` (`pytest.ini`: `testpaths=tests`, `pythonpath=.`):

- Most recent focused run (IaC): `tests/test_iac_scanner.py` (21) + `test_iac_parser.py` (13) + `test_iac_pipeline.py` (9) — **43 passed** (IaC suite); container 46, secrets 90.
- Most recent full run (worker): **849 passed, 1 failed, 1 skipped** (failure is `test_sca_scanner.py::test_dependency_count_correct` — pre-existing working-tree issue, see above; skip is expected). Backend: **257 passed**.
- Live verification (2026-09-04): `vapt-iac:latest` built, `checkov --version` → `3.3.16`, vulnerable Terraform SG `0.0.0.0/0` (`main.tf` with `aws_security_group` open) → 6 findings (`CKV_AWS_260` etc., `iac_resource`/`source_file` assets, `execution_engine=checkov`), clean `README.md` (no IaC) → 0 findings via `no iac files`, malformed/unsupported handled, JSON via `checkov -d /workspace -o json --quiet` → `IacParser` → `FindingEngine` → `iac_resource` evidence → risk → `sanitize_metadata`, workspace ro mount, no socket/privileged, strict path handling, timeout 180, workspace cleanup verified; container `alpine:3.10` → 1 finding `CVE-2021-36159` still verified.

# VAPT-Tool AI Agent Instructions

This file is the canonical rule set for every AI coding session on this repository.
Read it before any implementation. It exists to keep the platform coherent, secure, and token-efficient.

## Project Purpose

VAPT-Tool is a comprehensive, containerized Vulnerability Assessment and Penetration Testing (VAPT) platform. It unifies:

- Network security (nmap, dns, subdomain, tls)
- Web security (nuclei, zap, nikto, http_fingerprint)
- Application security — SAST (Semgrep), SCA (OSV-Scanner), Secrets (Gitleaks) and future container / IaC / API / cloud security
- Asset Intelligence (normalization, deduplication, relationships, change detection)
- Finding Intelligence (normalization, correlation, validation, evidence/provenance)
- Risk Intelligence (risk scoring, asset context, attack paths, prioritization)
- Execution observability, scan persistence, project-scoped multi-tenant foundation
- Backend API (FastAPI + PostgreSQL), Celery worker, Next.js SOC frontend
- Future: continuous monitoring, AI security analyst, reporting/compliance, remediation & retesting, external intelligence, integrations

Do not claim unfinished AppSec families (container, IaC, API, cloud) or future capabilities (repository ingestion, attack-graph visualization, AI analyst) as production-ready. Document them as PLANNED/DEFERRED where relevant.

## Core Architecture

High-level execution flow — do not reinvent it:

```
Celery (worker/app/tasks.py :: execute_scan)
  -> workspace (worker/app/scanner/workspace.py :: create_workspace) — isolated temp dir per scan/attempt
  -> ScanContext (worker/app/scanner/base.py) — target + workspace + project/scan metadata
  -> ScannerManager (worker/app/scanner/manager.py) — registry lookup + dispatch
  -> ScannerPipeline (worker/app/scanner/pipeline.py) — execution -> parsing -> finding-engine
  -> Scanner (worker/app/scanner/scanners/<name>.py :: scan / scan_with_context)
  -> DockerRunner (worker/app/scanner/docker_runner.py) — container lifecycle, volume validation, timeout polling
  -> Parser (worker/app/scanner/parsers/<name>_parser.py + sarif_parser.py)
  -> FindingEngine (worker/app/finding_engine/engine.py)
  -> correlation (worker/app/services/finding_correlation/)
  -> validation (worker/app/services/finding_correlation/validation.py)
  -> evidence/provenance (worker/app/services/finding_correlation/evidence.py)
  -> risk (worker/app/risk_engine/ + worker/app/services/risk_intelligence/)
  -> assets (worker/app/asset_intel/ + persistence)
  -> persistence (worker/app/persistence.py + scanner/result_store.py -> PostgreSQL)
  -> cleanup (workspace cleanup_workspace in finally, per attempt)
```

Legacy non-workspace scanners (nmap, nuclei, zap, nikto, tls, dns, subdomain, http_fingerprint) still expose `scan(target: str) -> str` and are dispatched via `ScannerManager.run`. AppSec scanners (sast, sca, secrets) set `requires_workspace=True` and implement `scan_with_context(ScanContext)`; they are dispatched via `ScannerManager.run_with_context` with a read-only `/workspace` mount. The `tasks.py` orchestrator creates a fresh workspace per attempt for workspace scanners and guarantees cleanup on every path.

## AI Coding Rules

1. **Inspect before modifying.** Read the files you intend to change. Prefer `Read` on the exact files over broad dumps. Reuse existing abstractions — do not duplicate `BaseScanner`, `ScanContext`, `ParserRegistry`, `FindingEngine`, `DockerRunner`, `workspace`, `persistence`, `execution` helpers.
2. **Keep changes scoped.** Touch only the files required for the requested stage. Avoid unnecessary rewrites and large refactors.
3. **Do not duplicate infrastructure.** Workspace, registry, pipeline, correlation, validation, evidence, and risk already exist. Extend them; do not rebuild them.
4. **No scanner-specific branches in generic engines unless unavoidable.** `FindingEngine`, `normalizer`, `evidence`, and `risk` must remain generic. Scanner-specific logic lives in the scanner's `scan_with_context` (provenance injection, redaction) and its parser/adapter. If you think you need `if scanner == "secrets"` in `FindingEngine`, reconsider — use the parser/normalizer contract instead.
5. **Preserve backward compatibility.** `scan(target)` continues to work for legacy scanners. `scan_with_context` is additive. Parser output shape `{scanner, assets, findings, errors, metadata}` and `FindingEngine` input shape are stable.
6. **Do not fabricate functionality.** Do not claim a scanner, profile, route, or migration exists until it does. Check registry, profiles, `scanners/` Dockerfiles, and backend/frontend route inventories.
7. **Do not silently change semantics.** If a fix requires changing normalization, fingerprinting, or risk scoring, call it out explicitly.
8. **Test and verify.** Run the relevant tests. Distinguish new failures from pre-existing or environmental ones. Prefer live verification for Docker scanners where required by the stage (see Completion Rule).

## Git Workflow

The coding agent MAY manage Git for implementation phases.

The agent MAY:

- create feature branches
- switch branches
- create commits
- push feature branches
- create pull requests
- merge pull requests when repository permissions and required checks allow
- update local main after successful PR merge

The agent MUST:

- NEVER push directly to main
- NEVER force-push main
- NEVER bypass branch protection
- NEVER rewrite or discard legitimate existing work
- keep commits scoped to the current implementation phase
- run focused tests before committing
- run git diff --check before committing
- inspect the staged diff before committing
- verify no secrets or credentials are included
- verify no unrelated changes are included
- use the normal protected-branch PR workflow

If the repository requires a pull request:

feature branch
    ↓
commit
    ↓
push feature branch
    ↓
create PR
    ↓
required checks
    ↓
merge PR
    ↓
checkout main
    ↓
git pull --ff-only origin main

If automatic PR creation or merge is unavailable because of missing permissions,
missing GitHub tooling, required human approval, or repository policy:

- do NOT bypass the restriction
- stop at that Git step
- report the exact action required from the human

## Token / Context Efficiency

- Read `AGENTS.md` first, then `docs/PROJECT_STATE.md`. Those two files are the persistent memory — do not re-derive the roadmap from scratch.
- Read only task-relevant source files. Use `Glob`/`Grep` to locate the exact modules, then `Read` narrowly.
- Do not dump the entire repository into context. Avoid printing huge files or full test logs unless the task requires it.
- Keep command output focused. Use `pytest -q` and truncate, or filter with `rg`/`Select-String`.
- Preserve useful context by updating the docs (`PROJECT_STATE.md`, `ARCHITECTURE.md`, `SECURITY_RULES.md`) when architecture changes materially, rather than repeating it in chat.

## Task Scope Rule

Implement only the requested stage.

- `S7.5` must not also implement `S7.6`/`S7.7`/`S7.8`.
- Repository / artifact ingestion (GitHub/GitLab cloning, artifact upload, webhooks, sync) is a future AppSec Expansion item. Do not add it during S7.5–S7.8. Current workspace scanners operate on manually populated workspaces (see `PROJECT_STATE.md` — Important Future Work).
- Do not enable fallback engines by default. `*_FALLBACK_ENABLED` must default to `false` (checked in `scanners/<family>.py` and `.env.example`). Fallback is an explicit, disabled-by-default degradation path.

## Completion Rule

Never declare a roadmap item complete solely because code was written. Where applicable, completion requires:

- implementation (scanner + parser + registry + profile wiring)
- tests (unit + pipeline/redaction where relevant) passing in isolation
- integration verification (pipeline end-to-end, finding-engine → correlation → validation → evidence → risk → asset linkage)
- live verification (Docker image builds, pinned version verified, vulnerable fixture detected, clean fixture produces no false positives, persistence inspected)
- security verification (non-root where practical, read-only workspace mount, no privileged/socket, path/traversal validation, redaction where handling secrets)
- persistence verification (no plaintext leakage to DB/logs/API/AI)
- documentation (scanner version/digest, redaction/raw-output policy, limitations)
- readiness assessment with an explicit classification: `READY` / `PARTIALLY READY` / `BLOCKED`

The final message of a stage task must include a `CHECKLIST UPDATE — <ID>` line and state exactly when the checklist item may be marked complete.

## Checklist Rule

Every implementation stage must end with:

```
CHECKLIST UPDATE — <STAGE_ID>
```

and state the precise condition under which the roadmap checklist item may be marked complete — typically: after implementation + tests + integration/live/security/persistence verification + documentation + readiness assessment, with a readiness classification. Do not mark a `P10.*` item `COMPLETE` until the verification chain has been satisfied.

## Secrets Rule

For any task that touches secrets (current: `S7.5`, future handling of credentials):

- Never persist, log, or return plaintext secret material — not in PostgreSQL, not in Celery logs, not in API responses, not in AI prompts.
- Redact early — scanner output must be sanitized before it leaves the scanner process (`_redact_text`, `_redact_sarif`), and sanitization must be repeated defense-in-depth at persistence (`persistence.py :: sanitize_metadata`, `tasks.py :: _sanitize_secrets_raw/_sanitize_secrets_error`).
- Use `[REDACTED]` for display and a one-way SHA-256 `_secret_hash` (first 32 hex chars) for deterministic correlation. No reversible encryption.
- Never use plaintext secret values as correlation keys, fingerprint inputs, or evidence text.
- Evidence type for secrets is `secret` (`EVIDENCE_TYPES` in `evidence.py`); asset type for source files is `source_file`.

## Repository Ingestion Rule

Repository / artifact ingestion is future work — not part of S7.5–S7.9.

Do not add until its designated phase:

- GitHub / GitLab / arbitrary Git URL cloning
- repository synchronization, artifact upload, webhooks
- any feature that pulls external code into the workspace automatically

Until ingestion lands, the contract is: the orchestrator creates an empty isolated workspace, and the caller (test harness or future ingestion layer) populates it. Parsers and the pipeline must handle empty workspaces gracefully (return empty findings with `execution_engine`/`execution_mode` provenance, not a failure).

## Security Rule

Scanner containers must be isolated by default:

- No privileged containers, no Docker socket mount (the worker reaches Docker via `docker-socket-proxy:2375`, not a direct socket mount)
- No broad host mounts — only the per-attempt workspace, mounted read-only at `/workspace` (or `/workspace/src`)
- Isolated workspaces: `tempfile.mkdtemp` with `0o700`, unique per scan/attempt, validated and cleaned up in `finally` (retry creates a fresh workspace)
- Validate paths and prevent traversal/symlink escape (`workspace.py`, `docker_runner.py :: _validate_volumes`, per-scanner `resolve().relative_to(workspace)`)
- Avoid command injection — prefer argument arrays over shell commands (avoid `shell=True` in Docker command; only use `sh -c` where the tool itself requires it, e.g., OSV-Scanner's `cat` pattern, and never interpolate untrusted values)
- Pin scanner versions and images: `FROM <image>@<digest>` where practical, with `PRODUCTION_VERSION` constants in scanner modules and `.env.example` overrides (`SECRETS_IMAGE`, `SAST_IMAGE`, `SCA_FALLBACK_ENABLED`, etc.)
- Non-root users in scanner images where practical (see `scanners/secrets/Dockerfile`, `scanners/sca/Dockerfile`)

## Testing Rule

- Do not claim tests passed without running them. Use `python -m pytest <focused suite> -q` and run a full regression (`python -m pytest` from `worker/`) where required, marking clearly which failures are new vs pre-existing.
- Respect `pytest.ini` (`testpaths=tests`, `pythonpath=.`) and shell constraints (Windows PowerShell 5.1: no `&&` chaining, no `head`; use `python -m pytest ... --tb=short` directly).
- Distinguish: new failures (introduced by this stage), pre-existing failures (already failing on the base branch / working tree before the stage), environmental failures (Docker unavailable, network-dependent analyzer fallback). Do not hide any of the three.

## Documentation Rule

When architecture changes materially (new scanner, new profile, new evidence/asset type, new execution mode), update the appropriate project doc:

- `AGENTS.md` — agent rules, invariants, new security contracts
- `docs/PROJECT_STATE.md` — roadmap position, scanner inventory, limitations
- `docs/ARCHITECTURE.md` — component, flow, storage, and frontend changes
- `docs/SECURITY_RULES.md` — new container/workspace/secret handling obligations

Docs must describe the real current state. Write concise but sufficiently complete coverage; label each item `COMPLETE` / `IN PROGRESS` / `PLANNED` / `DEFERRED` explicitly and do not claim functionality that verification has not confirmed.

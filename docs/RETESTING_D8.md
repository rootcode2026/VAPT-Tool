# D8 — Retesting & Verification

> Status: IMPLEMENTED (pending merge). No second scanner, engine, queue, or worker.
> No notifications (D9). No AI.

## Core statements

- "Remediation completion is an owner assertion."
- "Verification is an evidence-backed security determination."
- "Scanner/parser failure is never interpreted as successful remediation."
- "Absence of authoritative evidence is not proof of remediation."

## Flow

```
Finding (remediation completed, verification required)
  → retest requested (original scanner + stable version/digest + target from finding context)
  → verification Scan created + execute_scan enqueued via existing Celery/RabbitMQ path
  → worker runs the real scanner (pools, workspace isolation, retries — unchanged)
  → findings persisted by the existing pipeline (parsers, FindingEngine, correlation)
  → evaluator compares baseline fingerprint vs verification-scan fingerprints
  → PASSED / FAILED / ERROR → existing finding lifecycle (resolved / active / unchanged)
```

D8 is orchestration + evaluation over existing machinery. No worker changes were
required: the worker runs ordinary scans; the backend evaluates their persisted
evidence (lazily on read + explicit complete endpoint).

## Retest model (reused `finding_retests`, additive D8 columns)

Reused as-is: `finding/project/org`, `requested_by/executed_by`, `status/result`,
`scanner/target_value`, `started/completed_at`, `result_summary/evidence`,
one-active-per-finding (409), `FindingHistory` + `AuditService`.

D8 additions (`u8` migration `v8w9x0y1z2a3`):

- `scan_id` (FK scans SET NULL) — the verification execution, never client-supplied.
- `scanner_version`, `image_ref`, `image_digest`, `channel` — exact provenance.
- `baseline_fingerprint`, `resulting_fingerprint`, `fingerprint_algo` (`fp-v1`).
- `verification_note` — deterministic explanation.
- Indexes: `(scan_id)`, `(project_id, status)`, `(finding_id, status)`, `(baseline_fingerprint)`.

## Scanner selection & provenance

- Original scanner only (`finding.scanner`), must exist in `SCANNER_CATALOG`
  (arbitrary scanners impossible; no Docker args accepted anywhere).
- Version via `resolve_production_version` (stable + enabled + approved +
  non-deprecated + `image_ref` + digest + lifecycle stable). Missing → explicit
  `409`; never resolves `latest`, never silent fallback.
- Capacity via `get_pool_for_scanner` + `can_accept_job`; saturated pool → explicit
  `409`. Pool read failures degrade safely inside savepoints (verified live:
  a control-plane read error once poisoned the transaction; fixed with
  `db.begin_nested()` savepoints + regression test `test_d8_saturated_pool_refused`).
- Target from the original finding's `Scan → Target` (active, same project);
  request bodies cannot inject targets or scanners.
- Execution allowlist (`RETEST_EXECUTABLE_SCANNERS`): nmap, nuclei,
  http_fingerprint, zap, nikto, tls, dns, subdomain — scanners that verify a live
  target without a populated workspace. Workspace scanners (sast, sca, secrets,
  iac, api) are refused with explicit `400`: they would scan an empty workspace,
  yield zero findings, and produce a FALSE PASSED. container/sqlmap excluded (no
  supported verification profile / parser gap). Documented limitation, not silent.

## Fingerprint matching

- Baseline = canonical fingerprint of the finding at request time.
- The worker's `fingerprint_finding` is authoritative; the backend cannot import
  worker code at runtime (separate image), so D8 implements the identical
  canonical payload (same 13 fields, same canonical JSON, SHA-256) in
  `services/finding_lifecycle.py` (`d8_finding_input` / `d8_fingerprint`).
- Parity is enforced by `tests/test_retest_fingerprint_vector.py`, which imports
  both implementations and asserts byte-identical output (it caught real drift in
  hostname/URL/IP/port normalization during development).
- Scanner version changes never affect identity (scanner excluded, as in worker).

## Verification evaluator (`evaluate_retest_verification`)

1. Verification scan not `completed` → ERROR (scanner/target failure never passes).
2. `parser_ok=False` → ERROR.
3. `completeness != complete` → ERROR (partial evidence never passes).
4. Baseline fingerprint in scan findings → FAILED ("detected again").
5. Otherwise → PASSED ("absent from the completed verification scan").

Detected fingerprints are derived server-side from the verification scan's
persisted findings. Clients cannot submit fingerprints, results, or evidence for
terminal transitions: PATCH `passed/failed/error` and POST `complete` both run
the evaluator (409 while the scan is non-terminal). Click-to-verify is impossible
(tested). Deterministic notes are stored as `verification_note`/`result_summary`.

## Finding lifecycle interaction (existing semantics)

- PASSED → `resolved` (+ `RETEST_PASSED`, `FINDING_RESOLVED`), except
  `accepted_risk` findings keep their status (risk acceptance authoritative;
  factual result still recorded).
- FAILED → finding stays active; `reopened` only from terminal states,
  otherwise status unchanged (no severity/risk touched).
- ERROR → no finding change.
- Reopening: unchanged D2/FindingEngine fingerprint behavior; a later detection
  of the same fingerprint reopens per existing semantics. D8 adds no reopening logic.
- SLA: untouched (verified: SLA stays active/breached through retest completion).
- No severity downgrades, no risk-score changes, no scanner rollback (C7 owns it).

## Idempotency & concurrency

- One active retest per finding (409); duplicate requests send exactly one task.
- Terminal states stable; repeat `complete` returns the same record, no duplicate
  history/audit (tested). Same-status transitions are no-ops.
- Transactional updates; lazy sync is compare-and-set on (retest status, scan
  status). No distributed locks, no second queue. Worker retries reuse C11
  semantics; evaluation reads persisted scan state, so retries cannot duplicate
  verification results (retest ID + scan ID preserved).

## API

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/findings/{id}/retests/request` | validates + enqueues; 409 duplicate/no-version/saturated; 400 unsupported scanner/target |
| GET | `/api/v1/findings/{id}/retests` | per-finding, lazy sync |
| PATCH | `/api/v1/findings/{id}/retests/{rid}` | running/cancelled operational; terminal = evaluator only |
| GET | `/api/v1/projects/{pid}/retests` | queue: status/result/scanner/finding/since/until/limit≤200 |
| GET | `/api/v1/projects/{pid}/retests/{rid}` | single, project-scoped, lazy sync |
| POST | `.../retests/{rid}/cancel` | active → cancelled |
| POST | `.../retests/{rid}/complete` | evaluate now; 409 if scan non-terminal; idempotent |

Auth required; analyst/project_admin (or org_admin/super_admin) for mutations;
viewer read-only. All access project-scoped (`_require_project_retest`, 404
without existence leakage). Bounded payloads; evidence = provenance string only.

## Frontend (finding detail)

Run retest / Refresh / Cancel (active only); states render as Requested, Retest
running, Verified, Verification failed — finding still detected, Verification
inconclusive, Cancelled. Each entry shows scanner + version, digest, target,
requested/started/completed times, verification note. No manual pass/fail buttons;
no raw scanner output rendered (text only, provenance strings).

## RBAC / tenant isolation / RLS

- RBAC reuses `_require_finding_manage` + `require_project_access` (no new
  permissions). Viewer reads, cannot request/cancel (403, tested).
- Tenant isolation is application-layer (project-scoped queries, org-derived
  ownership, `CROSS_TENANT_ACCESS_DENIED` conventions); new columns inherit the
  table's existing posture. No new RLS claimed.
- Evidence protection: bounded provenance only; secrets rejected by construction
  (no free-text evidence accepted on terminal paths); audit IDs-only.

## Performance

- Queue: single project-scoped query + per-row scan fetch bounded by page
  (limit ≤ 200); evaluation queries one scan's findings. Composite indexes added.
- Verification scans are ordinary single-profile scans (quick/web), not full
  fleet runs. No N+1 owner lookups; no unbounded history loads.

## Limitations

1. `alembic upgrade head` remains blocked pre-existing at `o1p2q3r4s5t6`
   (duplicate `ix_workers_status`); D8 migration verified via offline SQL.
   Live verification applied D7+D8 DDL out-of-band (documented, additive,
   aliases the pending migrations; alembic version pointer untouched).
2. Verification execution limited to non-workspace quick/web scanners (see
   allowlist rationale). Workspace-scanner findings can record remediation but
   cannot yet be verified by an empty-workspace scan — ingestion-backed
   verification scans are future work.
3. SQLite suites with JSONB/stale-DDL fixtures fail pre-existing; D8 tests carry
   a local shim and pass (24 + 6 vectors).
4. SQLMapParser `scanner_name` gap untouched (sqlmap excluded from execution).
5. Evaluation is scan-completion driven (lazy + explicit); there is no
   worker→backend push callback — by design (no second queue, no worker changes).

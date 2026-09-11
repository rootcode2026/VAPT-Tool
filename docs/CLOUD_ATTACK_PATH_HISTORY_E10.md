# CLOUD ATTACK PATH HISTORY E10 — Persistence & Historical Risk Intelligence

## Business Objective

E9 answers: *What dangerous cloud attack paths exist right now?*
E10 answers: *How did those paths change over time?* — which paths appeared, disappeared, reopened, changed severity/priority/confidence, which remain persistent.

Value: CURRENT EXPOSURE + HISTORICAL CHANGE + PATH RISK + EVIDENCE. Enables security team to track newly created, resolved, reopened, severity-changed, priority-changed, recurring risky paths and most dangerous over time.

Not a generic analytics platform — only cloud attack-path history.

## Relationship to E9

E9 is on-read, bounded, provider-neutral (AWS/GCP/Azure), deterministic scoring/confidence, evidence/provenance, project/tenant isolation, RBAC/RLS, no graph DB, no AI, no active exploitation.

E10 builds **minimal durable persistence** on top, reusing E9 deterministic fingerprint as logical identity. Does not redesign E9, does not introduce graph DB, AI, autonomous remediation, active exploitation, new discovery, new CSPM checks, new providers.

## Persistence Model

### Tables (Alembic `f10a1b2c3d4e_add_cloud_attack_path_history_e10`)

**cloud_attack_paths**
- `id` PK (uuid)
- `project_id` FK projects CASCADE, indexed
- `organization_id` FK organizations CASCADE, indexed
- `fingerprint` String(64) — deterministic `sha256(project|path_type|provider|sorted asset_ids)[:32]`
- `provider` (aws/gcp/azure/multi/unknown)
- `path_type` (INTERNET_TO_VULNERABLE_RESOURCE etc)
- `severity` (critical/high/medium/low)
- `priority_score` Integer
- `confidence` (HIGH/MEDIUM/LOW)
- `entry_asset_id`, `target_asset_id` FK assets SET NULL
- `status` ACTIVE/RESOLVED (default ACTIVE)
- `asset_ids` JSON (bounded ≤20)
- `evidence` JSON (bounded findings ≤10, relationships ≤10, sanitized)
- `first_seen_at`, `last_seen_at`, `resolved_at`, `created_at`, `updated_at` TIMESTAMPTZ
- Unique: `project_id + fingerprint` (`uq_cloud_attack_path_project_fingerprint`) — concurrency protection
- Indexes: `(project_id, status)`, `(project_id, provider)`, `(project_id, path_type)`, `(project_id, fingerprint)`, `organization_id`

**cloud_attack_path_observations**
- `id` PK
- `project_id` FK CASCADE
- `attack_path_id` FK cloud_attack_paths CASCADE
- `monitoring_run_id` FK monitoring_runs SET NULL, nullable
- `fingerprint` String(64)
- `priority_score`, `severity`, `confidence`, `status`, `observed_at`, `created_at`
- Unique: `project_id + fingerprint + monitoring_run_id` (`uq_observation_project_fingerprint_run`) — idempotency per run
- Indexes: `(project_id, attack_path_id, observed_at)`, `(project_id, observed_at)`, `monitoring_run_id`

No credentials, tokens, private keys, connector secrets, unrestricted policy documents, arbitrary scanner output persisted. Evidence bounded and sanitized.

## Lifecycle

```
NEW (first observe) → ACTIVE (first_seen=last_seen=now)
ACTIVE observed again → update last_seen, severity/priority/confidence, clear resolved_at if was RESOLVED (reopen)
ACTIVE missing from valid completed observation → RESOLVED (resolved_at=now)
RESOLVED observed again → ACTIVE (reopened)
FAILED/PARTIAL/EMPTY invalid → no resolution (ACTIVE stays ACTIVE)
```

Only `ACTIVE`/`RESOLVED` (NEW is internal transient). Managed via `observe_attack_paths(project_id, db, monitoring_run_id, run_status, observed_at)`.

## Observation Semantics

- Each monitoring execution produces bounded current path observations via E9 `build_cloud_attack_paths`.
- For each fingerprint: if exists → update last_seen/metadata; if not → create.
- If previously ACTIVE not in current set and observation is **valid completed**, mark RESOLVED.
- If RESOLVED returns, mark ACTIVE and clear `resolved_at`.
- Fingerprint unchanged → same logical path (no duplicate).
- Valid completed = `run_status == "completed"` with E9 evaluation succeeded (even if 0 paths but graph evaluated). `failed`/`partial`/infrastructure failure → no resolution (preserve).
- Reuses D1/D2 `VALID_MONITOR_STATUS` semantics.

## Resolution & Reopen Rules

- Resolution only on `completed`. Failed/partial/empty invalid do not resolve.
- Reopen: `RESOLVED` + observed again → `ACTIVE`, update `last_seen_at`, clear `resolved_at`.
- Severity/priority/confidence changes emit virtual events (tracked via `severity_changed` counters, but not separate persisted events table — derived via comparison).

## Change Events

Reuses D2 `monitoring_change_events` taxonomy if needed, but E10 change types are derived:

- `ATTACK_PATH_CREATED` (first observe)
- `ATTACK_PATH_RESOLVED` (ACTIVE→RESOLVED)
- `ATTACK_PATH_REOPENED` (RESOLVED→ACTIVE)
- `ATTACK_PATH_SEVERITY_CHANGED`
- `ATTACK_PATH_PRIORITY_CHANGED`
- `ATTACK_PATH_CONFIDENCE_CHANGED`

Events are idempotent via `project_id + monitoring_run_id + fingerprint + change_type` (unique constraint on observation). Repeated same run does not duplicate paths/observations. Change detection is deterministic, not AI.

## Idempotency

- Path creation: unique `(project_id, fingerprint)` — concurrent duplicate → `IntegrityError` caught, second caller fetches existing and updates.
- Observation: unique `(project_id, fingerprint, monitoring_run_id)` — same run reprocessed → `first()` check skips duplicate, or unique violation swallowed.
- Safe retries: same monitoring_run_id re-observed → no duplicate active path, no duplicate created/resolved event.

## Concurrency

PostgreSQL unique constraints + transactional `db.flush()` + `IntegrityError` rollback ensure no duplicate path creation, simultaneous resolution/reopen safe. No in-memory locks.

## Historical Metrics

Project-level (via `get_summary`):
- `active`, `resolved`, `total`, `critical`, `high`, `providers` breakdown, `path_types` breakdown, `avg_priority`, `highest_priority`, `created_recently` (7d), `reopened_recently` (first_seen < last_seen).

Time-based derived via `first_seen_at`/`last_seen_at` range queries, bounded `limit 100`, indexed `project_id+observed_at`.

No arbitrary user-defined analytics; bounded aggregations only.

## API

Existing E9: `GET /projects/{project_id}/cloud-security/attack-paths` and `/{path_id}` remain functional, bounded, validated, project-scoped.

E10 adds (same prefix `/api/v1/projects/{project_id}/cloud-security/attack-paths`):

- `GET /history` — query `provider` (aws/gcp/azure), `severity` (critical/high/medium/low), `path_type`, `status` (ACTIVE/RESOLVED), `from` (ISO8601), `to` (ISO8601), `limit` 1-100 (bounded). Returns `{count, paths: [{id, fingerprint, provider, path_type, severity, priority_score, confidence, entry_asset_id, target_asset_id, status, first_seen_at, last_seen_at, resolved_at, asset_ids, evidence}]}`. Auth `require_project_access`, RLS, 400 invalid, 401 unauth, 404 cross-project.

- `GET /history/{path_id}` — path_id is `id` or `fingerprint`; returns single history with `observations` (≤50, ordered desc, each `{monitoring_run_id, priority_score, severity, confidence, status, observed_at}`). 404 if not found or wrong project.

- `GET /summary` — returns `{active, resolved, total, critical, high, providers, path_types, avg_priority, highest_priority, created_recently, reopened_recently}`.

- `POST /observe?monitoring_run_id=&run_status=completed|failed|partial` — triggers `observe_attack_paths` (used by monitoring hook and tests). Bounded, validated, project-scoped.

All bounded, no secrets, tenant-isolated (404 on cross-tenant), RLS via `set_tenant_context`.

## Frontend

Extends `frontend/src/app/(app)/cloud-security/page.jsx` — existing E9 table retained.

Adds “Attack Path History (E10)” section:

- Stats: Active, Resolved, Critical, Highest Priority (from `getAttackPathSummary`)
- Observe now button (`POST /observe?run_status=completed`)
- Provider breakdown, path-type breakdown
- History table: First Seen | Last Seen | Provider | Type | Severity (badge) | Priority | Status — sorted `last_seen_at desc`, click → detail
- Detail: `first_seen_at`, `last_seen_at`, `resolved_at`, `confidence`, observations list (≤5, `{observed_at, severity, priority_score, status}`)
- Lightweight, no heavy charting lib, reuses `SeverityBadge`, `useProjectContext`, `LoadingState`.

Uses `frontend/src/lib/api/cloudAttackPaths.js` (`listAttackPathHistory`, `getAttackPathHistory`, `getAttackPathSummary`, `observeAttackPaths`).

## Security / RBAC / RLS

- `get_current_user` + `require_project_access` on all E10 endpoints; same as E9.
- Tenant isolation via `project_id` filter; cross-tenant → 404 (no leak).
- IDOR via path_id/fingerprint blocked by `project_id` in query.
- Invalid dates → 400, excessive limit → 422 (FastAPI validation) or bounded to 100.
- Evidence sanitized, bounded; secrets never persisted (tested).
- RLS `_set_rls_context` same as E9 (transaction-local, SQLite no-op, PG SET LOCAL). Documented limitation: SQLite tests cannot exercise PG table ENABLE RLS; honest.

## Audit

Uses existing audit infrastructure if needed; E10 does not create second audit system. No noisy per-read audit; only security-sensitive admin actions would be audited. No secrets in audit.

## Retention

Schema retention-friendly (indexed `observed_at`, bounded JSON). No complex scheduler; retention policy deferred, documented. No automatic deletion in E10 unless platform retention exists.

## Performance

- Bounded observations, history queries `limit 100`, indexed `(project_id, fingerprint)`, `(project_id, status)`, `(project_id, observed_at)`, `(project_id, attack_path_id, observed_at)`.
- Batch upsert via single `build_cloud_attack_paths` + per-path flush, no N+1 (3 bounded batch queries for graph + 1 per existing paths).
- No full historical scan per dashboard (summary uses COUNTs with indexes).

## Migration

`f10a1b2c3d4e_add_cloud_attack_path_history_e10` — creates `cloud_attack_paths` + `cloud_attack_path_observations` with constraints/indexes. Reversible via `downgrade()` drop. Tested via `Base.metadata.create_all` with JSON patch for sqlite.

## Testing

`backend/tests/test_cloud_attack_path_history_e10.py` — 30 tests (unit + API):

1 create new, 2 update last_seen, 3 same fingerprint not duplicate, 4 resolves after valid completed, 5 failed does not resolve, 6 partial does not resolve, 7 empty invalid does not resolve, 8 reopen, 9 severity change, 10 priority change, 11 confidence change, 12 created idempotency, 13 resolved idempotency, 14 reopened idempotency, 15 concurrent duplicate protection, 16 project isolation, 17 tenant isolation, 18 unauthorized, 19 API list, 20 API detail, 21 history filtering, 22 date filtering, 23 bounded limit, 24 summary metrics, 25 provider aggregation, 26 path-type aggregation, 27 E9 remains functional, 28 no duplicate findings, 29 evidence bounded, 30 secrets never persisted.

## Limitations

- On-read E9 still provides current paths; history adds persistence but not full graph snapshot (bounded).
- Observations require valid completed run; failed runs preserve history.
- Retention deferred.
- RLS PG policies not live-tested in sqlite (known).
- No graph DB, no AI, no active exploitation, no attack simulation.

## Future

Interfaces allow later graph backend, AI reasoning, or automated remediation without rewriting domain model (fingerprint stable). Historical layer is minimal and can be extended with retention or ML risk prediction (deferred to E11+).

## Explicit Out-of-Scope

Graph DB/Neo4j, AI/LLM reasoning, autonomous remediation, automated exploitation, pen-testing, new discovery (AWS/GCP/Azure), new CSPM controls, new providers, new scanners, SIEM/SOAR, compliance expansion, new notification/reporting, new scheduler/monitoring system, packet simulation, full viz, arbitrary analytics, ML risk prediction, E11+.

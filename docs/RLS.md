# Row-Level Security (P14.3)

## Tenant Model

- **Organization** is the tenant boundary (`organizations.id`).
- **Project** is scoped to organization (`projects.organization_id`).
- **Project resources** (`targets`, `scans` via `target`, `findings` via `target`, `assets` via `project`, `reports` via `organization`/`project`, `ai_conversations` via `organization`, `repository_connections`/`cloud_connections` via `project`) are tenant-scoped.
- **Platform-global** (`users`, `organizations`, `audit_logs` with `SET NULL`, `scanner_*`) is not tenant-isolated for operational reasons.

## Trusted DB Context

```
JWT → get_current_user → organization_membership → project authorization → permission → trusted DB context → SQL transaction → RLS
```

- `app.current_organization_id`, `app.current_project_id`, `app.current_user_id` via `set_config(..., true)` (SET LOCAL, transaction-local).
- Only set from trusted server-side `user.organization_id` / `project.organization_id` after `require_project_access`, never from client-supplied `organization_id`/`project_id`.
- Validation via `validate_context_value` (UUID v4, strict, no injection).
- Bound parameters via `text("SELECT set_config(:k, :v, true)")`, no string interpolation.

## Transaction-Local

```
BEGIN; SELECT set_config('app.current_organization_id', :oid, true); SELECT ...; COMMIT;
```

- `SET LOCAL` via `set_config(..., true)` is transaction-local, cleared on `COMMIT`/`ROLLBACK`, no pool leakage.
- Requires explicit `with db.begin(): set_tenant_context(...)` for pool safety, enforced via `in_transaction()` check, `RuntimeError` otherwise.
- `clear_tenant_context` for tests.

## Policies

| Table | Scope | Policy |
|-------|-------|--------|
| projects | organization | `organization_id = current_setting('app.current_organization_id')` OR empty (system) |
| reports | organization | same |
| ai_conversations | organization | same |
| assets | project | `EXISTS (SELECT 1 FROM projects p WHERE p.id = assets.project_id AND p.organization_id = current_setting(...))` |
| targets | project | same |
| cloud_connections | project | same |
| repository_connections | project | same |
| scans | via_target | `EXISTS (SELECT 1 FROM targets rt JOIN projects p ON p.id = rt.project_id WHERE rt.id = scans.target_id AND p.organization_id = current_setting(...))` |
| findings | via_target | same |

All `FOR ALL USING (...) WITH CHECK (...)`, `FORCE RLS` for owner, permissive when `current_setting` is `''` or `NULL` (migrations, superuser).

## Super-admin

- No client-controlled `is_super_admin` GUC.
- Super-admin access via trusted `User.role == super_admin` → `require_super_admin` → allowed to set any `organization_id` via server-side, but still sets `app.current_organization_id` to the target org's ID, not a wildcard bypass.
- Customer-sensitive data (source code, secrets, private repo) not automatically exposed; future explicit audited capability required.

## Mutations

- `USING` and `WITH CHECK` both enforce `organization_id = current_setting`.
- `INSERT` with `organization_id = B` while context is `A` → denied (`WITH CHECK`).
- `UPDATE`/`DELETE` of B's row while context A → denied (`USING`).

## Relationships

- Direct `organization_id`/`project_id` preferred where exists.
- `via_target` uses `JOIN` to `projects` for `scans`/`findings`, verified not recursive, indexed `targets.project_id`, `projects.organization_id`.

## Migration

- `i9a0b1c2d3e4_enable_rls.py` — `ENABLE RLS` + `FORCE RLS` + `CREATE POLICY tenant_isolation_* FOR ALL USING/WITH CHECK`, reversible `DROP POLICY` + `DISABLE RLS`, preserves data, no new columns.

## Workers

- `worker/app/tasks.py:execute_scan` derives `(org_id, proj_id)` via `get_project_id` → `projects.organization_id` (trusted DB, not task payload), then `with db.begin(): set_tenant_context(...)` before `UPDATE scans` and subsequent `persist_parsed_bundle` etc., each task own transaction, no cross-tenant.

## Pooling

- `QueuePool` reuse safe: `SET LOCAL` cleared on `COMMIT`/`ROLLBACK`, verified via `test_postgres_transaction_local_and_pool_isolation` (real PG) and mocked `test_context_does_not_leak_between_transactions`.

## Rollout

- `RLS_ENABLED=false` default (dev), `true` in `.env.prod-local` (prod-like), feature flag via `is_rls_enabled()`, no misleading `true` with incomplete policies, eventual prod enforcement.

## Testing

- `backend/tests/test_rls.py` — 376 lines, 15 tests: disabled-by-default, validation, no-op on SQLite, malicious input rejected, transaction-local, pool isolation, real PG integration (skipped if no PG).
- Additional P14.3 integration tests for `SELECT`/`INSERT`/`UPDATE`/`DELETE` per table, IDOR, context isolation, pooling, rollback, missing context (deny-by-default), super-admin, worker.

## Performance

- `EXISTS` subquery with indexed `projects.id`/`organization_id`, `targets.id`/`project_id`, no redundant `organization_id` column, overhead <5% on `EXPLAIN ANALYZE` for `findings`/`assets`.

## Failure Behavior

- RLS denied → `403`/`404` via `require_project_access` (app) or `42501` via PG (sanitized to 403 via `publicErrorMessage`, no `Traceback`/`sqlalchemy`/`psycopg`, no policy definition, no schema).

## Limitations

- `audit_logs` not RLS-protected (platform-global, `SET NULL` FKs, tenant-isolated via app `WHERE organization_id`).
- `users`/`organizations` not RLS (platform-global, super_admin manages).
- `teams` not yet implemented.
- No `project_id` RLS for `onboarding` (per `user_id`, isolated via `user_id` check).

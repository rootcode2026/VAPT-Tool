# RBAC Model — Enterprise Multi-Tenancy Foundation

> **Status:** Foundation implemented (membership tables, permission model, authorization dependencies). **Not** fully enforced on every endpoint yet — transitional fallback preserves existing access. See `API_SECURITY_INVENTORY.md` for current vs target.
> **Branch:** `feat/multitenancy-rbac-foundation` from `main` @ `beffce3`
> **RLS:** `RLS_ENABLED=false`, no `ENABLE ROW LEVEL SECURITY`, no `CREATE POLICY` — helper `backend/app/db/rls.py` remains preparation-only.

## 1. Tenancy Concepts

| Concept | Table | Key | Uniqueness |
|---|---|---|---|
| Organization | `organizations` | `id` PK (UUID) | `slug` unique |
| User | `users` | `id` PK (UUID) | `email` unique; `organization_id` FK (legacy primary org, retained for backward compat) |
| OrganizationMembership | `organization_memberships` | `id` PK | `unique(organization_id, user_id)` |
| Project | `projects` | `id` PK | `organization_id` FK |
| ProjectMembership | `project_memberships` | `id` PK | `unique(project_id, user_id)` |

- Organizations are the top-level tenant.
- Users belong to one or more organizations via `organization_memberships` (explicit). Legacy `users.organization_id` is treated as fallback membership if no row exists (backward compat for existing data).
- Projects belong to exactly one organization (`projects.organization_id`).
- Users belong to projects via `project_memberships`. Transitional: if no row exists but user is org member of the project's organization, access is granted via org membership fallback (analyst/viewer mapping). This preserves existing projects where creator info is not stored.
- All IDs are UUID strings (36 chars), consistent with existing architecture. Foreign keys `ON DELETE CASCADE`.

## 2. Membership Schema

### organization_memberships
```
id               String(36) PK, uuid4
organization_id  String(36) FK -> organizations.id, indexed, CASCADE
user_id          String(36) FK -> users.id, indexed, CASCADE
role             String(50) ∈ {member, org_admin}, default member
status           String(20) ∈ {active, suspended, pending}, default active
created_at       DateTime, default now
updated_at       DateTime, default now, onupdate now
unique           (organization_id, user_id)
index            organization_id, user_id
```

### project_memberships
```
id         String(36) PK
project_id String(36) FK -> projects.id, indexed, CASCADE
user_id    String(36) FK -> users.id, indexed, CASCADE
role       String(50) ∈ {viewer, analyst, project_admin}, default viewer
status     String(20), default active
created_at DateTime
updated_at DateTime
unique     (project_id, user_id)
index      project_id, user_id
```

Migration: `9f8e7d6c5b4a_add_organization_project_memberships` creates both tables. Data migration populates `organization_memberships` from existing `users` (`admin` → `org_admin`, `member`/`super_admin` → `member`). Project memberships are **not** auto-populated because creator is not stored; transitional fallback (below) preserves access. No destructive data migration.

## 3. Role Model

### Platform role (User.role)
Separate from org/project roles. Stored in `users.role`:
- `member` (default)
- `admin` (legacy, mapped to `org_admin` in membership fallback)
- `super_admin` — platform-level, not an organization membership. Bypass for operational visibility, not per-org.

### Organization roles
- **member** — can read org, read projects/assets/etc., cannot create/delete projects or manage members.
- **org_admin** — all member perms plus `project.create`, `project.delete`, `organization.update`, `organization.manage_members`, `project.manage_members`, plus all project-level perms within org (implies `project_admin` on every project in org).

### Project roles
- **viewer** — read-only: `project.read`, `target.read`, `scan.read`, `finding.read`, `asset.read`, `cloud.read`, `dashboard.read`, `report.read`
- **analyst** — viewer plus `target.create`, `scan.execute`, `finding.triage`, `ingestion.create`, `cloud.manage`
- **project_admin** — analyst plus `target.delete`, `project.delete`, `project.update`, `project.manage_members`

`super_admin` has `ALL_PERMISSIONS`.

## 4. Super Admin

- Architectural concept only in this phase; **no dashboard built**.
- `User.role == 'super_admin'` is the only platform-level check (`_is_super_admin` in `deps.py`). Do not grant via org/project membership.
- Intended capabilities (documented, not yet implemented): platform operational visibility (organizations, users, projects, scanner fleet, health, audit/security events, platform configuration). Customer-sensitive data (`Asset.value`, `Finding.evidence`, `raw_output`) is minimized by default; super_admin actions must be auditable (future audit log).
- `require_super_admin` dependency exists (`deps.py`) but no route currently requires it — marked `FUTURE`.

## 5. Permission Model (`backend/app/core/permissions.py`)

Centralized, not scattered. Role → permission sets:

**Organization:**
- `organization.read`, `organization.update`, `organization.manage_members`
**Project:**
- `project.read`, `project.create`, `project.update`, `project.delete`, `project.manage_members`
**Targets:**
- `target.read`, `target.create`, `target.delete`
**Scans:**
- `scan.read`, `scan.execute`
**Findings/Assets/Cloud:**
- `finding.read`, `finding.triage`, `asset.read`, `cloud.read`, `cloud.manage`, `ingestion.create`, `dashboard.read`, `report.read`, `scanner.manage`, `audit.read`

Mappings:
- `ORG_ROLE_PERMISSIONS["member"] = {org.read, project.read, target.read, scan.read, finding.read, asset.read, cloud.read, dashboard.read, report.read}`
- `ORG_ROLE_PERMISSIONS["org_admin"] = all member plus {org.update, org.manage_members, project.create/delete/update/manage, target.create/delete, scan.execute, finding.triage, cloud.manage, ingestion.create, scanner.manage, audit.read}`
- `PROJECT_ROLE_PERMISSIONS["viewer"] = {project.read, target.read, scan.read, finding.read, asset.read, cloud.read, dashboard.read, report.read}`
- `PROJECT_ROLE_PERMISSIONS["analyst"] = viewer plus {target.create, scan.execute, finding.triage, ingestion.create, cloud.manage}`
- `PROJECT_ROLE_PERMISSIONS["project_admin"] = analyst plus {target.delete, project.delete/update/manage}`

`SUPER_ADMIN_PERMISSIONS = ALL_PERMISSIONS`.

## 6. Authorization Flow

```
JWT (sub=user_id) → get_current_user → User row
  → _is_super_admin? → bypass (super_admin has all perms)
  → _effective_org_role(user, organization_id, db) → role or None (404 if not member)
      → if OrganizationMembership exists with status active → that role
      → else fallback: User.organization_id == organization_id → admin→org_admin else member
  → _effective_project_role(user, project_id, db) → role or None
      → if ProjectMembership active exists → that role
      → else fallback: org_role of project's organization → org_admin→project_admin else analyst
  → Permissions check: role's permission set contains required permission → allow else 403
  → Resource ownership: require_project_access verifies Project belongs to org, then predicate
      `Asset.project_id==pid`, `Scan via Target→Project`, etc.
  → Database operation (WHERE project_id / organization_id)
```

For project-scoped resources the chain is:
```
authenticated user → verify org membership → verify project belongs to org
→ verify project membership / org fallback → verify permission → access resource
```

Never trust `organization_id`/`project_id`/`user_id` from body/query as identity — derive from `current_user` + membership lookup.

404 vs 403: use 404 for not-found or cross-tenant to avoid enumeration; 403 for insufficient permissions within same tenant.

## 7. Do Not Trust Client Tenant IDs

All tenant context is derived from `current_user` (`sub` from JWT) + `OrganizationMembership`/`ProjectMembership` + `Project.organization_id`. Client-supplied `project_id` is validated via `require_project_access` (checks `Project.organization_id == current_user.org`) before any permission check. Direct `organization_id` from body (e.g., `ProjectCreate.organization_id`) is ignored — `create_project` uses `current_user.organization_id`.

## 8. Resource Authorization (current vs target)

| Resource | Owner | Who can read | Who can create/update/delete/execute | Current (after P0 fixes) | Target RBAC |
|---|---|---|---|---|---|
| Organizations | — | member of org | org_admin update, super_admin manage | `get_user_organization` via `current_user.org` | `organization.read` vs `organization.update` via org role |
| Projects | `organization_id` | org members (via `get_projects` filter) | create/delete: org_admin (enforced), update/manage: org_admin/project_admin | POST/DELETE now require org_admin (enforced in `projects.py`) | Already enforced for create/delete; future: `project.update` via project_admin |
| Targets | `project_id` | viewer+ (org fallback) | create: analyst/project_admin, delete: analyst/project_admin (transitional, future project_admin only) | `POST`/`DELETE` now check `analyst`/`project_admin` via `_effective_project_role` | Viewer cannot create/delete (enforced) |
| Scans | `target_id→project_id` | viewer+ | execute: analyst/project_admin | `POST /scans` checks `analyst`/`project_admin` | Already enforced |
| Assets/Relationships/ChangeEvents | `project_id` | viewer+ | worker upsert only | `GET /assets` org-scoped, `GET /assets/{id}` project check | `asset.read` via viewer |
| Findings/Evidence | `scan_id/target_id→project_id` | viewer+ | triage: analyst | `GET /findings` org/project scoped | `finding.read` vs `finding.triage` |
| Cloud accounts/resources | `project_id` | viewer+ | manage: analyst/org_admin | `GET /cloud/*` project-scoped | `cloud.read` vs `cloud.manage` |
| Ingestions | `project_id` | — | create: analyst/project_admin | `POST /ingestions/prepare` currently only checks `require_project_access`; future will check `ingestion.create` (not yet enforced, documented gap) | Add `ingestion.create` check |
| Scan results | `scan_id` | via scan access | worker only | via `_require_scan_access` | same |
| Scanner config | static | any authed | `scanner.manage` → org_admin/super_admin (future) | `GET /scanners` any authed | Future gating |

Nested ownership is always verified through the full chain (finding→scan→target→project→organization).

## 9. Project Creation

Organization comes from `current_user.organization_id` (derived, not client `organization_id`). `POST /projects` now requires `org_admin` (checked via `_effective_org_role`). Member → 403. Transitional: existing `User.role=admin` maps to `org_admin`, so existing admin users retain ability; `member` users now correctly denied. No arbitrary `organization_id` from body is trusted.

## 10. Destructive Operations

- `DELETE /projects/{id}` → requires `org_admin` (enforced).
- `DELETE /targets/{id}` → requires `analyst`/`project_admin` (transitional; future will be `project_admin` only) — checked via `_effective_project_role`.
- Other destructive ops (scan results, assets) are worker-only.

No broad admin bypass — `super_admin` bypass is explicit and auditable.

## 11. Expensive Operations

Permissions defined but not all enforced via rate limiting (rate limiting deferred):
- `scan.execute` → `POST /scans` (enforced)
- `ingestion.create` → `POST /ingestions/prepare` (documented, not yet enforced — gap)
- `cloud.discovery` → `cloud.manage` (read-only discovery currently, future live discovery will check `cloud.manage`)
- `attack-path generation` → bounded (`max_depth` 1-10, `max_paths` 1-500)

Only authorization is established in this phase; rate limiting is separate.

## 12. Database Migration

`9f8e7d6c5b4a_add_organization_project_memberships`:
- Creates `organization_memberships` and `project_memberships` with FKs, unique constraints, indexes.
- Populates `organization_memberships` from existing `users` (`admin`→`org_admin`, else `member`). Project memberships not auto-populated — gap documented, fallback preserves access.
- Downgrade drops both tables/indexes.

## 13. Backward Compatibility

- `users.organization_id` retained; if `organization_memberships` row missing, fallback to `users.organization_id` mapping.
- `projects.organization_id` unchanged; project access fallback: if no `project_membership`, use org membership → `org_admin`→`project_admin`, else `analyst` (so existing org members retain read/create/execute on existing projects).
- No `super_admin` silently granted — only `users.role == 'super_admin'` is platform super_admin.
- Existing legitimate access (org member reading own org projects) remains functional; cross-tenant still 404.

## 14. Strict RBAC Cutover (Per-Project Strict + RBAC_STRICT_MODE)

- **Default:** `RBAC_STRICT_MODE=false` (transitional). `backend/app/api/deps.py::_effective_project_role` now checks: if project has any explicit `project_membership` rows, missing membership → `None` (DENIED) — per-project strict. If project has zero explicit rows, fallback `org member → analyst` / `org_admin → project_admin` is used (backward compat). If `RBAC_STRICT_MODE=true`, fallback is disabled for all projects (missing → DENIED globally).
- **Backfill:** `backend/app/services/project_backfill.py` (`backfill_project_memberships(dry_run=True)`) classifies each project as `ALREADY_BACKFILLED` (has explicit), `SAFE_TO_BACKFILL` (authoritative evidence — currently 0 because creator not stored), `AMBIGUOUS` (has targets/scans/assets but no creator), `NO_EVIDENCE` (no activity). It is deterministic, idempotent (`unique` constraint prevents duplicates), supports `--dry-run` (default) and `--apply` (only creates for `SAFE`, currently 0). Existing projects are `AMBIGUOUS`/`NO_EVIDENCE` and are **not** fabricated — manual assignment required. New projects get explicit `project_admin` for creator and are immediately strict.

## 15. RLS Compatibility

`RLS_ENABLED=false`, no policies, no `ENABLE ROW LEVEL SECURITY` (verified via `grep`). Future flow:

```
JWT → authenticated user → org membership → project membership → permission
→ verified tenant context (validate UUID) → BEGIN → set_tenant_context(db, org_id, project_id, user_id) → RLS USING (project_id = current_setting('app.current_project_id',true)::uuid) → rows
```

Helper `backend/app/db/rls.py` already uses `set_config(:k,:v,true)` transaction-local; future wiring will call it after `require_project_access` inside `with db.begin()`.

## 15. Auditability

Authorization decisions are via centralized `deps.py` helpers (`_effective_org_role`, `_effective_project_role`, `require_permission`) so they can later integrate with audit logging. Future audit log should record `organization_id`, `project_id`, `user_id`, `role`, `permission`, `action`, `resource`, `result`, `request_id`, `correlation_id`, `timestamp`. No secrets logged.

## 16. Limitations & Gaps

- Project memberships for existing projects not auto-created — relies on org fallback (documented transitional).
- `POST /ingestions/prepare` not yet checks `ingestion.create` permission.
- No UI for membership management; no API to create `organization_memberships`/`project_memberships` yet — must be created via direct DB or future admin API.
- `User.role` legacy mapping is heuristic (`admin`→`org_admin`); if an existing user had `admin` but should be `member`, migration over-grants.
- Super admin has no dashboard or audit trail yet.

## 17. Verification

- Tests: `backend/tests/test_rbac.py` (24 tests), `test_rls.py` (19), `test_authz_targets_dashboard.py` (8), `test_s61_api.py` (6), `test_auth.py` (4), `test_persistence.py` (7) — all pass; `alembic check` and `alembic heads` show single head `9f8e7d6c5b4a`.
- No scanner behavior changed; `GET /scanners` still any authed.


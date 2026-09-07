# RBAC — Role Hierarchy, Permissions, and Authorization (P14.2)

## Role Hierarchy

```
Platform: super_admin
  ↓
Organization: organization_admin > security_admin > security_analyst > developer > viewer > auditor (+ legacy member/org_admin)
  ↓
Project: project_admin > security_admin > security_analyst > developer > viewer > auditor (+ legacy analyst/viewer)
```

- One organization role per user per organization.
- Different project roles per project.
- Project role never grants org privileges; org role never grants other project's data.

## Permission Vocabulary (deterministic)

Projects: `projects.read/create/update/delete`, `project.manage_members`
Targets: `targets.read/create/update/delete`
Scans: `scans.read/create/cancel/delete`
Findings: `findings.read/triage/assign/update/accept_risk/close/reopen`
Assets: `assets.read/update`, `attack_surface.read`
Reports: `reports.read/create/delete`
Compliance: `compliance.read/manage`
Code Security: `code_security.read/manage`
Cloud Security: `cloud.read/manage`, `cloud_security.read/manage`
DAST: `dast.read/manage`
Repositories: `repositories.read/connect/manage`
Integrations: `integrations.read/manage`
Cloud Accounts: `cloud_accounts.read/connect/manage`
Users: `users.read/invite/update/disable/delete`
Teams: `teams.read/manage`
Audit: `audit.read`
Scanners: `scanners.read/manage/upgrade/rollback`
Administration: `organization.manage/read/update/manage_members`, `project.manage`, `policies.manage`
Legacy: `dashboard.read`, `ingestion.create` (mapped)

## Matrix (canonical, enterprise)

| Permission | org_admin | sec_admin | sec_analyst | developer | viewer | auditor | project_admin | sec_analyst (proj) |
|---|---|---|---|---|---|---|---|---|
| projects.read | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| projects.create | ✓ | ✓ | - | - | - | - | ✓ (proj) | - |
| projects.delete | ✓ | - | - | - | - | - | ✓ | - |
| targets.create | ✓ | ✓ | ✓ | - | - | - | ✓ | ✓ |
| scans.create | ✓ | ✓ | ✓ | - | - | - | ✓ | ✓ |
| findings.triage | ✓ | ✓ | ✓ | - | - | - | ✓ | ✓ |
| findings.accept_risk | ✓ | ✓ | - | - | - | - | ✓ | - |
| findings.close | ✓ | ✓ | - | - | - | - | ✓ | - |
| assets.update | ✓ | ✓ | - | - | - | - | ✓ | - |
| reports.create | ✓ | ✓ | ✓ | - | - | - | ✓ | ✓ |
| audit.read | ✓ | ✓ | ✓ | - | ✓ | ✓ | ✓ | - |
| organization.manage | ✓ | - | - | - | - | - | - | - |
| scanners.manage | ✓ | - | - | - | - | - | - | - |

Full matrix in `backend/app/core/permissions.py` (`_ORG_ROLE_PERMISSIONS_CANONICAL`, `_PROJECT_ROLE_PERMISSIONS_CANONICAL`).

Legacy aliases: `member`→`viewer`, `org_admin`→`organization_admin`, `analyst`→`security_analyst`.

## Authorization Flow

```
JWT → get_current_user → _is_super_admin? → bypass
  → _effective_org_role (OrganizationMembership or fallback User.organization_id, alias)
  → _effective_project_role (ProjectMembership or fallback org→project, strict if any explicit)
  → permissions_for_* → require_permission("findings.triage") → 403 or allow
  → require_project_access (Project.organization_id == user org) → 404
  → WHERE project_id / organization_id
```

`require_permission` checks `permission in perms` after merging org+project perms for project scope. Super_admin bypasses via `SUPER_ADMIN_PERMISSIONS`.

## Resource Ownership

- `projects` → `organization_id`
- `targets`/`scans`/`assets`/`findings` → `project_id` → `organization_id`
- `reports` → `project_id`
- `repositories`/`cloud_accounts` → `project_id`
- `audit` → `organization_id`/`project_id`
- `onboarding` → `user_id` (per user, not per org, isolated)

Every lookup uses `require_project_access` or `require_org_membership` before query, prevents IDOR via UUID.

## Super-admin Boundary

- Can manage `organizations`, `users`, `scanner fleet`, `system health`, platform `audit`.
- Does NOT automatically read customer `source_file`, `secret` evidence, private repo content — requires explicit audited capability (future, not in P14.2).
- Every super_admin action audited with `actor_user_id` + `organization_id` (if applicable) + `request_id`.

## Membership Management

- `POST /organizations/{id}/members` → `organization.manage_members` (org_admin), cannot grant `super_admin`, cannot self-escalate beyond own role, last-admin 409.
- `POST /projects/{id}/members` → `project.manage_members` (project_admin or org_admin), cannot grant higher than own, cannot grant `super_admin`, cross-org blocked, `viewer` cannot become `project_admin` without `project.manage_members`.
- All changes audited `ORGANIZATION_MEMBER_ADDED` etc., with `old_role`/`new_role`, `target_user_id`.

## Database

- `organization_memberships` (`unique(org_id,user_id)`, `role` check via `is_valid_org_role`, FK CASCADE, indexes)
- `project_memberships` (`unique(project_id,user_id)`, `role` check via `is_valid_project_role`, FK CASCADE)
- No new tables for P14.2 (reuses existing), permissions are code, not stored blob.
- Migration: none required for new roles (role column is `String(50)` free, validated via `is_valid_*`). Backward compat: existing `member`/`org_admin`/`viewer`/`analyst`/`project_admin` remain valid via aliases.

## Backward Compatibility

- Existing `admin` → `organization_admin`, `member` → `viewer` (org), `analyst` → `security_analyst` (project).
- `RBAC_STRICT_MODE=false` (transitional), per-project strict if any explicit membership, otherwise fallback `org→project` (org_admin→project_admin, member→analyst) preserved.
- Startup does not fail if new permission records missing — permissions are derived, not stored.

## Frontend

- `can(permission)` helper (future) — currently `user.role` checks remain, but backend is authoritative. Frontend hides buttons via `PROJECT_ROLE_PERMISSIONS` but does not expose privileged functionality.
- Navigation via `lib/permissions.js` (planned) — not yet in P14.2, documented as next.

## Audit

- `ORGANIZATION_MEMBER_ADDED/UPDATED/REMOVED`, `PROJECT_MEMBER_ADDED/UPDATED/REMOVED`, `SECURITY_CONFIGURATION_CHANGED`, `AUTHORIZATION_DENIED`/`CROSS_TENANT_ACCESS_DENIED`, `ONBOARDING_*`.
- Every event has `organization_id`/`project_id`/`actor`/`target`/`request_id`/`correlation_id`, redacted.

## RLS Preparation

- App auth remains authoritative (`get_current_user` + `require_project_access` → `WHERE`).
- Future `SET LOCAL app.current_organization_id` after `require_project_access` inside `with db.begin()` will add defense-in-depth. Migration `i9a0b1c2d3e4` remains untouched (`RLS_ENABLED=false`).

## Known Limitations

- `teams` not yet implemented (permission exists, no table).
- `policies.manage` not yet wired (permission exists).
- Frontend `can()` helper not yet implemented (next phase).
- No `project` table for `teams`/`policies`.
- `test_dependency_count_correct` still fails (pre-existing).

# API Security Inventory — Authorization & Tenant Isolation Audit

> **Scope:** Complete endpoint authorization matrix for the VAPT platform.
> **Branch:** `feat/api-security-inventory` from `main` @ `73bcfeb` (Merge feat/rls-foundation)
> **Verified against:** `backend/app/main.py`, `backend/app/api/routes/*.py` (10 modules), `backend/app/api/deps.py`, `backend/app/core/security.py`, `backend/app/core/config.py`, `backend/app/db/rls.py`, `backend/app/models/*.py`, `backend/tests/*.py`, `frontend/src/lib/api/*.js`
> **Labels:** `PASS` = enforces expected check, `FAIL` = vulnerability, `N/A` = not applicable, `FUTURE` = planned RBAC/RLS.
> **RLS status:** `RLS_ENABLED=false`, no table has `ENABLE ROW LEVEL SECURITY`, no `CREATE POLICY`, `backend/app/db/rls.py` helper is preparation-only and not wired into any route in this phase.

## 0. Terminology & Classifications

| Classification | Meaning |
|---|---|
| **PUBLIC** | No authentication required. Intended for unauthenticated clients (login, health). |
| **AUTHENTICATED** | Requires valid JWT `Authorization: Bearer` (`get_current_user`). No project/organization predicate. |
| **ORGANIZATION_SCOPED** | Requires auth + `user.organization_id == resource.organization_id` (or indirect via `Project`). |
| **PROJECT_SCOPED** | Requires auth + `require_project_access(project_id, db, current_user)` which verifies `Project.id == pid AND Project.organization_id == current_user.organization_id`, then predicates on `project_id`. |
| **SUPER_ADMIN_ONLY** | Requires `super_admin` role. Current codebase stores `User.role` but **no route enforces it** — marked `FUTURE / not currently implemented`. |

Resource ownership chain:
```
Organization (id)
 └─ User (organization_id FK)
 └─ Project (organization_id FK)
     └─ Target (project_id FK)
     │   └─ Scan (target_id FK) → ScanResult (scan_id) / Finding (scan_id, target_id, asset_id)
     ├─ Asset (project_id FK) → AssetRelationship (project_id, source/target_asset_id) → AssetChangeEvent (project_id, asset_id, scan_id)
     └─ CloudAccount/CloudResource → Asset (cloud_account/cloud_resource, canonical_value)
```

---

## 1. Complete Endpoint Inventory (42 endpoints)

### 1.1 Health / Docs (3) — PUBLIC

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 1 | GET | `/` | `main.py:root` | PUBLIC | N/A | none | PASS | None — public liveness, no sensitive data. |
| 2 | GET | `/health` | `main.py:health` | PUBLIC | N/A | none | PASS | Same. Exposed without auth is intentional. |
| 3 | GET | `/health/database` | `main.py:database_health` | PUBLIC | N/A | `SELECT 1` | PASS (LOW) | Unauthenticated DB probe leaks DB availability. Recommend rate-limit or require auth if probe is sensitive, but not a tenant leak. |

OpenAPI (`/docs`, `/openapi.json`) is mounted with default FastAPI when `DEBUG`, not enumerated as business endpoints.

### 1.2 Auth (3)

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 4 | POST | `/api/v1/auth/login` | `auth.py:login` | PUBLIC | N/A | `email.lower()`, `verify_password`, `JWT type=access` | PASS | No brute-force rate limit documented; rely on future API hardening. Uniform 401 “Invalid email or password.” is correct (no user-enumeration via 404). |
| 5 | GET | `/api/v1/auth/me` | `auth.py:read_current_user` | AUTHENTICATED | N/A (self) | `Depends(get_current_user)` + `get_user_organization` | PASS | Returns only `current_user` + `organization_name`. No ID from client, no IDOR. |
| 6 | POST | `/api/v1/auth/logout` | `auth.py:logout` | PUBLIC (stateless 204) | N/A | none (JWT stateless, no revocation list) | PASS (FUTURE) | Stateless logout is truthful — no server-side revocation. Future revocation list is `FUTURE`. Not a vulnerability in current stateless design. |

### 1.3 Projects (10) — PROJECT_SCOPED / ORGANIZATION_SCOPED

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 7 | POST | `/api/v1/projects` | `projects.py:create_project` | AUTH | ORGANIZATION_SCOPED | `user.organization_id` inserted, `Depends(get_current_user)` | PASS | Creates with `organization_id=current_user.organization_id` — correct. |
| 8 | GET | `/api/v1/projects` | `projects.py:get_projects` | AUTH | ORGANIZATION_SCOPED | `filter(Project.organization_id == current_user.organization_id)` | PASS | Strict org isolation. |
| 9 | GET | `/api/v1/projects/{project_id}` | `projects.py:get_project` | AUTH | ORGANIZATION_SCOPED | `filter(id==pid AND organization_id==current_user.organization_id)` | PASS | 404 on cross-org (no 403 leak). |
| 10 | DELETE | `/api/v1/projects/{project_id}` | `projects.py:delete_project` | AUTH | ORGANIZATION_SCOPED | Same predicate + `Target.project_id==pid` count guard | PASS | Count uses verified `pid` only after 404 guard — safe. |
| 11 | GET | `/api/v1/projects/{project_id}/scans` | `projects.py:get_project_scans` | AUTH | PROJECT_SCOPED | `require_project_access` then `Target.project_id==pid` | PASS | Correct. Note `status/profile` filter applied after count for `rows` but compensated by Python post-filter — functional, not security. |
| 12 | GET | `/api/v1/projects/{project_id}/assets` | `projects.py:get_project_assets` | AUTH | PROJECT_SCOPED | `require_project_access` + `Asset.project_id==pid` | PASS |  |
| 13 | GET | `/api/v1/projects/{project_id}/findings` | `projects.py:get_project_findings` | AUTH | PROJECT_SCOPED | `require_project_access` + `Target.project_id==pid` via Scan→Target join | PASS |  |
| 14 | GET | `/api/v1/projects/{project_id}/attack-paths` | `projects.py:get_project_attack_paths` | AUTH | PROJECT_SCOPED | `require_project_access` + asset ownership check `Asset.id==asset_id AND project_id==pid` | PASS |  |
| 15 | GET | `/api/v1/projects/{project_id}/security-summary` | `projects.py:get_project_security_summary_route` | AUTH | PROJECT_SCOPED | `require_project_access` | PASS |  |
| 16 | GET | `/api/v1/projects/{project_id}/risk-summary` | `projects.py:get_project_risk_summary` | AUTH | PROJECT_SCOPED | `require_project_access` (alias) | PASS |  |

### 1.4 Targets (4) — **CRITICAL FAIL**

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 17 | POST | `/api/v1/targets` | `targets.py:create_target` | AUTH (via `main.py` `protected` wrapper, **not** declared in handler) | **PROJECT_SCOPED required, none enforced** | `Target(project_id=data.project_id)` with no `require_project_access` | **FAIL — CRITICAL** | Any authed user can create a target in any project by guessing `project_id` (horizontal escalation, cross-org). |
| 18 | GET | `/api/v1/targets` | `targets.py:get_targets` | AUTH (wrapper) | PROJECT_SCOPED required | `db.query(Target).all()` — no predicate | **FAIL — CRITICAL** | Returns **all** targets across all organizations (cross-tenant enumeration, object enumeration). |
| 19 | GET | `/api/v1/targets/{target_id}` | `targets.py:get_target` | AUTH (wrapper) | PROJECT_SCOPED required | `filter(Target.id==target_id)` only — no org/project | **FAIL — CRITICAL** | IDOR: read any target by UUID, even cross-org. |
| 20 | DELETE | `/api/v1/targets/{target_id}` | `targets.py:delete_target` | AUTH (wrapper) | PROJECT_SCOPED required | Same unscoped fetch + `db.delete` | **FAIL — CRITICAL** | IDOR delete any target cross-org (destructive cross-tenant). |

### 1.5 Scans (5)

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 21 | POST | `/api/v1/scans` | `scans.py:create_scan` | AUTH | PROJECT_SCOPED | `filter(Target.id==target_id, is_active)` then `if target: require_project_access(target.project_id, ...)` | PASS (LOW) | Guard is post-fetch; if `target` is foreign org, 404 bubbles → safe but leaks existence via timing vs not-found. Not a data leak. Rate-limit and request validation exist; no role check. |
| 22 | GET | `/api/v1/scans` | `scans.py:get_scans` | AUTH | PROJECT_SCOPED or ORGANIZATION_SCOPED | If `project_id`/`project` supplied → `require_project_access` + `Target.project_id==pid`; else `join(Project).filter(organization_id==current_user.org)` | PASS | Paginated, org-scoped fallback correct. |
| 23 | GET | `/api/v1/scans/{scan_id}/progress` | `scans.py:get_scan_progress` | AUTH | PROJECT_SCOPED | `_require_scan_access(scan_id)` → `Scan→Target→Project→org` chain | PASS |  |
| 24 | GET | `/api/v1/scans/{scan_id}/details` | `scans.py:get_scan_details` | AUTH | PROJECT_SCOPED | Same `_require_scan_access` + `Finding.scan_id==scan_id` | PASS |  |
| 25 | GET | `/api/v1/scans/{scan_id}` | `scans.py:get_scan` | AUTH | PROJECT_SCOPED | Same | PASS |  |

### 1.6 Scanners (1)

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 26 | GET | `/api/v1/scanners` | `scanners.py:get_scanners` | AUTH (wrapper) | N/A (static) | none — static `SCANNERS` list (9 families) | PASS | No DB, no sensitive data. Auth via wrapper is sufficient. |

### 1.7 Findings (2)

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 27 | GET | `/api/v1/findings` | `findings.py:get_findings` | AUTH | PROJECT_SCOPED or ORGANIZATION_SCOPED | If `project_id`/`project` → `require_project_access` + `Target.project_id==pid`; else `join(Project).filter(org==current_user.org)` + `scan_id/severity/scanner/status/asset_id/search` filters (escaped `ilike`). | PASS |  |
| 28 | GET | `/api/v1/findings/{finding_id}` | `findings.py:get_finding` | AUTH | PROJECT_SCOPED | Raw `filter(Finding.id==fid)` then **post-fetch** `require_project_access(target.project_id)` via `Scan→Target` (or `Asset.project_id` fallback) | PASS (LOW) | Fetch is unscoped before guard, but guard 404s on cross-org. Acceptable pattern; no data returned on failure. No plaintext secret leak (worker redacts before API). |

### 1.8 Assets (7)

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 29 | GET | `/api/v1/assets` | `assets.py:get_assets` | AUTH | PROJECT_SCOPED or ORGANIZATION_SCOPED | If `project`/`project_id` → `require_project_access` + `Asset.project_id==pid`; else `join(Project).filter(org==current_user.org)` + `asset_type/status/search` (escaped). | PASS | Correctly org-scoped fallback (fixed vs earlier leak). |
| 30 | GET | `/api/v1/assets/summary` | `assets.py:get_assets_summary` | AUTH | PROJECT_SCOPED (if param) else **GLOBAL cross-tenant** | If `pid` → `require_project_access` + `get_project_security_intelligence_summary`; else `db.query(Asset).all()` → compute signals across **all rows** | **FAIL — CRITICAL** | No `project_id` → aggregates assets from **every organization** (cross-tenant leak, includes `signals` exposure). Endpoint should require `project_id` or scope to `current_user.organization_id`. |
| 31 | GET | `/api/v1/assets/security-intelligence-summary` | `assets.py:get_security_intelligence_summary` | AUTH | PROJECT_SCOPED | `Query(..., description="Project ID")` required → `require_project_access` | PASS |  |
| 32 | GET | `/api/v1/assets/attack-paths` | `assets.py:get_attack_paths` | AUTH | PROJECT_SCOPED | `require_project_access` + asset ownership `Asset.id==asset_id AND project_id==pid` | PASS |  |
| 33 | GET | `/api/v1/assets/relationships` | `assets.py:list_relationships_alias` | AUTH | PROJECT_SCOPED | `require_project_access` + `AssetRelationship.project_id==pid` | PASS |  |
| 34 | GET | `/api/v1/assets/{asset_id}` | `assets.py:get_asset` | AUTH | PROJECT_SCOPED | Raw `filter(Asset.id==asset_id)` then `require_project_access(asset.project_id)` | PASS (LOW) | Post-fetch guard 404s on cross-org — safe. |
| 35 | GET | `/api/v1/assets/{asset_id}/relationships` | `assets.py:get_asset_relationships` | AUTH | PROJECT_SCOPED | Same fetch-then-guard | PASS (LOW) | Same. |

### 1.9 Dashboard (1) — **CRITICAL FAIL**

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 36 | GET | `/api/v1/dashboard/summary` | `dashboard.py:get_dashboard_summary` | AUTH (wrapper) | ORGANIZATION_SCOPED required (or PROJECT_SCOPED) | `func.count(Scan.id)` / `Finding` counts / `avg(Scan.risk_score)` — all **global**, no `join(Project).filter(organization_id==current_user.org)` | **FAIL — CRITICAL** | Authenticated UserA sees totals for **all organizations** (scan count, finding by severity, average risk). Cross-tenant business data leak. |

### 1.10 Ingestions (1)

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 37 | POST | `/api/v1/ingestions/prepare` | `ingestions.py:prepare_ingestion` | AUTH | PROJECT_SCOPED | `require_project_access(project_id, db, current_user)` before any `Form` file handling; archive limits (100MiB, 500MiB extracted, 10k files, 50MiB/file), `_validate_entry_name` traversal/absolute/Windows/UNC/null, symlink validation, `mkdtemp 0o700`, `shutil.rmtree` cleanup always. | PASS | Correct. No IDOR. Rate-limit not yet wired (future). |

### 1.11 Cloud (5)

| # | Method | Path | Module:Handler | Auth | Scope | Current Check | Status | Gap |
|---|---|---|---|---|---|---|---|---|
| 38 | GET | `/api/v1/cloud/providers` | `cloud.py:list_providers` | AUTH | N/A (static) | No DB, `list_providers().to_dict()` fallback | PASS |  |
| 39 | GET | `/api/v1/cloud/accounts` | `cloud.py:list_cloud_accounts` | AUTH | PROJECT_SCOPED | `require_project_access` + `Asset.project_id==pid, asset_type==cloud_account` | PASS |  |
| 40 | GET | `/api/v1/cloud/assets` | `cloud.py:list_cloud_assets` | AUTH | PROJECT_SCOPED | Same guard + `Asset.project_id==pid` + `provider` substring | PASS |  |
| 41 | GET | `/api/v1/cloud/assets/{asset_id}` | `cloud.py:get_cloud_asset` | AUTH | PROJECT_SCOPED | Raw fetch then `require_project_access(asset.project_id)` + `asset_type in (cloud_account,cloud_resource)` | PASS (LOW) | Same post-fetch guard — safe. |
| 42 | GET | `/api/v1/cloud/assets/{asset_id}/related` | `cloud.py:get_related_assets` | AUTH | PROJECT_SCOPED | Same fetch-then-guard + `AssetRelationship.project_id==asset.project_id` + `a.project_id != asset.project_id` skip | PASS | Defensive filter correct. |

**Totals:** 42 endpoints discovered (3 health + 3 auth + 10 projects + 4 targets + 5 scans + 1 scanners + 2 findings + 7 assets + 1 dashboard + 1 ingestion + 5 cloud). Health/project/scans/scanners/findings/ingestion/cloud are predominantly `PASS`.

---

## 2. Authorization Matrix — Current vs Target

### Current dependency chain (verified in code)

```
User -> Authentication (get_current_user: Bearer decode_access_token -> User row lookup)
     -> request.state.user_id / organization_id (deps.py enriches for logging)
     -> Route handler: either explicit Depends(get_current_user) or global protected wrapper
     -> Optional: require_project_access(pid) verifies Project.id+organization_id == current_user.organization_id -> 404
     -> Resource query: handler scopes or not (see Status column)
     -> Service / repository layer: generally trusts route-layer scope; persistence.py uses WHERE project_id but does not re-verify organization.
```

### Current implementation summary

| Layer | Pattern | Coverage |
|---|---|---|
| `main.py` | `protected = [Depends(get_current_user)]` on 8 routers | Enforces auth, but implicit — removal silently opens 39 endpoints. |
| `deps.py:require_project_access` | `Project.id==pid AND organization_id==user.org` → 404 | Used in every project sub-route except `targets.py`, `dashboard`, `assets/summary` (global). |
| `deps.py:get_current_user` | `decode_access_token` + `User.id` lookup + `WWW-Authenticate: Bearer` 401 | No `require_role` helper exists. |
| `models` | Direct FK `project_id` only on `projects`/`assets`/relationships; transitive `Target→Project` for scans/findings | No `organization_id` denormalized — must join via `Project`. |
| `rls.py` | `RLS_ENABLED=false`, helper not wired | Not enforced this phase. |

### Required Target Architecture (for next RBAC phase)

| Method | Endpoint | Auth | Scope | Resource | Required Check | RLS Candidate |
|---|---|---|---|---|---|---|
| POST | `/api/v1/targets` | JWT | PROJECT_SCOPED | targets | `require_project_access(data.project_id)` + org-scoped insert | projects, targets |
| GET | `/api/v1/targets?project_id=` | JWT | PROJECT_SCOPED or ORGANIZATION_SCOPED | targets | `require_project_access` if param, else `join Project filter org` | targets |
| GET/DELETE | `/api/v1/targets/{id}` | JWT | PROJECT_SCOPED | target | `Target→Project→org` verify, then fetch | targets |
| GET | `/api/v1/dashboard/summary` | JWT | ORGANIZATION_SCOPED | scans/findings/assets (aggregate) | `join Target→Project filter org == current_user.org` (or `?project_id` with `require_project_access`) | scans, findings, assets |
| GET | `/api/v1/assets/summary` | JWT | ORGANIZATION_SCOPED or PROJECT_SCOPED | assets (aggregate) | Require `project_id` OR `join Project filter org` when absent | assets, relationships, findings |

All other endpoints remain as currently `PASS` but should gain explicit `Depends(get_current_user)` in handler signatures for clarity and add `require_role(["member","admin"])` where future RBAC restricts create/delete.

---

## 3. Trace Authorization End-to-End (protected resource example)

**Example: `GET /api/v1/assets/{asset_id}`**

```
Client → GET /api/v1/assets/<asset_id> with Authorization: Bearer <JWT>

main.py: protected dependency → get_current_user(request, credentials, db)
  → decode_access_token(token) validates type=access, exp, sub -> user_id
  → db.query(User).filter(id==user_id).first() -> user (or 401)
  → request.state.user_id, organization_id enriched

assets.py:get_asset(asset_id, db, current_user)
  → db.query(Asset).filter(id==asset_id).first()  // unscoped fetch
  → if not asset → 404
  → require_project_access(asset.project_id, db, current_user)
       → db.query(Project).filter(id==pid AND organization_id==current_user.org).first()
       → if not found → 404 (no org enumeration via 403)
  → _load_neighbors, findings, signals, contextual risk (all project_id-scoped)
  → return AssetDetailResponse

Missing: No second check in service layer (_load_neighbors already filters project_id, safe).
Alternative future: transaction → set_tenant_context(db, org, project) → RLS policy USING (project_id = current_setting('app.current_project_id',true)::uuid)
```

**Anti-pattern found (targets/dashboard/assets/summary global):**
```
Client → GET /api/v1/targets (or dashboard/summary, assets/summary without pid)
  → get_current_user succeeds (auth passes)
  → handler does db.query(Target).all() or func.count() with NO organization/project predicate
  → attacker from Org B receives Org A rows (cross-tenant leak)
  → frontend assumes backend isolates, but backend does not
```

Do not assume UUID secrecy: `target_id`, `asset_id`, `scan_id`, etc. are guessable via `/all` enumeration on vulnerable endpoints.

---

## 4. Resource Access Matrix

| Resource | Table(s) | Owner | Read | Create | Update | Delete | Expensive Exec | Current | Future RBAC |
|---|---|---|---|---|---|---|---|---|---|
| Organizations | `organizations` | — (root) | member of org (via `get_user_organization`) | super_admin only (bootstrap) | super_admin | super_admin | N/A | `GET /auth/me` returns `organization_name`; no list/update | Platform `super_admin` read-only across orgs, no customer data unless explicitly authorized |
| Projects | `projects` | `organization_id` | org members (filtered `org_id`) | org members | org members (delete if no active Targets) | org members | N/A | `require_project_access` on sub-routes | Add `project_admin` vs `project_viewer`; RLS `USING (organization_id = ...)` |
| Users | `users` | `organization_id` | self via `/auth/me`, admin via org | bootstrap | self | admin (future) | N/A | No list users endpoint | `org_admin` can list/manage org users |
| Targets | `targets` | `project_id` → `organization_id` | **ANY authed user (FAIL)** | **ANY authed user (FAIL)** | — | **ANY authed user (FAIL)** | N/A | 4/4 FAIL | `member` may read/listed by project, `admin` may create/delete; RLS `USING (project_id = ...)` |
| Scans | `scans` | `target_id→project_id` | org/project scoped | org/project members via `create_scan` | worker updates `status/phase` | — | `POST /scans` triggers Celery `execute_scan` (expensive) | Guarded via `_require_scan_access` | Rate-limit `create_scan`, add `can_execute_scan` permission |
| Scan results | `scan_results` | `scan_id` | via scan access | worker only | worker | — | N/A | Guarded via scan | Same as scans |
| Assets | `assets` | `project_id` | org/project scoped (except `/summary` global FAIL) | worker `upsert_assets` | worker / change detection | — | N/A | `/assets` PASS, `/summary` without pid FAIL | RLS candidate |
| Asset relationships | `asset_relationships` | `project_id` | project scoped | worker `upsert_relationships` | worker | — | N/A | PASS where project required | RLS candidate |
| Asset change events | `asset_change_events` | `project_id` | project scoped (via assets) | worker `persist_change_events` (savepoint isolated) | — | — | N/A | PASS | RLS candidate |
| Findings | `findings` | `scan_id/target_id/asset_id → project` | org/project scoped | worker `_persist_findings` | triage via `validation` (future) | — | N/A | PASS | RLS candidate; `evidence` type `secret` stays redacted |
| Evidence/Provenance | `evidence` (in `finding_correlation`) | finding-scoped | same as finding | worker | — | — | N/A | Not separately exposed | Same as findings |
| Repositories / Source artifacts | `worker/app/ingestion` workspace + `assets` `repository`/`source_file` | `project_id` | project scoped | via `POST /ingestions/prepare` | — | — | `POST /ingestions/prepare` (archive extraction, artifact detection, scanner routing) | Project-gated before file ops | Add upload rate-limit, quarantine |
| Cloud accounts/resources | `assets` `cloud_account`/`cloud_resource` | `project_id` | project scoped | via cloud discovery (mock) | — | — | `GET /cloud/*` (read-only discovery) | PASS | RLS candidate |
| Integrations | — | FUTURE | FUTURE | FUTURE | FUTURE | FUTURE | FUTURE | Not present | `integration_admin` |
| Reports/Jobs/Audit logs | `scans` `status/phase/progress` + future tables | project/org | project/org members | worker | — | — | Scan execution (Celery) | Scan progress/detail PASS | `job_viewer` vs `job_admin`, audit append-only |
| Settings | `projects` `organization` | org | org members | org_admin | org_admin | — | N/A | `projects` CRUD covers | `org_admin` |
| Scanner config/versions | `scanners.py` static `SCANNERS` + `scanners/*/Dockerfile` `PRODUCTION_VERSION` | platform | any authed user | platform only | — | — | N/A | `GET /scanners` public-to-authed, no mutation | `platform_admin` for version mutation |
| Dashboard | aggregate `scans/findings/assets` | org/project | **ANY authed user sees ALL orgs (FAIL)** | N/A | N/A | N/A | Aggregations | 1/1 FAIL | Org-scoped counts |

---

## 5. Authentication Audit

- **Protected routes require valid authentication:** `main.py:63` `protected = [Depends(get_current_user)]` is applied to 8 routers (39 endpoints). `auth/login`, `/`, `/health`, `/health/database` are intentionally `PUBLIC`. All other business routes 401 without token — verified via `test_auth.py::test_login_and_me_succeed_with_valid_credentials` → `GET /api/v1/projects` without token → 401.
- **Missing token → 401:** `get_current_user` uses `HTTPBearer(auto_error=False)` then raises `401 detail="Your session has expired..." headers={"WWW-Authenticate":"Bearer"}` when `credentials is None`.
- **Malformed token → 401:** Same path; scheme != bearer or empty credentials → 401.
- **Invalid token / wrong type:** `decode_access_token` checks `payload.type=="access"` and `sub` presence → raises `TokenError` → 401. Non-access tokens (e.g., refresh if introduced) are rejected.
- **Expired token → 401:** `ExpiredSignatureError` → `TokenError` → 401 with same `SESSION_EXPIRED_DETAIL`. No stack leak (handled, not 500).
- **Revoked token:** Current `auth.py:66` `logout` is stateless 204 with no DB — no revocation list. `TokenError("revoked")` branch exists in `security.py` but `logout` does not populate it. Documented as `FUTURE` — stateless JWT is truthful for current design.
- **Token claims validated:** `sub` (user_id), `exp`, `iat`, `type=="access"` are validated; `JWT_ALGORITHM=HS256`, `JWT_SECRET` from `DATABASE_URL` default `change-this-in-production` (dev). No `aud`/`iss` claims — noted as low.
- **Organization identity from trusted state:** `current_user.organization_id` comes from DB row looked up by `sub`, not from client header/body. `require_project_access` then uses `current_user.organization_id` as authoritative, never `request.query_params["organization_id"]`.
- **User identity not from client fields:** All handlers use `current_user.id` from token; no endpoint accepts `user_id` from query/body as identity.
- **Authorization header not logged:** Verified `backend/tests` no log of header; `test_persistence.py` etc. do not log. No evidence of header logging in `deps.py`/`main.py`.
- **CORS:** `allow_origins=sorted(cors_origins)` where `cors_origins` is localhost + `FRONTEND_URL` rstrip, `allow_credentials=True`, `allow_methods=["*"]`, `allow_headers=["*"]` — permissive methods/headers but credentials true with site-specific origins is acceptable for dev. Future hardening could narrow to explicit methods/headers.

**Gaps:** No brute-force rate limit on `POST /api/v1/auth/login` beyond future middleware; `ACCESS_TOKEN_EXPIRE_MINUTES=60` (1h) is longish — future could shorten to 15m + refresh. No `super_admin` enforcement present.

---

## 6. Project Authorization Audit

- **Project belongs to user's organization:** `require_project_access` verifies `Project.id==pid AND organization_id==current_user.organization_id`. Called in every project sub-route except `targets.py` (0/4), `dashboard` (0/1), `assets/summary` global (0/1).
- **Project existence via 404 not 403:** `404 detail="Project not found"` is used for both not-found and cross-org, avoiding org enumeration via 403 vs 404 differential — correct.
- **Every project-scoped endpoint uses the check:** Projects (10/10) yes, scans (5/5) yes, findings (2/2) yes, assets (5/7) yes (2 failures noted), cloud (5/5) yes, ingestions (1/1) yes, targets (0/4) no, dashboard (0/1) no.
- **Nested resources verified against the project:** `assets.py:get_attack_paths` verifies `Asset.id==asset_id AND project_id==pid` before `get_attack_paths_for_project`; `projects.py:get_project_attack_paths` same. `scans.py:_require_scan_access` verifies `Scan→Target→Project→org` chain before returning `ScanResult`/`Finding` rows.
- **Resource IDs can bypass project membership:** On vulnerable `targets` endpoints, raw `Target.id` or `project_id` from body/query bypasses — attacker with valid JWT from Org B can `POST /targets {project_id: <Org A pid>}` and it succeeds (cross-org injection). No `require_project_access` stops it.
- **Test for isolation:** `test_s61_api.py` uses two orgs (A/B) and verifies `User A / Org A / Project A` vs `User A / Org A / Project B` vs `User B / Org B / Project C` — expects 404 on cross-org/cross-project. Covers projects/scans/assets/findings/attack-paths, but **not** `targets`, `dashboard`, `assets/summary` global.

Expected `Company A user → Company B resource` = `DENY` (404). Currently 6 endpoints violate this.

---

## 7. Organization Authorization Audit

- **Organization-level endpoints:** `/api/v1/projects` (list/create/get), `/api/v1/scans` (list with org fallback), `/api/v1/assets` (org fallback when no project), `/api/v1/findings` (org fallback), `/api/v1/dashboard/summary` (aggregate intended org-level).
- **Verification:** `get_projects` filters `organization_id==current_user.org`; `get_assets`/`get_findings`/`get_scans` fallback `join(Project).filter(organization_id==current_user.org)` when no `project_id` — correct.
- **Vulnerable org-level aggregations:** `dashboard/summary` and `assets/summary` (global) omit the `organization_id` predicate entirely, so `Organization A user → Organization B resource` = `ALLOW` (leak).
- **No client-supplied `organization_id`:** No route accepts `organization_id` from query/body as tenant identifier — correct. Tenant comes from `current_user.organization_id` only.

---

## 8. Super Admin Audit

**CURRENT ROLE MODEL:** `User.role` column (`String`) exists (`user.py`). Bootstrap creates `role=admin` if `AUTH_BOOTSTRAP_*` set. No `require_role`/`require_admin` helper in `deps.py`, no route declares `Depends(require_role([...]))`. `test_s61_api.py` creates users with `role="admin"` but never tests role.

**CURRENT ADMIN MODEL:** Not implemented — any authenticated member can `POST /projects`, `DELETE /projects/{id}`, `POST /scans`, `POST /targets` (when fixed), `POST /ingestions/prepare`. No distinction `admin` vs `member`.

**MISSING ENTERPRISE ROLE MODEL:** Minimal viable is `member` (read project-scoped), `project_admin` (create/delete targets, trigger scans), `org_admin` (manage projects/users), `super_admin` (platform operational visibility across orgs, **read-only** across companies, minimizing access to customer-sensitive content unless explicitly authorized, with audit). Future design should:
  - Gate destructive/expensive ops (`DELETE /projects/{id}`, `POST /scans`, `POST /ingestions/prepare`) via `project_admin` or `org_admin`.
  - Make `GET /admin/...` platform routes `SUPER_ADMIN_ONLY` with audit logging, rate-limited, and not exposing `Asset.value`/`Finding.evidence` without explicit consent.
  - Store `role` as enum, add `organization_role` and `project_role` join tables later.

This task does **not** implement super-admin. Mark as `FUTURE`.

---

## 9. Expensive Operation Authorization

| Endpoint | Operation | Auth | Project Isolation | Rate Limit | Validation | Note |
|---|---|---|---|---|---|---|
| `POST /api/v1/scans` | Enqueue Celery `execute_scan` (Docker scanners) | YES (`_require_scan_access` after Target fetch) | YES (via `require_project_access`) | Not yet wired | `TargetCreate` via `pydantic`, `ScanCreate` `profile` validated | Expensive, should be rate-limited per org/project + `can_execute_scan` permission. |
| `POST /api/v1/ingestions/prepare` | Archive extraction (100MiB/500MiB, 10k files, traversal checks) + artifact detection + scanner routing | YES | YES (before file ops) | Not yet | `Form project_id`, file `UploadFile` type, size limits, traversal/absolute/Windows/UNC/null checks, `0o700` workspace | Most expensive file handling; already project-gated before extraction, but needs per-user upload rate limit. |
| `GET /api/v1/assets/attack-paths` | Graph `discover_attack_paths` (asset graph) | YES | YES | Not yet | `max_depth 1-10`, `max_paths 1-500` bounded | CPU-bound but bounded. |
| `DELETE /api/v1/projects/{id}` | Destructive (cascades) | YES | YES | Not yet | 404 guard | Destructive, should require `org_admin`. |
| `DELETE /api/v1/targets/{id}` | Destructive | YES (wrapper) but **no project check** | **NO** | Not yet | IDOR delete | Critical fix required. |

Scanner execution (`POST /scans`) does not change scanner architecture in this task.

---

## 10. IDOR / Cross-Tenant Audit — Detailed

**Pattern searched:** `db.get(...)`, `query.filter(Model.id == supplied_id)`, `query.get(supplied_id)` without `organization_id`/`project_id` predicate.

**Findings:**

1. **`targets.py:25 Target(project_id=data.project_id)` — IDOR create** — no `require_project_access`. Attack: `POST /api/v1/targets {"project_id":"<OrgA pid>","value":"evil.com","target_type":"domain"}` with Org B JWT → creates row in Org A project. Root cause: missing route-layer check.
2. **`targets.py:46 query.all()` — horizontal enumeration** — returns all `Target` rows regardless of org. Attack: `GET /api/v1/targets` with any valid JWT → dump every org’s targets.
3. **`targets.py:58-60 filter(id==target_id)` — IDOR read** — `GET /api/v1/targets/<id>` reads any org’s target. Same for `DELETE`.
4. **`dashboard.py:24-107 global counts` — cross-tenant aggregate leak** — `func.count(Scan.id)` etc. with no join. Attack: `GET /api/v1/dashboard/summary` → Org B sees Org A’s scan/finding totals + avg risk.
5. **`assets.py:139 db.query(Asset).all()` — cross-tenant aggregate leak** — `GET /api/v1/assets/summary` without `project_id` → `Asset` dump → `aggregate_security_signals_for_assets` across all orgs. Attack: Org B calls endpoint without param → receives Org A assets’ signals.
6. **Post-fetch guard pattern** (`findings.py:110` `filter(Finding.id==fid)` then `require_project_access` via `Scan→Target`): technically fetches unscoped row before check, but check 404s before returning body — **not** an exploitable IDOR (no data returned on failure). Accepted, but less efficient than predicate-early.
7. **No frontend-only authorization:** Frontend `src/lib/api/client.js` correctly attaches `Authorization: Bearer` for `auth!==false`, redirects 401 to `/login`, but never performs project authorization — backend is authoritative (correct). `ProjectProvider` loads projects and stores `selectedProjectId` in `sessionStorage`, but backend still verifies.

**Service layer:** `worker/app/persistence.py` uses `WHERE project_id = :project_id` but trusts caller’s `project_id` from `tasks.py::get_project_id(target_id)` which validates `target_id` ownership — safe if API layer already gated.

---

## 11. Existing Test Audit

| Test File | Covers | Missing |
|---|---|---|
| `test_auth.py` (112L) | `hash_password` round-trip, `create_access_token` round-trip, login rejects invalid (401), login+me success, `GET /projects` 401 without token | No 401 malformed/expired/revoked, no 401 on targets/dashboard/assets. |
| `test_s61_api.py` (494L) | Two-org isolation harness (`org_a/b`, `proj_a1/a2/b`, scans/assets/findings). Covers `projects` (list/get/404), `scans` (project isolation + pagination, `/progress`, `/details`), `assets` (project filter, type/search, pagination, detail/relationships), `findings` (severity/scanner/search, pagination, detail), `attack-paths`, `security-summary`/`risk-summary`, empty collections. | **Not covered:** `targets` (0), `dashboard/summary` (0), `assets/summary` global (0), `ingestions` (0), `cloud` (0), `scanners` auth. |
| `test_persistence.py` (566L) | Model dedup, `upsert_assets`, change detection, not HTTP isolation | Not HTTP — no auth checks. |
| `test_rls.py` (376L) | `RLS_ENABLED=false` default, UUID validation, SQLite no-op, mocked PG transaction-local, parameterized `set_config`, pool isolation, optional real PG | Not endpoint isolation. |
| `test_assets_api.py` (141L) | Route registration, `Asset` list filters by `project_type/search`, detail includes relationships/findings | No cross-org negative test. |
| `test_scan_observability.py`, `test_sca_*.py`, etc. | Scanner/catalog/observability | Not auth. |

**Missing critical authorization invariants:** 6 endpoints above have **zero** existing cross-tenant tests. Adding focused regression tests for `targets` (create/list/get/delete cross-org), `dashboard/summary` (org counts), `assets/summary` (global) is required.

No rewrite of entire suite — add `backend/tests/test_authz_targets_dashboard.py` with 8-10 focused tests only.

---

## 12. Security Findings — Classification

### CRITICAL

| # | Endpoint | Vulnerability | Attack Scenario | Affected Resource | Current Behavior | Expected Behavior | Root Cause | Recommended Fix | Test Required |
|---|---|---|---|---|---|---|---|---|---|
| C-1 | `POST /api/v1/targets` | Cross-organization object creation (IDOR write) | Org B user POSTs `{"project_id":"<Org A pid>"}` → target created in Org A project | `targets` | No `require_project_access` | Verify `project_id` belongs to `current_user.organization_id` before insert | Missing route-layer check | Add `require_project_access(data.project_id, db, current_user)` before `Target(...)` | `test_create_target_cross_org_404` |
| C-2 | `GET /api/v1/targets` | Cross-tenant enumeration leak | Any valid JWT → `GET /targets` returns all orgs’ targets | `targets` (all rows) | `query.all()` no predicate | `JOIN Project filter org` or `filter(Target.project_id IN user_org_projects)` | Missing predicate | Add org-scoped query (`join Project filter organization_id`) + optional `project_id` filter with `require_project_access` | `test_list_targets_cross_tenant_empty` |
| C-3 | `GET /api/v1/targets/{id}` | IDOR read | Guess `target_id` from Org A → `GET /targets/<id>` returns it to Org B user | `targets` single | `filter(id==param)` only | `filter(id==param).join(Project).filter(organization_id==user.org)` or fetch then `require_project_access` | Missing predicate | Add target→project→org verification | `test_get_target_cross_org_404` |
| C-4 | `DELETE /api/v1/targets/{id}` | IDOR destructive delete | Guess `target_id` → `DELETE /targets/<id>` deletes cross-org target | `targets` destructive | Same unscoped fetch + `db.delete` | Same org verification before delete | Same | Add same guard, idempotent 404 | `test_delete_target_cross_org_404` |
| C-5 | `GET /api/v1/dashboard/summary` | Cross-tenant aggregate leak | Org B → `GET /dashboard/summary` sees Org A’s scan/finding counts + avg risk (business data) | `scans`, `findings` (aggregate) | Global `func.count` no join | `join Target→Project filter org` or `require_project_access` if `?project_id` | Missing join | Scope all counts via `join(Project).filter(organization_id==user.org)` | `test_dashboard_summary_isolated` |
| C-6 | `GET /api/v1/assets/summary` (no `project_id`) | Cross-tenant aggregate leak (asset signals) | Org B → `GET /assets/summary` without param → receives `total_assets`, `internet_facing`, etc. across all orgs | `assets`, `asset_relationships`, `findings` (via signals) | `db.query(Asset).all()` no filter | Require `project_id` (404 if missing) OR `join Project filter org` when absent | Missing predicate | Make `project_id` required OR org-scope fallback; fix implements org-scoped fallback | `test_assets_summary_no_project_isolated` |

### HIGH

| # | Endpoint | Vulnerability / Gap | Expected Behavior | Root Cause | Recommended Fix |
|---|---|---|---|---|---|
| H-1 | Implicit auth via `main.py:protected` | 39 endpoints rely on global wrapper without explicit `Depends(get_current_user)` in handler signature — removal of wrapper silently opens endpoints; also `scanners.py:92 get_scanners` and `targets.py`/`dashboard.py` have no explicit dependency | Each handler declares `current_user: User = Depends(get_current_user)` for clarity/defense-in-depth | Architectural — wrapper is correct but fragile | Add explicit `Depends` to `targets.py`, `dashboard.py`, `scanners.py` handlers as part of fix (no behavior change) |
| H-2 | `GET /health/database` unauthenticated DB probe | `GET /health/database` (PUBLIC) runs `SELECT 1` with `Depends(get_db)` — leaks DB availability to unauthenticated callers | Require auth or rate-limit, or merge into `/health` | Health is PUBLIC by design | Accept as LOW or gate with `Depends(get_current_user)` if probe is sensitive — document as `INFORMATIONAL` |

### MEDIUM

| # | Gap | Expected Behavior |
|---|---|---|
| M-1 | No `require_role` / no `super_admin` enforcement | Any member can `POST /projects`, `DELETE /projects`, `POST /scans`, `POST /ingestions/prepare`. Future RBAC needs `member` vs `admin` vs `org_admin` vs `super_admin`. |
| M-2 | No rate limiting on expensive ops | `POST /scans`, `POST /ingestions/prepare`, `GET /attack-paths` are bounded but not rate-limited per org/project. Future: `rate_limit` middleware. |
| M-3 | `ACCESS_TOKEN_EXPIRE_MINUTES=60` + no refresh rotation documentation | 1h access is longish; refresh not implemented. Future: 15m access + httpOnly refresh. |

### LOW / INFORMATIONAL

- `CORS allow_methods=["*"] allow_headers=["*"]` with `allow_credentials=True` — permissive but origin-restricted (localhost + `FRONTEND_URL`). Future narrowing to explicit methods/headers is low priority.
- `JWT aud/iss` not set — low. `JWT_SECRET` default `change-this-in-production` in `config.py` is placeholder — env must override in prod (not code fix).
- Post-fetch-then-guard pattern (`findings/{id}`, `assets/{id}`) fetches unscoped row before 404 — not exploitable (no data returned on failure) but less efficient; acceptable.

**Distinction:** C-1…C-6 are `SECURITY VULNERABILITY` (exploitable cross-tenant access). H-1 is `ARCHITECTURAL GAP` (fragility). M-1…M-3 and super-admin absence are `FUTURE RBAC REQUIREMENT` (missing feature, not a vulnerability in current single-tenant-minded but multi-org-capable deployment).

---

## 13. Resource Ownership Summary (see Matrix §4)

All persistence is `WHERE project_id = :project_id` with ownership validated at API boundary via `require_project_access` — except the 6 endpoints above which omit it. Service layer trusts the API-provided `project_id` from `get_project_id(target_id)` validation. No resource is currently `SUPER_ADMIN_ONLY`.

---

## 14. Frontend Cross-Check

- **Centralized client:** `frontend/src/lib/api/client.js` (`getAccessToken` from `localStorage "vapt.access_token"` → `Authorization: Bearer` when `auth!==false`). All `src/lib/api/*.js` use `api.get/post` with `auth:true` default — no public business endpoint assumes public. `auth.js:login` uses `auth:false`.
- **Protected requests attach credentials:** Yes — `buildHeaders` adds `Bearer` for every non-`auth:false` call.
- **Protected endpoints assumed public by frontend:** No — frontend only calls authenticated routes; `ProjectProvider` loads projects via `listProjects()` (authed).
- **401 handling:** `client.js:145` on 401 (non-auth route) → `clearAccessToken`, `unauthorizedHandler()`, `redirectToLogin("/login?next=...")`. `AuthProvider.jsx:loadSession` also handles 401. Consistent.
- **Frontend-only authorization:** Frontend `ProjectProvider` stores `selectedProjectId` in `sessionStorage` but never enforces project membership — backend does (correct). No `if (user.role === "admin")` gate that backend should enforce.
- **Finding:** Frontend is aligned — backend remains authoritative. No frontend rewrite required in this audit; do not weaken backend to accommodate frontend.

---

## 15. RLS Compatibility

- **Current:** `RLS_ENABLED=false` (checked `config.py:41`), `backend/app/db/rls.py` helper exists but **not wired** into any route/middleware. No `ENABLE ROW LEVEL SECURITY`, no `CREATE POLICY`, no migration (verified `backend/alembic/versions/` 11 files).
- **Candidate resources for future RLS:** `projects` (`organization_id = current_setting('app.current_organization_id',true)::uuid`), `targets`/`assets`/`asset_relationships`/`asset_change_events` (`project_id = ...`), `scans` via `target_id→project_id` join, `findings` via `scan_id→project_id`, `scan_results` via `scan_id`, cloud `assets` (`cloud_account`/`cloud_resource` via `project_id`). Helper GUCs `app.current_organization_id`/`app.current_project_id`/`app.current_user_id` are already defined.
- **Future architecture (as in docs):**

```
Authenticated user → Application authentication (get_current_user)
  → Organization membership (User.organization_id)
  → Project membership (require_project_access verified)
  → Permission (FUTURE RBAC role check)
  → Verified tenant context (validate_context_value UUIDv4)
  → PostgreSQL transaction: BEGIN; set_tenant_context(db, org, project, user); queries; COMMIT (RLS policy USING (project_id = current_setting('...',true)::uuid))
  → Resource
```

- This phase does **not** enable RLS — document only.

---

## 16. Remediation Priorities (for next Multi-Tenancy + RBAC phase)

**P0 — This audit’s contained fixes (implement now, minimal, high-confidence):**
1. Fix `targets.py` (4 endpoints) — add `require_project_access` + org-scoped queries.
2. Fix `dashboard.py` — org-scope all aggregates via `join Target→Project filter org`.
3. Fix `assets.py:/summary` — make global summary org-scoped (when no `project_id`, `join Project filter org`).
4. Add `backend/tests/test_authz_targets_dashboard.py` (9 tests) covering all 6 failures.
5. Keep `RLS_ENABLED=false`, no policies, no RBAC redesign in this commit.

**P1 — Next RBAC phase (deferred, not in this commit):**
- Explicit `Depends(get_current_user)` on every handler (defense-in-depth).
- Introduce `require_role(["member","admin"])` and `require_org_admin` / `super_admin` gating for `DELETE /projects`, `POST /scans`, etc.
- Add `organization_id` denormalization on `scans`/`findings` for simpler RLS policies.
- Wire `set_tenant_context` after `require_project_access` inside `with db.begin():` for RLS defense-in-depth.
- Rate-limit `POST /auth/login`, `POST /scans`, `POST /ingestions/prepare` per `current_user.id`/`organization_id`.
- Add audit log table (`audit_logs` org/project scoped, append-only).

**P2 — Future (FUTURE):**
- Super Admin platform read-only across orgs with audit, `reports`/`jobs`/`integrations` tables, RBAC matrix per operation.

---

## 17. Fixes Implemented in This Audit Phase

> Implement only this section after `docs/API_SECURITY_INVENTORY.md` is committed or in the same commit as the fixes.

**This phase implements the P0 fixes (6 endpoints) as contained, high-confidence changes without architecture change:**

| File | Change | Verified |
|---|---|---|
| `backend/app/api/routes/targets.py` | Add `get_current_user` + `require_project_access` to all 4 handlers; scope `get_targets` org-wide (`join Project filter org`) + optional `project_id` filter; `create_target` validates `project_id` before insert; `get_target`/`delete_target` verify `Target→Project→org` | Tests `test_*_targets_dashboard` |
| `backend/app/api/routes/dashboard.py` | Replace global `func.count`/`avg` with org-scoped joins via `Target→Project filter organization_id==current_user.organization_id`; add `Depends(get_current_user)` | Same tests |
| `backend/app/api/routes/assets.py` | Replace `assets = db.query(Asset).all()` fallback with `join Project filter org` when no `project_id` | Same tests |
| `backend/tests/test_authz_targets_dashboard.py` | 9 focused regression tests (two orgs, cross-tenant 404/empty, dashboard isolation, assets summary isolation) | `pytest backend/tests/test_authz_targets_dashboard.py -q` |

No `RLS_ENABLED` toggle, no policies, no `super_admin` creation, no scanner change.

---

## 18. Testing & Verification (this phase)

Run after fixes:

```
python -m pytest backend/tests/test_rls.py backend/tests/test_auth.py backend/tests/test_authz_targets_dashboard.py backend/tests/test_persistence.py -q
python -m pytest backend/tests/test_s61_api.py -q          # existing isolation harness, must still 6 passed
python -c "import sys; sys.path.insert(0,'backend'); import app.main; import app.db.rls; print(app.db.rls.is_rls_enabled())"  # False
```

Expected invariant: `Company A user MUST NOT access Company B resources, even if the UUID is known.` Also `Project A user MUST NOT access Project B resources unless explicitly authorized` (verified via `require_project_access`).

---

## 19. Remaining Enterprise / RBAC Gaps (Deferred)

- `User.role` is stored but never enforced — no `require_role` helper, no `SUPER_ADMIN_ONLY` endpoint.
- No `organization_role`/`project_role` tables — single `role` string insufficient for enterprise.
- No audit log resource, no `reports`/`jobs`/`integrations` tables yet — matrices mark `FUTURE`.
- No rate limiting on expensive ops, no captcha/brute-force on login, no token revocation list.
- Frontend stores JWT in `localStorage` (XSS can steal) — future `httpOnly` cookie + refresh rotation.
- `POST /auth/logout` is stateless 204 — future revocation requires DB/Redis set.

Do not claim platform is fully multi-tenant, RBAC-complete, or RLS-enforced — this phase establishes the inventory and fixes the 6 critical cross-tenant leaks, preparing the next RBAC phase.

---

## 20. Post-Inventory Update — Enterprise Multi-Tenancy + RBAC Foundation (feat/multitenancy-rbac-foundation)

> **Current:** Transitional RBAC foundation implemented (membership tables, permission model, org_admin gating).
> **Target:** Full RBAC with explicit project membership enforcement and RLS defense-in-depth.

### Endpoint Classifications — Updated

| Method | Endpoint | Previous Class | New Class | Permission | Enforcement |
|---|---|---|---|---|---|
| POST | `/api/v1/projects` | PROJECT_SCOPED | ORGANIZATION_SCOPED (`org_admin`) | `project.create` → `org_admin` | **Enforced** via `_effective_org_role` check in `projects.py` (member → 403) |
| DELETE | `/api/v1/projects/{id}` | ORGANIZATION_SCOPED | ORGANIZATION_SCOPED (`org_admin`) | `project.delete` → `org_admin` | **Enforced** |
| POST | `/api/v1/targets` | PROJECT_SCOPED | PROJECT_SCOPED (`analyst`+) | `target.create` → `analyst`/`project_admin` | **Enforced** via `_effective_project_role` (viewer → 403) |
| DELETE | `/api/v1/targets/{id}` | PROJECT_SCOPED | PROJECT_SCOPED (`project_admin` transitional `analyst`+) | `target.delete` → `project_admin` (currently `analyst` also allowed for backward compat) | **Enforced** (transitional) |
| POST | `/api/v1/scans` | PROJECT_SCOPED | PROJECT_SCOPED (`analyst`+) | `scan.execute` → `analyst`/`project_admin` | **Enforced** |
| Others (`GET /projects`, `/targets`, `/scans`, `/assets`, `/findings`, `/dashboard`, `/cloud`, `/ingestions`) | PROJECT_SCOPED / ORGANIZATION_SCOPED | Same | `project.read`/`asset.read` etc. → `viewer`+ | **Transitional** — still via `require_project_access` + org fallback; not yet strict `viewer` check |
| `GET /scanners` | AUTHENTICATED | AUTHENTICATED | `scanner.manage` future | No change |

### Authorization Model — CURRENT / TRANSITIONAL / TARGET

- **CURRENT (after 6 fixes, before RBAC):** `get_current_user` → `User.organization_id` → `require_project_access` (`Project.organization_id == user.org`) → `WHERE project_id`.
- **TRANSITIONAL (this foundation):** Membership tables exist, `RLS_ENABLED=false`, permission model defined, `organization_memberships` populated from `users`, `project_memberships` explicit where created, fallback `org_member → analyst` / `org_admin → project_admin` preserves existing access. Project creation/deletion and target/scan creation now check `org_admin`/`analyst` roles. Other reads still use `require_project_access` fallback.
- **TARGET (future RBAC + RLS):** Explicit `project_membership` required for every project access (no fallback), `viewer`/`analyst`/`project_admin` strictly enforced per endpoint, `super_admin` platform visibility with audit, `BEGIN → set_tenant_context(org, project, user) → RLS USING (project_id = current_setting(...))`.

### Resource Ownership — Updated

Project creation now uses `current_user.organization_id` (not client `organization_id`) — body `organization_id` is ignored (existing schema still requires it but handler does not trust it). Organization membership is authoritative.

Do not claim RBAC is complete for endpoints not yet migrated (ingestion, cloud manage, dashboard, etc. remain transitional).

---

*Generated from direct `Read` of listed sources; no claim beyond verified code. Next step: implement P0 fixes and `test_authz_targets_dashboard.py`, then commit as `security(api): audit endpoint authorization and tenant isolation`.*

---

## 21. Update — RBAC Membership Enforcement (feat/rbac-membership-enforcement)

> **Status:** Strict-ish enforcement with membership management APIs, ingestion gap fixed, fallback preserved for existing projects.

### Membership APIs — Implemented

| Method | Endpoint | Auth | Permission | Enforcement |
|---|---|---|---|---|
| GET | `/api/v1/organizations/{org_id}/members` | org_admin | `organization.manage_members` | `_require_org_admin` (org_admin or super_admin) |
| POST | `/api/v1/organizations/{org_id}/members` | org_admin | `organization.manage_members` | Validate user exists, duplicate 409, role assignment security (cannot grant super_admin, member cannot grant org_admin), cross-org 403 |
| PATCH | `/api/v1/organizations/{org_id}/members/{user_id}` | org_admin | `organization.manage_members` | Last-admin protection (409 if last active org_admin) |
| DELETE | `/api/v1/organizations/{org_id}/members/{user_id}` | org_admin | `organization.manage_members` | Same last-admin protection |
| GET | `/api/v1/projects/{project_id}/members` | project_admin/org_admin | `project.manage_members` | `_require_project_manage` (project_admin or org_admin) |
| POST | `/api/v1/projects/{project_id}/members` | project_admin/org_admin | `project.manage_members` | Validate target user in same org (403 if not), duplicate 409, viewer/analyst cannot grant project_admin, cross-org 403 |
| PATCH | `/api/v1/projects/{project_id}/members/{user_id}` | project_admin/org_admin | `project.manage_members` | Similar role checks, no strict last project_admin (org_admin fallback ensures manageability) |
| DELETE | `/api/v1/projects/{project_id}/members/{user_id}` | project_admin/org_admin | `project.manage_members` | No last project_admin enforcement (documented) |

### Ingestion Gap — Fixed

`POST /api/v1/ingestions/prepare` now checks `_effective_project_role` → `analyst`/`project_admin` (viewer → 403) after `require_project_access`, before file processing. Verified via `test_membership.py::test_ingestion_viewer_denied_analyst_allowed`.

### Fallback Status

- `org member → analyst` / `org_admin → project_admin` fallback **preserved** for existing projects without explicit `project_membership` rows (creator not stored). New projects get explicit `project_admin` membership for creator. Future strict-deny (missing membership → DENIED) requires backfill of explicit memberships for all existing projects — not done in this phase, documented as transitional.

### Remaining Transitional Gaps

- `GET /projects`, `GET /targets`, `GET /scans`, `GET /assets`, `GET /findings`, `GET /dashboard` still rely on `require_project_access` fallback, not strict `viewer` check — will be tightened when explicit project memberships are backfilled.
- No UI for membership management; no audit log yet.

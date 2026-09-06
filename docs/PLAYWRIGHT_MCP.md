# Playwright E2E Security Validation (P13.1 + P13.2)

End-to-end browser tests plus an optional MCP harness that validate the VAPTool frontend against the running Docker stack **without weakening any security
control** and **without hitting external networks**.

Used to answer: does the app behave, stay tenant-isolated, enforce RBAC, keep
stored-XSS inert, and enforce MFA + password-reset flows when a real browser drives it?

**Status: COMPLETE / READY — 18 specs, 76 tests all passing** (53 P13.1 baseline + 13 MFA + 10 password-reset) against the rebuilt stack (2026-09-18). The suite docks around — never against — the live security controls: it works *within* the backend login rate limit instead of disabling it.

## What is covered

| Spec file | Coverage |
| --- | --- |
| `e2e/auth.spec.mjs` | Real form login, invalid credentials, next-param redirects, logout, token-removal re-auth (`/login?next=%2Fdashboard`) |
| `e2e/rbac.spec.mjs` | Viewer/analyst/project-admin 403 enforcement surfaced through the UI (generic `publicErrorMessage` on client vs raw `detail` on scans) |
| `e2e/tenant-isolation.spec.mjs` | Org A vs Org B isolation incl. deep-link safe-fallback + backend 404 / `CROSS_TENANT_ACCESS_DENIED` audit |
| `e2e/projects.spec.mjs` | Org-admin list/detail (targets on `?tab=targets`) + real create-project (API cleanup) |
| `e2e/findings.spec.mjs` | Inventory, severity filter, detail navigation |
| `e2e/scans.spec.mjs` | Seeded scan inventory (lowercase `quick` via CSS capitalize); real start-scan through the UI (`.test` target, NXDOMAIN fast-fail, no egress) |
| `e2e/assets.spec.mjs` | Asset Intelligence + Attack Surface (heading asserted with `exact: true`) |
| `e2e/code-security.spec.mjs` | SAST/SCA/Secrets page empty state |
| `e2e/cloud-security.spec.mjs` | Provider-neutral posture; deterministic seeded pool `CLOUD-001`.. (never empty) |
| `e2e/dast.spec.mjs` | Bounded/SSRF-protected safety posture |
| `e2e/reports.spec.mjs` | Tenant-scoped report inventory |
| `e2e/compliance.spec.mjs` | Self-seeded framework registry |
| `e2e/ai.spec.mjs` | Read-only assistant; disabled-state transparency |
| `e2e/admin.spec.mjs` | Super-admin console + admin nav |
| `e2e/security.spec.mjs` | Stored-XSS inertness, localStorage-only token, generic API errors, missing-header (CSP/HSTS) guard |
| `e2e/mfa.spec.mjs` | TOTP enrollment (QR, invalid/valid), challenge, recovery single-use, regeneration, disable, super-admin required, org policy blocked, no secret leakage, UI settings + login challenge |
| `e2e/password-reset.spec.mjs` | Forgot page, generic existent/non-existent, token lifecycle (invalid, full reset, reuse, MFA preserved), reset page, forgot link, session revocation after change |
| `e2e/responsive.spec.mjs` | Mobile drawer (`div.fixed.inset-0.z-50 > aside`) + stacked DataTable layout |

## Requirements

- Docker stack running with backend + frontend + PostgreSQL:
  `docker compose up -d --build`
- Node deps installed in `frontend/`: `npm install`
- Playwright Chromium downloaded: `npx playwright install chromium`
- Nothing else. No external/cloud browsers are used; the suite is offline-safe.

## Fixtures

Deterministic accounts/data are created by the backend seeder
`backend/scripts/seed_e2e_fixtures.py`, executed automatically by
`e2e/global-setup.mjs`:

```text
docker compose run --rm --no-deps -e E2E_SEED_ENABLED=true backend python scripts/seed_e2e_fixtures.py
```

- The seeder refuses to run against `ENVIRONMENT == "production"`, refuses to
  run unless `E2E_SEED_ENABLED == "true"` (or `--force` is passed), and is
  idempotent. `--purge` deletes only fixture-owned rows and never touches
  existing development data.
- Fixture credentials are test-only (`e2e.*@test.local` /
  `E2eTestPass!2026`), reserved in `.env.example` — they must never be used
  outside the test harness.
- The stored-XSS fixture `e2e/security.spec.mjs` relies on:
  `E2E XSS <img src=x onerror="window.__E2E_XSS_FIRED__=1"> Title`.

## Authentication strategy (storage-state)

Real browser authentication happens exactly once per fixture user, at the
start of a run, inside `global-setup.mjs`. The resulting token is persisted to
`frontend/test-results/state-<userKey>.json` (localStorage key
`vapt.access_token`, **no cookies**), and each spec declares
`test.use({ storageState })` per user, split into per-user `describe` blocks.

- Whole-suite login budget ≈ **9 hits**: 6 storage-state logins + auth
  form valid/invalid (2) + security wrong-creds (1) — far below the backend
  login rate limit (20/min/IP, Redis-backed) so **the rate-limit control stays
  enforced and is never bypassed**. `helpers.apiLogin` backs off under 429
  (75s deadline).
- `asUser` no longer logs in per test — it only sets the project context
  (`vapt.selectedProjectId`) and loads `/dashboard`.
- `ProjectContext` (frontend) silently discards a stored cross-tenant
  `selectedProjectId` and falls back to the user's first project, so a stale
  deep link never surfaces another org's data in the UI; tenant tests assert
  that safe fallback *and* assert the authoritative backend 404 via the API.

## DataTable note for locators

`DataTable` deliberately renders a mobile `<ul class="space-y-3 md:hidden">`
*first* and the desktop `<table role="table">` *second*. Always scope text
locators to `table[role="table"]` (and use `{ exact: true }` against URL cells)
or `.last()`, otherwise the hidden mobile copy matches first at desktop width.
This is a locator contract, not a reason to change the responsive layout.

## How to run

```text
cd frontend
npm run test:e2e            # headless run (1 worker)
npm run test:e2e:ui         # interactive UI mode
npm run test:e2e:debug      # step-through debugging
npm run test:e2e:report     # show the last HTML report
```

Optional environment overrides (see `frontend/.env.example`):

- `PLAYWRIGHT_BASE_URL` (default `http://localhost:3000`)
- `PLAYWRIGHT_API_URL` (default `http://localhost:8000`)
- `PLAYWRIGHT_SKIP_SEED=1` to skip fixture seeding in global-setup.

`global-setup.mjs` verifies the frontend is reachable and the backend
`/health` is healthy before running anything; it fails fast with instructions
otherwise. Run `npm run lint` and `npm run build` after changing specs.

## Security posture and known limitations

- **No security control is disabled or weakened** — auth, RBAC, tenant
  isolation, CSRF guards and rate limits all remain active; the tests
  exercise and assert their enforcement. The suite's ≈9-login budget and 429
  backoff exist *because* the 20/min login rate limit works; a 22-burst sanity
  probe returns 11 allowed + 11 × 429.
- **Tests are offline-safe**: the only network-touching scan is a `quick`
  profile against `e2e-alpha.example.test` (`.test` TLD → NXDOMAIN
  fast-fail). That UI-driven scan leaves one failed-scan row on the
  development database — an intentional end-to-end side effect.
- **Never commit** traces, screenshots, videos, or fixture tokens. Playwright
  artifacts are git-ignored (`test-results/`, `playwright-report/`) and only
  produced on failure (`trace: retain-on-failure`).
- **Known limitation (asserted as a guard):** the frontend currently emits no
  Content-Security-Policy / HSTS / frame-ancestors headers because there is no
  Next.js `middleware` yet. `e2e/security.spec.mjs` asserts this
  deliberately — the assertion starts failing the moment that hardening is
  added, which is the intended signal. Production-grade header hardening
  sits with the deployment/edge layer and is tracked in `PROJECT_STATE.md`.
- **Fixture data is disposable and guarded.** `seed_e2e_fixtures.py` is
  idempotent, `--purge` deletes only fixture-owned rows, and credentials are
  test-only (`e2e.*@test.local` / `E2eTestPass!2026`). Never use them outside
  the harness.

## MCP sidecar

`@playwright/mcp` is installed for interactive, permission-gated browser
automation from AI agents (e.g. driving the same app for ad-hoc
investigations). It is a development-only tool and is not part of the build or
production dependency graph.
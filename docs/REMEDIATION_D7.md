# D7 — Remediation Workflow

> Status: IMPLEMENTED (pending merge). No second finding lifecycle. No notifications (D9). No retest engine (D8).

## Product question

"For this security issue, who owns it, what needs to happen, what is the deadline,
what is its current remediation state, and has the issue actually been fixed?"

```
Finding → Risk/Priority → Owner → Remediation Action → SLA → Remediation State → Evidence/Retest → Resolved
```

## Architecture (reuse, not rebuild)

D7 extends the existing P14.5 `finding_remediations` workflow. Nothing is duplicated:

| Concern | Authoritative owner | D7 usage |
|---|---|---|
| Finding status | `findings.status` + `WORKFLOW_STATUSES` (`api/routes/findings.py`) | read-only context in payload (`finding_status`, `finding_severity`) |
| Remediation FSM | `services/finding_lifecycle.py` (`REMEDIATION_STATUSES/TRANSITIONS`) | extended additively with `blocked` |
| Owner | `FindingRemediation.assigned_to` + `_validate_user_in_org` | reused; cross-tenant rejected |
| SLA | `FindingSLA` + `get_sla_target_hours` + `evaluate_sla_status` | reused; `due_at` defaults from active SLA; payload exposes `sla_status`/`overdue`/`due_source` |
| Risk acceptance | `FindingRiskAcceptance` | read-only flag `accepted_risk`; SLA waive semantics untouched |
| History | `finding_history` | `remediation_created/assigned/due_changed/in_progress/blocked/submitted/completed/cancelled/evidence_added` |
| Audit | `AuditService` (`REMEDIATION_*` events) | bounded IDs-only metadata, no secrets/evidence bodies |
| Evidence | existing finding/scan evidence | D7 stores only bounded **references** (`evidence_ref` ≤ 2000 chars) |
| Verification | D8 retest (`finding_retests`) | D7 never marks `verified`; `completed` sets `verification_required: true` |

## Status model

```
open → in_progress → submitted → completed   (happy path)
open → cancelled
in_progress → blocked → in_progress          (block/unblock)
in_progress/submitted → blocked
any non-terminal → cancelled
completed/cancelled: terminal
```

- `blocked` is **active** (one-active-remediation-per-finding includes it) and requires
  `blocked_reason` (≤ 500 chars). It does **not** pause SLA and is **not** resolved.
- `submitted` is the optional "ready for review" step before `completed`.
- Same-status transitions are idempotent no-ops (safe for retries/double-clicks).
- Invalid transitions return `400` with no state change (transactional).

## Owner rules

- `assigned_to` must be a user in the finding's **organization** (`_validate_user_in_org`);
  cross-tenant assignment is rejected (`403`/`404`, never leaks existence).
- Writes require `analyst`/`project_admin` (via `_require_finding_manage`) or `org_admin`/`super_admin`;
  `viewer` can read the queue but cannot create/transition.
- Owner changes write `remediation_assigned` history (old → new) and audit.

## SLA behavior (reused, not recalculated)

- On create, omitted `due_at` defaults to the finding's active (or latest) SLA `due_at`
  (`due_source: "sla"`); explicit `due_at` wins (`due_source: "remediation"`).
- List/detail payloads expose `sla_status` (`active`/`breached`/`met`/`waived`),
  `overdue` (true only when breached), and `due_at`.
- No second SLA engine exists: `get_sla_target_hours`/`evaluate_sla_status` are the
  single implementation. Risk-accepted findings keep existing waive semantics;
  payload flags `accepted_risk: true` so UI never presents them as remediated.

## Evidence references

- `evidence_ref` is a bounded **reference** (e.g. `retest:run-123`, `scan:abc`), never raw
  bodies, credentials, secrets, source code, or scanner output.
- `sanitize_remediation_evidence_ref` truncates to 2000 chars and rejects secret-like
  content (`400`). History stores the first 200 chars only; audit stores IDs only.

## Completion vs verification (D7/D8 boundary)

- `completed` = **owner-reported** completion (actor + timestamp + notes preserved).
  It does **not** change `findings.status`, does **not** resolve, does **not** verify.
- The payload returns `verification_required: true, verified: false` with UI copy
  "Owner-reported complete — verification required (D8 retest)."
- D8 owns formal retesting and is the only path to `resolved`/`verified`.

## Reopening

D2/`FindingEngine` fingerprint logic remains authoritative. If a finding reopens
(`reopened` status, e.g. risk-acceptance expiry/revocation or failed retest),
remediation payloads surface the live `finding_status`; D7 creates no separate
reopening algorithm. A new remediation cycle can start after terminal states.

## API

All project-scoped, auth-required, RBAC + `require_project_access` enforced,
remediation rows re-scoped to `project_id` on every access (IDOR-safe).

| Method | Path | Notes |
|---|---|---|
| POST | `/api/v1/findings/{id}/remediations` | create (one active per finding → `409`) |
| GET | `/api/v1/findings/{id}/remediations` | per-finding list (+SLA rollup) |
| PATCH | `/api/v1/findings/{id}/remediations/{rid}` | assign/due/status/notes/evidence_ref |
| GET | `/api/v1/projects/{pid}/remediations` | queue: `status, severity, owner, overdue, finding_id, since, until, limit≤200, offset` |
| GET | `/api/v1/projects/{pid}/remediations/{rid}` | single (project-scoped) |
| POST | `.../remediations/{rid}/start` | → `in_progress` (idempotent) |
| POST | `.../remediations/{rid}/block` | requires `blocked_reason` |
| POST | `.../remediations/{rid}/unblock` | → `in_progress`, clears blocker |
| POST | `.../remediations/{rid}/complete` | owner-reported; `verification_required` |

List ordering: severity rank (critical → info), overdue first, oldest due first.
Queue query is bounded (`limit` ≤ 200) with a single batched SLA fetch (no N+1).

## Frontend

- `/projects/[project_id]/remediations` — queue table (finding, severity, owner,
  status, SLA/overdue, due, updated) with status/overdue filters, Start/Block/
  Unblock/Complete actions, loading skeleton, empty state
  ("No remediation work currently assigned."), bounded error + retry.
- Finding detail (`FindingLifecycle.jsx` remediation section) — blocked reason,
  evidence reference, SLA/overdue/due, accepted-risk note, verification-required
  banner, Block action (prompts for reason).

## RBAC

| Role | Read | Create/transition/assign/complete |
|---|---|---|
| viewer | yes | no (`403`) |
| analyst | yes | yes |
| project_admin | yes | yes |
| org_admin / super_admin | yes | yes (manage bypass) |

## Tenant isolation / RLS posture

- Enforcement is application-layer: `require_project_access` (404-vs-403, audited
  `CROSS_TENANT_ACCESS_DENIED`), `_finding_org_project` derivation (never trusts
  client `organization_id`), `_validate_user_in_org` for owners, project-scoped
  remediation fetch (`_require_remediation_row`).
- New `finding_remediations` columns inherit the table's existing posture; D7 adds
  no RLS policy. Development RLS remains as before — no database-enforced RLS is
  claimed for remediations.

## Performance

- Queue: one join (`remediations` ⨝ `findings`) + one batched SLA query; bounded
  `limit/offset`; composite index `(project_id, status)` (migration `u7v8w9x0y1z2`).
- No full-history scans; no per-row owner lookups (IDs returned, resolved client-side).

## Limitations

1. `alembic upgrade head` on existing databases is blocked by the **pre-existing**
   `o1p2q3r4s5t6` duplicate `ix_workers_status` index (unrelated to D7; not fixed here).
   D7 migration `u7v8w9x0y1z2` (revises `t6u7v8w9x0y1`) renders clean offline SQL.
2. A second alembic head (`6715084468e9`, scans `created_at`) pre-exists on a side
   chain; untouched by D7.
3. SQLite test suites that `create_all` `JSONB` columns or use stale raw-`findings`
   DDL fail pre-existing (fixture drift); D7 tests carry a local SQLite shim and pass 23/23.
4. No notifications (D9), no verification scans (D8), no external ticketing, no AI.

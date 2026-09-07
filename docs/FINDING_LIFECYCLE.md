# Finding Lifecycle (P14.4)

## States

- **Validation:** `detected` → `corroborated` → `needs_review` → `confirmed` → `false_positive`/`accepted_risk`/`remediated`/`reopened` (deterministic, `validation.py`)
- **Workflow:** `open`/`detected` → `triaged` → `in_progress` → `remediation_claimed` → `ready_for_retest` → `retesting` → `remediated` → `closed` → `reopened` (via `findings.status` + `workflow_status`, `FindingRemediation`/`FindingRetest` tables)
- **Dispositions:** `false_positive`, `accepted_risk` (require reason, audited, not deleted)

Workflow and validation are distinct: validation is scanner evidence, workflow is human triage.

## Ownership

- `assigned_to` (user_id, FK `users.id` SET NULL, indexed), `assigned_at`, `assigned_by`, `owner_user_id`, `owner_team_id` (nullable, deferred, no team table yet, documented).
- Assignment via `PATCH /findings/{id}` with `assigned_to`/`owner_user_id`, validates `user.organization_id` or `OrganizationMembership` active, same org, active user, history `assigned`/`owner_changed` with `actor`/`reason`/`request_id`/`correlation_id`.
- Team ownership prepared: `owner_team_id` column exists, no FK yet, will reference `teams` table in future Teams phase.

## Triage

- `POST /findings/{id}` `PATCH` with `status`/`severity_override`/`assigned_to`/`owner_user_id`/`tags`/`reason`, validates `WORKFLOW_STATUSES` (13), `SEVERITIES` (5), `TAG_RE` (`^[a-z0-9][a-z0-9._-]*$` 10 tags), `reason` required for `false_positive`/`accepted_risk`, `reopened` only from terminal (`resolved`/`false_positive`/`accepted_risk`/`remediated`/`closed`), `severity_override` preserves original `severity` and `score`, requires reason, audited, reversible.

## Severity/Risk Override

- `severity_override` separate from `severity`/`score`, `effective_severity = COALESCE(severity_override, severity)`, stored separately, `override_reason` via `reason`, audited `severity_override` history, reversible (`null` clears).

## False Positive

- `status = false_positive` with `reason`, not deleted, remains for history, `finding_history` `status_changed`, audit `FINDING_STATUS_CHANGED`, permission `findings.triage` (analyst/project_admin/org_admin), tenant-scoped.

## Accepted Risk

- `status = accepted_risk` with `reason`, `FindingRiskAcceptance` (`requested`/`approved`/`rejected`/`expired`/`revoked`, `expires_at`, `business_justification`, `compensating_controls`), `FindingHistory` `risk_acceptance_requested` etc., `status = accepted_risk` + `SLA waived`, not `closed`, distinct from `remediated`.

## Remediation

- `FindingRemediation` (`open`/`in_progress`/`submitted`/`completed`/`cancelled`, `assigned_to`, `due_at`, `completion_notes`), `POST /findings/{id}/remediations` (one active), `PATCH` transitions via `REMEDIATION_TRANSITIONS`, `remediation_claimed_at`/`by`, `ready_for_retest_at`, not auto `closed`, `retest` required.

## Retest

- `FindingRetest` (`requested`/`queued`/`running`/`passed`/`failed`/`error`/`cancelled`, `scanner`, `target_value`, `result`, `evidence`), `POST /findings/{id}/retests/request` (one active, scanner from original), `PATCH` transitions via `RETEST_TRANSITIONS`, `passed` → `finding.status = resolved` + `FINDING_RESOLVED`, `failed` → `reopened` + `FINDING_REOPENED`, `evidence` 2000 chars, not fake retest.

## Reopen/Closure

- `closed`/`remediated`/`resolved` → `reopened` only via `PATCH status=reopened` from terminal, `closed_at`/`closed_by` set on `closed`/`remediated`, cleared on `reopened`, `workflow_status` sync.

## History

- `finding_history` (`finding_id`, `actor_user_id`, `action`, `old_value`, `new_value`, `reason`, `organization_id`, `project_id`, `request_id`, `correlation_id`, `metadata`, `created_at`, indexes on `finding_id`/`organization_id`/`project_id`), `finding_comments` (2000 chars), `finding_tags`, plus `AuditService` (`FINDING_UPDATED`/`TRIAGED`/`STATUS_CHANGED`, `REMEDIATION_*`, `RETEST_*`, `RISK_ACCEPTANCE_*`), tenant-isolated, RLS `finding_history` via `findings` join, immutable append-only.

## RBAC

- `findings.read` (viewer+), `findings.triage` (analyst/project_admin/org_admin), `findings.assign` (analyst/project_admin), `findings.update` (analyst/project_admin), `findings.accept_risk` (security_admin/project_admin), `findings.close` (project_admin/security_admin), `findings.reopen` (project_admin). Viewer cannot triage/assign/close, developer cannot accept_risk unless `security_admin`, cross-project assign denied via `_validate_user_in_org`.

## API

- `GET /findings`, `GET /findings/{id}`, `PATCH /findings/{id}` (triage/assign/severity/tags), `POST /findings/{id}/assign` (alias), `POST /findings/{id}/unassign`, `POST /findings/{id}/remediation`, `POST /findings/{id}/retest`, `POST /findings/{id}/close`, `POST /findings/{id}/reopen`, `GET /findings/{id}/history` (50, paginated, tenant-isolated).

## RLS

- `findings` RLS via `target_id` → `projects.organization_id` (existing), `finding_history` RLS via `findings` join (new, `tenant_isolation_finding_history`), `user_onboarding` per `user_id` isolated, `findings` new columns `workflow_status`/`assigned_at` etc. indexed, `finding_history` `organization_id`/`project_id` RLS.

## Frontend

- `/findings` and `/findings/[finding_id]` show `severity`/`effective_severity`/`risk`/`validation`/`status`/`workflow_status`/`owner`/`assigned`/`evidence`/`remediation`/`retest`/`history`, actions respect `can("findings.triage")` etc., backend authoritative.

## Future

- Team ownership via `owner_team_id` → `teams` table (deferred), SLA engine P14.5, Git ownership deferred, scanner control-plane deferred.

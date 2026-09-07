# SLA & Risk Acceptance (P14.5)

## SLA Model

- `finding_slas` (`finding_id`, `organization_id`, `project_id`, `severity`, `target_hours`, `started_at`, `due_at`, `completed_at`, `breached_at`, `paused_at`, `resumed_at`, `cancelled_at`, `pause_reason`, `remaining_hours`, `status`, `policy_name`).
- `sla_policies` (`organization_id`, `severity`, `target_hours`).

## States

`active` → `paused` → `active` (resume) → `met`/`breached`/`waived`/`cancelled` → `overdue` (derived `due_at < now` and `active`).

- `ACTIVE`: within due, not completed/waived/cancelled.
- `PAUSED`: `paused_at` set, `remaining_hours` preserved, `due_at` recalculated on `resumed_at`.
- `COMPLETED`/`met`: `completed_at` set.
- `WAIVED`: `status=waived` via risk acceptance `approved` → `SLA waived`.
- `OVERDUE`: `due_at < now` and `active` (derived, not stored).
- `CANCELLED`: `cancelled_at` set.

Finding `IN_PROGRESS` with `OVERDUE` SLA is valid.

## Clock

- `started_at` = `now` UTC on `POST /sla/start` (triaged/confirmed), `due_at = started_at + target_hours`.
- Server `datetime.now(timezone.utc)` UTC, naive for SQLite, `due_at` indexed.
- `remaining_hours` preserved on `paused_at`, recalculated on `resumed_at`.

## Start

- Trigger: `POST /findings/{id}/sla/start` after triage (`analyst`/`project_admin`), severity from `severity_override` or `severity`, `target_hours` via `SLAPolicy` or `DEFAULT_SLA_HOURS` (critical 24, high 72, medium 168, low 336, info 720).

## Policy Engine

- Deterministic `get_sla_target_hours(db, org_id, severity)` → `SLAPolicy` or `DEFAULT`, extensible per org/severity, future per project/asset criticality.

## Pause/Resume

- `POST /findings/{id}/sla` with `action=pause` (requires `findings.triage`, reason, actor, `paused_at`, `remaining_hours`, audit `SLA_PAUSED`), `resume` (recalculates `due_at = now + remaining_hours`, `resumed_at`, audit `SLA_RESUMED`), not allowed to repeatedly pause.

## Waiver

- `action=waive` (requires `findings.accept_risk`, `approved` risk acceptance → `SLA waived` via `finding.status = accepted_risk` → `SLA waived`).

## Overdue

- Derived `due_at < now` and `active`, `refresh_sla_breach` sets `breached`/`breached_at`, `SLA_OVERDUE` audit, no scheduler.

## Completion

- `action=complete` (requires `findings.close`), `completed_at`, `met`, not via `remediation_claimed` alone, verified via `retest` `passed`.

## Reopened

- `finding.status = reopened` → new `FindingSLA` evaluated via `POST /sla/start` with new `started_at`/`due_at`, history `reopened` + new `sla_created`, audited.

## Risk Acceptance

- `finding_risk_acceptances` (`finding_id`, `org_id`, `project_id`, `requested_by`/`requested_at`, `approved_by`, `rejected_by`/`rejected_at`, `revoked_by`/`revoked_at`, `status` `requested`/`approved`/`rejected`/`expired`/`revoked`, `reason`, `business_justification`, `compensating_controls`, `valid_from`, `expires_at`, `reviewed_at`, `review_notes`).
- `POST /request` with `reason` + `expires_at` future, `GET`, `PATCH approve` (requires `findings.accept_risk`, `business_justification`, separation of duties: `requested_by != approved_by` unless `super_admin`/`organization_admin`), `reject`, `revoke` (requires `findings.accept_risk`, `revoked_at`, `finding` remains `accepted_risk` historically, `SLA` re-evaluated).

## Expiration

- `expires_at` future, `check_ra_expired` sets `expired` when `now > expires_at` and `approved`, preserves history, `finding` → `reopened` if `accepted_risk`, not `fixed`.

## Revocation

- `revoke` sets `revoked`/`revoked_at`/`revoked_by`, `finding` stays, `SLA` re-evaluated, `risk_acceptance_revoked` history, audit.

## Compensating Controls

- `compensating_controls` text (WAF, segmentation, etc.), documentation only.

## RBAC

- `findings.triage` (analyst/project_admin/org_admin), `findings.accept_risk` (security_admin/project_admin), `findings.close` (project_admin), `audit.read`, `project.read` for `GET`.

## RLS

- `finding_slas`/`finding_risk_acceptances` via `finding_id` → `project_id` → `organization_id` (existing RLS via `findings` join, new `finding_history` style), `trusted` `organization_id` from `require_project_access`, `USING`/`WITH CHECK` `organization_id = current_setting`.

## Audit

- `SLA_CREATED`/`STARTED`/`RECALCULATED`/`PAUSED`/`RESUMED`/`COMPLETED`/`WAIVED`/`CANCELLED`/`OVERDUE`, `RISK_ACCEPTANCE_REQUESTED`/`APPROVED`/`REJECTED`/`REVOKED`/`EXPIRED`, with `organization_id`/`project_id`/`finding_id`/`actor`/`request_id`/`correlation_id`, redacted.

## History

- `finding_history` `sla_*`/`risk_acceptance_*` with `organization_id`/`project_id`/`request_id`/`correlation_id`/`metadata`, plus `AuditService`.

## Future

- `SLAPolicy` per org/severity, future per project/asset criticality, `SLA` `paused`/`cancelled` already prepared, notification `SLA_OVERDUE` etc. for P14.6.

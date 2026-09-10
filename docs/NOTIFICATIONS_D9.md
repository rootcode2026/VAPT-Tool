# D9 — Notifications

> Status: IMPLEMENTED (pending merge). Delivery only — no messaging platform,
> no external providers, no webhooks, no AI content.

## Core statements

- "D3 is authoritative for alert creation."
- "D9 is responsible only for notification delivery."
- "Notification delivery failure does not change the underlying security alert."
- "Notifications never constitute security verification."

## Flow

```
D2 change event → D3 alert policy → Alert (deduped, authoritative)
  → D9 policy gate (enabled, severity, types)
  → recipient resolution (in-tenant project users only)
  → delivery record (UNIQUE identity per occurrence)
  → in_app: synchronous inbox + SENT
    local: Celery task → worker claim → bounded outbox sink → SENT/FAILED
  → audit (IDs + bounded values only)
```

Evaluation triggers (backend, all idempotent and bounded): explicit
`POST .../alerts/{id}/notify`, lazy on alert list/detail reads (returned page
only), never on internal transitions. D7/D8 flows are NOT hooked directly —
their effects surface through D3 alerts, which D9 then delivers.

## Policy (`notification_policies`, one row per project)

- `enabled` (default true), `channel` (`in_app` default | `local`),
  `min_severity` (default high; rank critical > high > medium > low > info),
  `alert_types` (null = all 8 D3 types), `recipient_mode` (`finding_owner`
  default | `project_analysts` | `explicit_users`), `explicit_user_ids`
  (validated active project members, max 20), `cooldown_seconds` (60–86400,
  default 3600), `notify_on_redetection` (default false),
  `provider_config` (allowlisted `fail_mode` test knob only — no secrets,
  URLs, or credentials accepted or stored).
- Reads: any project member. Writes: project_admin/org_admin/super_admin,
  validated (400 on invalid), audited (CREATED/UPDATED, IDs only).

## Recipients (tenant-isolated, bounded 50)

- `finding_owner`: alert's finding `assigned_to`/`owner_user_id` → active org
  user with project access. No owner → no delivery (explicit, no spam).
- `project_analysts`: active memberships with analyst/project_admin roles.
- `explicit_users`: policy allowlist, re-validated at evaluation.
- Cross-project/cross-tenant/inactive users are rejected or skipped; never
  external addresses by default.

## Occurrence & storm protection

- Identity `UNIQUE(alert, recipient, channel, type, occurrence)`; occurrence 1
  on first detection. Reopen and re-detection are observationally identical in
  the alerts table (both bump `event_count`), so by default only the first
  detection notifies. `notify_on_redetection=true` allows a new occurrence per
  `event_count` increment, still gated by per-key cooldown.
- Project hourly cap (50) bounds storms. Queue/reads bounded (limit ≤ 200).

## Channels & providers

- `in_app`: synchronous inbox (`notifications`, UNIQUE per alert+user) + SENT.
  No network, no queue.
- `local`: async `app.notifications.deliver_notification` Celery task (existing
  RabbitMQ/worker, no new queue). The worker CAS-claims `pending→sending`,
  re-validates tenant context, then accepts the pre-rendered bounded content
  into `notification_outbox` and marks SENT. Outbox PK makes redelivery a no-op.
- Deferred: production email (no secret store for SMTP/API credentials; the
  existing `development` email provider is unrelated), webhooks (SSRF scope —
  allowlist/HTTPS-only/private-IP blocking/redirect handling cannot be done
  safely in MMP-1 budget), SMS/push. SSRF section: N/A (no URL fetching exists).

## Retry & failure classification

- Temporary (`fail_mode=temporary`, timeouts, 5xx-class): claim released,
  bounded Celery retry (countdown 30s, max 3), then FAILED (`retries exhausted`).
- Permanent (misconfig, tenant mismatch, outbox write failure, attempts
  exhausted): FAILED immediately, sanitized `last_error` (classification only,
  no provider internals). Queue failure at enqueue → FAILED `queue_failed`.
- Concurrency: atomic claim (rowcount guard); losers return `claim_lost`,
  never double-send. Terminal states stable; duplicate task runs are no-ops.
- DB transactions never span provider calls (claim/commit → send → persist/commit).

## Content (deterministic, bounded, redacted)

Subject ≤255, body ≤2000, inbox summary ≤1000. Built from alert fields only
(project/type/severity/title≤200/description≤500/asset/finding IDs/timestamps/
relative platform link). Secret patterns (keys, tokens, password assignments)
become `[REDACTED]`. No raw scanner output, evidence bodies, credentials, or
source code. Provider secrets do not exist in D9 (nothing to leak — verified in
tests and live across API/DB/audit/payload/logs).

## RBAC

Viewer: inbox read + mark own read; cannot notify, manage policy, or cancel.
Analyst: explicit notify + reads. Project admin: policy, cancel, all reads.
Org/super admin per existing semantics. No new permission types.

## Tenant isolation / RLS posture

Application-layer (as elsewhere): `require_project_access`, project-scoped
fetches (404 without leakage), org-derived recipients, `CROSS_TENANT_ACCESS`
conventions. New tables inherit existing posture; no new RLS claimed.

## API

- `GET/PUT /projects/{pid}/notification-policies`
- `GET /projects/{pid}/notifications` (own inbox; `unread/type/severity/alert`,
  admin `user_id` filter; `unread_count`)
- `POST /projects/{pid}/notifications/{id}/read` (owner or project admin)
- `GET /projects/{pid}/notification-deliveries` (status/channel/type/alert filters)
- `POST /projects/{pid}/alerts/{aid}/notify` (analyst+, idempotent, 201)
- `POST /projects/{pid}/notification-deliveries/{id}/cancel` (pending/sending → cancelled)
- No manual send-to-arbitrary-destination; no test endpoint beyond `notify`
  (which only uses configured policy recipients).

## Frontend

`/projects/[project_id]/notifications`: inbox table (severity/type/time/read +
mark-read + alert link), delivery-policy form (enabled/channel/min-severity/
recipients/redetection), delivery history (status/attempts/error/sent).
Loading skeleton, empty ("No notifications..."), bounded error + retry.

## Audit

`NOTIFICATION_POLICY_CREATED/UPDATED`, `NOTIFICATION_REQUESTED/SENT/FAILED/
CANCELLED` (delivery resource; worker SENT/FAILED via savepoint raw SQL with
existence guards). Metadata: IDs + channel/type/reason only.

## Performance

Indexed project/user/alert queries; page-bounded lists; recipient queries capped
(50) with single membership join pattern; external delivery never blocks API
(Celery); inbox path is one transaction.

## Production configuration requirements

- `local` is a test sink: deployment must treat outbox as ephemeral.
- Email requires a secret store + approved sender + bounce handling (not built).
- Webhooks require allowlist + SSRF controls + secret management (not built).
- Tune `PROJECT_HOURLY_CAP`/cooldowns per scale; monitor FAILED deliveries.

## Limitations

1. `alembic upgrade head` pre-existing-blocked at `o1p2q3r4s5t6`; D9 migration
   verified via offline SQL; live DDL applied out-of-band additively.
2. Reopen vs re-detection indistinguishable without worker changes (documented;
   opt-in redetection covers reopen as new occurrence).
3. No resolution notifications in MMP-1 (only open/acknowledged alerts notify).
4. SQLite suites with JSONB/stale-DDL fixtures fail pre-existing; D9 suites
   carry the local shim and pass.
5. Evaluation is read/notify-driven; no worker push on alert creation by design.

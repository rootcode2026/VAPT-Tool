# Observability

## Structured Logging
- `backend/app/middleware/logging.py` — JSON with `timestamp`, `level`, `service`, `request_id`, `correlation_id`, `method`, `path`, `status_code`, `duration_ms`, `organization_id`, `project_id`
- Never logs `password`, `secret`, `token`, `authorization`, `cookie`
- Dev: readable, Prod: JSON

## Request/Correlation IDs
- `X-Request-ID`, `X-Correlation-ID` validated `^[A-Za-z0-9._-]+$` 64, `uuid4` fallback
- Returned in response, propagated to Celery `correlation_id`, audit `request_id`

## Health
- `GET /health` — liveness
- `GET /health/live` — liveness with timestamp
- `GET /health/ready` — readiness (postgres/redis/rabbitmq/celery)
- `GET /health/database` — postgres
- Docker `healthcheck` for all services

## Metrics (internal)
- `GET /api/v1/metrics` — `requests`, `errors`, `findings`, `scans`, `db`, `version` (protected, super_admin)
- Counters via `backend/app/api/routes/metrics.py` (in-memory fallback)

## Celery
- Logs: `task started/completed/failed` with `scan_id`, `project_id`, `correlation_id` (no secrets)
- `celery inspect ping` health

## Scanner
- `scanner_admin` fleet health (healthy/degraded/unhealthy), `audit` `SCANNER_HEALTH_CHANGED`

## Database
- Logs: `connection failures`, `RLS context errors` via `app.db.rls`
- `EXPLAIN` used for `findings`/`assets` indexes

## Audit
- `AuditService` immutable, `AUDIT_METADATA_MAX_BYTES 4096`, secret redaction, `request_id`/`correlation_id`

## Alert-ready events
- CRITICAL: `database unavailable`, `encryption key invalid`, `RLS failure`, `worker unavailable`
- WARNING: `scanner unhealthy`, `webhook failures`, `AI provider failures`

## No ELK/Prometheus required — uses PostgreSQL, Redis, Audit logs

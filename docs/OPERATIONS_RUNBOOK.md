# Operations Runbook

## Database failure
- Symptoms: `/health/ready` postgres=unavailable, `psycopg2.OperationalError`
- Health: `curl http://localhost:8000/health/ready`
- Recovery: `docker restart security_postgres; docker logs security_postgres; pg_isready`
- Validation: `curl http://localhost:8000/health/database` → healthy

## Redis failure
- Symptoms: rate limiting fallback to memory, `redis unavailable`
- Recovery: `docker restart security_redis; redis-cli ping`

## RabbitMQ failure
- Symptoms: `celery inspect ping` fails, scans queued not consumed
- Recovery: `docker restart security_rabbitmq; docker restart security_worker`

## Celery failure
- Recovery: `docker restart security_worker; celery -A app.celery_app inspect ping`

## Backend failure
- Recovery: `docker restart security_backend; docker logs security_backend`

## Scanner failure
- Symptoms: `scanner_health` unhealthy, `scan status failed`
- Recovery: `docker logs security_worker; POST /api/v1/admin/scanners/{key}/health/check`

## Secret-store failure
- Symptoms: `encryption key invalid`, `connector validation failed`
- Recovery: check `CONNECTOR_ENCRYPTION_KEY` 32-byte, `SECRET_STORE_MODE`

## Disk exhaustion
- Check: `docker system df; du -sh postgres_data`
- Recovery: `docker system prune; ./scripts/backup.sh` then prune old

## Migration failure
- Recovery: `alembic current; alembic upgrade head --sql` dry-run, restore backup

## RLS context failure
- Symptoms: `permission denied for table projects`
- Recovery: check `SET LOCAL app.current_organization_id` via `set_tenant_context` in transaction

## Rollback
`git log --oneline; docker compose down; git checkout <prev>; docker compose up --build -d; alembic downgrade`

## Log inspection
`docker logs security_backend --tail 200 | jq .` — request_id, correlation_id, no secrets

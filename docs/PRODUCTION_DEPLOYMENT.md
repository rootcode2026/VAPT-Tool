# Production Deployment — Local Production-Like

## Architecture
Internet → TLS Reverse Proxy (Nginx, TLS 1.3) → Frontend (3000) / Backend (8000) → PostgreSQL/Redis/RabbitMQ/Worker/Scanners (internal)

Internal only: 5432, 6379, 5672, 15672, scanner containers.

## Requirements
- Docker Desktop, Docker Compose
- 4 CPU, 8GB RAM, 20GB disk

## Quick Start (prod-like)
```bash
cp .env.example .env.prod-local
# Edit .env.prod-local: JWT_SECRET (32+ chars), CONNECTOR_ENCRYPTION_KEY (64 hex), etc.
docker compose -f docker-compose.yml -f docker-compose.prod-local.yml up --build -d
docker compose -f docker-compose.yml -f docker-compose.prod-local.yml ps
curl -f http://localhost:8000/health
curl -f http://localhost:8000/health/ready
curl -f http://localhost:8000/health/live
```

## Environment
- `ENVIRONMENT=production`, `DEBUG=false`, `RLS_ENABLED=true`, `AI_ENABLED=false`
- `DATABASE_URL`, `REDIS_URL`, `RABBITMQ_URL` — internal, not exposed
- `JWT_SECRET` — 32+ chars, `CONNECTOR_ENCRYPTION_KEY` — 64 hex (openssl rand -hex 32)
- `SECRET_STORE_MODE=production` with `CONNECTOR_ENCRYPTION_KEY` via Vault in real prod

## Reverse Proxy (Nginx)
- `deploy/nginx/nginx.conf` — TLS 1.3, HSTS, CSP, X-Frame-Options, rate limits, `client_max_body_size 2m`
- For local: HTTP 80 → backend/frontend. For prod: mount `fullchain.pem`/`privkey.pem` to `/etc/nginx/certs/` and enable 443 block.

## Secrets
Never commit `.env` or `.env.prod-local`. Production uses Vault/KMS for `CONNECTOR_ENCRYPTION_KEY`, `JWT_SECRET`.

## Migrations
```bash
docker exec security_backend alembic upgrade head
docker exec security_backend alembic current
```

## Backup/Restore
```bash
./scripts/backup.sh
./scripts/restore.sh backup_*.sql
```

## Health
- `GET /health/live` — liveness
- `GET /health/ready` — readiness (postgres/redis/rabbitmq)
- `GET /health/database` — postgres

## Rollback
```bash
docker compose -f docker-compose.yml -f docker-compose.prod-local.yml down
git checkout <previous-tag>
docker compose -f docker-compose.yml -f docker-compose.prod-local.yml up --build -d
```

## Firewall
Public: 443 (and 80 redirect), optional 22 restricted. Internal: 5432,6379,5672,15672 deny.

## CORS
Production: `FRONTEND_URL=https://your-domain.com` (not `*` with credentials).

## Logs
`docker logs security_backend --tail 100` — JSON with request_id/correlation_id, no secrets.

## Incident
See `docs/OPERATIONS_RUNBOOK.md`.

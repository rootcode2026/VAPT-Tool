# TLS 1.3 / mTLS Production Hardening — MMP-1

## Production Transport Architecture (Required)

```
Internet (HTTPS, TLS 1.3)
  ↓
Reverse Proxy (nginx / Traefik / ALB) — TLS termination
  ↓ HTTP (internal VPC only)
FastAPI (backend) — never directly Internet-facing in prod
  ↓
PostgreSQL / Redis / RabbitMQ (private network)
```

**Reverse proxy is the only Internet-facing TLS endpoint in production.** FastAPI must bind to `127.0.0.1` or private VPC and trust proxy headers only from the proxy.

## TLS 1.3 Minimum

- **Protocol:** `TLSv1.3` only (`ssl_protocols TLSv1.3;` in nginx). No TLS 1.0/1.1/1.2 in prod.
- **Ciphers:** TLS 1.3 ciphers are AEAD-only; do not configure custom ciphers for 1.3 (server preference irrelevant). If TLS 1.2 must be transitional, allow only `ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384`.
- **Certificates:** Managed via ACME (Let's Encrypt) or enterprise CA; reload proxy via `nginx -s reload`; never store private key beside ciphertext.
- **HSTS:** `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` — already set by `SecurityHeadersMiddleware`.
- **Redirect:** `80 → 443` with `308 Permanent Redirect` at proxy.
- **Secure cookies:** `Secure; HttpOnly; SameSite=Lax` (already via JWT cookie handling).
- **Trusted proxy:** `forwarded_for` only from proxy IP; `X-Forwarded-Proto` validated.

## Development vs Production

- **Development:** `ENVIRONMENT=development`, `http://localhost:3000 ↔ http://localhost:8000` plain HTTP allowed; `RLS_ENABLED`/`RBAC_STRICT_MODE` may be `false` for SQLite tests but prod defaults are `true`.
- **Production:** `ENVIRONMENT=production`, `RLS_ENABLED=true`, `RBAC_STRICT_MODE=true`, `SECRET_STORE_MODE=production`, `CONNECTOR_ENCRYPTION_KEY` 32-byte base64/hex from Vault/KMS, reverse proxy with TLS 1.3, `ENVIRONMENT=production` enforces `Secure` cookies.

## mTLS — Trusted Service Boundary Only

**Do NOT force mTLS on browser traffic.**

mTLS is for:
```
Trusted Scanner Gateway / Customer-controlled Scanner
  ↓ mTLS (client cert)
Scanner Control Plane / Worker boundary
```

- CA: enterprise internal CA; client cert `CN` mapped to `organization_id`.
- Proxy: `ssl_verify_client on; ssl_client_certificate /etc/nginx/ca.crt;`
- FastAPI receives `X-SSL-Client-CN` only from proxy; never trust direct client header.
- No fake CA in repo; mark `NOT LIVE VERIFIED` until certs provisioned.

## Middleware Preserved

`SecurityHeadersMiddleware` (HSTS, CSP, X-Frame, X-Content-Type), `RateLimitMiddleware` (Redis primary), `RequestContextMiddleware` remain authoritative. Do not weaken.

## Verification

- `curl -v --tlsv1.3 https://<prod-host>` → `TLS 1.3, HSTS present`
- `curl -v http://<prod-host>` → `308 → https`
- `nginx -t && nginx -s reload` without downtime

Live verification requires prod reverse proxy — **NOT LIVE VERIFIED** in dev (documented).

## RLS / RBAC Production Defaults (Hardened)

- `RLS_ENABLED=true` (was `false`) — transaction-local `set_config('app.current_organization_id', ..., true)` + `FORCE RLS` on 9 tables.
- `RBAC_STRICT_MODE=true` (was `false`) — missing membership → DENIED.

Set `RLS_ENABLED=false` / `RBAC_STRICT_MODE=false` only for legacy dev/SQLite tests explicitly.

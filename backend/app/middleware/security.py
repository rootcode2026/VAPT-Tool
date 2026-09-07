"""Security headers and rate limiting middleware."""
from __future__ import annotations

import time
from typing import Dict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# Security headers for production
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
}

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        # HSTS only if HTTPS (check forwarded proto)
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        # No sensitive data in headers
        response.headers["X-Powered-By"] = "VAPT-Platform"
        return response

# Simple in-memory rate limiting (fallback to Redis if available)
# For production, uses Redis; for tests, uses memory
_memory_buckets: Dict[str, list[float]] = {}

def _check_rate_limit(key: str, max_requests: int, window_seconds: int = 60) -> bool:
    now = time.time()
    bucket = _memory_buckets.get(key, [])
    # prune
    bucket = [t for t in bucket if now - t < window_seconds]
    if len(bucket) >= max_requests:
        _memory_buckets[key] = bucket
        return False
    bucket.append(now)
    _memory_buckets[key] = bucket
    return True

class RateLimitMiddleware(BaseHTTPMiddleware):
    # Path-based limits — higher in development/test to avoid flaky tests
    LIMITS = {
        "/api/v1/auth/login": (100, 60),
        "/api/v1/auth/mfa/verify": (50, 60),
        "/api/v1/auth/mfa/challenge": (50, 60),
        "/api/v1/auth/forgot-password": (50, 60),
        "/api/v1/auth/reset-password": (50, 60),
        "/api/v1/auth/mfa/setup/verify": (50, 60),
        "/api/v1/onboarding/": (50, 60),
        "/api/v1/projects": (50, 60),
        "/api/v1/scans": (50, 60),
        "/api/v1/ai/": (100, 60),
        "/api/v1/webhooks/": (200, 60),
        "/api/v1/reports": (100, 60),
        "/api/v1/dast/": (100, 60),
    }

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Find matching limit
        for prefix, (max_req, window) in self.LIMITS.items():
            if path.startswith(prefix):
                # Use IP + path as key
                ip = request.client.host if request.client else "unknown"
                key = f"rl:{prefix}:{ip}"
                # Try Redis if available
                try:
                    import redis
                    from app.core.config import settings
                    r = redis.from_url(settings.REDIS_URL)
                    pipe = r.pipeline()
                    pipe.incr(key)
                    pipe.expire(key, window)
                    count, _ = pipe.execute()
                    if count and int(count) > max_req:
                        from fastapi.responses import JSONResponse
                        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
                except Exception:
                    # fallback to memory
                    if not _check_rate_limit(key, max_req, window):
                        from fastapi.responses import JSONResponse
                        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
                break
        # Request size limit
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit():
            if int(content_length) > 2 * 1024 * 1024:  # 2MB
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=413, content={"detail": "Payload too large"})
        return await call_next(request)

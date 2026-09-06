"""Structured JSON logging — request_id, correlation_id, method, path, status, duration, org/project/user."""
import json
import logging
import time
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request

logger = logging.getLogger("app.access")
# Ensure no secrets in logs
SENSITIVE_KEYS = {"password", "secret", "token", "authorization", "cookie", "api_key"}

def _sanitize_headers(headers):
    sanitized = {}
    for k, v in headers.items():
        lk = k.lower()
        if lk in SENSITIVE_KEYS or "authorization" in lk or "cookie" in lk:
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v[:500]
    return sanitized

class StructuredLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.time()
        # Get request/correlation IDs from context (set by RequestContextMiddleware)
        try:
            from app.core.request_id import get_request_id, get_correlation_id
            req_id = get_request_id() or request.headers.get("x-request-id", "")[:64]
            corr_id = get_correlation_id() or request.headers.get("x-correlation-id", "")[:64]
        except Exception:
            req_id = request.headers.get("x-request-id", "")[:64]
            corr_id = request.headers.get("x-correlation-id", "")[:64]

        # Try to get org/project/user from request state if available
        org_id = getattr(request.state, "organization_id", "") or ""
        proj_id = getattr(request.state, "project_id", "") or ""
        # Don't try to decode token here; just log what we have

        response = None
        try:
            response = await call_next(request)
            duration_ms = int((time.time() - start) * 1000)
            log_data = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "level": "info",
                "service": "backend",
                "request_id": req_id,
                "correlation_id": corr_id,
                "method": request.method,
                "path": request.url.path[:500],
                "query": request.url.query[:500] if request.url.query else "",
                "status_code": response.status_code if response else 0,
                "duration_ms": duration_ms,
                "organization_id": str(org_id)[:36],
                "project_id": str(proj_id)[:36],
            }
            # Never log sensitive headers/body
            logger.info(json.dumps(log_data))
        except Exception as e:
            duration_ms = int((time.time() - start) * 1000)
            log_data = {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "level": "error",
                "service": "backend",
                "request_id": req_id,
                "correlation_id": corr_id,
                "method": request.method,
                "path": request.url.path[:500],
                "status_code": 500,
                "duration_ms": duration_ms,
                "error": str(e)[:200],
            }
            logger.error(json.dumps(log_data))
            raise
        return response

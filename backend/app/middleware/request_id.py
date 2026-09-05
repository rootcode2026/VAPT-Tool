"""
Request ID / Correlation ID middleware.

- Accepts X-Request-ID / X-Correlation-ID if safe, otherwise generates
- Stores in ContextVar for audit
- Returns both in response
- Captures IP via request.client.host (not X-Forwarded-For) and User-Agent bounded
- Never logs Authorization/Cookie/body
"""
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.request_id import (
    CORRELATION_ID_HEADER,
    REQUEST_ID_HEADER,
    clear_request_context,
    normalize_or_generate,
    set_request_context,
)


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Extract or generate IDs (bounded, safe)
        raw_req = request.headers.get(REQUEST_ID_HEADER)
        raw_corr = request.headers.get(CORRELATION_ID_HEADER)
        request_id = normalize_or_generate(raw_req)
        correlation_id = normalize_or_generate(raw_corr)

        # IP — use request.client.host, do NOT trust X-Forwarded-For (documented limitation)
        ip = None
        try:
            if request.client and request.client.host:
                ip = request.client.host
        except Exception:
            ip = None

        # User-Agent — bounded, no sensitive headers
        ua = request.headers.get("user-agent")
        if ua and len(ua) > 500:
            ua = ua[:500]

        set_request_context(request_id, correlation_id, ip, ua)
        # Also stash on request.state for direct access
        request.state.request_id = request_id
        request.state.correlation_id = correlation_id
        request.state.client_ip = ip
        request.state.user_agent = ua

        try:
            response: Response = await call_next(request)
            response.headers[REQUEST_ID_HEADER] = request_id
            response.headers[CORRELATION_ID_HEADER] = correlation_id
            return response
        finally:
            clear_request_context()

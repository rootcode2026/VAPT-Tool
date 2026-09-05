"""
Request ID / Correlation ID context.

- X-Request-ID: per-request unique, returned in response
- X-Correlation-ID: cross-service correlation, returned in response
- Both bounded, safe characters, generated via uuid4 if missing/invalid
- Stored in ContextVar for downstream handlers (audit, etc.)
- IP and User-Agent captured separately via Request
"""
import re
import uuid
from contextvars import ContextVar
from typing import Optional

REQUEST_ID_HEADER = "X-Request-ID"
CORRELATION_ID_HEADER = "X-Correlation-ID"
MAX_ID_LENGTH = 64
# Safe characters: alphanum, dash, underscore, dot
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._\-]+$")

_request_id_ctx: ContextVar[Optional[str]] = ContextVar("request_id", default=None)
_correlation_id_ctx: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)
_ip_ctx: ContextVar[Optional[str]] = ContextVar("request_ip", default=None)
_user_agent_ctx: ContextVar[Optional[str]] = ContextVar("request_user_agent", default=None)


def _is_valid_id(value: str | None) -> bool:
    if not value or not isinstance(value, str):
        return False
    v = value.strip()
    if not v or len(v) > MAX_ID_LENGTH:
        return False
    # Must be safe characters and not overly generic like "null"
    if not SAFE_ID_RE.match(v):
        return False
    return True


def generate_id() -> str:
    # Cryptographically strong via uuid4 hex (32 chars) — not sequential
    return uuid.uuid4().hex


def normalize_or_generate(value: str | None) -> str:
    if _is_valid_id(value):
        return value.strip()[:MAX_ID_LENGTH]
    return generate_id()


def set_request_context(request_id: str, correlation_id: str, ip: str | None, user_agent: str | None) -> None:
    _request_id_ctx.set(request_id)
    _correlation_id_ctx.set(correlation_id)
    _ip_ctx.set(ip[:45] if ip else None)
    _user_agent_ctx.set(user_agent[:500] if user_agent else None)


def get_request_id() -> Optional[str]:
    return _request_id_ctx.get()


def get_correlation_id() -> Optional[str]:
    return _correlation_id_ctx.get()


def get_request_ip() -> Optional[str]:
    return _ip_ctx.get()


def get_user_agent() -> Optional[str]:
    return _user_agent_ctx.get()


def get_audit_context() -> dict:
    return {
        "request_id": get_request_id(),
        "correlation_id": get_correlation_id(),
        "ip_address": get_request_ip(),
        "user_agent": get_user_agent(),
    }


def clear_request_context() -> None:
    _request_id_ctx.set(None)
    _correlation_id_ctx.set(None)
    _ip_ctx.set(None)
    _user_agent_ctx.set(None)

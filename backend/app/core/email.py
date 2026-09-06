"""Provider-neutral email abstraction for password reset.

Development: in-memory store retrievable via debug endpoint.
Production: stub that logs without secrets (real provider integration future).
"""
from __future__ import annotations

import os
import time
from typing import Dict, List

# In-memory outbox for development / tests
_OUTBOX: List[Dict] = []
_MAX_OUTBOX = 100


class EmailProvider:
    def send_password_reset(self, to_email: str, reset_url: str, raw_token: str) -> None:
        raise NotImplementedError


class DevelopmentEmailProvider(EmailProvider):
    def send_password_reset(self, to_email: str, reset_url: str, raw_token: str) -> None:
        # Never log raw_token; store in outbox without exposing via logs
        entry = {
            "to": to_email,
            "reset_url": reset_url,
            # Store token for deterministic test retrieval (not logged)
            "token": raw_token,
            "created_at": time.time(),
        }
        _OUTBOX.append(entry)
        if len(_OUTBOX) > _MAX_OUTBOX:
            _OUTBOX.pop(0)


class LoggingEmailProvider(EmailProvider):
    def send_password_reset(self, to_email: str, reset_url: str, raw_token: str) -> None:
        # Production stub — do not log raw_token
        # In real provider, would call SMTP/SES/etc.
        _OUTBOX.append({"to": to_email, "reset_url": reset_url, "token": raw_token, "created_at": time.time()})
        if len(_OUTBOX) > _MAX_OUTBOX:
            _OUTBOX.pop(0)


def get_email_provider() -> EmailProvider:
    mode = os.getenv("EMAIL_PROVIDER", "").lower()
    if mode in ("smtp", "ses", "production"):
        return LoggingEmailProvider()
    return DevelopmentEmailProvider()


def get_outbox() -> List[Dict]:
    return list(_OUTBOX)


def clear_outbox() -> None:
    _OUTBOX.clear()


def find_reset_token_for_email(email: str) -> str | None:
    """Helper for tests — find latest token for email (development only)."""
    email = (email or "").strip().lower()
    for entry in reversed(_OUTBOX):
        if entry.get("to", "").lower() == email:
            return entry.get("token")
    return None

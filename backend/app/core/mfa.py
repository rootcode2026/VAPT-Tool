"""TOTP + recovery code helpers."""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from typing import List

try:
    import pyotp
    _has_pyotp = True
except Exception:
    _has_pyotp = False
    pyotp = None  # type: ignore


ISSUER = os.getenv("MFA_ISSUER") or os.getenv("APP_NAME") or "VAPT Platform"
TOTP_PERIOD = 30
TOTP_DIGITS = 6
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_BYTES = 10  # ~13 base64 chars, formatted as XXXX-XXXX-XXXX
MFA_CHALLENGE_EXPIRE_MINUTES = 5
PASSWORD_RESET_EXPIRE_MINUTES = 15
# Rate limit tracking is handled in middleware + in-memory fallback; constants here for audits
TOTP_WINDOW = 1  # allow ±1 step
RECOVERY_CODE_LENGTH = 12  # display length target


def generate_totp_secret() -> str:
    if _has_pyotp:
        return pyotp.random_base32()
    # fallback: 20 bytes -> base32 (RFC 4226)
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode().rstrip("=")


def get_totp_uri(secret: str, email: str) -> str:
    # otpauth://totp/Issuer:email?secret=...&issuer=Issuer&algorithm=SHA1&digits=6&period=30
    if _has_pyotp:
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=ISSUER)
    # fallback manual
    import urllib.parse
    label = f"{ISSUER}:{email}"
    params = {"secret": secret, "issuer": ISSUER, "algorithm": "SHA1", "digits": str(TOTP_DIGITS), "period": str(TOTP_PERIOD)}
    return f"otpauth://totp/{urllib.parse.quote(label)}?{urllib.parse.urlencode(params)}"


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip()
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return False
    if _has_pyotp:
        totp = pyotp.TOTP(secret)
        # valid_window allows 1 step before/after
        return bool(totp.verify(code, valid_window=TOTP_WINDOW))
    # fallback: no pyotp — cannot verify safely
    return False


def hash_token(raw: str) -> str:
    # SHA-256 hex (64 chars) — one-way, deterministic for lookup
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> List[str]:
    codes: List[str] = []
    for _ in range(count):
        # 10 bytes -> 14 base32 chars, format as XXXX-XXXX-XXXX-ish
        raw = secrets.token_bytes(RECOVERY_CODE_BYTES)
        # Use hex-ish but more readable: base32 without padding, grouped
        b32 = base64.b32encode(raw).decode().rstrip("=")[:12]  # 12 chars entropy ~60 bits
        # Format as XXXX-XXXX-XXXX
        code = f"{b32[:4]}-{b32[4:8]}-{b32[8:12]}"
        codes.append(code.upper())
    return codes


def normalize_recovery_code(code: str) -> str:
    # Uppercase and strip dashes/spaces for comparison
    return "".join(c for c in (code or "").upper() if c.isalnum())


def hash_recovery_code(code: str) -> str:
    normalized = normalize_recovery_code(code)
    return hashlib.sha256(normalized.encode()).hexdigest()


def generate_reset_token() -> str:
    # 32 bytes urlsafe base64 (~43 chars)
    return secrets.token_urlsafe(32)


def is_super_admin_role(role: str | None) -> bool:
    return role == "super_admin"

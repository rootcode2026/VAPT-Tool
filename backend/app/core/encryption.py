"""Authenticated encryption for MFA secrets (AES-256-GCM).

Uses CONNECTOR_ENCRYPTION_KEY / VAULT_ENCRYPTION_KEY when configured (32 bytes
base64 or hex or raw). Falls back to a derived key from JWT_SECRET for
development — still AES-256-GCM, not Fernet, so storage format is consistent.
Production must set a proper 32-byte external key.
"""
from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _load_key() -> bytes:
    raw = os.getenv("CONNECTOR_ENCRYPTION_KEY") or os.getenv("VAULT_ENCRYPTION_KEY") or ""
    if raw:
        # base64 32 bytes
        try:
            decoded = base64.b64decode(raw)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        try:
            decoded = bytes.fromhex(raw)
            if len(decoded) == 32:
                return decoded
        except Exception:
            pass
        if len(raw.encode()) == 32:
            return raw.encode()
        # If raw is shorter but set, derive via SHA-256 to reach 32 bytes
        # (still better than failing; document limitation)
        return hashlib.sha256(raw.encode()).digest()
    # Development fallback — derive from JWT_SECRET
    fallback = os.getenv("JWT_SECRET") or "change-this-in-production-32-bytes!!"
    return hashlib.sha256(fallback.encode()).digest()


_KEY: bytes | None = None


def _key() -> bytes:
    global _KEY
    if _KEY is None:
        _KEY = _load_key()
    return _KEY


def encrypt_secret(plaintext: str) -> str:
    if not plaintext:
        raise ValueError("plaintext required")
    nonce = os.urandom(12)
    aesgcm = AESGCM(_key())
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_secret(ciphertext: str) -> str | None:
    if not ciphertext:
        return None
    try:
        raw = base64.b64decode(ciphertext.encode())
        nonce = raw[:12]
        ct = raw[12:]
        aesgcm = AESGCM(_key())
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode()
    except Exception:
        return None

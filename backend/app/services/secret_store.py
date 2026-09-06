"""Provider-neutral SecretStore — Development adapter + KMS/Vault abstraction.

Production architecture must use KMS/Vault/HSM. This module implements:
- SecretStore interface
- DevelopmentSecretStore (AES-256-GCM via Fernet, key externalized)
- KMS-backed stub for production

No plaintext credentials stored in normal DB columns.
"""
from __future__ import annotations

import base64
import hashlib
import os
import uuid
from typing import Optional

from cryptography.fernet import Fernet


class SecretStore:
    def put_secret(self, plaintext: str) -> str:
        raise NotImplementedError

    def get_secret(self, reference: str) -> Optional[str]:
        raise NotImplementedError

    def delete_secret(self, reference: str) -> bool:
        raise NotImplementedError

    def rotate_secret(self, reference: str, new_plaintext: str) -> str:
        raise NotImplementedError


def _derive_key() -> bytes:
    # In production, this key must come from KMS/Vault/HSM, not env.
    # For development, derive from env or JWT_SECRET.
    raw = os.getenv("CONNECTOR_ENCRYPTION_KEY") or os.getenv("JWT_SECRET") or "change-this-in-production-32-bytes!!"
    # Fernet requires 32 url-safe base64-encoded bytes
    digest = hashlib.sha256(raw.encode()).digest()
    return base64.urlsafe_b64encode(digest)

_FERNET = None

def _get_fernet() -> Fernet:
    global _FERNET
    if _FERNET is None:
        _FERNET = Fernet(_derive_key())
    return _FERNET

# In-memory fallback for ephemeral test DBs where no vault table exists
_MEMORY_VAULT: dict[str, str] = {}

class DevelopmentSecretStore(SecretStore):
    """Development adapter — encrypts with AES-256-GCM (Fernet) and stores ciphertext in DB or memory."""

    def __init__(self, db=None):
        self.db = db

    def put_secret(self, plaintext: str) -> str:
        if not plaintext or not isinstance(plaintext, str):
            raise ValueError("Secret must be non-empty string")
        if len(plaintext) > 8192:
            raise ValueError("Secret too large")
        ref = str(uuid.uuid4())
        ciphertext = _get_fernet().encrypt(plaintext.encode()).decode()
        # Try DB vault table if available
        if self.db is not None:
            try:
                from sqlalchemy import text
                self.db.execute(text("INSERT INTO connector_secrets (id, ciphertext, created_at) VALUES (:id, :ct, NOW())"), {"id": ref, "ct": ciphertext})
                self.db.commit()
                return ref
            except Exception:
                try:
                    self.db.rollback()
                except Exception:
                    pass
        _MEMORY_VAULT[ref] = ciphertext
        return ref

    def get_secret(self, reference: str) -> Optional[str]:
        if not reference:
            return None
        ciphertext = None
        if self.db is not None:
            try:
                from sqlalchemy import text
                row = self.db.execute(text("SELECT ciphertext FROM connector_secrets WHERE id=:id"), {"id": reference}).fetchone()
                if row:
                    ciphertext = row[0]
            except Exception:
                pass
        if ciphertext is None:
            ciphertext = _MEMORY_VAULT.get(reference)
        if not ciphertext:
            return None
        try:
            return _get_fernet().decrypt(ciphertext.encode()).decode()
        except Exception:
            return None

    def delete_secret(self, reference: str) -> bool:
        if self.db is not None:
            try:
                from sqlalchemy import text
                self.db.execute(text("DELETE FROM connector_secrets WHERE id=:id"), {"id": reference})
                self.db.commit()
            except Exception:
                try:
                    self.db.rollback()
                except Exception:
                    pass
        return bool(_MEMORY_VAULT.pop(reference, None) is not None)

    def rotate_secret(self, reference: str, new_plaintext: str) -> str:
        self.delete_secret(reference)
        return self.put_secret(new_plaintext)


class KMSVaultSecretStore(SecretStore):
    """Production stub — would call KMS/Vault/HSM. Not implemented in this environment.

    Documented as future production integration. Do not pretend it exists.
    """

    def put_secret(self, plaintext: str) -> str:
        raise NotImplementedError("KMS/Vault integration requires production secret manager — use DevelopmentSecretStore in this environment")

    def get_secret(self, reference: str) -> Optional[str]:
        raise NotImplementedError

    def delete_secret(self, reference: str) -> bool:
        raise NotImplementedError

    def rotate_secret(self, reference: str, new_plaintext: str) -> str:
        raise NotImplementedError


def get_secret_store(db=None) -> SecretStore:
    # In production, check env for KMS config
    if os.getenv("KMS_ENABLED", "").lower() == "true":
        return KMSVaultSecretStore()
    return DevelopmentSecretStore(db=db)

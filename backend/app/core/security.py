from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from app.core.config import settings

MAX_PASSWORD_BYTES = 72

# Argon2id hasher (production)
try:
    from argon2 import PasswordHasher
    _argon2_hasher = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16)
    _has_argon2 = True
except Exception:
    _has_argon2 = False
    _argon2_hasher = None


class TokenError(Exception):
    pass


def hash_password(password: str) -> str:
    # Prefer Argon2id for new passwords
    if _has_argon2 and _argon2_hasher:
        try:
            return _argon2_hasher.hash(password)
        except Exception:
            pass
    secret = password.encode("utf-8")[:MAX_PASSWORD_BYTES]
    return bcrypt.hashpw(secret, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    # Try Argon2 first
    if _has_argon2 and _argon2_hasher and password_hash.startswith("$argon2"):
        try:
            _argon2_hasher.verify(password_hash, password)
            # Check rehash if needed
            if _argon2_hasher.check_needs_rehash(password_hash):
                pass
            return True
        except Exception:
            return False
    secret = password.encode("utf-8")[:MAX_PASSWORD_BYTES]
    try:
        return bcrypt.checkpw(
            secret,
            password_hash.encode("utf-8"),
        )
    except ValueError:
        return False


def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )
    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access",
    }
    return jwt.encode(
        payload,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_access_token(token: str) -> str:
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except ExpiredSignatureError as exc:
        raise TokenError("expired") from exc
    except InvalidTokenError as exc:
        raise TokenError("invalid") from exc

    user_id = payload.get("sub")
    if not user_id or payload.get("type") != "access":
        raise TokenError("invalid")

    return str(user_id)

"""Centralized input validation — UUID, enum, safe string."""
import re
import uuid

UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SAFE_STRING_RE = re.compile(r"^[A-Za-z0-9._\-/ ]{1,255}$")
FORBIDDEN_CHARS = set(";|&$`'\"\\*?~<>^()[]{}!%")

def validate_uuid(value: str) -> str:
    if not value or not isinstance(value, str):
        raise ValueError("Invalid UUID")
    v = value.strip()
    if not UUID_RE.match(v):
        try:
            uuid.UUID(v)
        except Exception:
            raise ValueError("Invalid UUID format")
    return v

def validate_enum(value: str, allowed: set[str], field: str = "value") -> str:
    if not isinstance(value, str):
        raise ValueError(f"Invalid {field}")
    v = value.strip().lower()
    if v not in allowed:
        raise ValueError(f"Invalid {field}: {v}")
    return v

def sanitize_string(value: str, max_len: int = 255) -> str:
    if not isinstance(value, str):
        raise ValueError("Invalid string")
    v = value.strip()[:max_len]
    if any(c in v for c in FORBIDDEN_CHARS):
        # Allow some safe chars, but block shell metachars
        for ch in v:
            if ch in FORBIDDEN_CHARS and ch not in "/-._ ":
                raise ValueError(f"Invalid character {ch!r}")
    return v

def is_safe_path(path: str) -> bool:
    if not path or ".." in path or path.startswith("/"):
        return False
    if any(c in path for c in ";\n\r"):
        return False
    return True

"""Deterministic attack-surface helpers: exposure classification, asset state, change detection."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

ASSET_STALE_AFTER_DAYS = 7
ASSET_INACTIVE_AFTER_DAYS = 30

EXPOSURE_LEVELS = ("INTERNET_EXPOSED", "EXTERNALLY_REACHABLE", "INTERNAL", "UNKNOWN")

CRITICALITIES = {"critical", "high", "medium", "low", "unknown"}

_PRIVATE_RE = re.compile(r"^(localhost|.*\.local|.*\.internal)$", re.IGNORECASE)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def classify_exposure(asset_type: str | None, value: str | None, metadata: dict | None = None) -> str:
    """Conservative deterministic exposure. Never claims Internet exposure without evidence."""
    meta = metadata or {}
    atype = (asset_type or "").strip().lower()
    val = (value or "").strip()

    # Explicit scanner/cloud evidence wins
    for key in ("internet_facing", "internet_exposed", "publicly_exposed", "is_public"):
        if meta.get(key) is True:
            return "INTERNET_EXPOSED"
    exposure_hint = str(meta.get("exposure") or meta.get("exposure_level") or "").upper().replace(" ", "_")
    if exposure_hint in EXPOSURE_LEVELS:
        # Only trust explicit INTERNET_EXPOSED when corroborated by type/value below
        if exposure_hint != "INTERNET_EXPOSED":
            return exposure_hint

    # Private/local values are internal
    if _PRIVATE_RE.match(val):
        return "INTERNAL"

    # Public IP evidence
    if atype in ("ip", "ipv6", "public_ip"):
        try:
            ip = ipaddress.ip_address(val)
            if ip.is_global and not ip.is_reserved and not ip.is_multicast:
                return "INTERNET_EXPOSED"
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return "INTERNAL"
        except ValueError:
            pass
        return "UNKNOWN"

    # Externally reachable URL (http/https with public host)
    if atype in ("url", "web_application", "api_endpoint"):
        m = re.match(r"^https?://([^/:?#]+)", val, re.IGNORECASE)
        if m:
            host = m.group(1)
            try:
                ip = ipaddress.ip_address(host)
                if ip.is_global:
                    return "INTERNET_EXPOSED"
                return "INTERNAL"
            except ValueError:
                pass
            if _PRIVATE_RE.match(host):
                return "INTERNAL"
            # DNS-named web endpoint observed by scanner → externally reachable (not proven Internet)
            return "EXTERNALLY_REACHABLE"
        return "UNKNOWN"

    # DNS names observed externally
    if atype in ("domain", "subdomain", "hostname"):
        if "." in val and not _PRIVATE_RE.match(val):
            return "EXTERNALLY_REACHABLE"
        return "UNKNOWN"

    # Ports/services inherit exposure only from explicit metadata
    if atype in ("port", "service", "technology"):
        return "UNKNOWN"

    # Cloud resources only with explicit metadata
    if atype in ("cloud_account", "cloud_resource"):
        return "UNKNOWN"

    # Repositories/source are internal by default (not network-exposed)
    if atype in ("repository", "source_file", "package", "container_image", "iac_resource"):
        return "INTERNAL"

    return "UNKNOWN"


def compute_asset_state(last_seen_at: datetime | None, now: datetime | None = None) -> str:
    now = now or _utcnow()
    last = _as_aware(last_seen_at)
    if last is None:
        return "unknown"
    age_days = (now - last).total_seconds() / 86400
    if age_days >= ASSET_INACTIVE_AFTER_DAYS:
        return "inactive"
    if age_days >= ASSET_STALE_AFTER_DAYS:
        return "stale"
    return "active"


def ensure_asset_workflow_columns(db) -> None:
    """Backward compat for isolated SQLite test DBs with legacy assets table.

    Only runs on SQLite (checks PRAGMA first, so no failed statements).
    On Postgres this is a no-op (migrations are authoritative).
    """
    try:
        bind = db.get_bind() if hasattr(db, "get_bind") else None
        dialect = bind.dialect.name if bind is not None else "sqlite"
        if dialect != "sqlite":
            return
        from sqlalchemy import text as _text

        cols = {r[1] for r in db.execute(_text("PRAGMA table_info(assets)")).fetchall()}
        missing = {"criticality", "owner_user_id"} - cols
        for col in missing:
            default = "'unknown'" if col == "criticality" else "NULL"
            db.execute(_text(f"ALTER TABLE assets ADD COLUMN {col} TEXT DEFAULT {default}"))
        if missing:
            db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass


def sanitize_change_metadata(meta: dict | None) -> dict:
    """Strip secrets from change-event metadata; keep only safe operational fields."""
    if not isinstance(meta, dict):
        return {}
    safe: dict = {}
    for k, v in meta.items():
        lk = str(k).lower()
        if any(s in lk for s in ("password", "secret", "token", "api_key", "private_key", "credential", "cookie", "authorization")):
            safe[str(k)[:100]] = "[REDACTED]"
            continue
        if isinstance(v, str) and len(v) > 500:
            safe[str(k)[:100]] = v[:500]
        elif isinstance(v, (str, int, float, bool)) or v is None:
            safe[str(k)[:100]] = v
    return safe

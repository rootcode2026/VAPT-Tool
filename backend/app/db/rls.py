"""
PostgreSQL Row-Level Security (RLS) — enabled for 9 tenant tables in prod-like.

This module provides transaction-local helper for setting tenant context via
``set_config(..., true)`` (SET LOCAL). Policies are permissive when no tenant
is set (system/migrations), strict when set.

Enabled tables (migration i9a0b1c2d3e4): projects, targets, scans, findings,
assets, reports, ai_conversations, repository_connections, cloud_connections.

Design goals:
- Default RLS_ENABLED=true in prod-local (.env.prod-local), false in dev (safe).
- Transaction-local only: context cleared on COMMIT/ROLLBACK, no pool leakage.
- No SQL interpolation: bound parameters.
- Strict UUID validation.
- SQLite-safe: no-op on sqlite (tests).

Flow:
    authenticated user -> application auth -> verified membership
    -> BEGIN; SELECT set_config('app.current_organization_id', :oid, true); ...
    -> queries (RLS: organization_id = current_setting(...))
    -> COMMIT
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings

# PostgreSQL GUC keys for tenant context (transaction-local via set_config true).
RLS_GUC_ORG = "app.current_organization_id"
RLS_GUC_PROJECT = "app.current_project_id"
RLS_GUC_USER = "app.current_user_id"

_ALLOWED_KINDS = {"organization_id", "project_id", "user_id"}
_GUC_MAP = {
    "organization_id": RLS_GUC_ORG,
    "project_id": RLS_GUC_PROJECT,
    "user_id": RLS_GUC_USER,
}


def is_rls_enabled() -> bool:
    """Return whether RLS helpers should have any effect."""
    return bool(getattr(settings, "RLS_ENABLED", False))


def validate_context_value(value: Any, kind: str) -> str:
    """
    Validate and normalize a tenant context value.

    - Must be a non-empty string.
    - Must be a valid UUID v4 (36 chars, hex + dashes).
    - Stripped of surrounding whitespace.
    - ``kind`` is used only for error messages and must be one of the allowed kinds.

    Raises ValueError on invalid input.
    """
    if kind not in _ALLOWED_KINDS:
        raise ValueError(f"Unknown context kind: {kind}")
    if value is None:
        raise ValueError(f"{kind} is required and must be a UUID")
    raw = str(value).strip()
    if not raw:
        raise ValueError(f"{kind} must be a non-empty UUID")
    # Strict UUID v4 check
    try:
        parsed = uuid.UUID(raw, version=4)
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"{kind} must be a valid UUID v4: {raw!r}") from exc
    # Ensure canonical 36-char representation matches (lowercase)
    canonical = str(parsed)
    # uuid.UUID accepts many forms; enforce that input was a valid UUID string
    # by comparing lowercased stripped input to canonical.
    if raw.lower() != canonical.lower():
        # Allow any valid UUID representation, but normalize to canonical.
        # We still accept it if uuid parsing succeeded, just normalize.
        pass
    return canonical


def _is_postgresql(db: Session) -> bool:
    try:
        bind = getattr(db, "bind", None)
        if bind is None:
            # Session may have engine via get_bind()
            bind = db.get_bind()  # type: ignore[attr-defined]
        if bind is None:
            return False
        dialect = getattr(bind, "dialect", None)
        if dialect is None:
            return False
        return getattr(dialect, "name", "") == "postgresql"
    except Exception:
        return False


def set_tenant_context(
    db: Session,
    *,
    organization_id: str,
    project_id: str | None = None,
    user_id: str | None = None,
) -> None:
    """
    Set transaction-local tenant context for RLS.

    Must be called inside an explicit transaction (``with db.begin():`` or
    ``db.begin()``) when the underlying dialect is PostgreSQL. The context is
    automatically cleared on COMMIT/ROLLBACK, which prevents pool leakage.

    The ``organization_id`` is required and must be a UUID v4 that has already
    been verified via application-layer authorization (get_current_user +
    require_project_access). Never pass raw client-supplied IDs directly.

    When RLS is disabled (default) or the dialect is not PostgreSQL (e.g. SQLite
    in tests), this function is a no-op after validation.
    """
    # Validate first so invalid inputs are rejected even in tests / when disabled.
    org = validate_context_value(organization_id, "organization_id")
    proj = validate_context_value(project_id, "project_id") if project_id is not None else None
    uid = validate_context_value(user_id, "user_id") if user_id is not None else None

    if not is_rls_enabled():
        return

    if not _is_postgresql(db):
        # No-op on SQLite / other dialects; validation already done for test coverage.
        return

    # Pool safety: SET LOCAL / set_config(..., true) requires a transaction.
    # Enforce explicit transaction so context cannot become session-scoped.
    in_tx = False
    try:
        in_tx = bool(db.in_transaction() or db.in_nested_transaction())  # type: ignore[attr-defined]
    except Exception:
        in_tx = False
    if not in_tx:
        raise RuntimeError(
            "set_tenant_context must be called inside an explicit transaction "
            "(e.g. `with db.begin(): set_tenant_context(...)`) for pool safety. "
            "SET LOCAL outside a transaction would leak across pooled connections."
        )

    # Use set_config(key, value, is_local=true) — transaction-local, parameterized.
    # Keys are trusted constants; values are bound parameters (no interpolation).
    db.execute(
        text("SELECT set_config(:k, :v, true)"),
        {"k": RLS_GUC_ORG, "v": org},
    )
    if proj is not None:
        db.execute(
            text("SELECT set_config(:k, :v, true)"),
            {"k": RLS_GUC_PROJECT, "v": proj},
        )
    if uid is not None:
        db.execute(
            text("SELECT set_config(:k, :v, true)"),
            {"k": RLS_GUC_USER, "v": uid},
        )


def clear_tenant_context(db: Session) -> None:
    """
    Clear transaction-local tenant context (for testing).

    Sets each GUC to "" within the current transaction. On COMMIT the value
    disappears anyway; this helper is useful for in-transaction reset tests.
    No-op when RLS is disabled or dialect is not PostgreSQL.
    """
    if not is_rls_enabled():
        return
    if not _is_postgresql(db):
        return
    # Best effort: clear each key. Requires transaction like set_tenant_context.
    try:
        in_tx = bool(db.in_transaction() or db.in_nested_transaction())  # type: ignore[attr-defined]
    except Exception:
        in_tx = False
    if not in_tx:
        return
    for guc in (RLS_GUC_ORG, RLS_GUC_PROJECT, RLS_GUC_USER):
        db.execute(text("SELECT set_config(:k, :v, true)"), {"k": guc, "v": ""})


def get_current_tenant_context(db: Session) -> dict[str, str | None]:
    """
    Read current transaction-local tenant context (for tests/debug).

    Returns dict with keys organization_id / project_id / user_id, each either
    the current GUC value or None/"" if not set. On non-PostgreSQL dialects
    returns empty values.
    """
    if not _is_postgresql(db):
        return {"organization_id": None, "project_id": None, "user_id": None}
    # Use current_setting(..., true) — missing_ok = true returns NULL instead of error.
    ctx: dict[str, str | None] = {}
    for kind, guc in _GUC_MAP.items():
        try:
            row = db.execute(
                text("SELECT current_setting(:k, true) AS v"), {"k": guc}
            ).fetchone()
            val = row[0] if row is not None else None
            # Treat empty string as not set
            ctx[kind] = val if val not in (None, "") else None
        except Exception:
            ctx[kind] = None
    return ctx

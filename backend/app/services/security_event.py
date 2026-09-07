"""
Security Event Emitter — distinct from AuditService and FindingHistory.

- AuditService: durable, structured, tenant-aware, append-only, for accountability.
- SecurityEvent: meaningful security state signals, can later feed alerting/SIEM.
- FindingHistory: finding-specific lifecycle.
- Application logs: operational/debugging, sanitized.

Security events are not yet persisted to a separate table; they are emitted via
AuditService with a distinct prefix and can be consumed by future consumers
(D3 Alerting, D9 Notifications, SIEM) without modifying business logic.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.services.audit import AuditService


def emit_security_event(
    db: Session,
    *,
    event_type: str,
    actor_user_id: str | None = None,
    organization_id: str | None = None,
    project_id: str | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    severity: str = "INFO",
    before_state: Any | None = None,
    after_state: Any | None = None,
    reason: str | None = None,
    metadata: dict | None = None,
) -> None:
    """
    Emit a security event. Currently persists via AuditService with
    SECURITY_ prefix and severity in metadata, so future consumers can
    filter without requiring a separate table.

    Sensitive values are redacted via AuditService.sanitize_metadata.
    """
    safe_meta: dict[str, Any] = {}
    if metadata:
        safe_meta.update(metadata)
    safe_meta["security_event"] = True
    safe_meta["severity"] = severity
    if before_state is not None:
        safe_meta["before"] = str(before_state)[:500]
    if after_state is not None:
        safe_meta["after"] = str(after_state)[:500]
    if reason:
        safe_meta["reason"] = str(reason)[:500]

    # Use AuditService for durability and tenant awareness; future SIEM can query
    # where extra_data->>'security_event' = 'true'
    try:
        AuditService.record(
            db,
            event_type=f"SECURITY_{event_type}",
            action=f"SECURITY_{event_type}",
            result="SUCCESS",
            actor_user_id=actor_user_id,
            organization_id=organization_id,
            project_id=project_id,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata=safe_meta,
        )
    except Exception:
        pass

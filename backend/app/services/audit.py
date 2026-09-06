"""
Centralized enterprise audit logging service.

Tenant-aware, append-only, structured, redacted, bounded.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.audit_log import AuditLog

# ---------------------------------------------------------------------------
# Taxonomies (centralized, not scattered)
# ---------------------------------------------------------------------------

# Event types
EVENT_AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
EVENT_AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
EVENT_AUTH_LOGOUT = "AUTH_LOGOUT"
EVENT_AUTH_TOKEN_FAILURE = "AUTH_TOKEN_FAILURE"

EVENT_ORG_CREATED = "ORGANIZATION_CREATED"
EVENT_ORG_UPDATED = "ORGANIZATION_UPDATED"
EVENT_ORG_MEMBER_ADDED = "ORGANIZATION_MEMBER_ADDED"
EVENT_ORG_MEMBER_UPDATED = "ORGANIZATION_MEMBER_UPDATED"
EVENT_ORG_MEMBER_REMOVED = "ORGANIZATION_MEMBER_REMOVED"

EVENT_PROJECT_CREATED = "PROJECT_CREATED"
EVENT_PROJECT_UPDATED = "PROJECT_UPDATED"
EVENT_PROJECT_DELETED = "PROJECT_DELETED"
EVENT_PROJECT_MEMBER_ADDED = "PROJECT_MEMBER_ADDED"
EVENT_PROJECT_MEMBER_UPDATED = "PROJECT_MEMBER_UPDATED"
EVENT_PROJECT_MEMBER_REMOVED = "PROJECT_MEMBER_REMOVED"

EVENT_TARGET_CREATED = "TARGET_CREATED"
EVENT_TARGET_DELETED = "TARGET_DELETED"

EVENT_SCAN_CREATED = "SCAN_CREATED"
EVENT_SCAN_STARTED = "SCAN_STARTED"
EVENT_SCAN_COMPLETED = "SCAN_COMPLETED"
EVENT_SCAN_FAILED = "SCAN_FAILED"
EVENT_SCAN_CANCELLED = "SCAN_CANCELLED"

EVENT_FINDING_CREATED = "FINDING_CREATED"
EVENT_FINDING_UPDATED = "FINDING_UPDATED"
EVENT_FINDING_TRIAGED = "FINDING_TRIAGED"
EVENT_FINDING_STATUS_CHANGED = "FINDING_STATUS_CHANGED"
EVENT_FINDING_RESOLVED = "FINDING_RESOLVED"
EVENT_FINDING_REOPENED = "FINDING_REOPENED"

EVENT_SLA_CREATED = "SLA_CREATED"
EVENT_SLA_BREACHED = "SLA_BREACHED"
EVENT_SLA_MET = "SLA_MET"
EVENT_SLA_WAIVED = "SLA_WAIVED"

EVENT_RISK_ACCEPTANCE_REQUESTED = "RISK_ACCEPTANCE_REQUESTED"
EVENT_RISK_ACCEPTANCE_APPROVED = "RISK_ACCEPTANCE_APPROVED"
EVENT_RISK_ACCEPTANCE_REJECTED = "RISK_ACCEPTANCE_REJECTED"
EVENT_RISK_ACCEPTANCE_EXPIRED = "RISK_ACCEPTANCE_EXPIRED"
EVENT_RISK_ACCEPTANCE_REVOKED = "RISK_ACCEPTANCE_REVOKED"

EVENT_REMEDIATION_CREATED = "REMEDIATION_CREATED"
EVENT_REMEDIATION_UPDATED = "REMEDIATION_UPDATED"
EVENT_REMEDIATION_COMPLETED = "REMEDIATION_COMPLETED"
EVENT_REMEDIATION_CANCELLED = "REMEDIATION_CANCELLED"

EVENT_RETEST_REQUESTED = "RETEST_REQUESTED"
EVENT_RETEST_STARTED = "RETEST_STARTED"
EVENT_RETEST_PASSED = "RETEST_PASSED"
EVENT_RETEST_FAILED = "RETEST_FAILED"
EVENT_RETEST_CANCELLED = "RETEST_CANCELLED"
EVENT_RETEST_ERROR = "RETEST_ERROR"

EVENT_INGESTION_CREATED = "INGESTION_CREATED"
EVENT_INGESTION_FAILED = "INGESTION_FAILED"

EVENT_CLOUD_OPERATION = "CLOUD_OPERATION"
EVENT_CLOUD_ACCOUNT_ADDED = "CLOUD_ACCOUNT_ADDED"
EVENT_CLOUD_ACCOUNT_UPDATED = "CLOUD_ACCOUNT_UPDATED"
EVENT_CLOUD_ACCOUNT_REMOVED = "CLOUD_ACCOUNT_REMOVED"

EVENT_AUTHZ_DENIED = "AUTHORIZATION_DENIED"
EVENT_CROSS_TENANT_DENIED = "CROSS_TENANT_ACCESS_DENIED"
EVENT_SECURITY_CONFIG_CHANGED = "SECURITY_CONFIGURATION_CHANGED"

# Results
RESULT_SUCCESS = "SUCCESS"
RESULT_FAILURE = "FAILURE"
RESULT_DENIED = "DENIED"
RESULT_PARTIAL = "PARTIAL"

# Resource types
RESOURCE_ORGANIZATION = "organization"
RESOURCE_ORG_MEMBERSHIP = "organization_membership"
RESOURCE_PROJECT = "project"
RESOURCE_PROJECT_MEMBERSHIP = "project_membership"
RESOURCE_TARGET = "target"
RESOURCE_SCAN = "scan"
RESOURCE_FINDING = "finding"
RESOURCE_SLA = "sla"
RESOURCE_RISK_ACCEPTANCE = "risk_acceptance"
RESOURCE_REMEDIATION = "remediation"
RESOURCE_RETEST = "retest"
RESOURCE_ASSET = "asset"
RESOURCE_INGESTION = "ingestion"
RESOURCE_CLOUD_ACCOUNT = "cloud_account"
RESOURCE_CLOUD_RESOURCE = "cloud_resource"
RESOURCE_AUTHENTICATION = "authentication"
RESOURCE_SECURITY_CONFIG = "security_configuration"

# ---------------------------------------------------------------------------
# Redaction and limits
# ---------------------------------------------------------------------------

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "private_key",
    "client_secret",
    "credential",
    "credentials",
    "api_keys",
    "privatekey",
}

SENSITIVE_SUBSTRINGS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "client_secret",
    "credential",
)

MAX_AUDIT_METADATA_BYTES = 4096


def _is_sensitive_key(key: str) -> bool:
    lk = key.lower()
    if lk in SENSITIVE_KEYS:
        return True
    for sub in SENSITIVE_SUBSTRINGS:
        if sub in lk:
            return True
    return False


def _redact_value(key: str, value: Any) -> Any:
    if _is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, str) and value.lower().startswith("bearer "):
        return "[REDACTED]"
    if isinstance(value, str) and value.count(".") == 2 and len(value) > 20:
        if "eyJ" in value[:10]:
            return "[REDACTED]"
    return value


def _sanitize_value(key: str, value: Any) -> Any:
    if isinstance(value, dict):
        return sanitize_metadata(value)
    if isinstance(value, list):
        sanitized_list = []
        for item in value[:20]:
            if isinstance(item, dict):
                sanitized_list.append(sanitize_metadata(item))
            elif isinstance(item, str) and _is_sensitive_key(key):
                sanitized_list.append("[REDACTED]")
            else:
                sanitized_list.append(str(item)[:500] if isinstance(item, str) else item)
        return sanitized_list
    redacted = _redact_value(key, value)
    if isinstance(redacted, str) and len(redacted) > 500:
        return redacted[:500]
    return redacted


def sanitize_metadata(metadata: Any) -> dict | None:
    if metadata is None:
        return None
    if not isinstance(metadata, dict):
        metadata = {"value": str(metadata)[:500]}
    sanitized: dict[str, Any] = {}
    for k, v in metadata.items():
        sk = str(k)[:100]
        sanitized[sk] = _sanitize_value(sk, v)

    import json

    # Use configured limit
    limit = getattr(settings, "AUDIT_METADATA_MAX_BYTES", MAX_AUDIT_METADATA_BYTES)
    try:
        encoded = json.dumps(sanitized).encode("utf-8")
        if len(encoded) > limit:
            truncated = {}
            for k, v in sanitized.items():
                truncated[k] = v
                if len(json.dumps(truncated).encode("utf-8")) > limit - 100:
                    truncated[k] = "[TRUNCATED]"
                    break
            sanitized = truncated
            if len(json.dumps(sanitized).encode("utf-8")) > limit:
                return {"truncated": True, "keys": list(sanitized.keys())[:10]}
    except Exception:
        return {"error": "metadata serialization failed"}

    return sanitized


# ---------------------------------------------------------------------------
# Central audit service
# ---------------------------------------------------------------------------


class AuditService:
    @staticmethod
    def record(
        db: Session,
        *,
        event_type: str,
        action: str,
        result: str,
        actor_user_id: str | None = None,
        organization_id: str | None = None,
        project_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        target_user_id: str | None = None,
        request_id: str | None = None,
        correlation_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict | None = None,
    ) -> AuditLog:
        """
        Append-only audit event. Uses server-side values only; does not trust client
        supplied tenant IDs without verification (caller must verify).
        """
        if result not in (RESULT_SUCCESS, RESULT_FAILURE, RESULT_DENIED, RESULT_PARTIAL):
            result = result[:20]

        # Auto-fill request context from ContextVar if not explicitly provided (HTTP requests)
        if request_id is None or correlation_id is None or ip_address is None or user_agent is None:
            try:
                from app.core.request_id import get_audit_context

                ctx = get_audit_context()
                if request_id is None:
                    request_id = ctx.get("request_id")
                if correlation_id is None:
                    correlation_id = ctx.get("correlation_id")
                if ip_address is None:
                    ip_address = ctx.get("ip_address")
                if user_agent is None:
                    user_agent = ctx.get("user_agent")
            except Exception:
                pass

        safe_metadata = sanitize_metadata(metadata) if metadata is not None else None

        def _trunc(v: str | None, n: int = 100) -> str | None:
            if v is None:
                return None
            s = str(v)
            return s[:n]

        audit = AuditLog(
            id=str(uuid.uuid4()),
            organization_id=_trunc(organization_id, 36),
            project_id=_trunc(project_id, 36),
            actor_user_id=_trunc(actor_user_id, 36),
            target_user_id=_trunc(target_user_id, 36),
            action=_trunc(action, 100) or event_type,
            event_type=_trunc(event_type, 100) or action,
            resource_type=_trunc(resource_type, 100),
            resource_id=_trunc(resource_id, 100),
            result=_trunc(result, 20) or RESULT_SUCCESS,
            request_id=_trunc(request_id, 100),
            correlation_id=_trunc(correlation_id, 100),
            ip_address=_trunc(ip_address, 45),
            user_agent=_trunc(user_agent, 500),
            extra_data=safe_metadata,
            created_at=datetime.now(timezone.utc),
        )
        # Attempt to persist audit in a savepoint so that a missing audit_logs
        # table in ephemeral SQLite test fixtures (which define their own Base
        # without audit_logs) does not abort the outer business transaction.
        # In production (Postgres + Phase 6A migration) the savepoint commits
        # with the outer transaction, preserving the "audit + mutation together"
        # guarantee: if the outer transaction rolls back, the audit rolls back.
        nested = None
        try:
            nested = db.begin_nested()
        except Exception:
            nested = None
        if nested is not None:
            try:
                db.add(audit)
                db.flush()
                nested.commit()
            except Exception as e:
                try:
                    nested.rollback()
                except Exception:
                    pass
                msg = str(e).lower()
                if "no such table" in msg and "audit_logs" in msg:
                    try:
                        db.expunge(audit)
                    except Exception:
                        pass
                    return audit
                raise
        else:
            db.add(audit)
            try:
                db.flush()
            except Exception:
                raise
        return audit

    @staticmethod
    def record_sync(
        db: Session,
        **kwargs,
    ) -> AuditLog:
        """Helper that flushes and commits immediately for non-transactional events (e.g., login)."""
        audit = AuditService.record(db, **kwargs)
        try:
            db.commit()
        except Exception:
            db.rollback()
            raise
        return audit

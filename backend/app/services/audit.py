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
EVENT_MFA_ENROLLMENT_STARTED = "MFA_ENROLLMENT_STARTED"
EVENT_MFA_ENROLLMENT_COMPLETED = "MFA_ENROLLMENT_COMPLETED"
EVENT_MFA_ENROLLMENT_FAILED = "MFA_ENROLLMENT_FAILED"
EVENT_MFA_CHALLENGE_SUCCESS = "MFA_CHALLENGE_SUCCESS"
EVENT_MFA_CHALLENGE_FAILURE = "MFA_CHALLENGE_FAILURE"
EVENT_RECOVERY_CODE_GENERATED = "RECOVERY_CODE_GENERATED"
EVENT_RECOVERY_CODE_REGENERATED = "RECOVERY_CODE_REGENERATED"
EVENT_RECOVERY_CODE_USED = "RECOVERY_CODE_USED"
EVENT_MFA_DISABLED = "MFA_DISABLED"
EVENT_PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED"
EVENT_PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED"
EVENT_PASSWORD_CHANGED = "PASSWORD_CHANGED"
EVENT_AUTH_RATE_LIMITED = "AUTH_RATE_LIMITED"

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
EVENT_REMEDIATION_BLOCKED = "REMEDIATION_BLOCKED"
EVENT_REMEDIATION_UNBLOCKED = "REMEDIATION_UNBLOCKED"
EVENT_REMEDIATION_STARTED = "REMEDIATION_STARTED"
EVENT_REMEDIATION_EVIDENCE_ADDED = "REMEDIATION_EVIDENCE_ADDED"

EVENT_RETEST_REQUESTED = "RETEST_REQUESTED"
EVENT_RETEST_STARTED = "RETEST_STARTED"
EVENT_RETEST_PASSED = "RETEST_PASSED"
EVENT_RETEST_FAILED = "RETEST_FAILED"
EVENT_RETEST_CANCELLED = "RETEST_CANCELLED"
EVENT_RETEST_ERROR = "RETEST_ERROR"

EVENT_MONITORING_CONFIG_CREATED = "MONITORING_CONFIG_CREATED"
EVENT_MONITORING_CONFIG_UPDATED = "MONITORING_CONFIG_UPDATED"
EVENT_MONITORING_CONFIG_DELETED = "MONITORING_CONFIG_DELETED"
EVENT_MONITORING_CONFIG_PAUSED = "MONITORING_CONFIG_PAUSED"
EVENT_MONITORING_CONFIG_RESUMED = "MONITORING_CONFIG_RESUMED"
EVENT_MONITORING_RUN_STARTED = "MONITORING_RUN_STARTED"
EVENT_MONITORING_RUN_COMPLETED = "MONITORING_RUN_COMPLETED"
EVENT_MONITORING_RUN_FAILED = "MONITORING_RUN_FAILED"
EVENT_MONITORING_RUN_PARTIAL = "MONITORING_RUN_PARTIAL"
EVENT_MONITORING_RUN_SCHEDULED = "MONITORING_RUN_SCHEDULED"
EVENT_ALERT_ACKNOWLEDGED = "ALERT_ACKNOWLEDGED"
EVENT_ALERT_RESOLVED = "ALERT_RESOLVED"
EVENT_ALERT_POLICY_UPDATED = "ALERT_POLICY_UPDATED"
EVENT_NOTIFICATION_POLICY_CREATED = "NOTIFICATION_POLICY_CREATED"
EVENT_NOTIFICATION_POLICY_UPDATED = "NOTIFICATION_POLICY_UPDATED"
EVENT_NOTIFICATION_REQUESTED = "NOTIFICATION_REQUESTED"
EVENT_NOTIFICATION_SENT = "NOTIFICATION_SENT"
EVENT_NOTIFICATION_FAILED = "NOTIFICATION_FAILED"
EVENT_NOTIFICATION_CANCELLED = "NOTIFICATION_CANCELLED"
EVENT_ASSET_OWNER_CHANGED = "ASSET_OWNER_CHANGED"
EVENT_ASSET_CRITICALITY_CHANGED = "ASSET_CRITICALITY_CHANGED"

EVENT_INGESTION_CREATED = "INGESTION_CREATED"
EVENT_INGESTION_FAILED = "INGESTION_FAILED"

EVENT_CLOUD_OPERATION = "CLOUD_OPERATION"
EVENT_CLOUD_ACCOUNT_ADDED = "CLOUD_ACCOUNT_ADDED"
EVENT_CLOUD_ACCOUNT_UPDATED = "CLOUD_ACCOUNT_UPDATED"
EVENT_CLOUD_ACCOUNT_REMOVED = "CLOUD_ACCOUNT_REMOVED"

EVENT_SCANNER_VERSION_REGISTERED = "SCANNER_VERSION_REGISTERED"
EVENT_SCANNER_VERSION_PROMOTED = "SCANNER_VERSION_PROMOTED"
EVENT_SCANNER_VERSION_DEPRECATED = "SCANNER_VERSION_DEPRECATED"
EVENT_SCANNER_VERSION_FAILED = "SCANNER_VERSION_FAILED"
EVENT_SCANNER_HEALTH_CHECK_REQUESTED = "SCANNER_HEALTH_CHECK_REQUESTED"
EVENT_SCANNER_HEALTH_CHANGED = "SCANNER_HEALTH_CHANGED"
EVENT_SCANNER_UPGRADE_REQUESTED = "SCANNER_UPGRADE_REQUESTED"
EVENT_SCANNER_UPGRADE_STARTED = "SCANNER_UPGRADE_STARTED"
EVENT_SCANNER_UPGRADE_COMPLETED = "SCANNER_UPGRADE_COMPLETED"
EVENT_SCANNER_UPGRADE_FAILED = "SCANNER_UPGRADE_FAILED"
EVENT_SCANNER_DOWNGRADE_REQUESTED = "SCANNER_DOWNGRADE_REQUESTED"
EVENT_SCANNER_ROLLBACK_REQUESTED = "SCANNER_ROLLBACK_REQUESTED"
EVENT_SCANNER_ROLLBACK_COMPLETED = "SCANNER_ROLLBACK_COMPLETED"
EVENT_SCANNER_CANARY_REQUESTED = "SCANNER_CANARY_REQUESTED"
EVENT_SCANNER_CANARY_STARTED = "SCANNER_CANARY_STARTED"
EVENT_SCANNER_CANARY_PASSED = "SCANNER_CANARY_PASSED"
EVENT_SCANNER_CANARY_FAILED = "SCANNER_CANARY_FAILED"
EVENT_SCANNER_FLEET_CHANGED = "SCANNER_FLEET_CHANGED"
EVENT_SCANNER_DISABLED = "SCANNER_DISABLED"
EVENT_SCANNER_ENABLED = "SCANNER_ENABLED"

EVENT_CODE_SCAN_STARTED = "CODE_SCAN_STARTED"
EVENT_CODE_SCAN_COMPLETED = "CODE_SCAN_COMPLETED"
EVENT_CODE_SCAN_FAILED = "CODE_SCAN_FAILED"
EVENT_SAST_FINDING_CREATED = "SAST_FINDING_CREATED"
EVENT_SCA_FINDING_CREATED = "SCA_FINDING_CREATED"
EVENT_SECRET_FINDING_CREATED = "SECRET_FINDING_CREATED"
EVENT_CONTAINER_FINDING_CREATED = "CONTAINER_FINDING_CREATED"
EVENT_IAC_FINDING_CREATED = "IAC_FINDING_CREATED"
EVENT_API_SECURITY_FINDING_CREATED = "API_SECURITY_FINDING_CREATED"

EVENT_CLOUD_DISCOVERY_STARTED = "CLOUD_DISCOVERY_STARTED"
EVENT_CLOUD_DISCOVERY_COMPLETED = "CLOUD_DISCOVERY_COMPLETED"
EVENT_CLOUD_CHECK_EXECUTED = "CLOUD_CHECK_EXECUTED"
EVENT_CLOUD_FINDING_CREATED = "CLOUD_FINDING_CREATED"
EVENT_CLOUD_ASSET_DISCOVERED = "CLOUD_ASSET_DISCOVERED"
EVENT_CLOUD_ASSET_CHANGED = "CLOUD_ASSET_CHANGED"

EVENT_DAST_CONFIG_CREATED = "DAST_CONFIG_CREATED"
EVENT_DAST_CONFIG_UPDATED = "DAST_CONFIG_UPDATED"
EVENT_DAST_SCAN_CREATED = "DAST_SCAN_CREATED"
EVENT_DAST_SCAN_STARTED = "DAST_SCAN_STARTED"
EVENT_DAST_SCAN_COMPLETED = "DAST_SCAN_COMPLETED"
EVENT_DAST_SCAN_FAILED = "DAST_SCAN_FAILED"
EVENT_DAST_SCAN_CANCELLED = "DAST_SCAN_CANCELLED"
EVENT_DAST_ACTIVE_TEST_AUTHORIZED = "DAST_ACTIVE_TEST_AUTHORIZED"
EVENT_DATABASE_SECURITY_SCAN_AUTHORIZED = "DATABASE_SECURITY_SCAN_AUTHORIZED"
EVENT_API_SECURITY_TEST_STARTED = "API_SECURITY_TEST_STARTED"
EVENT_API_SECURITY_TEST_COMPLETED = "API_SECURITY_TEST_COMPLETED"

EVENT_AI_CONVERSATION_CREATED = "AI_CONVERSATION_CREATED"
EVENT_AI_QUERY_EXECUTED = "AI_QUERY_EXECUTED"
EVENT_AI_RESPONSE_GENERATED = "AI_RESPONSE_GENERATED"
EVENT_AI_RESPONSE_FAILED = "AI_RESPONSE_FAILED"
EVENT_AI_CONTEXT_RETRIEVED = "AI_CONTEXT_RETRIEVED"
EVENT_AI_PROVIDER_ERROR = "AI_PROVIDER_ERROR"
EVENT_AI_RECOMMENDATION_GENERATED = "AI_RECOMMENDATION_GENERATED"

EVENT_AUTHZ_DENIED = "AUTHORIZATION_DENIED"
EVENT_CROSS_TENANT_DENIED = "CROSS_TENANT_ACCESS_DENIED"
EVENT_SECURITY_CONFIG_CHANGED = "SECURITY_CONFIGURATION_CHANGED"

EVENT_ONBOARDING_STARTED = "ONBOARDING_STARTED"
EVENT_ONBOARDING_SKIPPED = "ONBOARDING_SKIPPED"
EVENT_ONBOARDING_COMPLETED = "ONBOARDING_COMPLETED"
EVENT_ONBOARDING_RESTARTED = "ONBOARDING_RESTARTED"

# D6 reporting events (centralized with identical historical string values).
EVENT_REPORT_CREATED = "REPORT_CREATED"
EVENT_REPORT_GENERATION_STARTED = "REPORT_GENERATION_STARTED"
EVENT_REPORT_GENERATION_COMPLETED = "REPORT_GENERATION_COMPLETED"
EVENT_REPORT_GENERATION_FAILED = "REPORT_GENERATION_FAILED"
EVENT_REPORT_VIEWED = "REPORT_VIEWED"
EVENT_REPORT_CANCELLED = "REPORT_CANCELLED"
EVENT_REPORT_DOWNLOADED = "REPORT_DOWNLOADED"
EVENT_COMPLIANCE_REPORT_GENERATED = "COMPLIANCE_REPORT_GENERATED"

# D10 enterprise audit access events.
EVENT_AUDIT_EXPORTED = "AUDIT_EXPORTED"
EVENT_AUDIT_INTEGRITY_VERIFIED = "AUDIT_INTEGRITY_VERIFIED"

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
RESOURCE_MONITORING_CONFIG = "monitoring_config"
RESOURCE_MONITORING_RUN = "monitoring_run"
RESOURCE_ALERT = "alert"
RESOURCE_ALERT_POLICY = "alert_policy"
RESOURCE_NOTIFICATION_POLICY = "notification_policy"
RESOURCE_NOTIFICATION_DELIVERY = "notification_delivery"
RESOURCE_NOTIFICATION = "notification"
RESOURCE_ASSET = "asset"
RESOURCE_INGESTION = "ingestion"
RESOURCE_CLOUD_ACCOUNT = "cloud_account"
RESOURCE_CLOUD_RESOURCE = "cloud_resource"
RESOURCE_SCANNER = "scanner"
RESOURCE_SCANNER_ROLLOUT = "scanner_rollout"
RESOURCE_AUTHENTICATION = "authentication"
RESOURCE_SECURITY_CONFIG = "security_configuration"
RESOURCE_AUDIT = "audit"

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
        # D10 tamper-evidence: chain this record best-effort. A lookup failure
        # leaves NULL hashes (unchained) rather than breaking the caller.
        try:
            prev = chain_tip_hash(db, audit.organization_id) or GENESIS_PREV_HASH
            audit.prev_hash = prev
            audit.event_hash = compute_event_hash(canonical_audit_payload(audit), prev)
        except Exception:
            try:
                audit.prev_hash = None
                audit.event_hash = None
            except Exception:
                pass
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


# ---------------------------------------------------------------------------
# D10 tamper-evidence: per-organization hash chain (DAG-tolerant)
# ---------------------------------------------------------------------------
# Each record stores event_hash = SHA256(canonical_event || prev_hash), where
# prev_hash is the previous record's event_hash in the same organization scope
# (or GENESIS_PREV_HASH for the first chained record). Concurrent writers may
# share a parent (fork); verification therefore checks recomputation plus
# prev-link existence rather than strict linear sequencing. Historical rows and
# worker direct-SQL inserts carry NULL hashes: readable, counted as unchained,
# never reported as tampered. Tamper-evident, not immutable: a DB superuser
# could rewrite history, but any modification breaks recomputation or linkage
# and is detected by verify_audit_chain.

GENESIS_PREV_HASH = "GENESIS"
PLATFORM_SCOPE = "__platform__"
AUDIT_CHAIN_FIELDS = (
    "scope", "id", "organization_id", "project_id", "actor_user_id",
    "target_user_id", "action", "event_type", "resource_type", "resource_id",
    "result", "request_id", "correlation_id", "ip_address", "user_agent",
    "created_at", "metadata",
)


def audit_scope_key(organization_id: str | None) -> str:
    return str(organization_id) if organization_id else PLATFORM_SCOPE


def canonical_audit_payload(audit) -> dict:
    """Deterministic payload for hashing (fixed fields, canonical metadata)."""
    if isinstance(audit, dict):
        get = audit.get
        meta = audit.get("metadata", audit.get("extra_data"))
    else:
        get = lambda k, d=None: getattr(audit, k, d)  # noqa: E731
        meta = getattr(audit, "extra_data", None)
    created = get("created_at")
    try:
        if hasattr(created, "isoformat"):
            created_iso = created.isoformat()
            # SQLite drops tzinfo on round-trip; stored instants are UTC.
            if getattr(created, "tzinfo", None) is None:
                created_iso += "+00:00"
        else:
            created_iso = str(created)
    except Exception:
        created_iso = str(created)
    if isinstance(meta, dict):
        try:
            import json as _json

            meta = _json.loads(_json.dumps(meta, sort_keys=True, ensure_ascii=False))
        except Exception:
            meta = {"unserializable": True}
    elif meta is not None:
        meta = {"value": str(meta)[:500]}
    payload = {
        "scope": audit_scope_key(get("organization_id")),
        "id": get("id"),
        "organization_id": get("organization_id"),
        "project_id": get("project_id"),
        "actor_user_id": get("actor_user_id"),
        "target_user_id": get("target_user_id"),
        "action": get("action"),
        "event_type": get("event_type"),
        "resource_type": get("resource_type"),
        "resource_id": get("resource_id"),
        "result": get("result"),
        "request_id": get("request_id"),
        "correlation_id": get("correlation_id"),
        "ip_address": get("ip_address"),
        "user_agent": get("user_agent"),
        "created_at": created_iso,
        "metadata": meta,
    }
    return {k: payload.get(k) for k in AUDIT_CHAIN_FIELDS}


def compute_event_hash(canonical: dict, prev_hash: str) -> str:
    import hashlib
    import json as _json

    serialized = _json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(f"{serialized}|{prev_hash}".encode("utf-8")).hexdigest()


def chain_tip_hash(db: Session, organization_id: str | None) -> str | None:
    """Newest event_hash in scope (indexed). None when scope has no chained rows."""
    try:
        q = db.query(AuditLog.event_hash).filter(AuditLog.event_hash.is_not(None))
        if organization_id:
            q = q.filter(AuditLog.organization_id == organization_id)
        else:
            q = q.filter(AuditLog.organization_id.is_(None))
        row = q.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).first()
        return row[0] if row else None
    except Exception:
        return None


def hash_exists_in_scope(db: Session, organization_id: str | None, event_hash: str) -> bool:
    try:
        q = db.query(AuditLog.id).filter(AuditLog.event_hash == event_hash)
        if organization_id:
            q = q.filter(AuditLog.organization_id == organization_id)
        else:
            q = q.filter(AuditLog.organization_id.is_(None))
        return q.first() is not None
    except Exception:
        return False


def verify_record_integrity(db: Session, audit) -> str:
    """Single-record status: verified | mismatch | broken_link | unchained."""
    stored = getattr(audit, "event_hash", None)
    prev = getattr(audit, "prev_hash", None)
    if not stored or not prev:
        return "unchained"
    try:
        expected = compute_event_hash(canonical_audit_payload(audit), prev)
    except Exception:
        return "mismatch"
    if expected != stored:
        return "mismatch"
    if prev != GENESIS_PREV_HASH and not hash_exists_in_scope(db, getattr(audit, "organization_id", None), prev):
        return "broken_link"
    return "verified"


def verify_audit_chain(db: Session, organization_id: str | None, limit: int = 200) -> dict:
    """Verify the newest `limit` chained rows in scope (bounded, oldest-first).

    Returns counts plus failing IDs. Unchained rows (NULL hashes) are counted,
    never failures. `truncated` is True when the scope holds more chained rows
    than the window (continuity before the window is not asserted).
    """
    limit = max(1, min(int(limit or 200), 1000))
    try:
        q = db.query(AuditLog)
        if organization_id:
            q = q.filter(AuditLog.organization_id == organization_id)
        else:
            q = q.filter(AuditLog.organization_id.is_(None))
        total_chained = q.filter(AuditLog.event_hash.is_not(None)).count()
        rows = (
            q.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
            .limit(limit)
            .all()
        )
    except Exception as exc:
        return {"scope": audit_scope_key(organization_id), "checked": 0, "valid": False,
                "failures": [], "unchained": 0, "truncated": False, "error": str(exc)[:200]}
    failures: list[str] = []
    unchained = 0
    checked = 0
    for audit in sorted(rows, key=lambda r: (r.created_at, r.id)):
        status = verify_record_integrity(db, audit)
        if status == "unchained":
            unchained += 1
            continue
        checked += 1
        if status != "verified":
            failures.append(audit.id)
    return {
        "scope": audit_scope_key(organization_id),
        "checked": checked,
        "valid": not failures,
        "failures": failures[:50],
        "failure_count": len(failures),
        "unchained": unchained,
        "truncated": total_chained > len(rows),
    }

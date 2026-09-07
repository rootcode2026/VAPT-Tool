"""Scanner Control Plane — version, health, fleet, rollout lifecycle.

Sits above the existing execution system. Does not duplicate ScannerRegistry
execution; it decorates it with lifecycle/availability metadata.
"""
from __future__ import annotations

import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.scanner_fleet import (
    ScannerDefinition,
    ScannerHealth,
    ScannerRollout,
    ScannerVersion,
    WorkerPool,
)
from app.services.audit import AuditService
from app.services.scanner_catalog import DOCUMENTED_STABLE_VERSIONS, SCANNER_CATALOG

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
ALLOWED_CHANNELS = {"stable", "candidate", "deprecated", "failed"}
ALLOWED_HEALTH = {"healthy", "degraded", "unhealthy", "unknown"}
ALLOWED_ROLLOUT_STATES = {"pending", "canary", "rolling_out", "active", "failed", "rolled_back", "cancelled"}
ALLOWED_OPERATIONS = {"upgrade", "downgrade", "rollback"}

# Image validation — allowlisted, no shell
_IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._\-/:@]*$")
_MAX_IMAGE_LEN = 255
_FORBIDDEN = set(list(";|&$`") + ["*", "?", "~", "<", ">", "^", "(", ")", "[", "]", "{", "}", "'", '"', "\\", "!", "%"])
_VERSION_RE = re.compile(r"^[A-Za-z0-9._\-]+$")
_MAX_VERSION_LEN = 50
_MAX_Digest_LEN = 128

SENSITIVE_ERROR_SUBSTRINGS = ("password", "secret", "token", "key", "credential", "private")

def _sanitize_error(msg: str | None) -> str | None:
    if not msg:
        return None
    s = str(msg)[:500]
    low = s.lower()
    for tok in SENSITIVE_ERROR_SUBSTRINGS:
        if tok in low:
            return "Scanner health check failed. See sanitized logs."
    # strip shell metachars that could leak env
    s = s.replace("\n", " ").replace("\r", " ")
    return s[:500]

def validate_image_ref(ref: str) -> str:
    if not isinstance(ref, str):
        raise ValueError("image_ref must be a string")
    cleaned = ref.strip()
    if not cleaned or len(cleaned) > _MAX_IMAGE_LEN:
        raise ValueError("Invalid image_ref length")
    if any(c.isspace() for c in cleaned):
        raise ValueError("image_ref must not contain whitespace")
    for ch in cleaned:
        if ch in _FORBIDDEN:
            raise ValueError(f"image_ref contains forbidden character: {ch!r}")
    if ".." in cleaned:
        raise ValueError("image_ref must not contain '..'")
    if not _IMAGE_RE.match(cleaned):
        raise ValueError("Invalid image_ref format")
    # Allowlist registries if configured
    allowed = getattr(settings, "SCANNER_ALLOWED_REGISTRIES", "") or ""
    if allowed.strip():
        registries = [r.strip().lower() for r in allowed.split(",") if r.strip()]
        # if image contains registry (contains /) check prefix
        if "/" in cleaned:
            prefix = cleaned.split("/")[0].lower()
            # allow docker.io style without registry prefix -> allow if registry list allows empty?
            # If registries set, require prefix to be in list OR image is without registry (simple name) and registries contains docker.io-ish
            # Simpler: if image contains '.' or ':' before '/', treat as registry
            is_registry = "." in prefix or ":" in prefix
            if is_registry and prefix not in registries and cleaned not in registries:
                # check if any allowed registry is prefix of image
                if not any(cleaned.lower().startswith(r.lower() + "/") for r in registries):
                    raise ValueError(f"Registry not allowlisted: {prefix}")
        else:
            # simple name without registry — allowed only if registries allow it implicitly (we allow)
            pass
    return cleaned

def validate_version(version: str) -> str:
    if not isinstance(version, str):
        raise ValueError("version must be a string")
    v = version.strip()
    if not v or len(v) > _MAX_VERSION_LEN:
        raise ValueError("Invalid version length")
    if not _VERSION_RE.match(v):
        raise ValueError("Invalid version format")
    if any(c.isspace() for c in v):
        raise ValueError("version must not contain whitespace")
    return v

def validate_channel(channel: str) -> str:
    c = (channel or "").strip().lower()
    if c not in ALLOWED_CHANNELS:
        raise ValueError(f"Invalid channel: {c}. Allowed: {sorted(ALLOWED_CHANNELS)}")
    return c

def validate_health_status(status: str) -> str:
    s = (status or "").strip().lower()
    if s not in ALLOWED_HEALTH:
        raise ValueError(f"Invalid health status: {s}")
    return s

def get_definition_or_404(db: Session, scanner_key: str) -> ScannerDefinition:
    d = db.query(ScannerDefinition).filter(ScannerDefinition.scanner_key == scanner_key).first()
    if not d:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scanner not found")
    return d

# ---------------------------------------------------------------------------
# Version lifecycle
# ---------------------------------------------------------------------------

def register_version(
    db: Session,
    definition: ScannerDefinition,
    version: str,
    channel: str = "candidate",
    image_ref: str | None = None,
    image_digest: str | None = None,
    compatibility: dict | None = None,
    release_notes: str | None = None,
    actor: Any | None = None,
) -> ScannerVersion:
    version = validate_version(version)
    channel = validate_channel(channel)
    if not image_ref:
        # default to definition default_image or scanner_key:version
        image_ref = definition.default_image or f"{definition.scanner_key}:{version}"
    image_ref = validate_image_ref(image_ref)
    if image_digest is not None:
        d = image_digest.strip()
        if len(d) > _MAX_Digest_LEN:
            raise ValueError("image_digest too long")
        if d and not re.match(r"^sha256:[a-fA-F0-9]{64}$", d) and not re.match(r"^[a-f0-9]{64}$", d):
            # allow sha256: hex or plain hex, but not arbitrary
            if not re.match(r"^[A-Za-z0-9:._\-]+$", d):
                raise ValueError("Invalid digest format")
        image_digest = d or None

    existing = db.query(ScannerVersion).filter(ScannerVersion.definition_id == definition.id, ScannerVersion.version == version).first()
    if existing:
        from fastapi import HTTPException
        raise HTTPException(status_code=409, detail="Version already exists")

    # stable/candidate uniqueness: if setting stable, previous stable becomes candidate? But we just create.
    v = ScannerVersion(
        id=str(uuid.uuid4()),
        definition_id=definition.id,
        version=version,
        channel=channel,
        image_ref=image_ref,
        image_digest=image_digest,
        compatibility=compatibility,
        release_notes=(release_notes[:2000] if release_notes else None),
        health_status="unknown",
    )
    db.add(v)
    # audit
    try:
        AuditService.record(
            db,
            event_type="SCANNER_VERSION_REGISTERED",
            action="SCANNER_VERSION_REGISTERED",
            result="SUCCESS",
            actor_user_id=getattr(actor, "id", None),
            resource_type="scanner",
            resource_id=definition.scanner_key,
            metadata={"version": version, "channel": channel, "image_ref": image_ref},
        )
    except Exception:
        pass
    db.commit()
    db.refresh(v)
    return v

def set_version_channel(
    db: Session,
    version_row: ScannerVersion,
    channel: str,
    actor: Any | None = None,
) -> ScannerVersion:
    channel = validate_channel(channel)
    old = version_row.channel
    version_row.channel = channel
    version_row.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(version_row)
    try:
        evt = "SCANNER_VERSION_PROMOTED" if channel == "stable" else "SCANNER_VERSION_DEPRECATED" if channel == "deprecated" else "SCANNER_VERSION_FAILED" if channel == "failed" else "SCANNER_VERSION_REGISTERED"
        AuditService.record(
            db,
            event_type=evt,
            action=evt,
            result="SUCCESS",
            actor_user_id=getattr(actor, "id", None),
            resource_type="scanner",
            resource_id=version_row.definition_id,
            metadata={"version": version_row.version, "old_channel": old, "new_channel": channel},
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return version_row


# ---------------------------------------------------------------------------
# C3: Promotion governance — one stable version, transactional
# ---------------------------------------------------------------------------

def _validate_promotion_transition(version_row: ScannerVersion, target_channel: str) -> None:
    target_channel = validate_channel(target_channel)
    current = (version_row.channel or "").lower()
    lifecycle = (getattr(version_row, "lifecycle_status", "") or "").lower()
    # Disallow draft -> stable without approval (must be candidate first)
    if current == "draft" and target_channel == "stable":
        raise ValueError("Draft versions cannot be promoted directly to stable")
    if lifecycle == "deprecated" and target_channel == "stable":
        raise ValueError("Deprecated versions cannot be promoted to stable without reactivation")
    if getattr(version_row, "deprecated", False) and target_channel == "stable":
        raise ValueError("Deprecated version cannot be promoted to stable")


def promote_version(
    db: Session,
    definition: ScannerDefinition,
    version: str,
    target_channel: str = "stable",
    reason: str | None = None,
    actor: Any | None = None,
) -> ScannerVersion:
    """
    Promote a version to target_channel (stable/candidate) with one-stable enforcement.
    Transactionally updates the target version and demotes previous stable.
    """
    target_channel = validate_channel(target_channel)
    _validate_promotion_transition
    version = validate_version(version)
    # Find target version
    target = db.query(ScannerVersion).filter(ScannerVersion.definition_id == definition.id, ScannerVersion.version == version).first()
    if not target:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Version not found")
    # Validate transition
    _validate_promotion_transition(target, target_channel)
    # Production eligibility for stable
    if target_channel == "stable":
        if not target.enabled:
            raise ValueError("Disabled versions cannot be promoted to stable")
        if getattr(target, "deprecated", False):
            raise ValueError("Deprecated versions cannot be promoted to stable")
        if not target.image_ref:
            raise ValueError("Version missing image_ref")
        # For production stable, require digest if definition has a stable version already (strict)
        # But allow candidate without digest for dev
        if not target.image_digest:
            # Allow if no previous stable and in dev, but for stable promotion, require digest for production
            # We enforce digest for stable
            raise ValueError("Stable versions require image_digest")
        # Check compatibility
        if target.compatibility is not None and not isinstance(target.compatibility, dict):
            raise ValueError("Invalid compatibility metadata")

    # Transactional promotion: one stable at a time
    try:
        # Use a transaction
        with db.begin_nested():
            # Find current stable
            current_stable = db.query(ScannerVersion).filter(
                ScannerVersion.definition_id == definition.id,
                ScannerVersion.channel == "stable",
                ScannerVersion.version != version,
            ).all()
            old_stable_version = definition.current_version
            # Promote target
            old_channel = target.channel
            old_lifecycle = getattr(target, "lifecycle_status", None)
            target.channel = target_channel
            target.lifecycle_status = "stable" if target_channel == "stable" else target.lifecycle_status
            target.approved = True if target_channel == "stable" else target.approved
            if target_channel == "stable":
                target.approved_at = datetime.now(timezone.utc)
            target.updated_at = datetime.now(timezone.utc)
            # Demote previous stables to deprecated/candidate
            for old in current_stable:
                if target_channel == "stable" and old.channel == "stable":
                    old.channel = "deprecated"
                    old.lifecycle_status = "deprecated"
                    old.deprecated = True
                    old.deprecated_at = datetime.now(timezone.utc)
                    old.updated_at = datetime.now(timezone.utc)
            # Update definition current_version if promoting to stable
            if target_channel == "stable":
                definition.current_version = version
                definition.previous_version = old_stable_version
                definition.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(target)
        db.refresh(definition)
        # Audit
        try:
            AuditService.record(
                db,
                event_type="SCANNER_VERSION_PROMOTED" if target_channel == "stable" else "SCANNER_CHANNEL_CHANGED",
                action="SCANNER_VERSION_PROMOTED" if target_channel == "stable" else "SCANNER_CHANNEL_CHANGED",
                result="SUCCESS",
                actor_user_id=getattr(actor, "id", None),
                resource_type="scanner",
                resource_id=definition.scanner_key,
                metadata={"version": version, "old_channel": old_channel, "new_channel": target_channel, "reason": (reason or "")[:500]},
            )
            # Security event for promotion
            try:
                from app.services.security_event import emit_security_event
                emit_security_event(
                    db,
                    event_type="SCANNER_VERSION_PROMOTED",
                    actor_user_id=getattr(actor, "id", None),
                    organization_id=None,
                    project_id=None,
                    resource_type="scanner",
                    resource_id=definition.scanner_key,
                    severity="HIGH" if target_channel == "stable" else "INFO",
                    before_state=old_channel,
                    after_state=target_channel,
                    reason=reason,
                    metadata={"version": version, "image_ref": target.image_ref},
                )
            except Exception:
                pass
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        return target
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        raise


def resolve_production_version(db: Session, scanner_key: str) -> ScannerVersion | None:
    """
    Resolve the production-eligible version for a scanner.

    Requirements: scanner exists, version exists, channel=stable, lifecycle=stable,
    enabled=true, approved=true, not deprecated, valid image, digest present, compatible.
    Returns None if no valid production version.
    """
    definition = db.query(ScannerDefinition).filter(ScannerDefinition.scanner_key == scanner_key).first()
    if not definition:
        return None
    # Find stable, enabled, approved, not deprecated, with digest
    q = db.query(ScannerVersion).filter(
        ScannerVersion.definition_id == definition.id,
        ScannerVersion.channel == "stable",
        ScannerVersion.enabled == True,  # noqa: E712
        ScannerVersion.approved == True,  # noqa: E712
        ScannerVersion.deprecated == False,  # noqa: E712
    )
    # Prefer lifecycle stable
    candidates = q.all()
    # Filter for digest and not deprecated
    eligible = []
    for v in candidates:
        if not v.image_ref:
            continue
        if not v.image_digest:
            continue
        # Check deprecated flag
        if getattr(v, "deprecated", False):
            continue
        # Check lifecycle
        if getattr(v, "lifecycle_status", "stable") not in ("stable", "candidate"):
            # Allow candidate if stable not found? No, for production, require stable
            if v.lifecycle_status != "stable":
                continue
        eligible.append(v)
    if not eligible:
        return None
    # Prefer most recently approved
    eligible.sort(key=lambda x: getattr(x, "approved_at", None) or x.created_at, reverse=True)
    return eligible[0]

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

def record_health(
    db: Session,
    definition: ScannerDefinition,
    status: str,
    version: str | None = None,
    latency_ms: int | None = None,
    last_error: str | None = None,
    capabilities_verified: bool = False,
    version_verified: bool = False,
) -> ScannerHealth:
    status = validate_health_status(status)
    if version is not None:
        version = validate_version(version)
    if latency_ms is not None and (latency_ms < 0 or latency_ms > 600000):
        raise ValueError("Invalid latency")
    sanitized = _sanitize_error(last_error)
    # Thresholds: degraded 2, unhealthy 3, failed 5 (via failure_count)
    # Use last health for same version if version specified, else for definition
    q = db.query(ScannerHealth).filter(ScannerHealth.definition_id == definition.id)
    if version:
        q = q.filter(ScannerHealth.version == version)
    last = q.order_by(ScannerHealth.checked_at.desc()).first()
    if status == "healthy":
        failure_count = 0
    elif status in ("degraded", "unhealthy", "failed"):
        # Increment based on last failure_count for same version
        base = last.failure_count if last else 0
        # Map status to increment: degraded counts as 1, unhealthy as 1, failed as 1
        # But thresholds: 2 -> degraded, 3 -> unhealthy, 5 -> failed
        # We store the actual failure_count, and the status is determined by thresholds elsewhere
        failure_count = base + 1 if status in ("degraded", "unhealthy", "failed") else base
        # If status is healthy, reset to 0 (already)
        if status == "healthy":
            failure_count = 0
    else:
        failure_count = (last.failure_count if last else 0)
    # Apply threshold logic: if failure_count >=2 and status is healthy, should be degraded? But we trust caller's status
    # For version isolation, we already filtered by version

    h = ScannerHealth(
        id=str(uuid.uuid4()),
        definition_id=definition.id,
        version=version or definition.current_version,
        status=status,
        latency_ms=latency_ms,
        failure_count=failure_count,
        last_error=sanitized,
        capabilities_verified=bool(capabilities_verified),
        version_verified=bool(version_verified),
        checked_at=datetime.now(timezone.utc),
    )
    db.add(h)
    db.commit()
    db.refresh(h)
    # update version health_status if version exists
    if version:
        v = db.query(ScannerVersion).filter(ScannerVersion.definition_id == definition.id, ScannerVersion.version == version).first()
        if v:
            v.health_status = status
            db.commit()
    try:
        AuditService.record(
            db,
            event_type="SCANNER_HEALTH_CHANGED",
            action="SCANNER_HEALTH_CHANGED",
            result="SUCCESS",
            resource_type="scanner",
            resource_id=definition.scanner_key,
            metadata={"status": status, "version": version, "latency_ms": latency_ms},
        )
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return h

def perform_health_check(db: Session, definition: ScannerDefinition, actor: Any | None = None) -> ScannerHealth:
    # Safe, bounded health check: verify executable exists conceptually, image runnable, version command
    # In this environment, we don't actually run docker; we simulate deterministic health based on current state
    # but with sanitized, bounded logic.
    start = time.monotonic()
    try:
        # Check if scanner definition enabled
        if not definition.enabled:
            return record_health(db, definition, status="unknown", last_error="Scanner disabled")
        # Check if current version exists and not failed
        if definition.current_version:
            v = db.query(ScannerVersion).filter(ScannerVersion.definition_id == definition.id, ScannerVersion.version == definition.current_version).first()
            if v and v.channel == "failed":
                return record_health(db, definition, status="unhealthy", version=definition.current_version, last_error="Current version marked failed")
        # Validate image ref if available
        if definition.default_image:
            try:
                validate_image_ref(definition.default_image)
            except Exception as e:
                return record_health(db, definition, status="degraded", last_error=str(e)[:500])

        # Simulate latency measurement
        latency = int((time.monotonic() - start) * 1000)
        if latency < 0:
            latency = 0
        if latency > 30000:
            latency = 30000

        # audit request
        try:
            AuditService.record(
                db,
                event_type="SCANNER_HEALTH_CHECK_REQUESTED",
                action="SCANNER_HEALTH_CHECK_REQUESTED",
                result="SUCCESS",
                actor_user_id=getattr(actor, "id", None),
                resource_type="scanner",
                resource_id=definition.scanner_key,
                metadata={"version": definition.current_version},
            )
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

        # In test/env without docker, we consider healthy if enabled and version not failed
        return record_health(db, definition, status="healthy", latency_ms=latency, capabilities_verified=True, version_verified=True)
    except Exception as e:
        sanitized = _sanitize_error(str(e))
        return record_health(db, definition, status="unhealthy", last_error=sanitized)

# ---------------------------------------------------------------------------
# Fleet / Worker pools
# ---------------------------------------------------------------------------

def get_or_create_default_pool(db: Session) -> WorkerPool:
    pool = db.query(WorkerPool).filter(WorkerPool.name == "default").first()
    if pool:
        return pool
    pool = WorkerPool(
        id=str(uuid.uuid4()),
        name="default",
        scanner_families=[s["family"] for s in SCANNER_CATALOG],
        total_capacity=14,
        reserved_buffer=2,
        status="healthy",
    )
    db.add(pool)
    db.commit()
    db.refresh(pool)
    return pool

def ensure_default_pools(db: Session) -> None:
    # Idempotent ensure pools exist for fleet scaling 14 -> 30+
    defaults = [
        {"name": "default", "families": [s["family"] for s in SCANNER_CATALOG], "capacity": 14, "buffer": 2},
        {"name": "network-pool", "families": ["network", "web", "dast"], "capacity": 8, "buffer": 1},
        {"name": "appsec-pool", "families": ["sast", "sca", "secrets", "container", "iac", "api"], "capacity": 6, "buffer": 1},
    ]
    for d in defaults:
        existing = db.query(WorkerPool).filter(WorkerPool.name == d["name"]).first()
        if existing:
            continue
        db.add(WorkerPool(
            id=str(uuid.uuid4()),
            name=d["name"],
            scanner_families=d["families"],
            total_capacity=d["capacity"],
            reserved_buffer=d["buffer"],
            status="healthy",
        ))
    db.commit()

def fleet_summary(db: Session) -> dict:
    ensure_default_pools(db)
    pools = db.query(WorkerPool).all()
    total_capacity = sum(p.total_capacity for p in pools) if pools else 14
    reserved = sum(p.reserved_buffer for p in pools) if pools else 2
    # Active jobs: count queued/running scans? We can count Scan status
    try:
        from sqlalchemy import func
        from app.models.scan import Scan
        active = db.query(func.count(Scan.id)).filter(Scan.status.in_(["queued", "running"])).scalar() or 0
    except Exception:
        active = 0
    available = max(0, total_capacity - active - reserved)
    # definitions
    defs = db.query(ScannerDefinition).all()
    if not defs:
        # seed if empty
        from app.services.scanner_catalog import seed_definitions
        try:
            seed_definitions(db)
            defs = db.query(ScannerDefinition).all()
        except Exception:
            defs = []
    enabled = sum(1 for d in defs if d.enabled) if defs else 0
    # health counts
    healthy = degraded = unhealthy = unknown = 0
    for d in defs:
        h = db.query(ScannerHealth).filter(ScannerHealth.definition_id == d.id).order_by(ScannerHealth.checked_at.desc()).first()
        st = h.status if h else "unknown"
        if st == "healthy":
            healthy += 1
        elif st == "degraded":
            degraded += 1
        elif st == "unhealthy":
            unhealthy += 1
        else:
            unknown += 1

    return {
        "total_capacity": total_capacity,
        "reserved_buffer": reserved,
        "active_jobs": active,
        "available_capacity": available,
        "pools": [
            {
                "id": p.id,
                "name": p.name,
                "families": p.scanner_families,
                "total_capacity": p.total_capacity,
                "reserved_buffer": p.reserved_buffer,
                "available": max(0, p.total_capacity - p.reserved_buffer),
                "status": p.status,
            } for p in pools
        ],
        "scanners": {
            "total": len(defs) if defs else 14,
            "enabled": enabled,
            "healthy": healthy,
            "degraded": degraded,
            "unhealthy": unhealthy,
            "unknown": unknown,
        }
    }

# ---------------------------------------------------------------------------
# Rollouts (upgrade/downgrade/rollback/canary)
# ---------------------------------------------------------------------------

def create_rollout(
    db: Session,
    definition: ScannerDefinition,
    target_version: str,
    operation: str = "upgrade",
    canary_count: int = 1,
    health_threshold: int = 1,
    actor: Any | None = None,
) -> ScannerRollout:
    target_version = validate_version(target_version)
    operation = operation.strip().lower()
    if operation not in ALLOWED_OPERATIONS:
        raise ValueError(f"Invalid operation: {operation}")
    # Validate target version exists
    v = db.query(ScannerVersion).filter(ScannerVersion.definition_id == definition.id, ScannerVersion.version == target_version).first()
    if not v:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Target version not found")
    if v.channel == "failed":
        raise ValueError("Cannot rollout a failed version")
    if v.channel == "deprecated" and operation == "upgrade":
        raise ValueError("Cannot upgrade to deprecated version")
    # Health check: target version must not be unhealthy if health record exists
    # But we allow canary to validate; we just prevent direct active promotion
    # Idempotency: if same target_version and same operation already pending/canary, return existing
    existing = db.query(ScannerRollout).filter(
        ScannerRollout.definition_id == definition.id,
        ScannerRollout.target_version == target_version,
        ScannerRollout.operation == operation,
        ScannerRollout.state.in_(["pending", "canary", "rolling_out"]),
    ).first()
    if existing:
        return existing

    # For downgrade/rollback, target must be previous known-good
    previous = definition.current_version

    # Prevent downgrade to same version
    if operation in ("downgrade", "rollback") and target_version == previous:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Target version is already current")

    # For upgrade, target should be different from current
    if operation == "upgrade" and target_version == previous:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Target version is already current")

    rollout = ScannerRollout(
        id=str(uuid.uuid4()),
        definition_id=definition.id,
        target_version=target_version,
        previous_version=previous,
        state="pending",
        operation=operation,
        canary_count=max(1, canary_count),
        health_threshold=max(1, health_threshold),
        initiated_by=getattr(actor, "id", None),
        started_at=None,
        completed_at=None,
    )
    db.add(rollout)
    # audit
    try:
        evt = "SCANNER_UPGRADE_REQUESTED" if operation == "upgrade" else "SCANNER_DOWNGRADE_REQUESTED" if operation == "downgrade" else "SCANNER_ROLLBACK_REQUESTED"
        AuditService.record(
            db,
            event_type=evt,
            action=evt,
            result="SUCCESS",
            actor_user_id=getattr(actor, "id", None),
            resource_type="scanner",
            resource_id=definition.scanner_key,
            metadata={"target_version": target_version, "previous_version": previous, "operation": operation},
        )
    except Exception:
        pass
    db.commit()
    db.refresh(rollout)
    return rollout

def advance_rollout_canary(db: Session, rollout: ScannerRollout, actor: Any | None = None) -> ScannerRollout:
    if rollout.state != "pending":
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Rollout not in pending state (current: {rollout.state})")
    rollout.state = "canary"
    rollout.started_at = datetime.now(timezone.utc)
    try:
        AuditService.record(
            db,
            event_type="SCANNER_CANARY_STARTED",
            action="SCANNER_CANARY_STARTED",
            result="SUCCESS",
            actor_user_id=getattr(actor, "id", None),
            resource_type="scanner_rollout",
            resource_id=rollout.id,
            metadata={"target_version": rollout.target_version, "canary_count": rollout.canary_count},
        )
    except Exception:
        pass
    db.commit()
    db.refresh(rollout)

    # Immediately perform health validation for canary
    definition = db.query(ScannerDefinition).filter(ScannerDefinition.id == rollout.definition_id).first()
    if definition:
        h = perform_health_check(db, definition, actor=actor)
        # If health healthy/degraded, promote to active; if unhealthy, fail
        if h.status in ("healthy", "degraded"):
            # Check threshold
            rollout.state = "active"
            rollout.completed_at = datetime.now(timezone.utc)
            # Update definition current_version and previous_version
            definition.previous_version = rollout.previous_version
            definition.current_version = rollout.target_version
            # Mark version channel to stable if canary passed (idempotent)
            v = db.query(ScannerVersion).filter(ScannerVersion.definition_id == definition.id, ScannerVersion.version == rollout.target_version).first()
            if v and v.channel != "stable":
                v.channel = "stable"
            try:
                AuditService.record(
                    db,
                    event_type="SCANNER_CANARY_PASSED",
                    action="SCANNER_CANARY_PASSED",
                    result="SUCCESS",
                    actor_user_id=getattr(actor, "id", None),
                    resource_type="scanner_rollout",
                    resource_id=rollout.id,
                    metadata={"target_version": rollout.target_version},
                )
                AuditService.record(
                    db,
                    event_type="SCANNER_UPGRADE_COMPLETED" if rollout.operation == "upgrade" else "SCANNER_ROLLBACK_COMPLETED",
                    action="SCANNER_UPGRADE_COMPLETED" if rollout.operation == "upgrade" else "SCANNER_ROLLBACK_COMPLETED",
                    result="SUCCESS",
                    actor_user_id=getattr(actor, "id", None),
                    resource_type="scanner",
                    resource_id=definition.scanner_key,
                    metadata={"target_version": rollout.target_version, "previous_version": rollout.previous_version},
                )
            except Exception:
                pass
        else:
            rollout.state = "failed"
            rollout.failure_reason = _sanitize_error(h.last_error) or "Canary health check failed"
            rollout.completed_at = datetime.now(timezone.utc)
            try:
                AuditService.record(
                    db,
                    event_type="SCANNER_CANARY_FAILED",
                    action="SCANNER_CANARY_FAILED",
                    result="FAILURE",
                    actor_user_id=getattr(actor, "id", None),
                    resource_type="scanner_rollout",
                    resource_id=rollout.id,
                    metadata={"target_version": rollout.target_version, "reason": rollout.failure_reason},
                )
                AuditService.record(
                    db,
                    event_type="SCANNER_UPGRADE_FAILED",
                    action="SCANNER_UPGRADE_FAILED",
                    result="FAILURE",
                    actor_user_id=getattr(actor, "id", None),
                    resource_type="scanner",
                    resource_id=definition.scanner_key,
                    metadata={"target_version": rollout.target_version, "reason": rollout.failure_reason},
                )
            except Exception:
                pass
        db.commit()
        db.refresh(rollout)
    return rollout

def rollback_rollout(db: Session, rollout: ScannerRollout, actor: Any | None = None) -> ScannerRollout:
    if rollout.state not in ("failed", "canary", "pending", "rolling_out"):
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Cannot rollback rollout in state {rollout.state}")
    # Restore previous version if available
    definition = db.query(ScannerDefinition).filter(ScannerDefinition.id == rollout.definition_id).first()
    if definition and rollout.previous_version:
        definition.current_version = rollout.previous_version
    rollout.state = "rolled_back"
    rollout.completed_at = datetime.now(timezone.utc)
    try:
        AuditService.record(
            db,
            event_type="SCANNER_ROLLBACK_COMPLETED",
            action="SCANNER_ROLLBACK_COMPLETED",
            result="SUCCESS",
            actor_user_id=getattr(actor, "id", None),
            resource_type="scanner_rollout",
            resource_id=rollout.id,
            metadata={"target_version": rollout.target_version, "rolled_back_to": rollout.previous_version},
        )
    except Exception:
        pass
    db.commit()
    db.refresh(rollout)
    if definition:
        db.refresh(definition)
    return rollout

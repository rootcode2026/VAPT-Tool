from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import require_super_admin
from app.db.database import get_db
from app.models.scanner_fleet import ScannerDefinition, ScannerHealth, ScannerRollout, ScannerVersion, WorkerPool
from app.models.user import User
from app.services.audit import AuditService
from app.services.scanner_catalog import SCANNER_CATALOG, get_catalog, get_scanner_entry, seed_definitions
from app.services.scanner_control import (
    advance_rollout_canary,
    create_rollout,
    get_definition_or_404,
    perform_health_check,
    record_health,
    register_version,
    rollback_rollout,
    validate_channel,
    validate_health_status,
    validate_image_ref,
    validate_version,
)

router = APIRouter(prefix="/api/v1/admin", tags=["Scanner Control Plane"])

def _ensure_seed(db: Session):
    try:
        if db.query(ScannerDefinition).count() == 0:
            seed_definitions(db)
    except Exception:
        pass
    # also ensure pools
    try:
        from app.services.scanner_control import ensure_default_pools
        ensure_default_pools(db)
    except Exception:
        pass

def _health_for(definition: ScannerDefinition, db: Session) -> dict | None:
    h = db.query(ScannerHealth).filter(ScannerHealth.definition_id == definition.id).order_by(ScannerHealth.checked_at.desc()).first()
    if not h:
        return None
    return {
        "id": h.id,
        "status": h.status,
        "version": h.version,
        "latency_ms": h.latency_ms,
        "failure_count": h.failure_count,
        "last_error": h.last_error,
        "capabilities_verified": h.capabilities_verified,
        "version_verified": h.version_verified,
        "checked_at": h.checked_at.isoformat() if h.checked_at else None,
    }

def _versions_for(definition: ScannerDefinition, db: Session) -> list[dict]:
    rows = db.query(ScannerVersion).filter(ScannerVersion.definition_id == definition.id).order_by(ScannerVersion.created_at.desc()).all()
    return [
        {
            "id": r.id,
            "version": r.version,
            "channel": r.channel,
            "image_ref": r.image_ref,
            "image_digest": r.image_digest,
            "health_status": r.health_status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        } for r in rows
    ]

def _enriched(definition: ScannerDefinition, db: Session) -> dict:
    health = _health_for(definition, db)
    versions = _versions_for(definition, db)
    stable = next((v for v in versions if v["channel"] == "stable"), None)
    candidate = next((v for v in versions if v["channel"] == "candidate"), None)
    # fallback to documented stable if no version rows
    return {
        "key": definition.scanner_key,
        "name": definition.display_name,
        "category": definition.category,
        "family": definition.family,
        "description": definition.description,
        "enabled": definition.enabled,
        "current_version": definition.current_version,
        "previous_version": definition.previous_version,
        "capabilities": definition.capabilities,
        "requirements": definition.requirements,
        "supported_profiles": definition.supported_profiles,
        "requires_workspace": definition.requires_workspace,
        "execution_type": definition.execution_type,
        "timeout_seconds": definition.timeout_seconds,
        "default_image": definition.default_image,
        "health": health,
        "health_status": health["status"] if health else "unknown",
        "versions": versions,
        "stable_version": stable["version"] if stable else definition.current_version,
        "candidate_version": candidate["version"] if candidate else None,
        "created_at": definition.created_at.isoformat() if definition.created_at else None,
        "updated_at": definition.updated_at.isoformat() if definition.updated_at else None,
    }

# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------

@router.get("/scanners")
def list_scanners(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    defs = db.query(ScannerDefinition).order_by(ScannerDefinition.scanner_key.asc()).all()
    # ensure 14
    if len(defs) < 14:
        # try to seed missing
        try:
            seed_definitions(db)
            defs = db.query(ScannerDefinition).order_by(ScannerDefinition.scanner_key.asc()).all()
        except Exception:
            pass
    items = [_enriched(d, db) for d in defs]
    # add capacity context
    try:
        from app.services.scanner_control import fleet_summary
        fleet = fleet_summary(db)
    except Exception:
        fleet = None
    return {"items": items, "total": len(items), "fleet": fleet}

@router.get("/scanners/{scanner_key}")
def get_scanner(
    scanner_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    return _enriched(definition, db)

@router.patch("/scanners/{scanner_key}")
def patch_scanner(
    scanner_key: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    if "enabled" in payload:
        enabled = payload["enabled"]
        if not isinstance(enabled, bool):
            raise HTTPException(status_code=400, detail="enabled must be boolean")
        old = definition.enabled
        definition.enabled = enabled
        definition.updated_at = datetime.now(timezone.utc)
        try:
            AuditService.record(
                db,
                event_type="SCANNER_ENABLED" if enabled else "SCANNER_DISABLED",
                action="SCANNER_ENABLED" if enabled else "SCANNER_DISABLED",
                result="SUCCESS",
                actor_user_id=current_user.id,
                resource_type="scanner",
                resource_id=definition.scanner_key,
                metadata={"old_enabled": old, "new_enabled": enabled},
            )
        except Exception:
            pass
        db.commit()
        db.refresh(definition)
    return _enriched(definition, db)

# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

@router.get("/scanners/{scanner_key}/versions")
def list_versions(
    scanner_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    rows = db.query(ScannerVersion).filter(ScannerVersion.definition_id == definition.id).order_by(ScannerVersion.created_at.desc()).all()
    return {"items": [
        {
            "id": r.id,
            "version": r.version,
            "channel": r.channel,
            "image_ref": r.image_ref,
            "image_digest": r.image_digest,
            "health_status": r.health_status,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in rows
    ], "total": len(rows)}

@router.post("/scanners/{scanner_key}/versions/{version}/promote", status_code=200)
def promote_version_route(
    scanner_key: str,
    version: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    target_channel = payload.get("target_channel") or payload.get("channel") or "stable"
    reason = payload.get("reason")
    # Reject arbitrary fields
    for k in ("image_ref", "image_digest", "command", "shell", "volumes", "privileged"):
        if k in payload and k not in ("target_channel", "channel", "reason"):
            raise HTTPException(status_code=400, detail=f"Forbidden field: {k}")
    try:
        from app.services.scanner_control import promote_version
        v = promote_version(db, definition, version=version, target_channel=target_channel, reason=reason, actor=current_user)
        return {"id": v.id, "version": v.version, "channel": v.channel, "lifecycle_status": getattr(v, "lifecycle_status", None), "image_ref": v.image_ref, "image_digest": v.image_digest}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)[:500])

@router.post("/scanners/{scanner_key}/versions/{version}/approve", status_code=200)
def approve_version_route(
    scanner_key: str,
    version: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    from app.models.scanner_fleet import ScannerVersion
    v = db.query(ScannerVersion).filter(ScannerVersion.definition_id == definition.id, ScannerVersion.version == version).first()
    if not v:
        raise HTTPException(status_code=404, detail="Version not found")
    if v.approved:
        return {"id": v.id, "version": v.version, "approved": True}
    v.approved = True
    v.approved_at = datetime.now(timezone.utc)
    v.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(v)
    try:
        AuditService.record(db, event_type="SCANNER_VERSION_APPROVED", action="SCANNER_VERSION_APPROVED", result="SUCCESS", actor_user_id=current_user.id, resource_type="scanner", resource_id=definition.scanner_key, metadata={"version": version})
        db.commit()
    except Exception:
        pass
    return {"id": v.id, "version": v.version, "approved": True, "approved_at": v.approved_at.isoformat() if v.approved_at else None}

@router.post("/scanners/{scanner_key}/versions/{version}/deprecate", status_code=200)
def deprecate_version_route(
    scanner_key: str,
    version: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    from app.models.scanner_fleet import ScannerVersion
    v = db.query(ScannerVersion).filter(ScannerVersion.definition_id == definition.id, ScannerVersion.version == version).first()
    if not v:
        raise HTTPException(status_code=404, detail="Version not found")
    v.deprecated = True
    v.deprecated_at = datetime.now(timezone.utc)
    v.lifecycle_status = "deprecated"
    v.channel = "deprecated"
    v.updated_at = datetime.now(timezone.utc)
    # If this was stable, need to handle current_version?
    if definition.current_version == version:
        # Find previous stable or leave as is but mark as deprecated — current_version will be stale but not deleted
        pass
    db.commit()
    db.refresh(v)
    try:
        AuditService.record(db, event_type="SCANNER_VERSION_DEPRECATED", action="SCANNER_VERSION_DEPRECATED", result="SUCCESS", actor_user_id=current_user.id, resource_type="scanner", resource_id=definition.scanner_key, metadata={"version": version})
        db.commit()
    except Exception:
        pass
    return {"id": v.id, "version": v.version, "deprecated": True, "lifecycle_status": v.lifecycle_status}

@router.post("/scanners/{scanner_key}/versions", status_code=201)
def create_version(
    scanner_key: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    version = payload.get("version")
    channel = payload.get("channel", "candidate")
    image_ref = payload.get("image_ref")
    image_digest = payload.get("image_digest")
    if not version:
        raise HTTPException(status_code=400, detail="version is required")
    # validate image_ref early to block arbitrary
    if image_ref is not None:
        try:
            validate_image_ref(image_ref)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
    if image_digest is not None and len(str(image_digest)) > 128:
        raise HTTPException(status_code=400, detail="image_digest too long")
    try:
        validate_channel(channel)
        validate_version(version)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # check arbitrary shell/mount attempts in payload
    for forbidden_key in ("command", "docker_command", "shell", "volumes", "mounts", "privileged", "network_mode", "host_path"):
        if forbidden_key in payload:
            raise HTTPException(status_code=400, detail=f"Forbidden field: {forbidden_key}")

    v = register_version(db, definition, version=version, channel=channel, image_ref=image_ref, image_digest=image_digest, compatibility=payload.get("compatibility"), release_notes=payload.get("release_notes"), actor=current_user)
    return {
        "id": v.id,
        "version": v.version,
        "channel": v.channel,
        "image_ref": v.image_ref,
        "image_digest": v.image_digest,
        "health_status": v.health_status,
    }

# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@router.get("/scanners/{scanner_key}/health")
def get_health(
    scanner_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    h = db.query(ScannerHealth).filter(ScannerHealth.definition_id == definition.id).order_by(ScannerHealth.checked_at.desc()).first()
    if not h:
        return {"status": "unknown", "checked_at": None}
    return {
        "id": h.id,
        "status": h.status,
        "version": h.version,
        "latency_ms": h.latency_ms,
        "failure_count": h.failure_count,
        "last_error": h.last_error,
        "capabilities_verified": h.capabilities_verified,
        "version_verified": h.version_verified,
        "checked_at": h.checked_at.isoformat() if h.checked_at else None,
    }

@router.post("/scanners/{scanner_key}/health/check")
def trigger_health_check(
    scanner_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    h = perform_health_check(db, definition, actor=current_user)
    return {
        "id": h.id,
        "status": h.status,
        "version": h.version,
        "latency_ms": h.latency_ms,
        "last_error": h.last_error,
        "checked_at": h.checked_at.isoformat() if h.checked_at else None,
    }

@router.get("/scanners/{scanner_key}/health/history")
def health_history(
    scanner_key: str,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    rows = db.query(ScannerHealth).filter(ScannerHealth.definition_id == definition.id).order_by(ScannerHealth.checked_at.desc()).limit(limit).all()
    return {"items": [
        {
            "id": r.id,
            "status": r.status,
            "version": r.version,
            "latency_ms": r.latency_ms,
            "last_error": r.last_error,
            "checked_at": r.checked_at.isoformat() if r.checked_at else None,
        } for r in rows
    ]}

# ---------------------------------------------------------------------------
# Rollout lifecycle
# ---------------------------------------------------------------------------

@router.post("/scanners/{scanner_key}/upgrade")
def upgrade_scanner(
    scanner_key: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    target_version = payload.get("target_version") or payload.get("version")
    if not target_version:
        raise HTTPException(status_code=400, detail="target_version is required")
    try:
        validate_version(target_version)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # block arbitrary fields
    for k in ("image_ref", "docker", "command", "shell", "volumes", "privileged"):
        if k in payload and k != "target_version":
            # we allow target_version only; image_ref is not allowed via upgrade (must be registered version)
            if k == "image_ref":
                raise HTTPException(status_code=400, detail="Use POST /versions to register image, then upgrade by version")
            raise HTTPException(status_code=400, detail=f"Forbidden field: {k}")
    try:
        rollout = create_rollout(db, definition, target_version=target_version, operation="upgrade", actor=current_user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    # advance to canary/health validation (safe, bounded, no customer target)
    rollout = advance_rollout_canary(db, rollout, actor=current_user)
    return {
        "id": rollout.id,
        "scanner_key": scanner_key,
        "target_version": rollout.target_version,
        "previous_version": rollout.previous_version,
        "state": rollout.state,
        "operation": rollout.operation,
        "failure_reason": rollout.failure_reason,
    }

@router.post("/scanners/{scanner_key}/downgrade")
def downgrade_scanner(
    scanner_key: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    target_version = payload.get("target_version") or payload.get("version")
    if not target_version:
        raise HTTPException(status_code=400, detail="target_version is required")
    try:
        validate_version(target_version)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    for k in ("image_ref", "command", "shell", "volumes", "privileged"):
        if k in payload and k != "target_version":
            raise HTTPException(status_code=400, detail=f"Forbidden field: {k}")
    try:
        rollout = create_rollout(db, definition, target_version=target_version, operation="downgrade", actor=current_user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    rollout = advance_rollout_canary(db, rollout, actor=current_user)
    return {
        "id": rollout.id,
        "scanner_key": scanner_key,
        "target_version": rollout.target_version,
        "previous_version": rollout.previous_version,
        "state": rollout.state,
        "operation": rollout.operation,
        "failure_reason": rollout.failure_reason,
    }

@router.post("/scanners/{scanner_key}/rollback")
def rollback_scanner(
    scanner_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    definition = get_definition_or_404(db, scanner_key.strip())
    # find last failed/canary rollout
    rollout = db.query(ScannerRollout).filter(
        ScannerRollout.definition_id == definition.id,
        ScannerRollout.state.in_(["failed", "canary", "pending", "rolling_out"]),
    ).order_by(ScannerRollout.created_at.desc()).first()
    if not rollout:
        # also check last active rollout to rollback
        rollout = db.query(ScannerRollout).filter(ScannerRollout.definition_id == definition.id).order_by(ScannerRollout.created_at.desc()).first()
        if not rollout:
            raise HTTPException(status_code=404, detail="No rollout to rollback")
        if rollout.state == "active" and rollout.previous_version:
            # create a new rollback rollout to previous
            try:
                new_rollout = create_rollout(db, definition, target_version=rollout.previous_version, operation="rollback", actor=current_user)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))
            # advance canary
            new_rollout = advance_rollout_canary(db, new_rollout, actor=current_user)
            return {
                "id": new_rollout.id,
                "scanner_key": scanner_key,
                "target_version": new_rollout.target_version,
                "previous_version": new_rollout.previous_version,
                "state": new_rollout.state,
                "operation": new_rollout.operation,
                "failure_reason": new_rollout.failure_reason,
            }
        raise HTTPException(status_code=400, detail=f"Cannot rollback rollout in state {rollout.state}")
    rolled = rollback_rollout(db, rollout, actor=current_user)
    return {
        "id": rolled.id,
        "scanner_key": scanner_key,
        "target_version": rolled.target_version,
        "previous_version": rolled.previous_version,
        "state": rolled.state,
        "operation": rolled.operation,
        "failure_reason": rolled.failure_reason,
    }

# ---------------------------------------------------------------------------
# Fleet
# ---------------------------------------------------------------------------

@router.get("/scanner-fleet")
def get_fleet(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    try:
        from app.services.scanner_control import fleet_summary
        return fleet_summary(db)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to load fleet")

@router.get("/scanner-fleet/pools")
def get_pools(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    pools = db.query(WorkerPool).all()
    return {"items": [
        {
            "id": p.id,
            "name": p.name,
            "families": p.scanner_families,
            "total_capacity": p.total_capacity,
            "reserved_buffer": p.reserved_buffer,
            "available": max(0, p.total_capacity - p.reserved_buffer),
            "status": p.status,
        } for p in pools
    ], "total": len(pools)}

# ---------------------------------------------------------------------------
# Rollouts
# ---------------------------------------------------------------------------

@router.get("/scanner-rollouts")
def list_rollouts(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
    scanner_key: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
):
    _ensure_seed(db)
    q = db.query(ScannerRollout).order_by(ScannerRollout.created_at.desc())
    if scanner_key:
        definition = db.query(ScannerDefinition).filter(ScannerDefinition.scanner_key == scanner_key).first()
        if not definition:
            raise HTTPException(status_code=404, detail="Scanner not found")
        q = q.filter(ScannerRollout.definition_id == definition.id)
    rows = q.limit(limit).all()
    # enrich with scanner_key
    defs = {d.id: d.scanner_key for d in db.query(ScannerDefinition).all()}
    return {"items": [
        {
            "id": r.id,
            "scanner_key": defs.get(r.definition_id, "unknown"),
            "target_version": r.target_version,
            "previous_version": r.previous_version,
            "state": r.state,
            "operation": r.operation,
            "canary_count": r.canary_count,
            "failure_reason": r.failure_reason,
            "initiated_by": r.initiated_by,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in rows
    ], "total": len(rows)}

@router.get("/scanner-rollouts/{rollout_id}")
def get_rollout(
    rollout_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_super_admin),
):
    _ensure_seed(db)
    r = db.query(ScannerRollout).filter(ScannerRollout.id == rollout_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Rollout not found")
    d = db.query(ScannerDefinition).filter(ScannerDefinition.id == r.definition_id).first()
    return {
        "id": r.id,
        "scanner_key": d.scanner_key if d else "unknown",
        "target_version": r.target_version,
        "previous_version": r.previous_version,
        "state": r.state,
        "operation": r.operation,
        "canary_count": r.canary_count,
        "health_threshold": r.health_threshold,
        "failure_reason": r.failure_reason,
        "initiated_by": r.initiated_by,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }

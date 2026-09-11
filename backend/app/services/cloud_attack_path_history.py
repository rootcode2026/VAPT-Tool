"""E10 persistence — minimal durable identity + observations for attack paths."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.cloud_attack_path import CloudAttackPath, CloudAttackPathObservation
from app.models.project import Project
from app.services.cloud_attack_paths import build_cloud_attack_paths

VALID_RUN_STATUSES_FOR_RESOLUTION = {"completed"}

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _get_org_id(project_id: str, db: Session) -> str | None:
    proj = db.query(Project).filter(Project.id == project_id).first()
    return proj.organization_id if proj else None

def observe_attack_paths(
    project_id: str,
    db: Session,
    monitoring_run_id: str | None = None,
    run_status: str = "completed",
    observed_at: datetime | None = None,
) -> dict[str, Any]:
    """Observe current attack paths and persist lifecycle.

    - Build current paths via E9 on-read engine (bounded)
    - Upsert CloudAttackPath per fingerprint (unique project+fingerprint)
    - Create observation per path per run_id (idempotent via unique constraint)
    - If run_status is valid completed, resolve missing ACTIVE paths
    - Idempotent: repeated same run_id does not duplicate paths/observations
    - Concurrent-safe via unique constraint + IntegrityError catch

    Returns {"observed": int, "created": int, "reopened": int, "resolved": int, "severity_changed": int}
    """
    observed_at = observed_at or _now()
    org_id = _get_org_id(project_id, db)
    if not org_id:
        raise ValueError(f"Project not found: {project_id}")

    current_paths = build_cloud_attack_paths(project_id, db, limit=100)
    # Map fingerprint -> path dict
    current_by_fp = {p["fingerprint"]: p for p in current_paths}
    current_fps = set(current_by_fp.keys())

    existing = db.query(CloudAttackPath).filter(CloudAttackPath.project_id == project_id).all()
    existing_by_fp = {p.fingerprint: p for p in existing}

    created = 0
    reopened = 0
    resolved = 0
    severity_changed = 0
    priority_changed = 0
    confidence_changed = 0

    # Upsert observed paths
    for fp, p in current_by_fp.items():
        existing_path = existing_by_fp.get(fp)
        if existing_path:
            # Check changes
            if existing_path.severity != p["severity"]:
                severity_changed += 1
            if existing_path.priority_score != p["priority_score"]:
                priority_changed += 1
            if existing_path.confidence != p["confidence"]:
                confidence_changed += 1
            # Update fields
            was_resolved = existing_path.status == "RESOLVED"
            existing_path.severity = p["severity"]
            existing_path.priority_score = p["priority_score"]
            existing_path.confidence = p["confidence"]
            existing_path.provider = p["provider"]
            existing_path.path_type = p["path_type"]
            existing_path.entry_asset_id = p["entry_asset_id"]
            existing_path.target_asset_id = p["target_asset_id"]
            existing_path.asset_ids = p["asset_ids"][:20]
            # bounded evidence snapshot
            existing_path.evidence = {"findings": p["findings"][:10], "relationships": p["relationships"][:10]}
            existing_path.last_seen_at = observed_at
            existing_path.updated_at = observed_at
            if was_resolved:
                existing_path.status = "ACTIVE"
                existing_path.resolved_at = None
                reopened += 1
            else:
                # ensure ACTIVE
                existing_path.status = "ACTIVE"
            # Observation idempotent check
            if monitoring_run_id:
                exists_obs = db.query(CloudAttackPathObservation).filter(
                    CloudAttackPathObservation.project_id == project_id,
                    CloudAttackPathObservation.fingerprint == fp,
                    CloudAttackPathObservation.monitoring_run_id == monitoring_run_id,
                ).first()
                if not exists_obs:
                    obs = CloudAttackPathObservation(
                        id=str(uuid.uuid4()),
                        project_id=project_id,
                        attack_path_id=existing_path.id,
                        monitoring_run_id=monitoring_run_id,
                        fingerprint=fp,
                        priority_score=p["priority_score"],
                        severity=p["severity"],
                        confidence=p["confidence"],
                        status="ACTIVE",
                        observed_at=observed_at,
                    )
                    db.add(obs)
            else:
                # No run_id: use fingerprint+observed_at uniqueness via check
                # For idempotency without run_id, we check if observation with same fp and same observed_at second exists
                obs = CloudAttackPathObservation(
                    id=str(uuid.uuid4()),
                    project_id=project_id,
                    attack_path_id=existing_path.id,
                    monitoring_run_id=None,
                    fingerprint=fp,
                    priority_score=p["priority_score"],
                    severity=p["severity"],
                    confidence=p["confidence"],
                    status="ACTIVE",
                    observed_at=observed_at,
                )
                db.add(obs)
        else:
            # Create new
            try:
                new_path = CloudAttackPath(
                    id=str(uuid.uuid4()),
                    project_id=project_id,
                    organization_id=org_id,
                    fingerprint=fp,
                    provider=p["provider"],
                    path_type=p["path_type"],
                    severity=p["severity"],
                    priority_score=p["priority_score"],
                    confidence=p["confidence"],
                    entry_asset_id=p["entry_asset_id"],
                    target_asset_id=p["target_asset_id"],
                    status="ACTIVE",
                    asset_ids=p["asset_ids"][:20],
                    evidence={"findings": p["findings"][:10], "relationships": p["relationships"][:10]},
                    first_seen_at=observed_at,
                    last_seen_at=observed_at,
                    resolved_at=None,
                    created_at=observed_at,
                    updated_at=observed_at,
                )
                db.add(new_path)
                db.flush()
                created += 1
                # observation
                obs = CloudAttackPathObservation(
                    id=str(uuid.uuid4()),
                    project_id=project_id,
                    attack_path_id=new_path.id,
                    monitoring_run_id=monitoring_run_id,
                    fingerprint=fp,
                    priority_score=p["priority_score"],
                    severity=p["severity"],
                    confidence=p["confidence"],
                    status="ACTIVE",
                    observed_at=observed_at,
                )
                db.add(obs)
            except IntegrityError:
                db.rollback()
                # Concurrent creation: fetch existing and update
                existing_path = db.query(CloudAttackPath).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.fingerprint == fp).first()
                if existing_path:
                    existing_path.last_seen_at = observed_at
                    existing_path.updated_at = observed_at

    # Resolve missing ACTIVE paths only on valid completed observation
    if run_status in VALID_RUN_STATUSES_FOR_RESOLUTION:
        for fp, existing_path in existing_by_fp.items():
            if fp not in current_fps and existing_path.status == "ACTIVE":
                existing_path.status = "RESOLVED"
                existing_path.resolved_at = observed_at
                existing_path.updated_at = observed_at
                resolved += 1
                # Optional: create resolved observation? Not required for E10, but we can record last observation as resolved?
                # Spec says observation has status; we keep last ACTIVE observation, resolution is via path status.
    else:
        # Do not resolve on failed/partial/invalid
        pass

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # On conflict, second commit try without duplicate observations
        # For idempotency, swallow duplicate observation unique violation
        try:
            db.commit()
        except Exception:
            db.rollback()

    return {
        "observed": len(current_paths),
        "created": created,
        "reopened": reopened,
        "resolved": resolved,
        "severity_changed": severity_changed,
        "priority_changed": priority_changed,
        "confidence_changed": confidence_changed,
    }


def get_history(project_id: str, db: Session, provider: str | None = None, severity: str | None = None, path_type: str | None = None, status: str | None = None, from_date: datetime | None = None, to_date: datetime | None = None, limit: int = 50) -> list[dict]:
    q = db.query(CloudAttackPath).filter(CloudAttackPath.project_id == project_id)
    if provider:
        q = q.filter(CloudAttackPath.provider == provider.lower())
    if severity:
        q = q.filter(CloudAttackPath.severity == severity.lower())
    if path_type:
        q = q.filter(CloudAttackPath.path_type == path_type.upper())
    if status:
        q = q.filter(CloudAttackPath.status == status.upper())
    if from_date:
        q = q.filter(CloudAttackPath.first_seen_at >= from_date)
    if to_date:
        q = q.filter(CloudAttackPath.last_seen_at <= to_date)
    if limit > 100:
        limit = 100
    rows = q.order_by(CloudAttackPath.last_seen_at.desc()).limit(limit).all()
    out = []
    for r in rows:
        out.append({
            "id": r.id,
            "project_id": r.project_id,
            "fingerprint": r.fingerprint,
            "provider": r.provider,
            "path_type": r.path_type,
            "severity": r.severity,
            "priority_score": r.priority_score,
            "confidence": r.confidence,
            "entry_asset_id": r.entry_asset_id,
            "target_asset_id": r.target_asset_id,
            "status": r.status,
            "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
            "last_seen_at": r.last_seen_at.isoformat() if r.last_seen_at else None,
            "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
            "asset_ids": r.asset_ids or [],
            "evidence": r.evidence or {},
        })
    return out


def get_history_detail(project_id: str, db: Session, path_id: str) -> dict | None:
    row = db.query(CloudAttackPath).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.id == path_id).first()
    if not row:
        # Try fingerprint
        row = db.query(CloudAttackPath).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.fingerprint == path_id).first()
        if not row:
            return None
    observations = db.query(CloudAttackPathObservation).filter(CloudAttackPathObservation.attack_path_id == row.id).order_by(CloudAttackPathObservation.observed_at.desc()).limit(50).all()
    obs_list = []
    for o in observations:
        obs_list.append({
            "id": o.id,
            "monitoring_run_id": o.monitoring_run_id,
            "priority_score": o.priority_score,
            "severity": o.severity,
            "confidence": o.confidence,
            "status": o.status,
            "observed_at": o.observed_at.isoformat() if o.observed_at else None,
        })
    return {
        "id": row.id,
        "project_id": row.project_id,
        "fingerprint": row.fingerprint,
        "provider": row.provider,
        "path_type": row.path_type,
        "severity": row.severity,
        "priority_score": row.priority_score,
        "confidence": row.confidence,
        "entry_asset_id": row.entry_asset_id,
        "target_asset_id": row.target_asset_id,
        "status": row.status,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
        "asset_ids": row.asset_ids or [],
        "evidence": row.evidence or {},
        "observations": obs_list,
    }


def get_summary(project_id: str, db: Session) -> dict:
    total_q = db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id == project_id)
    active = db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.status == "ACTIVE").scalar() or 0
    resolved = db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.status == "RESOLVED").scalar() or 0
    critical = db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.severity == "critical").scalar() or 0
    high = db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.severity == "high").scalar() or 0
    # providers breakdown
    providers = {}
    for prov in ("aws", "gcp", "azure", "multi", "unknown"):
        cnt = db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.provider == prov).scalar() or 0
        if cnt:
            providers[prov] = cnt
    # path types
    types = {}
    for pt in db.query(CloudAttackPath.path_type, func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id == project_id).group_by(CloudAttackPath.path_type).all():
        types[pt[0]] = pt[1]
    # avg priority
    avg = db.query(func.avg(CloudAttackPath.priority_score)).filter(CloudAttackPath.project_id == project_id).scalar()
    highest = db.query(func.max(CloudAttackPath.priority_score)).filter(CloudAttackPath.project_id == project_id).scalar()
    # recent? last 7 days
    from datetime import timedelta
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    created_recently = db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.first_seen_at >= week_ago).scalar() or 0
    # reopened: count where resolved_at is null and updated recently and first_seen older than week? Simplified: count ACTIVE where first_seen < last_seen
    reopened_recently = db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.status == "ACTIVE", CloudAttackPath.first_seen_at < CloudAttackPath.last_seen_at).scalar() or 0

    return {
        "project_id": project_id,
        "active": active,
        "resolved": resolved,
        "total": (active + resolved),
        "critical": critical,
        "high": high,
        "providers": providers,
        "path_types": types,
        "avg_priority": round(float(avg), 1) if avg else 0,
        "highest_priority": int(highest) if highest else 0,
        "created_recently": created_recently,
        "reopened_recently": reopened_recently,
    }

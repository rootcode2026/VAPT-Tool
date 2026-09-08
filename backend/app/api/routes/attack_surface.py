"""Attack Surface & Exposure workspace + continuous monitoring foundation (project-scoped)."""

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.api.deps import _effective_org_role, _is_super_admin, get_current_user, require_project_access
from app.db.database import get_db
from app.models.asset import Asset
from app.models.asset_change_event import AssetChangeEvent
from app.models.asset_relationship import AssetRelationship
from app.models.finding import Finding
from app.models.monitoring import MonitoringConfig, MonitoringRun
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.services import attack_surface as surf
from app.services.audit import (
    EVENT_ASSET_CRITICALITY_CHANGED,
    EVENT_ASSET_OWNER_CHANGED,
    EVENT_MONITORING_CONFIG_CREATED,
    EVENT_MONITORING_CONFIG_DELETED,
    EVENT_MONITORING_CONFIG_PAUSED,
    EVENT_MONITORING_CONFIG_RESUMED,
    EVENT_MONITORING_CONFIG_UPDATED,
    EVENT_MONITORING_RUN_COMPLETED,
    EVENT_MONITORING_RUN_FAILED,
    EVENT_MONITORING_RUN_PARTIAL,
    EVENT_MONITORING_RUN_SCHEDULED,
    EVENT_MONITORING_RUN_STARTED,
    RESOURCE_ASSET,
    RESOURCE_MONITORING_CONFIG,
    RESOURCE_MONITORING_RUN,
    RESULT_PARTIAL,
    RESULT_SUCCESS,
    AuditService,
)
from app.services.monitoring_service import (
    MONITOR_FREQUENCIES,
    MONITOR_RUN_ACTIVE,
    compute_next_run,
    frequency_interval_seconds,
    shift_run_window,
)
from app.services.scanner_catalog import scanners_for_profile

router = APIRouter(prefix="/api/v1", tags=["Attack Surface"])

GRAPH_NODE_LIMIT = 500
GRAPH_EDGE_LIMIT = 1000

MONITOR_PROFILES = {"quick", "web", "full"}
MONITOR_SCOPES = {"all", "target"}


def _utcnow():
    return datetime.now(timezone.utc)


def _ensure_asset_columns(db: Session) -> None:
    """Backward compat for isolated SQLite test DBs with legacy assets table."""
    try:
        surf.ensure_asset_workflow_columns(db)
    except Exception:
        pass


def _require_monitor_manage(project_id: str, db: Session, current_user: User) -> None:
    if _is_super_admin(current_user):
        return
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj:
        org_role = _effective_org_role(current_user, proj.organization_id, db)
        if org_role == "org_admin":
            return
    from app.api.deps import _effective_project_role

    role = _effective_project_role(current_user, project_id, db)
    if role != "project_admin":
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires project_admin or org_admin")


def _require_monitor_run(project_id: str, db: Session, current_user: User) -> None:
    if _is_super_admin(current_user):
        return
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj:
        org_role = _effective_org_role(current_user, proj.organization_id, db)
        if org_role == "org_admin":
            return
    from app.api.deps import _effective_project_role

    role = _effective_project_role(current_user, project_id, db)
    if role not in ("analyst", "project_admin"):
        raise HTTPException(status_code=403, detail="Insufficient permissions: requires analyst to run monitoring")


def _parse_dt(value: str | None, field: str):
    if value is None:
        return None
    try:
        s = value.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid {field}")


def _asset_enrichment(db: Session, assets: list[Asset]) -> dict:
    """One GROUP BY query for finding counts + max score per asset (avoids N+1)."""
    ids = [a.id for a in assets]
    if not ids:
        return {}
    rows = (
        db.query(
            Finding.asset_id,
            func.count(Finding.id),
            func.sum(case((Finding.severity == "critical", 1), else_=0)),
            func.sum(case((Finding.severity == "high", 1), else_=0)),
            func.max(Finding.score),
            func.sum(case((Finding.status.in_(["open", "detected", "corroborated", "needs_review", "confirmed"]), 1), else_=0)),
        )
        .filter(Finding.asset_id.in_(ids))
        .group_by(Finding.asset_id)
        .all()
    )
    out: dict = {}
    for asset_id, total, crit, high, max_score, open_c in rows:
        out[asset_id] = {
            "finding_count": int(total or 0),
            "critical_count": int(crit or 0),
            "high_count": int(high or 0),
            "max_score": max_score,
            "open_count": int(open_c or 0),
        }
    return out


def _asset_payload(a: Asset, enrich: dict | None = None) -> dict:
    meta = a.extra_data or {}
    exposure = surf.classify_exposure(a.asset_type, a.value, meta if isinstance(meta, dict) else {})
    state = (a.status or "unknown").strip().lower()
    if state not in ("active", "stale", "inactive"):
        state = surf.compute_asset_state(a.last_seen_at)
    e = (enrich or {}).get(a.id, {})
    return {
        "id": a.id,
        "project_id": a.project_id,
        "asset_type": a.asset_type,
        "value": a.value,
        "status": state,
        "state": state,
        "exposure": exposure,
        "criticality": getattr(a, "criticality", "unknown") or "unknown",
        "owner_user_id": getattr(a, "owner_user_id", None),
        "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
        "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        "finding_count": e.get("finding_count", 0),
        "critical_count": e.get("critical_count", 0),
        "high_count": e.get("high_count", 0),
        "open_count": e.get("open_count", 0),
        "max_score": e.get("max_score"),
        "metadata": surf.sanitize_change_metadata(meta if isinstance(meta, dict) else {}),
    }


# -------------------------------------------------------------------
# Summary
# -------------------------------------------------------------------

@router.get("/projects/{project_id}/attack-surface/summary")
def attack_surface_summary(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _ensure_asset_columns(db)
    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    total = len(assets)
    active = sum(1 for a in assets if (a.status or "").lower() == "active")
    stale = sum(1 for a in assets if (a.status or "").lower() == "stale")
    inactive = sum(1 for a in assets if (a.status or "").lower() == "inactive")

    by_type: dict[str, int] = {}
    exposures = {"INTERNET_EXPOSED": 0, "EXTERNALLY_REACHABLE": 0, "INTERNAL": 0, "UNKNOWN": 0}
    for a in assets:
        by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
        meta = a.extra_data if isinstance(a.extra_data, dict) else {}
        exp = surf.classify_exposure(a.asset_type, a.value, meta)
        exposures[exp] = exposures.get(exp, 0) + 1

    enrich = _asset_enrichment(db, assets)
    with_findings = sum(1 for a in assets if enrich.get(a.id, {}).get("finding_count", 0) > 0)
    critical_assets = sum(1 for a in assets if enrich.get(a.id, {}).get("critical_count", 0) > 0)
    high_risk = sum(1 for a in assets if (enrich.get(a.id, {}).get("max_score") or 0) >= 75)

    since = _utcnow().replace(tzinfo=None)
    recent_changes = 0
    try:
        from datetime import timedelta

        cutoff = since - timedelta(days=7)
        recent_changes = (
            db.query(func.count(AssetChangeEvent.id))
            .filter(AssetChangeEvent.project_id == project_id, AssetChangeEvent.detected_at >= cutoff)
            .scalar()
            or 0
        )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        recent_changes = 0

    def _t(t: str) -> int:
        return by_type.get(t, 0)

    return {
        "project_id": project_id,
        "total_assets": total,
        "active_assets": active,
        "stale_assets": stale,
        "inactive_assets": inactive,
        "internet_exposed": exposures.get("INTERNET_EXPOSED", 0),
        "externally_reachable": exposures.get("EXTERNALLY_REACHABLE", 0),
        "public_ips": sum(1 for a in assets if a.asset_type in ("ip", "ipv6") and surf.classify_exposure(a.asset_type, a.value, a.extra_data if isinstance(a.extra_data, dict) else {}) == "INTERNET_EXPOSED"),
        "domains": _t("domain"),
        "subdomains": _t("subdomain"),
        "web_assets": _t("url") + _t("web_application"),
        "api_endpoints": _t("api_endpoint"),
        "open_ports": _t("port"),
        "services": _t("service"),
        "cloud_resources": _t("cloud_resource") + _t("cloud_account"),
        "repositories": _t("repository"),
        "assets_with_findings": with_findings,
        "critical_assets": critical_assets,
        "high_risk_assets": high_risk,
        "recent_changes": recent_changes,
    }


# -------------------------------------------------------------------
# Assets
# -------------------------------------------------------------------

@router.get("/projects/{project_id}/attack-surface/assets")
def attack_surface_assets(
    project_id: str,
    asset_type: str | None = Query(default=None, max_length=50),
    state: str | None = Query(default=None, max_length=20),
    exposure: str | None = Query(default=None, max_length=30),
    criticality: str | None = Query(default=None, max_length=20),
    owner: str | None = Query(default=None, max_length=36),
    has_findings: bool | None = Query(default=None),
    risk_level: str | None = Query(default=None, max_length=30),
    changed_since: str | None = Query(default=None, description="ISO8601"),
    search: str | None = Query(default=None, max_length=256),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _ensure_asset_columns(db)
    q = db.query(Asset).filter(Asset.project_id == project_id)
    if asset_type and asset_type.strip():
        q = q.filter(Asset.asset_type == asset_type.strip().lower())
    if state and state.strip():
        st = state.strip().lower()
        if st not in ("active", "stale", "inactive", "unknown"):
            raise HTTPException(status_code=400, detail="Invalid state")
        q = q.filter(Asset.status == st)
    if criticality and criticality.strip():
        c = criticality.strip().lower()
        if c not in surf.CRITICALITIES:
            raise HTTPException(status_code=400, detail="Invalid criticality")
        q = q.filter(Asset.criticality == c)
    if owner and owner.strip():
        q = q.filter(Asset.owner_user_id == owner.strip())
    if changed_since and changed_since.strip():
        dt = _parse_dt(changed_since.strip(), "changed_since")
        q = q.filter(Asset.updated_at >= dt)
    if search and search.strip():
        lookup = search.strip()[:256].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        q = q.filter(Asset.value.ilike(f"%{lookup}%", escape="\\"))
    q = q.order_by(Asset.last_seen_at.desc(), Asset.created_at.desc())

    # Exposure / has_findings / risk_level need enrichment — filter in Python on page? No:
    # apply exposure filter via pre-filter on asset_type is insufficient; do full filtered fetch then
    # paginate in Python only when those filters are present (bounded by 2000 scan).
    needs_post = bool((exposure and exposure.strip()) or has_findings is not None or (risk_level and risk_level.strip()))
    if not needs_post:
        total = q.count()
        total_pages = (total + page_size - 1) // page_size if total else 0
        rows = q.offset((page - 1) * page_size).limit(page_size).all()
        enrich = _asset_enrichment(db, rows)
        return {
            "items": [_asset_payload(a, enrich) for a in rows],
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
        }

    # Post-filter path (bounded)
    candidates = q.limit(2000).all()
    enrich_all = _asset_enrichment(db, candidates)
    filtered = []
    exp_filter = exposure.strip().upper() if exposure and exposure.strip() else None
    if exp_filter and exp_filter not in surf.EXPOSURE_LEVELS:
        raise HTTPException(status_code=400, detail="Invalid exposure")
    for a in candidates:
        payload = _asset_payload(a, enrich_all)
        if exp_filter and payload["exposure"] != exp_filter:
            continue
        if has_findings is not None:
            if has_findings and payload["finding_count"] == 0:
                continue
            if not has_findings and payload["finding_count"] > 0:
                continue
        if risk_level and risk_level.strip():
            rl = risk_level.strip().lower()
            score = payload["max_score"] or 0
            level = "critical" if score >= 90 else "high" if score >= 75 else "medium" if score >= 50 else "low" if score > 0 else "info"
            if level != rl:
                continue
        filtered.append(payload)
    total = len(filtered)
    total_pages = (total + page_size - 1) // page_size if total else 0
    start = (page - 1) * page_size
    return {"items": filtered[start:start + page_size], "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}


# -------------------------------------------------------------------
# Changes
# -------------------------------------------------------------------

@router.get("/projects/{project_id}/attack-surface/changes")
def attack_surface_changes(
    project_id: str,
    change_type: str | None = Query(default=None, max_length=50),
    asset_type: str | None = Query(default=None, max_length=50),
    scanner: str | None = Query(default=None, max_length=50),
    start_time: str | None = Query(default=None),
    end_time: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    q = db.query(AssetChangeEvent).filter(AssetChangeEvent.project_id == project_id)
    if change_type and change_type.strip():
        q = q.filter(AssetChangeEvent.change_type == change_type.strip()[:50])
    if start_time and start_time.strip():
        q = q.filter(AssetChangeEvent.detected_at >= _parse_dt(start_time.strip(), "start_time"))
    if end_time and end_time.strip():
        q = q.filter(AssetChangeEvent.detected_at <= _parse_dt(end_time.strip(), "end_time"))
    q = q.order_by(AssetChangeEvent.detected_at.desc())
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    rows = q.offset((page - 1) * page_size).limit(page_size).all()

    # Join asset info in one query
    asset_ids = list({r.asset_id for r in rows})
    assets = {a.id: a for a in db.query(Asset).filter(Asset.id.in_(asset_ids)).all()} if asset_ids else {}
    if asset_type and asset_type.strip():
        at = asset_type.strip().lower()
        rows = [r for r in rows if assets.get(r.asset_id) and assets[r.asset_id].asset_type == at]
    if scanner and scanner.strip():
        sc = scanner.strip().lower()
        kept = []
        for r in rows:
            meta = r.extra_data if isinstance(r.extra_data, dict) else {}
            if str(meta.get("scanner", "")).lower() == sc or str(meta.get("source", "")).lower() == sc:
                kept.append(kept and r or r)
        rows = kept

    items = []
    for r in rows:
        a = assets.get(r.asset_id)
        meta = r.extra_data if isinstance(r.extra_data, dict) else {}
        items.append(
            {
                "id": r.id,
                "asset_id": r.asset_id,
                "asset_type": a.asset_type if a else None,
                "asset_value": a.value if a else None,
                "change_type": r.change_type,
                "old_value": r.previous_state,
                "new_value": r.current_state,
                "source": meta.get("source"),
                "scanner": meta.get("scanner"),
                "scan_id": r.scan_id,
                "detected_at": r.detected_at.isoformat() if r.detected_at else None,
                "metadata": surf.sanitize_change_metadata(meta),
            }
        )
    return {"items": items, "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}


# -------------------------------------------------------------------
# Relationships
# -------------------------------------------------------------------

@router.get("/projects/{project_id}/attack-surface/relationships")
def attack_surface_relationships(
    project_id: str,
    relationship_type: str | None = Query(default=None, max_length=50),
    source_asset: str | None = Query(default=None, max_length=36),
    target_asset: str | None = Query(default=None, max_length=36),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    q = db.query(AssetRelationship).filter(AssetRelationship.project_id == project_id)
    if relationship_type and relationship_type.strip():
        q = q.filter(AssetRelationship.relationship_type == relationship_type.strip()[:50])
    if source_asset and source_asset.strip():
        q = q.filter(AssetRelationship.source_asset_id == source_asset.strip())
    if target_asset and target_asset.strip():
        q = q.filter(AssetRelationship.target_asset_id == target_asset.strip())
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    rows = q.offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [
            {
                "id": r.id,
                "source_asset_id": r.source_asset_id,
                "target_asset_id": r.target_asset_id,
                "relationship_type": r.relationship_type,
                "project_id": r.project_id,
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
    }


# -------------------------------------------------------------------
# Graph
# -------------------------------------------------------------------

@router.get("/projects/{project_id}/attack-surface/graph")
def attack_surface_graph(
    project_id: str,
    asset_type: str | None = Query(default=None, max_length=50),
    exposure: str | None = Query(default=None, max_length=30),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _ensure_asset_columns(db)
    q = db.query(Asset).filter(Asset.project_id == project_id)
    if asset_type and asset_type.strip():
        q = q.filter(Asset.asset_type == asset_type.strip().lower())
    assets = q.order_by(Asset.last_seen_at.desc()).limit(GRAPH_NODE_LIMIT).all()
    enrich = _asset_enrichment(db, assets)
    nodes = []
    allowed_ids: set[str] = set()
    for a in assets:
        payload = _asset_payload(a, enrich)
        if exposure and exposure.strip() and payload["exposure"] != exposure.strip().upper():
            continue
        allowed_ids.add(a.id)
        nodes.append(
            {
                "id": a.id,
                "type": a.asset_type,
                "value": a.value[:256],
                "exposure": payload["exposure"],
                "criticality": payload["criticality"],
                "risk": payload["max_score"],
                "finding_count": payload["finding_count"],
            }
        )
        if len(nodes) >= GRAPH_NODE_LIMIT:
            break
    edges = []
    if allowed_ids:
        rels = (
            db.query(AssetRelationship)
            .filter(AssetRelationship.project_id == project_id)
            .limit(GRAPH_EDGE_LIMIT * 2)
            .all()
        )
        for r in rels:
            if r.source_asset_id in allowed_ids and r.target_asset_id in allowed_ids:
                edges.append(
                    {
                        "source": r.source_asset_id,
                        "target": r.target_asset_id,
                        "relationship_type": r.relationship_type,
                    }
                )
                if len(edges) >= GRAPH_EDGE_LIMIT:
                    break
    return {"nodes": nodes, "edges": edges, "truncated": len(nodes) >= GRAPH_NODE_LIMIT or len(edges) >= GRAPH_EDGE_LIMIT}


# -------------------------------------------------------------------
# Asset administration (criticality / owner)
# -------------------------------------------------------------------

@router.patch("/assets/{asset_id}")
def update_asset_admin(
    asset_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_asset_columns(db)
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    require_project_access(asset.project_id, db, current_user)
    # Manage permission: project_admin / org_admin / super_admin
    proj = db.query(Project).filter(Project.id == asset.project_id).first()
    if not _is_super_admin(current_user):
        org_role = _effective_org_role(current_user, proj.organization_id, db) if proj else None
        if org_role != "org_admin":
            from app.api.deps import _effective_project_role

            role = _effective_project_role(current_user, asset.project_id, db)
            if role != "project_admin":
                raise HTTPException(status_code=403, detail="Insufficient permissions")
    data = payload if isinstance(payload, dict) else {}
    changed_owner = False
    changed_crit = False
    old_owner = getattr(asset, "owner_user_id", None)
    old_crit = getattr(asset, "criticality", "unknown") or "unknown"
    if "criticality" in data and data["criticality"] is not None:
        c = str(data["criticality"]).strip().lower()
        if c not in surf.CRITICALITIES:
            raise HTTPException(status_code=400, detail="Invalid criticality")
        if c != old_crit:
            asset.criticality = c
            changed_crit = True
    if "owner_user_id" in data:
        if data["owner_user_id"] is None:
            if old_owner is not None:
                asset.owner_user_id = None
                changed_owner = True
        else:
            ouid = str(data["owner_user_id"]).strip()
            if not ouid:
                raise HTTPException(status_code=400, detail="Invalid owner_user_id")
            u = db.query(User).filter(User.id == ouid).first()
            if not u:
                raise HTTPException(status_code=404, detail="Owner not found")
            # Same org + active + project access
            if proj and u.organization_id != proj.organization_id:
                try:
                    from app.models.organization_membership import OrganizationMembership

                    m = (
                        db.query(OrganizationMembership)
                        .filter(
                            OrganizationMembership.user_id == u.id,
                            OrganizationMembership.organization_id == proj.organization_id,
                            OrganizationMembership.status == "active",
                        )
                        .first()
                    )
                    if not m:
                        raise HTTPException(status_code=403, detail="Owner is not in the asset organization")
                except HTTPException:
                    raise
                except Exception:
                    raise HTTPException(status_code=403, detail="Owner is not in the asset organization")
            if getattr(u, "status", "active") != "active":
                raise HTTPException(status_code=403, detail="Owner is not active")
            if ouid != old_owner:
                asset.owner_user_id = ouid
                changed_owner = True
    if not changed_owner and not changed_crit:
        return _asset_payload(asset, _asset_enrichment(db, [asset]))
    if changed_owner:
        AuditService.record(db, event_type=EVENT_ASSET_OWNER_CHANGED, action=EVENT_ASSET_OWNER_CHANGED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=proj.organization_id if proj else current_user.organization_id, project_id=asset.project_id, resource_type=RESOURCE_ASSET, resource_id=asset.id, metadata={"old_owner": old_owner, "new_owner": getattr(asset, "owner_user_id", None)})
    if changed_crit:
        AuditService.record(db, event_type=EVENT_ASSET_CRITICALITY_CHANGED, action=EVENT_ASSET_CRITICALITY_CHANGED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=proj.organization_id if proj else current_user.organization_id, project_id=asset.project_id, resource_type=RESOURCE_ASSET, resource_id=asset.id, metadata={"old_criticality": old_crit, "new_criticality": getattr(asset, "criticality", None)})
    db.commit()
    db.refresh(asset)
    return _asset_payload(asset, _asset_enrichment(db, [asset]))


# -------------------------------------------------------------------
# Monitoring configuration
# -------------------------------------------------------------------

def _monitoring_payload(cfg: MonitoringConfig, last_run=None) -> dict:
    return {
        "id": cfg.id,
        "organization_id": cfg.organization_id,
        "project_id": cfg.project_id,
        "target_id": cfg.target_id,
        "name": cfg.name,
        "enabled": bool(cfg.enabled),
        "frequency": cfg.frequency,
        "profile": cfg.profile,
        "target_scope": cfg.target_scope,
        "baseline_established": bool(cfg.baseline_established),
        "created_by": cfg.created_by,
        "created_at": cfg.created_at.isoformat() if cfg.created_at else None,
        "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
        "last_run": last_run,
        "last_run_at": cfg.last_run_at.isoformat() if cfg.last_run_at else None,
        "last_scan_id": cfg.last_scan_id,
        "last_status": cfg.last_status,
        "consecutive_failures": cfg.consecutive_failures,
        "next_run": cfg.next_run_at.isoformat() if cfg.next_run_at else None,
        "next_run_at": cfg.next_run_at.isoformat() if cfg.next_run_at else None,
        "paused_at": cfg.paused_at.isoformat() if cfg.paused_at else None,
        "pause_reason": cfg.pause_reason,
        "schedule": cfg.schedule,
    }


@router.get("/projects/{project_id}/monitoring")
def list_monitoring_configs(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    rows = db.query(MonitoringConfig).filter(MonitoringConfig.project_id == project_id).order_by(MonitoringConfig.created_at.desc()).all()
    items = []
    for c in rows:
        last = (
            db.query(MonitoringRun)
            .filter(MonitoringRun.monitoring_config_id == c.id)
            .order_by(MonitoringRun.created_at.desc())
            .first()
        )
        items.append(_monitoring_payload(c, {"id": last.id, "status": last.status, "created_at": last.created_at.isoformat() if last.created_at else None} if last else None))
    return {"items": items, "total": len(items)}


@router.post("/projects/{project_id}/monitoring", status_code=201)
def create_monitoring_config(
    project_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _require_monitor_manage(project_id, db, current_user)
    proj = db.query(Project).filter(Project.id == project_id).first()
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    data = payload if isinstance(payload, dict) else {}
    name = str(data.get("name", "")).strip()[:255]
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    frequency = str(data.get("frequency", "daily")).strip().lower()
    if frequency not in MONITOR_FREQUENCIES:
        raise HTTPException(status_code=400, detail="Invalid frequency. Use hourly, six_hourly, daily, or weekly.")
    profile = str(data.get("profile", "quick")).strip().lower()
    if profile not in MONITOR_PROFILES:
        raise HTTPException(status_code=400, detail="Invalid profile. Use quick, web, or full.")
    scope = str(data.get("target_scope", "all")).strip().lower()
    if scope not in MONITOR_SCOPES:
        raise HTTPException(status_code=400, detail="Invalid target_scope")

    # D1: optional single-target scope. Must belong to this project.
    target_id = data.get("target_id") or None
    if target_id:
        target_id = str(target_id).strip()[:36]
        if not target_id:
            target_id = None
    if target_id:
        t = db.query(Target).filter(Target.id == target_id, Target.project_id == project_id).first()
        if not t:
            raise HTTPException(status_code=404, detail="Target not found in this project")

    now = _utcnow().replace(tzinfo=None)
    schedule_kind = str(data.get("schedule", "")).strip()[:50] or None
    cfg = MonitoringConfig(
        id=str(uuid.uuid4()),
        organization_id=proj.organization_id,
        project_id=project_id,
        target_id=target_id,
        name=name,
        enabled=bool(data.get("enabled", True)),
        frequency=frequency,
        profile=profile,
        target_scope=scope,
        created_by=current_user.id,
        baseline_established=False,
        next_run_at=(now + timedelta(seconds=frequency_interval_seconds(frequency))) if bool(data.get("enabled", True)) else None,
        schedule=schedule_kind,
    )
    db.add(cfg)
    AuditService.record(db, event_type=EVENT_MONITORING_CONFIG_CREATED, action=EVENT_MONITORING_CONFIG_CREATED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=proj.organization_id, project_id=project_id, resource_type=RESOURCE_MONITORING_CONFIG, resource_id=cfg.id, metadata={"name": name, "frequency": frequency, "profile": profile, "target_scope": scope, "target_id": target_id})
    db.commit()
    db.refresh(cfg)
    return _monitoring_payload(cfg)


@router.patch("/monitoring/{config_id}")
def update_monitoring_config(
    config_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cfg = db.query(MonitoringConfig).filter(MonitoringConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Monitoring config not found")
    require_project_access(cfg.project_id, db, current_user)
    _require_monitor_manage(cfg.project_id, db, current_user)
    data = payload if isinstance(payload, dict) else {}
    schedule_changed = False
    now = _utcnow().replace(tzinfo=None)
    if "name" in data and data["name"] is not None:
        name = str(data["name"]).strip()[:255]
        if not name:
            raise HTTPException(status_code=400, detail="Invalid name")
        cfg.name = name
    if "frequency" in data and data["frequency"] is not None:
        f = str(data["frequency"]).strip().lower()
        if f not in MONITOR_FREQUENCIES:
            raise HTTPException(status_code=400, detail="Invalid frequency")
        if f != cfg.frequency:
            cfg.frequency = f
            schedule_changed = True
    if "profile" in data and data["profile"] is not None:
        p = str(data["profile"]).strip().lower()
        if p not in MONITOR_PROFILES:
            raise HTTPException(status_code=400, detail="Invalid profile")
        cfg.profile = p
    if "target_scope" in data and data["target_scope"] is not None:
        s = str(data["target_scope"]).strip().lower()
        if s not in MONITOR_SCOPES:
            raise HTTPException(status_code=400, detail="Invalid target_scope")
        cfg.target_scope = s
    if "target_id" in data:
        tid = data["target_id"] or None
        if tid:
            tid = str(tid).strip()[:36]
            exists = db.query(Target).filter(Target.id == tid, Target.project_id == cfg.project_id).first()
            if not exists:
                raise HTTPException(status_code=404, detail="Target not found in this project")
        if tid != cfg.target_id:
            cfg.target_id = tid
            schedule_changed = True
    if "enabled" in data and data["enabled"] is not None:
        was = bool(cfg.enabled)
        cfg.enabled = bool(data["enabled"])
        if was != cfg.enabled:
            schedule_changed = True
    if "schedule" in data:
        cfg.schedule = str(data.get("schedule") or "").strip()[:50] or None
    # Keep next_run deterministic: updated immediately when scheduling changed.
    if schedule_changed:
        cfg.next_run_at = compute_next_run(cfg.next_run_at, cfg.frequency, now) if cfg.enabled else None
    AuditService.record(db, event_type=EVENT_MONITORING_CONFIG_UPDATED, action=EVENT_MONITORING_CONFIG_UPDATED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=cfg.project_id, resource_type=RESOURCE_MONITORING_CONFIG, resource_id=cfg.id, metadata={"config_id": cfg.id, "schedule_changed": schedule_changed})
    db.commit()
    db.refresh(cfg)
    return _monitoring_payload(cfg)


@router.delete("/monitoring/{config_id}", status_code=204)
def delete_monitoring_config(
    config_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cfg = db.query(MonitoringConfig).filter(MonitoringConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Monitoring config not found")
    require_project_access(cfg.project_id, db, current_user)
    _require_monitor_manage(cfg.project_id, db, current_user)
    AuditService.record(db, event_type=EVENT_MONITORING_CONFIG_DELETED, action=EVENT_MONITORING_CONFIG_DELETED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=cfg.project_id, resource_type=RESOURCE_MONITORING_CONFIG, resource_id=cfg.id, metadata={"config_id": cfg.id})
    db.delete(cfg)
    db.commit()
    return None


@router.post("/monitoring/{config_id}/pause", status_code=200)
def pause_monitoring_config(
    config_id: str,
    payload: dict | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cfg = db.query(MonitoringConfig).filter(MonitoringConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Monitoring config not found")
    require_project_access(cfg.project_id, db, current_user)
    _require_monitor_manage(cfg.project_id, db, current_user)
    if cfg.paused_at is not None:
        return _monitoring_payload(cfg)
    data = payload if isinstance(payload, dict) else {}
    reason = str(data.get("reason", "") or "").strip()[:500]
    cfg.paused_at = _utcnow().replace(tzinfo=None)
    cfg.pause_reason = reason or None
    cfg.next_run_at = None
    AuditService.record(db, event_type=EVENT_MONITORING_CONFIG_PAUSED, action=EVENT_MONITORING_CONFIG_PAUSED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=cfg.project_id, resource_type=RESOURCE_MONITORING_CONFIG, resource_id=cfg.id, metadata={"config_id": cfg.id, "reason": cfg.pause_reason})
    db.commit()
    db.refresh(cfg)
    return _monitoring_payload(cfg)


@router.post("/monitoring/{config_id}/resume", status_code=200)
def resume_monitoring_config(
    config_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cfg = db.query(MonitoringConfig).filter(MonitoringConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Monitoring config not found")
    require_project_access(cfg.project_id, db, current_user)
    _require_monitor_manage(cfg.project_id, db, current_user)
    if not cfg.enabled:
        raise HTTPException(status_code=409, detail="Monitor is disabled; enable it before resuming")
    if cfg.paused_at is None:
        return _monitoring_payload(cfg)
    now = _utcnow().replace(tzinfo=None)
    cfg.paused_at = None
    cfg.pause_reason = None
    cfg.next_run_at = compute_next_run(None, cfg.frequency, now)
    AuditService.record(db, event_type=EVENT_MONITORING_CONFIG_RESUMED, action=EVENT_MONITORING_CONFIG_RESUMED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=cfg.project_id, resource_type=RESOURCE_MONITORING_CONFIG, resource_id=cfg.id, metadata={"config_id": cfg.id})
    db.commit()
    db.refresh(cfg)
    return _monitoring_payload(cfg)


@router.get("/monitoring/{config_id}/runs")
def list_monitoring_runs_for_config(
    config_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cfg = db.query(MonitoringConfig).filter(MonitoringConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Monitoring config not found")
    require_project_access(cfg.project_id, db, current_user)
    q = db.query(MonitoringRun).filter(MonitoringRun.monitoring_config_id == cfg.id).order_by(MonitoringRun.created_at.desc())
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    rows = q.offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [_run_payload(r) for r in rows], "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}


@router.get("/monitoring/{config_id}/runs/{run_id}")
def get_monitoring_run(
    config_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cfg = db.query(MonitoringConfig).filter(MonitoringConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Monitoring config not found")
    require_project_access(cfg.project_id, db, current_user)
    run = db.query(MonitoringRun).filter(MonitoringRun.id == run_id, MonitoringRun.monitoring_config_id == cfg.id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Monitoring run not found")
    return _run_payload(run)


# -------------------------------------------------------------------
# Monitoring runs
# -------------------------------------------------------------------

def _run_payload(run: MonitoringRun) -> dict:
    return {
        "id": run.id,
        "monitoring_config_id": run.monitoring_config_id,
        "organization_id": run.organization_id,
        "project_id": run.project_id,
        "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "error": run.error,
        "assets_discovered": run.assets_discovered,
        "assets_changed": run.assets_changed,
        "assets_stale": run.assets_stale,
        "findings_created": run.findings_created,
        "scan_ids": run.scan_ids or [],
        "scanner_count": run.scanner_count,
        "successful_scanners": run.successful_scanners,
        "failed_scanners": run.failed_scanners,
        "correlation_id": run.correlation_id,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


@router.get("/projects/{project_id}/monitoring/runs")
def list_monitoring_runs(
    project_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    q = db.query(MonitoringRun).filter(MonitoringRun.project_id == project_id).order_by(MonitoringRun.created_at.desc())
    total = q.count()
    total_pages = (total + page_size - 1) // page_size if total else 0
    rows = q.offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [_run_payload(r) for r in rows], "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}


@router.post("/monitoring/{config_id}/run", status_code=201)
def start_monitoring_run(
    config_id: str,
    payload: dict | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    cfg = db.query(MonitoringConfig).filter(MonitoringConfig.id == config_id).first()
    if not cfg:
        raise HTTPException(status_code=404, detail="Monitoring config not found")
    require_project_access(cfg.project_id, db, current_user)
    _require_monitor_run(cfg.project_id, db, current_user)

    # Duplicate concurrent run protection
    active = (
        db.query(MonitoringRun)
        .filter(MonitoringRun.monitoring_config_id == cfg.id, MonitoringRun.status.in_(list(MONITOR_RUN_ACTIVE)))
        .first()
    )
    if active:
        raise HTTPException(status_code=409, detail="A monitoring run is already in progress")

    # Resolve scope: single target (target_id) OR all active project targets (bounded).
    targets = None
    if cfg.target_id:
        targets = (
            db.query(Target)
            .filter(Target.id == cfg.target_id, Target.project_id == cfg.project_id, Target.is_active.is_(True))
            .limit(1)
            .all()
        )
    else:
        targets = (
            db.query(Target)
            .filter(Target.project_id == cfg.project_id, Target.is_active.is_(True))
            .limit(20)
            .all()
        )

    run = MonitoringRun(
        id=str(uuid.uuid4()),
        monitoring_config_id=cfg.id,
        organization_id=cfg.organization_id,
        project_id=cfg.project_id,
        status="running",
        started_at=_utcnow().replace(tzinfo=None),
        correlation_id=f"mr:{str(uuid.uuid4())[:8]}",
    )
    db.add(run)
    db.flush()
    AuditService.record(db, event_type=EVENT_MONITORING_RUN_STARTED, action=EVENT_MONITORING_RUN_STARTED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=cfg.project_id, resource_type=RESOURCE_MONITORING_RUN, resource_id=run.id, metadata={"config_id": cfg.id, "profile": cfg.profile, "targets": len(targets)})

    # Reuse existing scan execution infrastructure: create one Scan per target.
    # Dispatch happens AFTER commit (same pattern as scans.py) so a Celery
    # worker can never observe an uncommitted Scan row.
    scan_ids = []
    pending_dispatch: list = []
    expected_scanners = len(scanners_for_profile(cfg.profile))
    for t in targets:
        scan = Scan(
            id=str(uuid.uuid4()),
            target_id=t.id,
            profile=cfg.profile,
            status="queued",
            scan_metadata={
                "monitoring_run_id": run.id,
                "trigger": "manual",
                "scheduled": False,
            },
        )
        db.add(scan)
        db.flush()
        scan_ids.append(scan.id)
        pending_dispatch.append((scan.id, t.id, t.value))
    run.scan_ids = scan_ids
    run.scanner_count = expected_scanners if targets else 0

    # Change-detection pass over persisted assets (baseline-aware, no fake events).
    # Counting queries run in a savepoint: their failure must mark the run
    # failed WITHOUT discarding the run, scans, or audit records accumulated
    # above in this transaction (a full rollback would lose them and the final
    # refresh would raise).
    now = _utcnow().replace(tzinfo=None)
    change_error: str | None = None
    try:
        with db.begin_nested():
            if not cfg.baseline_established:
                discovered = 0
                changed = 0
                stale = 0
            else:
                last_run = (
                    db.query(MonitoringRun)
                    .filter(MonitoringRun.monitoring_config_id == cfg.id, MonitoringRun.status == "completed")
                    .order_by(MonitoringRun.created_at.desc())
                    .first()
                )
                cutoff = last_run.created_at if last_run and last_run.created_at else (now - timedelta(days=1))
                discovered = (
                    db.query(func.count(Asset.id))
                    .filter(Asset.project_id == cfg.project_id, Asset.first_seen_at >= cutoff)
                    .scalar()
                    or 0
                )
                changed = (
                    db.query(func.count(AssetChangeEvent.id))
                    .filter(AssetChangeEvent.project_id == cfg.project_id, AssetChangeEvent.detected_at >= cutoff)
                    .scalar()
                    or 0
                )
                stale = (
                    db.query(func.count(Asset.id))
                    .filter(Asset.project_id == cfg.project_id, Asset.status == "stale")
                    .scalar()
                    or 0
                )
    except Exception as exc:
        change_error = str(exc)[:500]
        discovered = 0
        changed = 0
        stale = 0
    if not cfg.baseline_established:
        cfg.baseline_established = True
    run.assets_discovered = int(discovered or 0)
    run.assets_changed = int(changed or 0)
    run.assets_stale = int(stale or 0)
    run.findings_created = 0
    if change_error is not None:
        run.status = "failed"
        run.error = change_error
        run.completed_at = now
        AuditService.record(db, event_type=EVENT_MONITORING_RUN_FAILED, action=EVENT_MONITORING_RUN_FAILED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=cfg.project_id, resource_type=RESOURCE_MONITORING_RUN, resource_id=run.id, metadata={"config_id": cfg.id, "error": change_error[:200]})
    elif not targets:
        run.status = "failed"
        run.error = "No targets in scope"
        run.completed_at = now
        AuditService.record(db, event_type=EVENT_MONITORING_RUN_FAILED, action=EVENT_MONITORING_RUN_FAILED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=cfg.project_id, resource_type=RESOURCE_MONITORING_RUN, resource_id=run.id, metadata={"config_id": cfg.id, "error": "empty scope"})
    else:
        run.status = "completed"
        run.completed_at = now
        AuditService.record(db, event_type=EVENT_MONITORING_RUN_COMPLETED, action=EVENT_MONITORING_RUN_COMPLETED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=cfg.project_id, resource_type=RESOURCE_MONITORING_RUN, resource_id=run.id, metadata={"config_id": cfg.id, "targets": len(targets)})
    # Subsequent scheduling state.
    if cfg.enabled and cfg.paused_at is None:
        cfg.next_run_at = compute_next_run(cfg.next_run_at, cfg.frequency, now)
    cfg.last_run_at = run.started_at or now
    cfg.last_scan_id = scan_ids[-1] if scan_ids else None
    cfg.last_status = run.status
    if run.status == "completed":
        cfg.consecutive_failures = 0
    elif run.status == "failed":
        cfg.consecutive_failures = (cfg.consecutive_failures or 0) + 1
    db.commit()
    db.refresh(run)

    # Post-commit dispatch: workers always observe committed rows. Pending scans
    # are dispatched even when the run itself already failed (e.g.
    # change-observation error) so security coverage is not lost; the run
    # stays failed and finalize ignores terminal runs.
    dispatch_errors = 0
    if pending_dispatch:
        from app.core.celery import celery_app as _celery_app

        for _scan_id, _target_id, _target_value in pending_dispatch:
            try:
                _celery_app.send_task("app.tasks.execute_scan", args=[_scan_id, _target_id, _target_value, cfg.profile])
            except Exception:
                dispatch_errors += 1
    if dispatch_errors and run.status == "completed":
        # Canonical "partial" vocabulary (same terminal status the scheduler
        # finalize path persists): some scans were created but not all
        # dispatches reached the broker.
        try:
            run.error = f"{dispatch_errors} scan dispatch(es) failed"
            run.status = "partial"
            AuditService.record(db, event_type=EVENT_MONITORING_RUN_PARTIAL, action=EVENT_MONITORING_RUN_PARTIAL, result=RESULT_PARTIAL, actor_user_id=current_user.id, organization_id=cfg.organization_id, project_id=cfg.project_id, resource_type=RESOURCE_MONITORING_RUN, resource_id=run.id, metadata={"config_id": cfg.id, "targets": len(targets)})
            cfg.last_status = run.status
            cfg.consecutive_failures = (cfg.consecutive_failures or 0) + 1
            db.commit()
            db.refresh(run)
        except Exception:
            db.rollback()
    return _run_payload(run)

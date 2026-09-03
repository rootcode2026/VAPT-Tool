from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.asset import Asset
from app.models.asset_change_event import AssetChangeEvent
from app.models.asset_relationship import AssetRelationship
from app.models.finding import Finding
from app.schemas.asset import (
    AssetClassifications,
    AssetDetailResponse,
    AssetNeighborResponse,
    AssetResponse,
    AssetSecuritySignals,
    AssetSecuritySummary,
    AttackPathsResponse,
    ContextualRisk,
    ProjectSecurityIntelligenceSummary,
    ProjectSecuritySummary,
)
from app.schemas.finding import FindingResponse
from app.services.asset_attack_paths import get_attack_paths_for_project
from app.services.asset_classification import classify_assets_batch
from app.services.asset_security_signals import (
    aggregate_security_signals_for_assets,
    get_project_security_summary,
)
from app.services.asset_contextual_risk import (
    aggregate_contextual_risk_for_assets,
    contextual_risk_from_signals,
)
from app.services.project_security_intelligence import (
    get_project_security_intelligence_summary,
)


router = APIRouter(
    prefix="/api/v1/assets",
    tags=["Assets"],
)


@router.get(
    "",
    response_model=list[AssetResponse],
)
def get_assets(
    project: str | None = None,
    project_id: str | None = None,
    asset_type: str | None = None,
    search: str | None = None,
    value: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = db.query(Asset)
    selected_project = project or project_id

    if selected_project:
        query = query.filter(Asset.project_id == selected_project)

    if asset_type:
        query = query.filter(Asset.asset_type == asset_type.strip().lower())

    lookup = (search or value or "").strip()[:256]
    if lookup:
        escaped = (
            lookup.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        query = query.filter(Asset.value.ilike(f"%{escaped}%", escape="\\"))

    return (
        query
        .order_by(Asset.last_seen_at.desc(), Asset.created_at.desc())
        .limit(limit)
        .all()
    )


@router.get(
    "/summary",
    response_model=ProjectSecurityIntelligenceSummary,
)
def get_assets_summary(
    project_id: str | None = Query(default=None),
    project: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    # Extended D6.2 intelligence summary — additive, preserves old fields
    pid = project_id or project
    if pid:
        return get_project_security_intelligence_summary(db, pid)
    # No project: aggregate across all assets via intelligence summary helper
    # Fallback: compute across all projects (still project-scoped per asset)
    # Reuse same helper by iterating distinct project_ids
    # For simplicity, if no pid, return empty summary (avoid cross-project aggregation)
    # Alternatively compute across all assets
    assets = db.query(Asset).all()
    if not assets:
        return ProjectSecurityIntelligenceSummary()
    # Use same intelligence logic across all assets (grouped)
    # For cross-project, we call intelligence per distinct project and aggregate
    # But simpler: just return aggregated via all assets
    # We can call get_project_security_intelligence_summary for each distinct pid and sum? For now return first pid or aggregate via all
    # To keep efficient, aggregate via signals across all
    signals = aggregate_security_signals_for_assets(db, assets)
    total_assets = len(assets)
    stale_assets = sum(1 for a in assets if a.status == "stale")
    inactive_assets = sum(1 for a in assets if a.status == "inactive")
    internet_facing_assets = sum(1 for s in signals.values() if s["exposure_signal"]["internet_facing"])
    web_applications = sum(1 for s in signals.values() if s["exposure_signal"]["web_application"])
    exposed_services = sum(1 for s in signals.values() if s["exposure_signal"]["exposed_service"])
    vulnerable_assets = sum(1 for s in signals.values() if s["posture"]["vulnerable"])
    critical_assets = sum(1 for s in signals.values() if s["finding_signal"]["critical"] > 0)
    sensitive_assets = sum(1 for s in signals.values() if s["sensitivity_signal"]["potentially_sensitive"])
    recently_changed_assets = sum(1 for s in signals.values() if s["change_signal"]["recently_changed"])
    return ProjectSecurityIntelligenceSummary(
        total_assets=total_assets,
        internet_facing_assets=internet_facing_assets,
        externally_resolvable_assets=sum(1 for v in signals.values() if False),  # fallback
        web_application_assets=web_applications,
        exposed_service_assets=exposed_services,
        vulnerable_assets=vulnerable_assets,
        critical_assets=critical_assets,
        high_assets=sum(1 for v in signals.values() if v["finding_signal"]["high"] > 0),
        medium_assets=sum(1 for v in signals.values() if v["finding_signal"]["medium"] > 0),
        low_assets=sum(1 for v in signals.values() if v["finding_signal"]["low"] > 0),
        technology_bearing_assets=0,
        sensitive_assets=sensitive_assets,
        recently_changed_assets=recently_changed_assets,
        stale_assets=stale_assets,
        inactive_assets=inactive_assets,
        critical_exposure_assets=sum(1 for v in signals.values() if v["posture"]["critical_exposure"]),
        exposed_vulnerable_assets=sum(1 for v in signals.values() if v["posture"]["exposed_vulnerable"]),
        sensitive_exposed_assets=sum(1 for v in signals.values() if v["posture"]["sensitive_exposed"]),
        changed_vulnerable_assets=sum(1 for v in signals.values() if v["posture"]["changed_and_vulnerable"]),
        attack_path_count=0,
        attack_paths_truncated=False,
        highest_contextual_priority=None,
        web_applications=web_applications,
        exposed_services=exposed_services,
    )


@router.get(
    "/security-intelligence-summary",
    response_model=ProjectSecurityIntelligenceSummary,
)
def get_security_intelligence_summary(
    project_id: str = Query(..., description="Project ID"),
    db: Session = Depends(get_db),
):
    # Clearly named sibling endpoint per D6.2 — preserves /summary
    return get_project_security_intelligence_summary(db, project_id)


@router.get(
    "/attack-paths",
    response_model=AttackPathsResponse,
)
def get_attack_paths(
    project_id: str = Query(..., description="Project ID for attack path analysis"),
    asset_id: str | None = Query(default=None, description="Optional asset filter"),
    max_depth: int = Query(default=5, ge=1, le=10, description="Maximum path depth (edges)"),
    max_paths: int = Query(default=100, ge=1, le=500, description="Maximum paths to return"),
    db: Session = Depends(get_db),
):
    # Project-scoped deterministic attack path foundation
    result = get_attack_paths_for_project(
        db, project_id, max_depth=max_depth, max_paths=max_paths, asset_id=asset_id
    )
    return result


@router.get(
    "/{asset_id}",
    response_model=AssetDetailResponse,
)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    neighbors = _load_neighbors(db, asset)
    findings = (
        db.query(Finding)
        .filter(Finding.asset_id == asset.id)
        .order_by(Finding.created_at.desc())
        .all()
    )
    security_summary = _get_asset_security_summary(db, asset)
    # D2 classifications — bounded batch for single asset (reuses batch engine)
    classifications_dict = classify_assets_batch(db, [asset])
    classifications = AssetClassifications(**classifications_dict.get(asset.id, {}))
    # D3 security signals — batch aggregation (reuses D2, no N+1)
    signals_dict = aggregate_security_signals_for_assets(db, [asset])
    sig = signals_dict.get(asset.id, {})
    security_signals = AssetSecuritySignals(**sig)
    # D4 contextual risk — consumes D3 signals in-memory (no extra DB query)
    contextual_raw = contextual_risk_from_signals(sig, asset) if sig else {"priority": "informational", "risk_factors": [], "explanation": "No significant contextual risk signals.", "context": {}}
    contextual_risk = ContextualRisk(
        priority=contextual_raw.get("priority", "informational"),
        risk_factors=contextual_raw.get("risk_factors", []),
        explanation=contextual_raw.get("explanation", "No significant contextual risk signals."),
        context=contextual_raw.get("context", {}),
    )

    payload = AssetDetailResponse.model_validate(asset)
    return payload.model_copy(
        update={
            "relationships": neighbors,
            "findings": [
                FindingResponse.model_validate(item).model_dump()
                for item in findings
            ],
            "security_summary": security_summary,
            "classifications": classifications,
            "security_signals": security_signals,
            "contextual_risk": contextual_risk,
        }
    )


def _get_asset_security_summary(db: Session, asset: Asset) -> AssetSecuritySummary:
    # Bounded aggregate queries — no loading of all findings into Python
    counts = dict(
        db.query(Finding.severity, func.count(Finding.id))
        .filter(Finding.asset_id == asset.id)
        .group_by(Finding.severity)
        .all()
    )
    total_findings = sum(counts.values()) if counts else 0
    critical = int(counts.get("critical", 0))
    high = int(counts.get("high", 0))
    medium = int(counts.get("medium", 0))
    low = int(counts.get("low", 0))
    info = int(counts.get("info", 0))

    # Determine highest severity by rank
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    highest_severity = None
    best_rank = -1
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev, 0) > 0 and rank[sev] > best_rank:
            best_rank = rank[sev]
            highest_severity = sev

    highest_score = db.query(func.max(Finding.score)).filter(Finding.asset_id == asset.id).scalar()
    has_findings = total_findings > 0
    has_critical = critical > 0
    has_high = high > 0

    # externally_exposed: true if asset has an "exposes" relationship or is an externally reachable type with findings
    externally_exposed = False
    try:
        exposed = (
            db.query(AssetRelationship.id)
            .filter(
                AssetRelationship.project_id == asset.project_id,
                (AssetRelationship.source_asset_id == asset.id) | (AssetRelationship.target_asset_id == asset.id),
                AssetRelationship.relationship_type == "exposes",
            )
            .first()
        )
        if exposed is not None:
            externally_exposed = True
        elif asset.asset_type in {"ip", "ipv6", "domain", "url", "subdomain", "hostname", "web_site", "web_host"} and has_findings:
            # Consider internet-reachable assets with findings as externally exposed
            externally_exposed = True
    except Exception:
        externally_exposed = False

    # recently_changed: true if last_seen / updated within 7 days or recent change event
    recently_changed = False
    try:
        now = datetime.now(timezone.utc)
        window = now - timedelta(days=7)
        # normalize asset timestamps to UTC aware
        for ts in (asset.last_seen_at, asset.updated_at, asset.created_at):
            if ts is None:
                continue
            aware = ts
            if aware.tzinfo is None:
                aware = aware.replace(tzinfo=timezone.utc)
            if aware >= window:
                recently_changed = True
                break
        if not recently_changed:
            recent_event = (
                db.query(AssetChangeEvent.id)
                .filter(
                    AssetChangeEvent.asset_id == asset.id,
                    AssetChangeEvent.project_id == asset.project_id,
                    AssetChangeEvent.detected_at >= window,
                )
                .first()
            )
            if recent_event is not None:
                recently_changed = True
    except Exception:
        recently_changed = False

    return AssetSecuritySummary(
        total_findings=total_findings,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        info=info,
        highest_severity=highest_severity,
        highest_score=highest_score,
        has_findings=has_findings,
        has_critical=has_critical,
        has_high=has_high,
        externally_exposed=externally_exposed,
        recently_changed=recently_changed,
    )


def _load_neighbors(db: Session, asset: Asset) -> list[AssetNeighborResponse]:
    outgoing = (
        db.query(AssetRelationship, Asset)
        .join(Asset, Asset.id == AssetRelationship.target_asset_id)
        .filter(
            AssetRelationship.source_asset_id == asset.id,
            AssetRelationship.project_id == asset.project_id,
            Asset.project_id == asset.project_id,
        )
        .all()
    )
    incoming = (
        db.query(AssetRelationship, Asset)
        .join(Asset, Asset.id == AssetRelationship.source_asset_id)
        .filter(
            AssetRelationship.target_asset_id == asset.id,
            AssetRelationship.project_id == asset.project_id,
            Asset.project_id == asset.project_id,
        )
        .all()
    )

    neighbors = []
    current = AssetResponse.model_validate(asset)
    for relationship, related in outgoing:
        neighbor = AssetResponse.model_validate(related)
        neighbors.append(
            AssetNeighborResponse(
                direction="outgoing",
                relationship_type=relationship.relationship_type,
                relationship_id=relationship.id,
                asset=neighbor,
                metadata=relationship.extra_data or {},
                source_asset_id=asset.id,
                target_asset_id=related.id,
                source_asset=current,
                target_asset=neighbor,
                created_at=relationship.created_at,
                updated_at=relationship.updated_at,
            )
        )
    for relationship, related in incoming:
        neighbor = AssetResponse.model_validate(related)
        neighbors.append(
            AssetNeighborResponse(
                direction="incoming",
                relationship_type=relationship.relationship_type,
                relationship_id=relationship.id,
                asset=neighbor,
                metadata=relationship.extra_data or {},
                source_asset_id=related.id,
                target_asset_id=asset.id,
                source_asset=neighbor,
                target_asset=current,
                created_at=relationship.created_at,
                updated_at=relationship.updated_at,
            )
        )
    return neighbors

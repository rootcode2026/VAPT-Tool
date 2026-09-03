"""
D3 — Security Signal Aggregation.

Reusable, deterministic, project-scoped, database-efficient.
Reuses D2 classification as source of truth for exposure/tech/sensitivity.
Aggregates finding, technology, change, lifecycle signals via grouped queries.
"""

from __future__ import annotations

from datetime import timedelta, timezone, datetime
from collections import defaultdict

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_change_event import AssetChangeEvent
from app.models.asset_relationship import AssetRelationship
from app.models.finding import Finding
from app.services.asset_classification import classify_assets_batch

RECENT_DAYS = 7


def _get_recent_window() -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)


def _highest_severity(counts: dict[str, int]) -> str | None:
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    best = None
    best_rank = -1
    for sev in ("critical", "high", "medium", "low", "info"):
        if counts.get(sev, 0) > 0 and rank[sev] > best_rank:
            best_rank = rank[sev]
            best = sev
    return best


def aggregate_security_signals_for_assets(
    db: Session, assets: list[Asset]
) -> dict[str, dict]:
    """
    Batch aggregation for N assets (same or mixed projects, but project-scoped queries).
    Returns dict asset_id -> security_signals dict with
    finding_signal, exposure_signal, technology_signal, change_signal,
    sensitivity_signal, lifecycle_signal, posture

    Uses fixed number of grouped queries (no N+1).
    """
    if not assets:
        return {}

    # Group by project for isolation
    by_project: dict[str, list[Asset]] = {}
    for a in assets:
        by_project.setdefault(a.project_id, []).append(a)

    # Reuse D2 classification for exposure/tech/sensitivity/recent/vulnerable
    classifications = classify_assets_batch(db, assets)

    result: dict[str, dict] = {}

    for project_id, proj_assets in by_project.items():
        asset_ids = [a.id for a in proj_assets]
        asset_map = {a.id: a for a in proj_assets}

        # ---- Finding aggregation grouped by asset_id, severity ----
        sev_rows = (
            db.query(Finding.asset_id, Finding.severity, func.count(Finding.id))
            .filter(Finding.asset_id.in_(asset_ids))
            .group_by(Finding.asset_id, Finding.severity)
            .all()
        )
        # Build per-asset severity counts
        sev_by_asset: dict[str, dict[str, int]] = defaultdict(dict)
        total_by_asset: dict[str, int] = defaultdict(int)
        for aid, sev, cnt in sev_rows:
            sev_by_asset[aid][sev] = cnt
            total_by_asset[aid] += cnt

        # Highest score per asset
        max_score_rows = (
            db.query(Finding.asset_id, func.max(Finding.score))
            .filter(Finding.asset_id.in_(asset_ids))
            .group_by(Finding.asset_id)
            .all()
        )
        max_score_by_asset = {aid: score for aid, score in max_score_rows}

        # ---- Technology count: distinct technology assets via serves/uses ----
        tech_rows = (
            db.query(
                AssetRelationship.source_asset_id,
                func.count(func.distinct(AssetRelationship.target_asset_id)),
            )
            .join(Asset, Asset.id == AssetRelationship.target_asset_id)
            .filter(
                AssetRelationship.project_id == project_id,
                AssetRelationship.source_asset_id.in_(asset_ids),
                AssetRelationship.relationship_type.in_(("serves", "uses")),
                Asset.asset_type == "technology",
                Asset.project_id == project_id,  # ensure target also same project (defensive)
            )
            .group_by(AssetRelationship.source_asset_id)
            .all()
        )
        tech_count_by_asset: dict[str, int] = {aid: 0 for aid in asset_ids}
        for aid, cnt in tech_rows:
            tech_count_by_asset[aid] = cnt

        # ---- Change recent count ----
        window = _get_recent_window()
        change_rows = (
            db.query(AssetChangeEvent.asset_id, func.count(AssetChangeEvent.id))
            .filter(
                AssetChangeEvent.project_id == project_id,
                AssetChangeEvent.asset_id.in_(asset_ids),
                AssetChangeEvent.detected_at >= window,
            )
            .group_by(AssetChangeEvent.asset_id)
            .all()
        )
        change_count_by_asset: dict[str, int] = {aid: 0 for aid in asset_ids}
        for aid, cnt in change_rows:
            change_count_by_asset[aid] = cnt

        # Build per-asset signals
        for aid, asset in asset_map.items():
            cls = classifications.get(aid, {})
            sev_counts = sev_by_asset.get(aid, {})
            total = total_by_asset.get(aid, 0)
            critical = sev_counts.get("critical", 0)
            high = sev_counts.get("high", 0)
            medium = sev_counts.get("medium", 0)
            low = sev_counts.get("low", 0)
            info = sev_counts.get("info", 0)
            highest_severity = _highest_severity(sev_counts)
            highest_score = max_score_by_asset.get(aid)

            # Exposure reuse D2
            internet_facing = cls.get("internet_facing", False)
            externally_resolvable = cls.get("externally_resolvable", False)
            web_application = cls.get("web_application", False)
            exposed_service = cls.get("exposed_service", False)

            technology_bearing = cls.get("technology_bearing", False)
            technology_count = tech_count_by_asset.get(aid, 0)
            # Ensure consistency: if count>0 then bearing true
            if technology_count > 0 and not technology_bearing:
                technology_bearing = True

            recently_changed = cls.get("recently_changed", False)
            recent_change_count = change_count_by_asset.get(aid, 0)
            # If recent count >0, recently_changed should be true (defensive)
            if recent_change_count > 0 and not recently_changed:
                recently_changed = True

            potentially_sensitive = cls.get("potentially_sensitive", False)
            vulnerable = cls.get("vulnerable", False)
            # Alternatively vulnerable from total>0 (should match)
            if total > 0 and not vulnerable:
                vulnerable = True

            status = asset.status or "active"

            # Posture flags (descriptive, not risk scores)
            critical_exposure = vulnerable and critical > 0 and internet_facing
            exposed_vulnerable = vulnerable and internet_facing
            sensitive_exposed = potentially_sensitive and internet_facing
            changed_and_vulnerable = vulnerable and recently_changed

            finding_signal = {
                "total": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
                "highest_severity": highest_severity,
                "highest_score": highest_score,
            }
            exposure_signal = {
                "internet_facing": internet_facing,
                "externally_resolvable": externally_resolvable,
                "web_application": web_application,
                "exposed_service": exposed_service,
            }
            technology_signal = {
                "technology_bearing": technology_bearing,
                "technology_count": technology_count,
            }
            change_signal = {
                "recently_changed": recently_changed,
                "recent_change_count": recent_change_count,
            }
            sensitivity_signal = {"potentially_sensitive": potentially_sensitive}
            lifecycle_signal = {"status": status}
            posture = {
                "vulnerable": vulnerable,
                "critical_exposure": critical_exposure,
                "exposed_vulnerable": exposed_vulnerable,
                "sensitive_exposed": sensitive_exposed,
                "changed_and_vulnerable": changed_and_vulnerable,
            }

            result[aid] = {
                "finding_signal": finding_signal,
                "exposure_signal": exposure_signal,
                "technology_signal": technology_signal,
                "change_signal": change_signal,
                "sensitivity_signal": sensitivity_signal,
                "lifecycle_signal": lifecycle_signal,
                "posture": posture,
            }

    return result


def aggregate_security_signals_for_asset(db: Session, asset: Asset) -> dict:
    """Single-asset wrapper (bounded)."""
    return aggregate_security_signals_for_assets(db, [asset]).get(asset.id, _empty_signals(asset))


def _empty_signals(asset: Asset) -> dict:
    return {
        "finding_signal": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "highest_severity": None, "highest_score": None},
        "exposure_signal": {"internet_facing": False, "externally_resolvable": False, "web_application": False, "exposed_service": False},
        "technology_signal": {"technology_bearing": False, "technology_count": 0},
        "change_signal": {"recently_changed": False, "recent_change_count": 0},
        "sensitivity_signal": {"potentially_sensitive": False},
        "lifecycle_signal": {"status": asset.status or "active"},
        "posture": {"vulnerable": False, "critical_exposure": False, "exposed_vulnerable": False, "sensitive_exposed": False, "changed_and_vulnerable": False},
    }


def get_project_security_summary(db: Session, project_id: str) -> dict:
    """
    Lightweight project summary using grouped queries + classification batch.
    Returns counters for dashboard.
    Does not load all findings into Python.
    """
    # Total assets
    total_assets = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id).scalar() or 0

    # Stale/inactive from status column (indexed)
    stale_assets = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.status == "stale").scalar() or 0
    inactive_assets = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.status == "inactive").scalar() or 0

    # Load assets for classification batch (need asset objects for D2)
    # For efficiency, load all assets for project (bounded by project)
    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    if not assets:
        return {
            "total_assets": 0,
            "internet_facing_assets": 0,
            "web_applications": 0,
            "exposed_services": 0,
            "vulnerable_assets": 0,
            "critical_assets": 0,
            "sensitive_assets": 0,
            "recently_changed_assets": 0,
            "stale_assets": stale_assets,
            "inactive_assets": inactive_assets,
        }

    signals = aggregate_security_signals_for_assets(db, assets)
    # Counters from signals
    internet_facing_assets = sum(1 for s in signals.values() if s["exposure_signal"]["internet_facing"])
    web_applications = sum(1 for s in signals.values() if s["exposure_signal"]["web_application"])
    exposed_services = sum(1 for s in signals.values() if s["exposure_signal"]["exposed_service"])
    vulnerable_assets = sum(1 for s in signals.values() if s["posture"]["vulnerable"])
    critical_assets = sum(1 for s in signals.values() if s["finding_signal"]["critical"] > 0)
    sensitive_assets = sum(1 for s in signals.values() if s["sensitivity_signal"]["potentially_sensitive"])
    recently_changed_assets = sum(1 for s in signals.values() if s["change_signal"]["recently_changed"])

    return {
        "total_assets": total_assets,
        "internet_facing_assets": internet_facing_assets,
        "web_applications": web_applications,
        "exposed_services": exposed_services,
        "vulnerable_assets": vulnerable_assets,
        "critical_assets": critical_assets,
        "sensitive_assets": sensitive_assets,
        "recently_changed_assets": recently_changed_assets,
        "stale_assets": stale_assets,
        "inactive_assets": inactive_assets,
    }

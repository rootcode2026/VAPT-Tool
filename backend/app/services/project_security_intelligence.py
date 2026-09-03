"""
D6.2 — Project Security Intelligence Summary.

Aggregation/visibility layer using D2/D3/D4/D5.
No new risk engine, no new DB tables, deterministic, project-scoped, batch-efficient.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.services.asset_attack_paths import get_attack_paths_for_project
from app.services.asset_classification import classify_assets_batch
from app.services.asset_contextual_risk import aggregate_contextual_risk_for_assets
from app.services.asset_security_signals import aggregate_security_signals_for_assets

PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def get_project_security_intelligence_summary(
    db: Session,
    project_id: str,
    max_depth: int = 5,
    max_paths: int = 100,
) -> dict:
    """
    Project-level security intelligence summary.

    Uses:
    - D2 classify_assets_batch for internet_facing etc.
    - D3 aggregate_security_signals_for_assets for finding/technology/change counts
    - D4 aggregate_contextual_risk_for_assets for contextual priority & exposure combos
    - D5 get_attack_paths_for_project for attack_path_count/truncated

    All bulk/batch, no N+1.
    """
    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    total_assets = len(assets)
    if total_assets == 0:
        return {
            "total_assets": 0,
            "internet_facing_assets": 0,
            "externally_resolvable_assets": 0,
            "web_application_assets": 0,
            "exposed_service_assets": 0,
            "vulnerable_assets": 0,
            "critical_assets": 0,
            "high_assets": 0,
            "medium_assets": 0,
            "low_assets": 0,
            "technology_bearing_assets": 0,
            "sensitive_assets": 0,
            "recently_changed_assets": 0,
            "stale_assets": 0,
            "inactive_assets": 0,
            "critical_exposure_assets": 0,
            "exposed_vulnerable_assets": 0,
            "sensitive_exposed_assets": 0,
            "changed_vulnerable_assets": 0,
            "attack_path_count": 0,
            "attack_paths_truncated": False,
            "highest_contextual_priority": None,
            "web_applications": 0,
            "exposed_services": 0,
        }

    # Batch helpers — each does grouped queries, no N+1
    classifications = classify_assets_batch(db, assets)
    signals = aggregate_security_signals_for_assets(db, assets)
    contextual = aggregate_contextual_risk_for_assets(db, assets)

    # D2 counts
    internet_facing_assets = sum(1 for v in classifications.values() if v.get("internet_facing"))
    externally_resolvable_assets = sum(1 for v in classifications.values() if v.get("externally_resolvable"))
    web_application_assets = sum(1 for v in classifications.values() if v.get("web_application"))
    exposed_service_assets = sum(1 for v in classifications.values() if v.get("exposed_service"))
    technology_bearing_assets = sum(1 for v in classifications.values() if v.get("technology_bearing"))
    sensitive_assets = sum(1 for v in classifications.values() if v.get("potentially_sensitive"))
    recently_changed_assets = sum(1 for v in classifications.values() if v.get("recently_changed"))

    # D3 counts — distinct assets
    vulnerable_assets = sum(1 for v in signals.values() if v.get("posture", {}).get("vulnerable"))
    critical_assets = sum(1 for v in signals.values() if v.get("finding_signal", {}).get("critical", 0) > 0)
    high_assets = sum(1 for v in signals.values() if v.get("finding_signal", {}).get("high", 0) > 0)
    medium_assets = sum(1 for v in signals.values() if v.get("finding_signal", {}).get("medium", 0) > 0)
    low_assets = sum(1 for v in signals.values() if v.get("finding_signal", {}).get("low", 0) > 0)

    # Lifecycle from asset status (already in DB)
    stale_assets = sum(1 for a in assets if a.status == "stale")
    inactive_assets = sum(1 for a in assets if a.status == "inactive")

    # D4 exposure+vuln combos
    critical_exposure_assets = sum(1 for v in signals.values() if v.get("posture", {}).get("critical_exposure"))
    exposed_vulnerable_assets = sum(1 for v in signals.values() if v.get("posture", {}).get("exposed_vulnerable"))
    sensitive_exposed_assets = sum(1 for v in signals.values() if v.get("posture", {}).get("sensitive_exposed"))
    changed_vulnerable_assets = sum(1 for v in signals.values() if v.get("posture", {}).get("changed_and_vulnerable"))

    # Highest contextual priority
    highest_contextual_priority = None
    best_rank = 99
    for art in contextual.values():
        prio = art.get("priority", "informational")
        rank = PRIORITY_RANK.get(prio, 99)
        if rank < best_rank:
            best_rank = rank
            highest_contextual_priority = prio

    # Attack paths — existing D5/D6.1 bulk traversal (bounded)
    attack_paths_result = get_attack_paths_for_project(db, project_id, max_depth=max_depth, max_paths=max_paths)
    attack_path_count = attack_paths_result.get("total", 0)
    attack_paths_truncated = attack_paths_result.get("truncated", False)

    return {
        "total_assets": total_assets,
        "internet_facing_assets": internet_facing_assets,
        "externally_resolvable_assets": externally_resolvable_assets,
        "web_application_assets": web_application_assets,
        "exposed_service_assets": exposed_service_assets,
        "vulnerable_assets": vulnerable_assets,
        "critical_assets": critical_assets,
        "high_assets": high_assets,
        "medium_assets": medium_assets,
        "low_assets": low_assets,
        "technology_bearing_assets": technology_bearing_assets,
        "sensitive_assets": sensitive_assets,
        "recently_changed_assets": recently_changed_assets,
        "stale_assets": stale_assets,
        "inactive_assets": inactive_assets,
        "critical_exposure_assets": critical_exposure_assets,
        "exposed_vulnerable_assets": exposed_vulnerable_assets,
        "sensitive_exposed_assets": sensitive_exposed_assets,
        "changed_vulnerable_assets": changed_vulnerable_assets,
        "attack_path_count": attack_path_count,
        "attack_paths_truncated": attack_paths_truncated,
        "highest_contextual_priority": highest_contextual_priority,
        # Backward-compat aliases
        "web_applications": web_application_assets,
        "exposed_services": exposed_service_assets,
    }

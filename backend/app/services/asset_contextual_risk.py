"""
D4 — Contextual Risk Intelligence.

Deterministic, project-scoped, reuses D3 signals.
Does NOT replace RiskAssessmentEngine, does NOT alter Finding.severity/score.
Produces contextual priority, risk factors, explanations.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.services.asset_security_signals import aggregate_security_signals_for_assets

# Priority levels in order
PRIORITY_ORDER = ["critical", "high", "medium", "low", "informational"]
PRIORITY_RANK = {p: i for i, p in enumerate(PRIORITY_ORDER)}  # 0=critical highest

# Factor severity ranking for deterministic ordering
FACTOR_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

# Stable factor definitions: code -> (severity, description template)
# Descriptions are deterministic templates, not AI.
FACTOR_DEFS: dict[str, dict[str, str]] = {
    "CRITICAL_FINDING": {"severity": "critical", "description": "Asset has one or more critical findings."},
    "HIGH_FINDING": {"severity": "high", "description": "Asset has one or more high findings."},
    "VULNERABLE_ASSET": {"severity": "medium", "description": "Asset has correlated findings and is considered vulnerable."},
    "INTERNET_FACING": {"severity": "high", "description": "Asset is exposed to the public internet."},
    "EXTERNALLY_RESOLVABLE": {"severity": "low", "description": "Asset is externally resolvable via DNS."},
    "WEB_APPLICATION": {"severity": "low", "description": "Asset is a web application."},
    "EXPOSED_SERVICE": {"severity": "medium", "description": "Asset exposes a network service."},
    "RECENTLY_CHANGED": {"severity": "medium", "description": "Asset was recently changed."},
    "SENSITIVE_ASSET": {"severity": "low", "description": "Asset is potentially sensitive."},
    "SENSITIVE_EXPOSED": {"severity": "high", "description": "Potentially sensitive asset is internet-facing."},
    "CHANGED_AND_VULNERABLE": {"severity": "medium", "description": "Asset has vulnerabilities and was recently changed."},
    "CRITICAL_EXPOSURE": {"severity": "critical", "description": "Critical finding affects an internet-facing asset."},
    "EXPOSED_VULNERABLE": {"severity": "high", "description": "Vulnerable asset is internet-facing."},
    "CRITICAL_FINDINGS": {"severity": "critical", "description": "Asset has critical findings."},  # alias
}

# Contextual priority rule engine — explicit, easy to extend
# Each rule: condition lambda signals -> bool, priority, factor codes implied
# We evaluate in priority order: critical first, then high, etc.
# This list is the single source of truth for priority.
CONTEXTUAL_PRIORITY_RULES = [
    {
        "priority": "critical",
        "condition": lambda s: s["finding_signal"]["critical"] > 0 and s["exposure_signal"]["internet_facing"],
        "reason": "CRITICAL_EXPOSURE",
    },
    {
        "priority": "high",
        "condition": lambda s: (s["finding_signal"]["critical"] > 0 or s["finding_signal"]["high"] > 0) and s["exposure_signal"]["internet_facing"],
        "reason": "EXPOSED_VULNERABLE_HIGH",
    },
    {
        "priority": "high",
        "condition": lambda s: s["posture"]["vulnerable"] and s["exposure_signal"]["internet_facing"] and s["sensitivity_signal"]["potentially_sensitive"],
        "reason": "SENSITIVE_EXPOSED",
    },
    {
        "priority": "medium",
        "condition": lambda s: s["posture"]["vulnerable"] and not s["exposure_signal"]["internet_facing"],
        "reason": "VULNERABLE_PRIVATE",
    },
    {
        "priority": "medium",
        "condition": lambda s: s["posture"]["changed_and_vulnerable"],
        "reason": "CHANGED_AND_VULNERABLE",
    },
    {
        "priority": "medium",
        "condition": lambda s: s["posture"]["vulnerable"] and s["exposure_signal"]["exposed_service"],
        "reason": "EXPOSED_SERVICE_VULNERABLE",
    },
    {
        "priority": "low",
        "condition": lambda s: s["exposure_signal"]["internet_facing"] and not s["posture"]["vulnerable"],
        "reason": "INTERNET_FACING_NO_FINDINGS",
    },
    {
        "priority": "low",
        "condition": lambda s: s["exposure_signal"]["exposed_service"] and not s["posture"]["vulnerable"],
        "reason": "EXPOSED_SERVICE_NO_FINDINGS",
    },
    {
        "priority": "low",
        "condition": lambda s: s["technology_signal"]["technology_bearing"] and not s["posture"]["vulnerable"],
        "reason": "TECHNOLOGY_NO_VULN",
    },
]


def _determine_priority(signals: dict[str, Any]) -> str:
    """Deterministic priority based on ordered rules."""
    for rule in CONTEXTUAL_PRIORITY_RULES:
        if rule["condition"](signals):
            return rule["priority"]
    # Fallback
    if signals["posture"]["vulnerable"]:
        return "medium"
    if signals["exposure_signal"]["internet_facing"] or signals["exposure_signal"]["exposed_service"] or signals["technology_signal"]["technology_bearing"]:
        return "low"
    return "informational"


def _build_risk_factors(signals: dict[str, Any]) -> list[dict[str, str]]:
    """Deterministic risk factors sorted by severity rank then code."""
    factors: list[dict[str, str]] = []
    fs = signals["finding_signal"]
    es = signals["exposure_signal"]
    ts = signals["technology_signal"]
    cs = signals["change_signal"]
    ss = signals["sensitivity_signal"]
    posture = signals["posture"]
    lifecycle = signals["lifecycle_signal"]

    # Map signals to factor codes
    if fs["critical"] > 0:
        factors.append({"code": "CRITICAL_FINDING", "severity": "critical", "description": FACTOR_DEFS["CRITICAL_FINDING"]["description"]})
    if fs["high"] > 0:
        factors.append({"code": "HIGH_FINDING", "severity": "high", "description": FACTOR_DEFS["HIGH_FINDING"]["description"]})
    if posture["vulnerable"]:
        factors.append({"code": "VULNERABLE_ASSET", "severity": "medium", "description": FACTOR_DEFS["VULNERABLE_ASSET"]["description"]})
    if es["internet_facing"]:
        factors.append({"code": "INTERNET_FACING", "severity": "high", "description": FACTOR_DEFS["INTERNET_FACING"]["description"]})
    if es["externally_resolvable"]:
        factors.append({"code": "EXTERNALLY_RESOLVABLE", "severity": "low", "description": FACTOR_DEFS["EXTERNALLY_RESOLVABLE"]["description"]})
    if es["web_application"]:
        factors.append({"code": "WEB_APPLICATION", "severity": "low", "description": FACTOR_DEFS["WEB_APPLICATION"]["description"]})
    if es["exposed_service"]:
        factors.append({"code": "EXPOSED_SERVICE", "severity": "medium", "description": FACTOR_DEFS["EXPOSED_SERVICE"]["description"]})
    if cs["recently_changed"]:
        factors.append({"code": "RECENTLY_CHANGED", "severity": "medium", "description": FACTOR_DEFS["RECENTLY_CHANGED"]["description"]})
    if ss["potentially_sensitive"]:
        factors.append({"code": "SENSITIVE_ASSET", "severity": "low", "description": FACTOR_DEFS["SENSITIVE_ASSET"]["description"]})
    # Composite posture factors
    if posture["critical_exposure"]:
        factors.append({"code": "CRITICAL_EXPOSURE", "severity": "critical", "description": FACTOR_DEFS["CRITICAL_EXPOSURE"]["description"]})
    if posture["exposed_vulnerable"]:
        # Avoid duplicate if CRITICAL_EXPOSURE already added (it implies exposed_vulnerable)
        if not posture["critical_exposure"]:
            factors.append({"code": "EXPOSED_VULNERABLE", "severity": "high", "description": FACTOR_DEFS["EXPOSED_VULNERABLE"]["description"]})
    if posture["sensitive_exposed"]:
        factors.append({"code": "SENSITIVE_EXPOSED", "severity": "high", "description": FACTOR_DEFS["SENSITIVE_EXPOSED"]["description"]})
    if posture["changed_and_vulnerable"]:
        factors.append({"code": "CHANGED_AND_VULNERABLE", "severity": "medium", "description": FACTOR_DEFS["CHANGED_AND_VULNERABLE"]["description"]})
    # Deduplicate by code (deterministic)
    seen = {}
    deduped = []
    for f in factors:
        if f["code"] not in seen:
            seen[f["code"]] = True
            deduped.append(f)
    # Sort deterministically: severity rank then code
    deduped.sort(key=lambda x: (FACTOR_SEVERITY_RANK.get(x["severity"], 99), x["code"]))
    return deduped


def _build_explanation(signals: dict[str, Any], priority: str, factors: list[dict]) -> str:
    """Deterministic concise explanation templates."""
    # Highest priority explanation first
    if priority == "critical" and any(f["code"] == "CRITICAL_EXPOSURE" for f in factors):
        return "Critical finding affects an internet-facing asset."
    if any(f["code"] == "SENSITIVE_EXPOSED" for f in factors):
        return "Potentially sensitive asset is internet-facing."
    if any(f["code"] == "CHANGED_AND_VULNERABLE" for f in factors):
        return "Asset has vulnerabilities and was recently changed."
    if any(f["code"] == "EXPOSED_VULNERABLE" for f in factors):
        return "Vulnerable asset is exposed to the internet."
    if any(f["code"] == "CRITICAL_FINDING" for f in factors):
        return "Asset has critical findings."
    if any(f["code"] == "VULNERABLE_ASSET" for f in factors):
        return "Asset has correlated findings."
    if any(f["code"] == "INTERNET_FACING" for f in factors):
        return "Asset is internet-facing."
    if any(f["code"] == "EXPOSED_SERVICE" for f in factors):
        return "Asset exposes a network service."
    if signals["lifecycle_signal"]["status"] in ("stale", "inactive"):
        return f"Asset is {signals['lifecycle_signal']['status']}."
    return "No significant contextual risk signals."


def _build_context(signals: dict[str, Any]) -> dict:
    """Build contextual risk context blocks from D3 signals."""
    return {
        "exposure_context": {
            "internet_facing": signals["exposure_signal"]["internet_facing"],
            "externally_resolvable": signals["exposure_signal"]["externally_resolvable"],
            "web_application": signals["exposure_signal"]["web_application"],
            "exposed_service": signals["exposure_signal"]["exposed_service"],
        },
        "vulnerability_context": {
            "vulnerable": signals["posture"]["vulnerable"],
            "critical_findings": signals["finding_signal"]["critical"],
            "high_findings": signals["finding_signal"]["high"],
            "highest_severity": signals["finding_signal"]["highest_severity"],
            "highest_score": signals["finding_signal"]["highest_score"],
        },
        "change_context": {
            "recently_changed": signals["change_signal"]["recently_changed"],
            "recent_change_count": signals["change_signal"]["recent_change_count"],
        },
        "sensitivity_context": {
            "potentially_sensitive": signals["sensitivity_signal"]["potentially_sensitive"],
        },
        "technology_context": {
            "technology_bearing": signals["technology_signal"]["technology_bearing"],
            "technology_count": signals["technology_signal"]["technology_count"],
        },
        "lifecycle_context": {
            "status": signals["lifecycle_signal"]["status"],
        },
    }


def contextual_risk_from_signals(signals: dict[str, Any], asset: Asset) -> dict:
    """Pure in-memory deterministic derivation from D3 signals (no DB)."""
    context = _build_context(signals)
    priority = _determine_priority(signals)
    factors = _build_risk_factors(signals)
    explanation = _build_explanation(signals, priority, factors)
    return {
        "context": context,
        "priority": priority,
        "risk_factors": factors,
        "explanation": explanation,
        "signals": signals,
    }


def get_contextual_risk_for_asset(db: Session, asset: Asset) -> dict:
    """Single-asset contextual risk (bounded, reuses D3 batch)."""
    return aggregate_contextual_risk_for_assets(db, [asset]).get(asset.id, _empty_context(asset))


def aggregate_contextual_risk_for_assets(db: Session, assets: list[Asset]) -> dict[str, dict]:
    """
    Batch contextual risk for N assets.
    Ideal flow: D3 batch -> in-memory D4 deterministic evaluation (no N+1).
    Consumes D3 aggregate_security_signals_for_assets output.
    """
    if not assets:
        return {}
    signals_by_asset = aggregate_security_signals_for_assets(db, assets)
    result: dict[str, dict] = {}
    for asset in assets:
        sig = signals_by_asset.get(asset.id)
        if sig is None:
            result[asset.id] = _empty_context(asset)
            continue
        context = _build_context(sig)
        priority = _determine_priority(sig)
        factors = _build_risk_factors(sig)
        explanation = _build_explanation(sig, priority, factors)
        result[asset.id] = {
            "context": context,
            "priority": priority,
            "risk_factors": factors,
            "explanation": explanation,
            # Also expose raw signals for consumers that need them (optional)
            "signals": sig,
        }
    return result


def _empty_context(asset: Asset) -> dict:
    return {
        "context": {
            "exposure_context": {"internet_facing": False, "externally_resolvable": False, "web_application": False, "exposed_service": False},
            "vulnerability_context": {"vulnerable": False, "critical_findings": 0, "high_findings": 0, "highest_severity": None, "highest_score": None},
            "change_context": {"recently_changed": False, "recent_change_count": 0},
            "sensitivity_context": {"potentially_sensitive": False},
            "technology_context": {"technology_bearing": False, "technology_count": 0},
            "lifecycle_context": {"status": asset.status or "active"},
        },
        "priority": "informational",
        "risk_factors": [],
        "explanation": "No significant contextual risk signals.",
        "signals": {},
    }


def get_project_contextual_summary(db: Session, project_id: str) -> dict:
    """
    Lightweight project contextual summary.
    Reuses D3 project summary but adds contextual priority counters.
    Uses batch aggregation (no per-asset query).
    """
    from app.services.asset_security_signals import get_project_security_summary

    base = get_project_security_summary(db, project_id)
    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    if not assets:
        return {
            **base,
            "critical_exposure_assets": 0,
            "exposed_vulnerable_assets": 0,
            "sensitive_exposed_assets": 0,
            "changed_vulnerable_assets": 0,
            "critical_finding_assets": base.get("critical_assets", 0),
            "high_finding_assets": 0,
        }
    batch = aggregate_contextual_risk_for_assets(db, assets)
    critical_exposure_assets = sum(1 for v in batch.values() if v["priority"] == "critical")
    # Also count posture flags
    exposed_vulnerable_assets = sum(1 for v in batch.values() if any(f["code"] == "EXPOSED_VULNERABLE" or f["code"] == "CRITICAL_EXPOSURE" for f in v["risk_factors"]))
    sensitive_exposed_assets = sum(1 for v in batch.values() if any(f["code"] == "SENSITIVE_EXPOSED" for f in v["risk_factors"]))
    changed_vulnerable_assets = sum(1 for v in batch.values() if any(f["code"] == "CHANGED_AND_VULNERABLE" for f in v["risk_factors"]))
    # High finding assets from signals
    high_finding_assets = sum(1 for v in batch.values() if v["context"]["vulnerability_context"]["high_findings"] > 0)
    critical_finding_assets = sum(1 for v in batch.values() if v["context"]["vulnerability_context"]["critical_findings"] > 0)
    return {
        **base,
        "critical_exposure_assets": critical_exposure_assets,
        "exposed_vulnerable_assets": exposed_vulnerable_assets,
        "sensitive_exposed_assets": sensitive_exposed_assets,
        "changed_vulnerable_assets": changed_vulnerable_assets,
        "critical_finding_assets": critical_finding_assets,
        "high_finding_assets": high_finding_assets,
    }

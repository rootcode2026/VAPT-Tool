"""
S5.2 Finding-to-Asset Risk Mapping — deterministic, no DB/network, project-isolated.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any
import ipaddress

try:
    from app.asset_intel.change_detection import ASSET_STALE_AFTER_DAYS, ASSET_INACTIVE_AFTER_DAYS
except ImportError:
    ASSET_STALE_AFTER_DAYS = 7
    ASSET_INACTIVE_AFTER_DAYS = 30

def _parse_dt(val) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val)
        except ValueError:
            return None
    return None

def _is_public_ip(value: str) -> bool | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
        # Use is_global where available (Python 3.8+)
        if hasattr(ip, "is_global"):
            return bool(ip.is_global)
        # Fallback
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)
    except ValueError:
        return None

def _exposure_from_asset(asset: dict | None) -> tuple[bool | None, str | None]:
    if not asset or not isinstance(asset, dict):
        return None, None
    atype = str(asset.get("asset_type") or asset.get("type") or "").lower()
    value = str(asset.get("value") or asset.get("asset_value") or "").strip()
    # URL/web asset with public host -> exposed
    if atype in ("url", "web_site", "web_host"):
        # Check if URL host is public IP or if asset is web
        # For simplicity, url assets are considered externally exposed if they are http(s)
        if value.startswith("http://") or value.startswith("https://"):
            return True, "url_asset"
    if atype in ("ip", "ipv6"):
        pub = _is_public_ip(value)
        if pub is True:
            return True, "public_ip"
        if pub is False:
            return False, "private_ip"
    # Check relationships: if asset has exposes/resolves_to/serves
    rels = asset.get("relationships") or asset.get("asset_relationships") or []
    if isinstance(rels, list) and rels:
        for rel in rels:
            if not isinstance(rel, dict):
                continue
            rtype = str(rel.get("relationship_type") or rel.get("type") or "").lower()
            if rtype in ("exposes", "resolves_to", "serves"):
                return True, f"relationship_{rtype}"
    # Domain without enough evidence -> unknown
    if atype in ("domain", "subdomain", "hostname"):
        return None, None
    return None, None

def _freshness(asset: dict | None) -> tuple[str | None, bool | None]:
    if not asset or not isinstance(asset, dict):
        return None, None
    first = _parse_dt(asset.get("first_seen_at"))
    last = _parse_dt(asset.get("last_seen_at") or asset.get("updated_at"))
    if not first and not last:
        return None, None
    # Use last_seen for staleness
    ref = last or first
    if ref is None:
        return None, None
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    age_days = (now - ref).total_seconds() / 86400
    if age_days >= ASSET_INACTIVE_AFTER_DAYS:
        return "inactive", True
    if age_days >= ASSET_STALE_AFTER_DAYS:
        return "stale", True
    # Fresh: recently seen within stale threshold
    # Also check first_seen for age signal
    if first:
        if first.tzinfo is None:
            first = first.replace(tzinfo=timezone.utc)
        total_age = (now - first).total_seconds() / 86400
        if total_age < 7:
            return "fresh", False
    return "fresh", False

def map_finding_to_asset_context(
    finding: dict | None = None,
    asset: dict | None = None,
    enriched_risk: dict | None = None,
) -> dict[str, Any]:
    """
    Deterministic asset-context mapping.

    finding: enriched finding dict (may contain asset_id, project_id, etc.)
    asset: optional asset dict (must be from same project if provided)
    enriched_risk: optional S5.1 enriched risk result (for composition)
    """
    finding = finding if isinstance(finding, dict) else {}
    asset = asset if isinstance(asset, dict) and asset else None

    # Preserve original asset_id if present
    finding_asset_id = finding.get("asset_id") or finding.get("assetId")
    # Also check in enriched_risk? No, use finding
    # Determine effective asset
    effective_asset = None
    project_isolation_ok = True
    if finding_asset_id and asset:
        # Check project isolation
        finding_project = finding.get("project_id") or finding.get("projectId") or (finding.get("metadata") or {}).get("project_id") if isinstance(finding.get("metadata"), dict) else None
        asset_project = asset.get("project_id") or asset.get("projectId")
        if finding_project and asset_project and str(finding_project) != str(asset_project):
            # Project mismatch -> do not associate
            project_isolation_ok = False
            effective_asset = None
        else:
            # Check asset_id matches
            if str(asset.get("id") or asset.get("asset_id")) == str(finding_asset_id):
                effective_asset = asset
            else:
                # Asset provided does not match finding's asset_id -> treat as no asset
                effective_asset = None
    elif finding_asset_id and not asset:
        # Finding has asset_id but no asset object provided -> we cannot enrich, mark as unavailable
        effective_asset = None
    elif not finding_asset_id and asset:
        # Finding has no asset_id but asset provided -> do not invent association
        # Only associate if finding has no asset_id and asset is explicitly provided via same project? Per spec, do NOT automatically associate based only on loose URL/hostname
        # So we treat as no asset unless finding already has asset_id
        effective_asset = None
    else:
        effective_asset = None

    # If no effective asset, check if finding has asset info directly?
    # For now, no asset

    # Build asset context
    asset_id = str(finding_asset_id) if finding_asset_id else None
    asset_type = None
    asset_value = None
    if effective_asset:
        asset_id = str(effective_asset.get("id") or effective_asset.get("asset_id") or asset_id)
        asset_type = str(effective_asset.get("asset_type") or effective_asset.get("type") or "").lower() or None
        asset_value = str(effective_asset.get("value") or effective_asset.get("asset_value") or "").strip() or None
    elif finding and finding.get("asset_type") and finding.get("asset_value"):
        asset_type = str(finding.get("asset_type")).lower()
        asset_value = str(finding.get("asset_value")).strip()

    # Exposure
    is_externally_exposed: bool | None = None
    exposure_signal: str | None = None
    relationship_types: list[str] = []
    asset_relationship_count = 0
    if effective_asset:
        is_externally_exposed, exposure_signal = _exposure_from_asset(effective_asset)
        # Relationship summary
        rels = effective_asset.get("relationships") or effective_asset.get("asset_relationships") or []
        if isinstance(rels, list):
            asset_relationship_count = len(rels)
            for rel in rels:
                if isinstance(rel, dict):
                    rt = str(rel.get("relationship_type") or rel.get("type") or "").strip().lower()
                    if rt and rt not in relationship_types:
                        relationship_types.append(rt)
            relationship_types = sorted(relationship_types)[:20]
    elif asset and not project_isolation_ok:
        # Project mismatch -> exposure unavailable
        is_externally_exposed = None
        exposure_signal = None

    # Freshness
    freshness_signal: str | None = None
    is_stale = None
    if effective_asset:
        freshness_signal, is_stale = _freshness(effective_asset)
    # Asset age signal
    asset_age_signal = None
    if effective_asset and effective_asset.get("first_seen_at"):
        first = _parse_dt(effective_asset.get("first_seen_at"))
        if first:
            if first.tzinfo is None:
                first = first.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - first).total_seconds() / 86400
            if age_days < 7:
                asset_age_signal = "new"
            elif age_days < 30:
                asset_age_signal = "established"
            else:
                asset_age_signal = "aged"

    # Criticality - do not invent
    asset_criticality = None
    if effective_asset and isinstance(effective_asset, dict):
        # Check explicit criticality fields
        for k in ("criticality", "business_criticality", "priority", "tier"):
            if k in effective_asset and effective_asset[k] not in (None, ""):
                val = str(effective_asset[k]).strip().lower()
                if val in ("critical", "high", "medium", "low", "info"):
                    asset_criticality = val
                    break
                # Also allow numeric
                if val.isdigit():
                    asset_criticality = val
                    break

    # Asset risk modifier — bounded deterministic, based on available signals
    # Do not override severity, just modifier
    modifier = 0
    reasons: list[str] = []
    if is_externally_exposed is True:
        modifier += 10
        reasons.append("Externally exposed asset increases risk.")
    if is_externally_exposed is False:
        modifier -= 2
        reasons.append("Internal asset slightly decreases risk.")
    if freshness_signal == "fresh":
        modifier += 3
        reasons.append("Fresh asset recently observed.")
    elif freshness_signal == "stale":
        modifier -= 2
        reasons.append("Stale asset slightly decreases risk.")
    elif freshness_signal == "inactive":
        modifier -= 5
        reasons.append("Inactive asset decreases risk.")
    if asset_relationship_count > 3:
        modifier += 2
        reasons.append("Highly connected asset slightly increases risk.")
    if asset_criticality in ("critical", "high"):
        modifier += 5
        reasons.append(f"Asset criticality {asset_criticality} increases risk.")
    # Clamp -10 to +15
    if modifier > 15:
        modifier = 15
    if modifier < -10:
        modifier = -10

    # Available/unavailable signals
    available: list[str] = []
    unavailable: list[str] = []
    if effective_asset:
        available.append("asset")
        if is_externally_exposed is not None:
            available.append("exposure")
        else:
            unavailable.append("exposure")
        if asset_relationship_count > 0:
            available.append("relationships")
        else:
            unavailable.append("relationships")
        if freshness_signal is not None:
            available.append("freshness")
        else:
            unavailable.append("freshness")
        if asset_criticality is not None:
            available.append("criticality")
        else:
            unavailable.append("criticality")
    else:
        unavailable.extend(["asset", "exposure", "relationships", "freshness", "criticality"])
        if not finding.get("asset_id"):
            unavailable.append("asset_id")

    # Ensure project isolation reason
    if not project_isolation_ok:
        reasons.append("Project isolation prevented asset association.")

    # Bounded
    reasons = reasons[:20]
    available = sorted(set(available))
    unavailable = sorted(set(unavailable))

    # Build asset_context
    asset_context = {
        "is_externally_exposed": is_externally_exposed,
        "exposure_signal": exposure_signal,
        "asset_relationship_count": asset_relationship_count,
        "relationship_types": relationship_types,
        "asset_age_signal": asset_age_signal,
        "freshness_signal": freshness_signal,
        "asset_risk_modifier": modifier,
    }

    # Preserve original finding fields
    original_severity = finding.get("severity") if isinstance(finding, dict) else None
    original_validation_state = None
    if isinstance(enriched_risk, dict):
        original_validation_state = enriched_risk.get("state") or enriched_risk.get("validation_state")

    return {
        "asset_id": asset_id,
        "asset_type": asset_type,
        "asset_value": asset_value,
        "asset_context": asset_context,
        "available_signals": available,
        "unavailable_signals": unavailable,
        "reasons": reasons,
        "original_severity": original_severity,
        "original_validation_state": original_validation_state,
        "project_isolation_ok": project_isolation_ok,
    }

def enrich_with_asset_context(
    enriched_risk: dict | None,
    finding: dict | None = None,
    asset: dict | None = None,
) -> dict[str, Any]:
    """
    Composition helper: enrich S5.1 risk result with asset context without breaking API.
    Returns new dict with S5.1 fields plus asset_context.
    """
    enriched_risk = enriched_risk if isinstance(enriched_risk, dict) else {}
    # Copy
    result = dict(enriched_risk)
    asset_ctx = map_finding_to_asset_context(finding or enriched_risk.get("finding") or {}, asset, enriched_risk)
    # Merge asset context into result
    result["asset_context"] = asset_ctx["asset_context"]
    result["asset_id"] = asset_ctx["asset_id"]
    result["asset_type"] = asset_ctx["asset_type"]
    result["asset_value"] = asset_ctx["asset_value"]
    # Merge available/unavailable
    result["available_signals"] = sorted(set(result.get("available_signals", []) + asset_ctx["available_signals"]))
    result["unavailable_signals"] = sorted(set(result.get("unavailable_signals", []) + asset_ctx["unavailable_signals"]))
    # Keep original severity/state unchanged
    return result

# Alias for spec naming
map_finding_to_asset_context = map_finding_to_asset_context

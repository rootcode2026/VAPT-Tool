"""Risk intelligence services — S5.1, S5.2, S5.3, S5.4."""

from app.services.risk_intelligence.enricher import enrich_finding_risk, enrich_findings_risk
from app.services.risk_intelligence.asset_context import map_finding_to_asset_context, enrich_with_asset_context

try:
    from app.services.risk_intelligence.attack_paths import discover_attack_paths, DEFAULT_MAX_PATH_LENGTH, DEFAULT_MAX_PATHS
except ImportError:
    discover_attack_paths = None  # type: ignore
    DEFAULT_MAX_PATH_LENGTH = 6  # type: ignore
    DEFAULT_MAX_PATHS = 100  # type: ignore

try:
    from app.services.risk_intelligence.prioritizer import prioritize_attack_paths
except ImportError:
    prioritize_attack_paths = None  # type: ignore

__all__ = [
    "enrich_finding_risk",
    "enrich_findings_risk",
    "map_finding_to_asset_context",
    "enrich_with_asset_context",
    "discover_attack_paths",
    "prioritize_attack_paths",
    "DEFAULT_MAX_PATH_LENGTH",
    "DEFAULT_MAX_PATHS",
]

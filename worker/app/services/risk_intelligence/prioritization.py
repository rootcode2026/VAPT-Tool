"""Alias for prioritizer — supports multiple import paths for S5.4."""

from app.services.risk_intelligence.prioritizer import prioritize_attack_paths

__all__ = ["prioritize_attack_paths"]

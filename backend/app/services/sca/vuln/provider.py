"""
Vulnerability Provider abstraction.
Deterministic, no network by default, O(1) lookup.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.services.sca.models import Dependency, VulnerabilityResult


class VulnerabilityProvider(ABC):
    @abstractmethod
    def lookup(self, dependency: Dependency) -> list[VulnerabilityResult]:
        """Lookup vulnerabilities for a dependency. Returns list (may be empty)."""
        raise NotImplementedError

    def supports_range_matching(self) -> bool:
        return False

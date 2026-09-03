"""
SCA Dependency and Vulnerability models.
Deterministic, no network, no execution.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Dependency:
    ecosystem: str  # npm, pypi
    name: str
    version: str | None  # exact version or range, None if unresolved
    manifest: str  # package.json, requirements.txt, etc.
    dependency_type: str = "runtime"  # runtime, development, optional
    version_resolved: bool = False
    extras: list[str] = field(default_factory=list)
    raw_version: str | None = None  # original string before normalization

    def identity_key(self) -> tuple[str, str, str | None]:
        # For deduplication: ecosystem + lower name + version (or None)
        return (self.ecosystem, self.name.lower(), self.version)


@dataclass(frozen=True)
class VulnerabilityResult:
    ecosystem: str
    package_name: str
    installed_version: str
    vulnerability_id: str  # CVE-2021-23337
    severity: str  # critical, high, medium, low, info
    score: float | None
    summary: str | None = None
    fixed_version: str | None = None
    source: str = "fixture"
    metadata: dict[str, Any] = field(default_factory=dict)

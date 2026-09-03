"""
SCA Vulnerability Provider Factory — tiny, deterministic, no silent fallback.
"""

from __future__ import annotations

import os

from app.services.sca.vuln.fixture import FixtureVulnerabilityProvider
from app.services.sca.vuln.provider import VulnerabilityProvider

try:
    from app.services.sca.vuln.osv import OSVVulnerabilityProvider
except ImportError:
    OSVVulnerabilityProvider = None  # type: ignore


def get_vulnerability_provider(name: str | None = None) -> VulnerabilityProvider:
    """
    Factory for VulnerabilityProvider.

    - name explicit: "fixture" or "osv" (case-insensitive)
    - else: env SCA_VULNERABILITY_PROVIDER (case-insensitive)
    - else: default based on ENVIRONMENT (production -> osv, else fixture)

    Unknown name -> ValueError (explicit, no silent fallback).
    """
    raw = name
    if raw is None:
        raw = os.getenv("SCA_VULNERABILITY_PROVIDER")
    if raw is None or str(raw).strip() == "":
        # No explicit provider: default to osv in production, else fixture
        # This keeps tests offline (ENVIRONMENT != production) while production defaults to osv
        # Note: do not use cached Settings.SCA_VULNERABILITY_PROVIDER which is computed at import time
        env = os.getenv("ENVIRONMENT", "development").lower()
        if env == "production":
            raw = "osv"
        else:
            raw = "fixture"

    norm = str(raw).strip().lower()
    if norm == "fixture":
        return FixtureVulnerabilityProvider()
    if norm == "osv":
        if OSVVulnerabilityProvider is None:
            raise ValueError("OSV provider not available (missing httpx)")
        return OSVVulnerabilityProvider()
    raise ValueError(f"Unknown SCA vulnerability provider: {raw!r}. Expected 'fixture' or 'osv'.")


def create_sca_analyzer(provider: VulnerabilityProvider | None = None, registry=None):
    """
    Helper to create SCAAnalyzer with correct provider selection.

    If provider is explicitly passed, use it.
    Otherwise, use factory (environment-aware).
    """
    from app.services.sca.analyzer import SCAAnalyzer

    if provider is not None:
        return SCAAnalyzer(registry=registry, provider=provider)
    return SCAAnalyzer(registry=registry, provider=get_vulnerability_provider())

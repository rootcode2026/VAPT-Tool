"""
Fixture vulnerability provider — TEST/DVELOPMENT DATA ONLY.
Not a production vulnerability database.
Tiny deterministic dataset for S1.

Architecture allows future providers: NVD, OSV, GitHub Advisory DB.
"""

from app.services.sca.models import Dependency, VulnerabilityResult
from app.services.sca.vuln.provider import VulnerabilityProvider


# Fixture dataset: (ecosystem, package_lower, version) -> list[VulnerabilityResult]
FIXTURE_VULNS: list[dict] = [
    {
        "ecosystem": "npm",
        "package": "lodash",
        "version": "4.17.20",
        "vulnerability_id": "CVE-2021-23337",
        "severity": "high",
        "score": 7.2,
        "summary": "Lodash 4.17.20 is vulnerable to command injection via template.",
        "fixed_version": "4.17.21",
        "source": "fixture",
    },
    {
        "ecosystem": "npm",
        "package": "express",
        "version": "4.17.1",
        "vulnerability_id": "CVE-2022-24999",
        "severity": "high",
        "score": 7.5,
        "summary": "Express 4.17.1 vulnerable to qs prototype poisoning.",
        "fixed_version": "4.17.3",
        "source": "fixture",
    },
    {
        "ecosystem": "pypi",
        "package": "requests",
        "version": "2.25.0",
        "vulnerability_id": "CVE-2023-32681",
        "severity": "medium",
        "score": 6.1,
        "summary": "Requests 2.25.0 vulnerable to unintended proxy leakage.",
        "fixed_version": "2.31.0",
        "source": "fixture",
    },
    {
        "ecosystem": "pypi",
        "package": "urllib3",
        "version": "1.26.4",
        "vulnerability_id": "CVE-2021-33503",
        "severity": "high",
        "score": 7.5,
        "summary": "urllib3 1.26.4 vulnerable to CRLF injection.",
        "fixed_version": "1.26.5",
        "source": "fixture",
    },
]


class FixtureVulnerabilityProvider(VulnerabilityProvider):
    def __init__(self, fixtures: list[dict] | None = None):
        data = fixtures if fixtures is not None else FIXTURE_VULNS
        # Index for O(1) lookup: (ecosystem, package_lower, version) -> list
        self._index: dict[tuple[str, str, str], list[VulnerabilityResult]] = {}
        for item in data:
            key = (item["ecosystem"], item["package"].lower(), item["version"])
            vuln = VulnerabilityResult(
                ecosystem=item["ecosystem"],
                package_name=item["package"],
                installed_version=item["version"],
                vulnerability_id=item["vulnerability_id"],
                severity=item["severity"],
                score=item["score"],
                summary=item.get("summary"),
                fixed_version=item.get("fixed_version"),
                source=item.get("source", "fixture"),
                metadata={"fixture": True},
            )
            self._index.setdefault(key, []).append(vuln)

    def lookup(self, dependency: Dependency) -> list[VulnerabilityResult]:
        # Exact package + ecosystem + exact version when available
        if not dependency.version or not dependency.version_resolved:
            return []
        key = (dependency.ecosystem, dependency.name.lower(), dependency.version)
        return list(self._index.get(key, []))

"""
SCA Analyzer — orchestrates manifest parsing, deduplication, vulnerability matching, finding generation.
Deterministic, no subprocess, no network, no package installation.

Architecture:
Manifest Parser -> Dependency -> VulnerabilityProvider -> VulnerabilityResult -> Finding Candidate -> FindingEngine
"""

from __future__ import annotations

from typing import Any

from app.services.sca.models import Dependency
from app.services.sca.parsers.registry import SCARegistry
from app.services.sca.vuln.provider import VulnerabilityProvider

MAX_MANIFEST_SIZE = 2 * 1024 * 1024  # 2 MB per manifest
MAX_TOTAL_MANIFESTS = 10


class SCAAnalyzer:
    def __init__(
        self,
        registry: SCARegistry | None = None,
        provider: VulnerabilityProvider | None = None,
    ):
        self.registry = registry or SCARegistry()
        if provider is not None:
            self.provider = provider
        else:
            # Use factory for environment-aware default (production -> osv, test/dev -> fixture)
            # Import lazily to avoid circular
            try:
                from app.services.sca.factory import get_vulnerability_provider

                self.provider = get_vulnerability_provider()
            except Exception:
                # Fallback to fixture if factory not available
                from app.services.sca.vuln.fixture import FixtureVulnerabilityProvider

                self.provider = FixtureVulnerabilityProvider()

    def analyze(
        self,
        manifests: dict[str, str] | list[tuple[str, str]],
        source: str | None = None,
    ) -> dict[str, Any]:
        """
        Analyze multiple manifests.

        Args:
            manifests: dict {manifest_type: content} or list[(manifest_type, content)]
            source: optional source identifier (repo/project)

        Returns:
            {
                "scanner": "sca",
                "dependencies": [...],
                "vulnerabilities": [...],
                "findings": [...],  # standardized via FindingEngine
                "errors": [...]  # structured parsing errors
            }
        """
        if isinstance(manifests, dict):
            items = list(manifests.items())
        else:
            items = list(manifests)

        if len(items) > MAX_TOTAL_MANIFESTS:
            raise ValueError(f"Too many manifests (max {MAX_TOTAL_MANIFESTS})")

        dependencies: list[Dependency] = []
        errors: list[dict] = []
        for manifest_type, content in items:
            if not isinstance(content, str):
                errors.append({"manifest": manifest_type, "error": "Content must be string"})
                continue
            if len(content.encode("utf-8")) > MAX_MANIFEST_SIZE:
                errors.append({"manifest": manifest_type, "error": "Manifest exceeds size limit"})
                continue
            try:
                parser = self.registry.get(manifest_type)
            except ValueError as e:
                errors.append({"manifest": manifest_type, "error": str(e)})
                continue
            try:
                deps = parser.parse(content)
                dependencies.extend(deps)
            except Exception as e:
                errors.append({"manifest": manifest_type, "error": str(e)})
                continue

        # Deduplicate: prefer lockfile exact versions over ranges
        # Key: (ecosystem, name.lower())
        merged: dict[tuple[str, str], Dependency] = {}
        # Sort to ensure deterministic: lockfile types first if they are resolved
        # Priority: version_resolved True > False, and manifest order (lockfile overrides)
        # We'll sort dependencies so resolved versions come last and overwrite
        # Actually we want resolved to win, so we iterate and let resolved overwrite unresolved
        for dep in dependencies:
            key = (dep.ecosystem, dep.name.lower())
            existing = merged.get(key)
            if existing is None:
                merged[key] = dep
            else:
                # Prefer resolved over unresolved
                if dep.version_resolved and not existing.version_resolved:
                    merged[key] = dep
                elif dep.version_resolved == existing.version_resolved:
                    # Prefer lockfile manifests over package.json
                    # package-lock.json and poetry.lock are lockfiles
                    lockfiles = {"package-lock.json", "poetry.lock"}
                    if dep.manifest in lockfiles and existing.manifest not in lockfiles:
                        merged[key] = dep
                    elif dep.manifest == existing.manifest:
                        # Keep first occurrence for determinism
                        pass
                    # else keep existing
                # else keep existing if existing resolved and dep not

        final_deps = list(merged.values())
        # Sort for determinism: ecosystem, name
        final_deps.sort(key=lambda d: (d.ecosystem, d.name.lower(), d.version or ""))

        # Vulnerability matching — O(1) per dep via provider index
        # Distinguish provider errors from no matches
        vulnerabilities = []
        findings_candidates = []
        seen_findings: set[tuple[str, str, str, str]] = set()
        provider_errors: list[dict] = []

        for dep in final_deps:
            try:
                vulns = self.provider.lookup(dep)
            except Exception as e:
                # Provider failure: preserve distinction, do not treat as clean
                provider_errors.append(
                    {
                        "manifest": dep.manifest,
                        "package": dep.name,
                        "ecosystem": dep.ecosystem,
                        "version": dep.version,
                        "error": str(e),
                        "provider_error": True,
                    }
                )
                continue
            for vuln in vulns:
                vulnerabilities.append(vuln)
                # Finding identity includes ecosystem, package, installed_version, vulnerability_id
                fid_key = (vuln.ecosystem, vuln.package_name.lower(), vuln.installed_version, vuln.vulnerability_id)
                if fid_key in seen_findings:
                    continue
                seen_findings.add(fid_key)
                # Build finding candidate compatible with FindingEngine
                # Use provider severity directly
                title = f"Vulnerable {vuln.ecosystem} dependency: {vuln.package_name} {vuln.installed_version}"
                description = f"Dependency {vuln.package_name} {vuln.installed_version} is affected by {vuln.vulnerability_id}."
                if vuln.summary:
                    description += f" {vuln.summary}"
                evidence = f"ecosystem={vuln.ecosystem} package={vuln.package_name} installed_version={vuln.installed_version} manifest={dep.manifest} vulnerability_id={vuln.vulnerability_id}"
                remediation = f"Upgrade {vuln.package_name} to {vuln.fixed_version} or later." if vuln.fixed_version else f"Update {vuln.package_name} to a non-vulnerable version."
                # Preserve CVE alias for OSV (GHSA -> CVE)
                cve_val = None
                if vuln.vulnerability_id.startswith("CVE-"):
                    cve_val = vuln.vulnerability_id
                elif isinstance(vuln.metadata, dict) and vuln.metadata.get("cve_alias"):
                    cve_val = vuln.metadata["cve_alias"]
                findings_candidates.append(
                    {
                        "scanner": "sca",
                        "title": title,
                        "description": description,
                        "severity": vuln.severity,
                        "score": vuln.score,
                        "status": "open",
                        "evidence": evidence,
                        "remediation": remediation,
                        "cve": cve_val,
                        "cwe": None,
                        "metadata": {
                            "ecosystem": vuln.ecosystem,
                            "package_name": vuln.package_name,
                            "installed_version": vuln.installed_version,
                            "manifest": dep.manifest,
                            "dependency_type": dep.dependency_type,
                            "vulnerability_id": vuln.vulnerability_id,
                            "fixed_version": vuln.fixed_version,
                            "source": vuln.source,
                            "version_resolved": dep.version_resolved,
                            **({"cve_alias": vuln.metadata.get("cve_alias")} if isinstance(vuln.metadata, dict) and vuln.metadata.get("cve_alias") else {}),
                            **({"osv_id": vuln.metadata.get("osv_id")} if isinstance(vuln.metadata, dict) and vuln.metadata.get("osv_id") else {}),
                        },
                    }
                )

        # Merge provider errors (preserve distinction from parsing errors)
        errors.extend(provider_errors)

        # Pass through existing FindingEngine for standardization (preserves severity/score semantics)
        # Import here to avoid circular
        try:
            from worker.app.finding_engine.engine import FindingEngine as WorkerFindingEngine

            engine = WorkerFindingEngine()
            findings = engine.analyze({"scanner": "sca", "findings": findings_candidates, "assets": []})
        except ImportError:
            try:
                # Fallback: try backend finding_engine if exists
                from app.finding_engine.engine import FindingEngine

                engine = FindingEngine()
                findings = engine.analyze({"scanner": "sca", "findings": findings_candidates, "assets": []})
            except Exception:
                # If no engine available, use candidates directly (already compatible)
                findings = findings_candidates

        return {
            "scanner": "sca",
            "source": source,
            "dependencies": [
                {
                    "ecosystem": d.ecosystem,
                    "name": d.name,
                    "version": d.version,
                    "manifest": d.manifest,
                    "dependency_type": d.dependency_type,
                    "version_resolved": d.version_resolved,
                    "raw_version": d.raw_version,
                }
                for d in final_deps
            ],
            "vulnerabilities": [
                {
                    "ecosystem": v.ecosystem,
                    "package_name": v.package_name,
                    "installed_version": v.installed_version,
                    "vulnerability_id": v.vulnerability_id,
                    "severity": v.severity,
                    "score": v.score,
                    "summary": v.summary,
                    "fixed_version": v.fixed_version,
                    "source": v.source,
                }
                for v in vulnerabilities
            ],
            "findings": findings,
            "errors": errors,
        }

"""
OSV Vulnerability Provider — real OSV API via HTTPS.
No API key, bounded timeout, no retries except one on 429, deterministic.

Uses existing VulnerabilityProvider interface.
"""

from __future__ import annotations

import json
import time
from typing import Any

try:
    import httpx
except ImportError:
    httpx = None  # type: ignore

from app.services.sca.models import Dependency, VulnerabilityResult
from app.services.sca.vuln.provider import VulnerabilityProvider


OSV_API_URL = "https://api.osv.dev/v1/query"
TIMEOUT_SECONDS = 5.0
MAX_RESPONSE_BYTES = 1 * 1024 * 1024  # 1 MB

# Ecosystem mapping: S1 ecosystem -> OSV ecosystem
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
}

# Valid ecosystems for OSV
SUPPORTED_OSV_ECOSYSTEMS = {"npm", "PyPI"}


class OSVProviderError(Exception):
    """Provider failure — distinct from 'no vulnerabilities'."""

    pass


class OSVVulnerabilityProvider(VulnerabilityProvider):
    def __init__(
        self,
        api_url: str = OSV_API_URL,
        timeout: float = TIMEOUT_SECONDS,
        client: Any | None = None,
    ):
        self.api_url = api_url
        self.timeout = timeout
        self._client = client  # injectable for tests

    def _get_client(self):
        if self._client is not None:
            return self._client
        if httpx is None:
            raise OSVProviderError("httpx not available")
        return httpx

    def lookup(self, dependency: Dependency) -> list[VulnerabilityResult]:
        if not dependency.version or not dependency.version_resolved:
            return []

        osv_ecosystem = ECOSYSTEM_MAP.get(dependency.ecosystem)
        if osv_ecosystem not in SUPPORTED_OSV_ECOSYSTEMS:
            return []

        # Basic SSRF / injection protection: validate package name and version are sane
        # Package name already sanitized by parser, but double-check
        if len(dependency.name) > 214 or ".." in dependency.name:
            raise OSVProviderError(f"Invalid package name: {dependency.name}")
        if len(dependency.version) > 100:
            raise OSVProviderError(f"Version too long: {dependency.version}")

        payload = {
            "package": {"name": dependency.name, "ecosystem": osv_ecosystem},
            "version": dependency.version,
        }

        # Use httpx with bounded timeout and response size
        try:
            client = self._get_client()
            # Support both httpx module and injected mock
            if hasattr(client, "post"):
                # httpx style
                response = client.post(
                    self.api_url,
                    json=payload,
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json"},
                )
                # Handle mock that returns dict directly
                if isinstance(response, dict):
                    data = response
                    status = 200
                else:
                    status = getattr(response, "status_code", 200)
                    # Check response size
                    content = response.content if hasattr(response, "content") else b""
                    if len(content) > MAX_RESPONSE_BYTES:
                        raise OSVProviderError("OSV response too large")
                    if status == 429:
                        # One short retry after 0.5s
                        time.sleep(0.5)
                        response2 = client.post(
                            self.api_url,
                            json=payload,
                            timeout=self.timeout,
                            headers={"Content-Type": "application/json"},
                        )
                        status = getattr(response2, "status_code", 200)
                        if status == 429:
                            raise OSVProviderError("OSV rate limited (429)")
                        content = response2.content if hasattr(response2, "content") else b""
                        if len(content) > MAX_RESPONSE_BYTES:
                            raise OSVProviderError("OSV response too large")
                        try:
                            data = response2.json() if hasattr(response2, "json") else json.loads(content)
                        except Exception as e:
                            raise OSVProviderError(f"Malformed OSV JSON: {e}") from e
                    elif status >= 400:
                        if status == 404:
                            return []
                        raise OSVProviderError(f"OSV HTTP {status}")
                    else:
                        try:
                            data = response.json() if hasattr(response, "json") else json.loads(content)
                        except Exception as e:
                            raise OSVProviderError(f"Malformed OSV JSON: {e}") from e
            else:
                raise OSVProviderError("Invalid HTTP client")
        except OSVProviderError:
            raise
        except Exception as e:
            # Distinguish timeout/connection
            err_str = str(e).lower()
            if "timeout" in err_str or "timed out" in err_str:
                raise OSVProviderError(f"OSV timeout: {e}") from e
            if "connect" in err_str or "dns" in err_str or "connection" in err_str:
                raise OSVProviderError(f"OSV connection error: {e}") from e
            raise OSVProviderError(f"OSV provider error: {e}") from e

        # Validate response structure
        if not isinstance(data, dict):
            raise OSVProviderError("Malformed OSV response: not a dict")

        vulns = data.get("vulns", [])
        if vulns is None:
            return []
        if not isinstance(vulns, list):
            raise OSVProviderError("Malformed OSV response: vulns not list")

        results: list[VulnerabilityResult] = []
        seen_ids: set[str] = set()

        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            osv_id = str(vuln.get("id", "")).strip()
            if not osv_id or osv_id in seen_ids:
                continue
            seen_ids.add(osv_id)

            # CVE alias extraction
            aliases = vuln.get("aliases", [])
            cve_alias = None
            if isinstance(aliases, list):
                for alias in aliases:
                    if isinstance(alias, str) and alias.startswith("CVE-"):
                        cve_alias = alias
                        break

            # Severity extraction
            severity = self._extract_severity(vuln)
            score = self._extract_score(vuln)

            # Summary
            summary = vuln.get("summary") or vuln.get("details")
            if summary and len(summary) > 500:
                summary = summary[:500]

            # Fixed version extraction
            fixed_version = self._extract_fixed_version(vuln)

            # Use OSV id as vulnerability_id, preserve CVE alias in metadata
            metadata: dict[str, Any] = {"osv_id": osv_id, "osv_source": True}
            if cve_alias:
                metadata["cve_alias"] = cve_alias
            if aliases:
                metadata["aliases"] = aliases
            # Preserve OSV raw severity for debugging
            raw_sev = vuln.get("severity")
            if raw_sev:
                metadata["osv_severity"] = raw_sev

            result = VulnerabilityResult(
                ecosystem=dependency.ecosystem,
                package_name=dependency.name,
                installed_version=dependency.version,
                vulnerability_id=osv_id,
                severity=severity,
                score=score,
                summary=summary,
                fixed_version=fixed_version,
                source="osv",
                metadata=metadata,
            )
            results.append(result)

        return results

    def _extract_severity(self, vuln: dict) -> str:
        # Try database_specific severity first
        db_spec = vuln.get("database_specific")
        if isinstance(db_spec, dict):
            sev = db_spec.get("severity")
            if isinstance(sev, str) and sev.lower() in ("critical", "high", "medium", "low", "info"):
                return sev.lower()
        # Try severity list
        severity_list = vuln.get("severity")
        if isinstance(severity_list, list):
            for item in severity_list:
                if isinstance(item, dict):
                    t = item.get("type", "")
                    # If type is CVSS_V3, score is vector, need to derive severity from score if available
                    # Look for score field
                    score_str = item.get("score", "")
                    if isinstance(score_str, str) and score_str.startswith("CVSS:"):
                        # Try to parse CVSS score via database_specific or severity score
                        pass
        # Fallback: try to infer from CVSS score if present
        score = self._extract_score(vuln)
        if score is not None:
            if score >= 9.0:
                return "critical"
            if score >= 7.0:
                return "high"
            if score >= 4.0:
                return "medium"
            if score > 0:
                return "low"
        # Default if no severity found
        return "high"

    def _extract_score(self, vuln: dict) -> float | None:
        # Try severity score
        severity_list = vuln.get("severity")
        if isinstance(severity_list, list):
            for item in severity_list:
                if isinstance(item, dict):
                    score = item.get("score")
                    if isinstance(score, (int, float)):
                        return float(score)
                    # CVSS vector string not numeric, skip
        # Try database_specific
        db_spec = vuln.get("database_specific")
        if isinstance(db_spec, dict):
            cvss = db_spec.get("cvss")
            if isinstance(cvss, (int, float)):
                return float(cvss)
            # Sometimes severity is numeric
            sev = db_spec.get("severity")
            if isinstance(sev, (int, float)):
                return float(sev)
        # No score
        return None

    def _extract_fixed_version(self, vuln: dict) -> str | None:
        fixed_versions: list[str] = []
        # Check top-level database_specific first
        db_top = vuln.get("database_specific")
        if isinstance(db_top, dict):
            fixed = db_top.get("fixed_version")
            if fixed and str(fixed).strip() not in fixed_versions:
                fixed_versions.append(str(fixed).strip())
        affected = vuln.get("affected")
        if isinstance(affected, list):
            for aff in affected:
                if not isinstance(aff, dict):
                    continue
                ranges = aff.get("ranges")
                if isinstance(ranges, list):
                    for r in ranges:
                        if not isinstance(r, dict):
                            continue
                        events = r.get("events")
                        if isinstance(events, list):
                            for ev in events:
                                if isinstance(ev, dict) and "fixed" in ev:
                                    fixed = str(ev["fixed"]).strip()
                                    if fixed and fixed not in fixed_versions:
                                        fixed_versions.append(fixed)
                # Also check database_specific fixed inside affected
                db_spec = aff.get("database_specific")
                if isinstance(db_spec, dict):
                    fixed = db_spec.get("fixed_version")
                    if fixed and str(fixed).strip() not in fixed_versions:
                        fixed_versions.append(str(fixed).strip())
        if len(fixed_versions) == 1:
            return fixed_versions[0]
        if len(fixed_versions) > 1:
            # Multiple fixes ambiguous, do not invent
            return None
        return None

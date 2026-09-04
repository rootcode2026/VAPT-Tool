"""
S4.4 Evidence Provenance & Confidence Enrichment
Deterministic, bounded, no DB, no network, no LLM.
"""

from __future__ import annotations

from typing import Any

# Evidence type vocabulary — extensible for AppSec (additive)
EVIDENCE_TYPES = {
    "scanner_output",
    "http_response",
    "http_request",
    "url",
    "hostname",
    "ip",
    "port",
    "source_code",
    "dependency",
    "configuration",
    "dns_record",
    "tls_certificate",
    "technology_detection",
    "unknown",
    # AppSec families (additive, bounded)
    "secret",
    "container_layer",
    "iac_resource",
    "api_endpoint",
    "repository",
}

def _classify_evidence_type(normalized: dict[str, Any], scanner: str) -> str:
    # Deterministic primary type
    # AppSec families first
    if scanner in ("gitleaks", "trufflehog", "secrets"):
        return "secret"
    if scanner in ("trivy", "grype", "container"):
        return "container_layer"
    if scanner in ("checkov", "kics", "iac", "terraform"):
        return "iac_resource"
    if scanner in ("zap_api", "api", "openapi"):
        return "api_endpoint"
    # Priority: source_code for SAST (file), dependency for SCA (ecosystem/package), then specific location types
    if scanner == "sca":
        return "dependency"
    if normalized.get("file"):
        return "source_code"
    if normalized.get("parameter"):
        # Parameter often with url/host
        if normalized.get("url"):
            return "http_request"
        return "unknown"
    if normalized.get("url"):
        # Check if scanner is nuclei/zap/nikto/http_fingerprint -> http_response
        if scanner in ("nuclei", "zap", "nikto", "http_fingerprint"):
            return "http_response"
        return "url"
    if normalized.get("hostname") and not normalized.get("url"):
        # Check if scanner is dns/subdomain
        if scanner in ("dns", "subdomain"):
            return "dns_record"
        if scanner == "tls":
            return "tls_certificate"
        return "hostname"
    if normalized.get("ip"):
        return "ip"
    if normalized.get("port"):
        return "port"
    if normalized.get("asset_type") == "technology" or normalized.get("technology"):
        return "technology_detection"
    if normalized.get("asset_type") in ("package", "container_image", "repository", "source_file"):
        # AppSec asset types map to evidence
        at = normalized.get("asset_type")
        if at == "package":
            return "dependency"
        if at == "container_image":
            return "container_layer"
        if at == "source_file":
            return "source_code"
        if at == "repository":
            return "repository"
    # Check for SCA dependency signals
    if normalized.get("ecosystem") or normalized.get("package_name"):
        return "dependency"
    # Check for evidence text containing dependency
    ev = normalized.get("normalized_evidence") or ""
    if "package" in str(ev).lower() and "version" in str(ev).lower():
        return "dependency"
    return "unknown"

def _normalize_evidence_type(evidence_type: str) -> str:
    if evidence_type in EVIDENCE_TYPES:
        return evidence_type
    return "unknown"

def build_evidence_provenance(correlated_finding: dict[str, Any] | None) -> dict[str, Any]:
    """
    Build evidence provenance for a correlated finding.
    Bounded, deterministic, no mutation.
    """
    if correlated_finding is None or not isinstance(correlated_finding, dict):
        return {
            "evidence_items": [],
            "evidence_count": 0,
            "independent_scanner_count": 0,
            "scanners": [],
            "evidence_types": [],
            "coverage": {
                "has_asset": False,
                "has_location": False,
                "has_url": False,
                "has_hostname": False,
                "has_ip": False,
                "has_port": False,
                "has_parameter": False,
                "has_file": False,
                "has_cve": False,
                "has_cwe": False,
                "has_rule_id": False,
                "has_evidence": False,
            },
            "provenance_quality_score": 0,
            "provenance_quality_level": "low",
            "cves": [],
            "cwes": [],
            "rule_ids": [],
        }

    # Extract fields from correlated finding
    finding_count = int(correlated_finding.get("finding_count") or 0)
    scanners = correlated_finding.get("scanners") or []
    if not isinstance(scanners, list):
        scanners = []
    scanners = sorted({str(s).lower() for s in scanners if s})[:20]

    # Evidence list from S4.2
    raw_evidence = correlated_finding.get("evidence") or []
    if not isinstance(raw_evidence, list):
        raw_evidence = []

    # Build enriched evidence items
    enriched: list[dict] = []
    seen_ev_keys: set[str] = set()
    for ev in raw_evidence:
        if not isinstance(ev, dict):
            continue
        scanner = str(ev.get("scanner") or correlated_finding.get("scanners", [""])[0] if correlated_finding.get("scanners") else "").lower() or "unknown"
        evidence_text = str(ev.get("evidence") or "")[:500]
        fingerprint = str(ev.get("fingerprint") or correlated_finding.get("fingerprint") or "")
        # Deduplicate by scanner+fingerprint+evidence (allow empty evidence for file-based)
        key = f"{scanner}:{fingerprint}:{evidence_text[:100]}"
        if key in seen_ev_keys:
            continue
        seen_ev_keys.add(key)
        # Determine evidence type
        norm_for_type = {
            "file": correlated_finding.get("file"),
            "parameter": correlated_finding.get("parameter"),
            "url": correlated_finding.get("url"),
            "hostname": correlated_finding.get("hostname"),
            "ip": correlated_finding.get("ip"),
            "port": correlated_finding.get("port"),
            "asset_type": correlated_finding.get("asset_type"),
            "normalized_evidence": evidence_text,
            "ecosystem": correlated_finding.get("ecosystem") or (correlated_finding.get("metadata") or {}).get("ecosystem") if isinstance(correlated_finding.get("metadata"), dict) else None,
            "package_name": correlated_finding.get("package_name"),
        }
        ev_type = _classify_evidence_type(norm_for_type, scanner)
        ev_type = _normalize_evidence_type(ev_type)
        # Allow evidence items even with empty evidence_text if file-based (SAST) or scanner is sca
        if not evidence_text and ev_type not in ("source_code", "dependency"):
            continue
        enriched.append({
            "scanner": scanner,
            "fingerprint": fingerprint,
            "evidence": evidence_text[:500] if evidence_text else "",
            "evidence_type": ev_type,
            "asset_id": correlated_finding.get("asset_id"),
            "asset_type": correlated_finding.get("asset_type"),
            "asset_value": correlated_finding.get("asset_value"),
            "hostname": correlated_finding.get("hostname"),
            "url": correlated_finding.get("url"),
            "ip": correlated_finding.get("ip"),
            "port": correlated_finding.get("port"),
            "parameter": correlated_finding.get("parameter"),
            "file": correlated_finding.get("file"),
            "line": correlated_finding.get("line"),
            "rule_id": correlated_finding.get("rule_id"),
            "cve": correlated_finding.get("cve"),
            "cwe": correlated_finding.get("cwe"),
        })
        if len(enriched) >= 50:
            break
    # Fallback: if no evidence items but correlated finding has file (SAST) or scanner sca, create synthetic
    if not enriched and (correlated_finding.get("file") or correlated_finding.get("scanners") and "sca" in [str(s).lower() for s in correlated_finding.get("scanners", [])]):
        # Create a synthetic evidence item for file-based or SCA
        scanner = str(correlated_finding.get("scanners", ["unknown"])[0] if correlated_finding.get("scanners") else "unknown").lower() or "unknown"
        if correlated_finding.get("file"):
            ev_type = "source_code"
        elif scanner == "sca":
            ev_type = "dependency"
        else:
            ev_type = "unknown"
        enriched.append({
            "scanner": scanner,
            "fingerprint": str(correlated_finding.get("fingerprint") or ""),
            "evidence": "",
            "evidence_type": ev_type,
            "asset_id": correlated_finding.get("asset_id"),
            "asset_type": correlated_finding.get("asset_type"),
            "asset_value": correlated_finding.get("asset_value"),
            "hostname": correlated_finding.get("hostname"),
            "url": correlated_finding.get("url"),
            "ip": correlated_finding.get("ip"),
            "port": correlated_finding.get("port"),
            "parameter": correlated_finding.get("parameter"),
            "file": correlated_finding.get("file"),
            "line": correlated_finding.get("line"),
            "rule_id": correlated_finding.get("rule_id"),
            "cve": correlated_finding.get("cve"),
            "cwe": correlated_finding.get("cwe"),
        })

    # Deterministic ordering
    enriched.sort(key=lambda x: (x["scanner"], x["fingerprint"], x["evidence"]))

    # Scanner counts
    independent_scanner_count = len(scanners)
    evidence_count = len(enriched)

    # Evidence types
    evidence_types = sorted({e["evidence_type"] for e in enriched})[:20]

    # CVE/CWE/rule aggregation (from correlated finding)
    cves = correlated_finding.get("cves") or ([correlated_finding.get("cve")] if correlated_finding.get("cve") else [])
    cwes = correlated_finding.get("cwes") or ([correlated_finding.get("cwe")] if correlated_finding.get("cwe") else [])
    rule_ids = correlated_finding.get("rule_ids") or ([correlated_finding.get("rule_id")] if correlated_finding.get("rule_id") else [])
    # Ensure bounded and sorted
    cves = sorted({str(c).strip().upper() for c in cves if c})[:20]
    cwes = sorted({str(c).strip().upper() for c in cwes if c})[:20]
    rule_ids = sorted({str(c).strip().upper() for c in rule_ids if c})[:20]

    # Coverage
    has_asset = bool(correlated_finding.get("asset_id"))
    has_url = bool(correlated_finding.get("url"))
    has_hostname = bool(correlated_finding.get("hostname"))
    has_ip = bool(correlated_finding.get("ip"))
    has_port = bool(correlated_finding.get("port"))
    has_parameter = bool(correlated_finding.get("parameter"))
    has_file = bool(correlated_finding.get("file"))
    has_location = any([has_url, has_hostname, has_ip, has_port, has_parameter, has_file])
    has_cve = bool(cves)
    has_cwe = bool(cwes)
    has_rule_id = bool(rule_ids)
    has_evidence = evidence_count > 0

    coverage = {
        "has_asset": has_asset,
        "has_location": has_location,
        "has_url": has_url,
        "has_hostname": has_hostname,
        "has_ip": has_ip,
        "has_port": has_port,
        "has_parameter": has_parameter,
        "has_file": has_file,
        "has_cve": has_cve,
        "has_cwe": has_cwe,
        "has_rule_id": has_rule_id,
        "has_evidence": has_evidence,
    }

    # Provenance quality score 0-100
    score = 0
    if scanners:
        score += 20
    if has_evidence:
        score += 20
    if has_asset or has_location:
        score += 20
    if has_url or has_hostname or has_ip:
        score += 15
    if has_port or has_parameter or has_file:
        score += 10
    if has_cve or has_cwe or has_rule_id:
        score += 10
    if independent_scanner_count >= 2:
        score += 5
    if score > 100:
        score = 100

    if score >= 90:
        level = "very_high"
    elif score >= 70:
        level = "high"
    elif score >= 40:
        level = "medium"
    else:
        level = "low"

    return {
        "evidence_items": enriched,
        "evidence_count": evidence_count,
        "independent_scanner_count": independent_scanner_count,
        "scanners": scanners,
        "evidence_types": evidence_types,
        "coverage": coverage,
        "provenance_quality_score": score,
        "provenance_quality_level": level,
        "cves": cves,
        "cwes": cwes,
        "rule_ids": rule_ids,
    }

def enrich_finding_confidence(
    validation_assessment: dict[str, Any] | None,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Enrich S4.3 confidence with provenance quality.
    Bounded enrichment: +5 if provenance_quality >=70, +5 if evidence_count>=2 and independent>=2, max 100.
    Does not double-count same evidence, documented distinction.
    """
    if validation_assessment is None or not isinstance(validation_assessment, dict):
        return validation_assessment or {}
    if provenance is None or not isinstance(provenance, dict):
        return validation_assessment

    # Copy to avoid mutation
    enriched = dict(validation_assessment)
    original_score = int(validation_assessment.get("confidence_score") or 0)
    new_score = original_score

    prov_score = int(provenance.get("provenance_quality_score") or 0)
    if prov_score >= 70:
        new_score += 5
    if provenance.get("evidence_count", 0) >= 2 and provenance.get("independent_scanner_count", 0) >= 2:
        new_score += 5
    if new_score > 100:
        new_score = 100

    # Determine new level
    if new_score >= 90:
        new_level = "very_high"
    elif new_score >= 70:
        new_level = "high"
    elif new_score >= 40:
        new_level = "medium"
    else:
        new_level = "low"

    enriched["confidence_score"] = new_score
    enriched["confidence_level"] = new_level

    # Extend reasons with provenance-specific, bounded, sorted
    reasons = list(validation_assessment.get("reasons") or [])
    prov_reasons: list[str] = []
    if provenance.get("evidence_count", 0) > 0:
        prov_reasons.append("Evidence has a traceable scanner source.")
        prov_reasons.append("Finding has bounded evidence.")
    if provenance.get("independent_scanner_count", 0) >= 2:
        prov_reasons.append("Finding has multiple independent evidence sources.")
    if provenance.get("coverage", {}).get("has_url"):
        prov_reasons.append("Evidence includes an affected URL.")
    if provenance.get("coverage", {}).get("has_port"):
        prov_reasons.append("Evidence includes an affected port.")
    if provenance.get("coverage", {}).get("has_cve"):
        prov_reasons.append("Evidence includes a CVE.")
    if provenance.get("coverage", {}).get("has_file"):
        prov_reasons.append("Evidence includes a source-code location.")

    # Merge and dedup, keep fixed order as above, but sort for determinism if needed
    # Keep original reasons order, then add new ones that are not already present
    for r in prov_reasons:
        if r not in reasons:
            reasons.append(r)
    # Bound to 20
    reasons = reasons[:20]
    enriched["reasons"] = reasons

    # Extend signals
    signals = dict(validation_assessment.get("signals") or {})
    signals["evidence_count"] = provenance.get("evidence_count", 0)
    signals["independent_scanner_count"] = provenance.get("independent_scanner_count", 0)
    signals["provenance_quality_score"] = provenance.get("provenance_quality_score", 0)
    signals["has_evidence"] = provenance.get("coverage", {}).get("has_evidence", False)
    signals["has_url"] = provenance.get("coverage", {}).get("has_url", False)
    signals["has_hostname"] = provenance.get("coverage", {}).get("has_hostname", False)
    signals["has_ip"] = provenance.get("coverage", {}).get("has_ip", False)
    signals["has_port"] = provenance.get("coverage", {}).get("has_port", False)
    signals["has_parameter"] = provenance.get("coverage", {}).get("has_parameter", False)
    signals["has_file"] = provenance.get("coverage", {}).get("has_file", False)
    enriched["signals"] = signals

    return enriched

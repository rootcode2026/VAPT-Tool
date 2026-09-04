"""
S5.1 Finding Risk Enrichment — additive, deterministic, no DB/network/AI.
Reuses existing RiskAssessmentEngine terminology where possible.
"""

from __future__ import annotations

from typing import Any

# Reuse existing severity scores for contribution
SEVERITY_SCORES = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 5}
SEVERITY_CONTRIBUTION = {"critical": 35, "high": 20, "medium": 10, "low": 3, "info": 0}

RISK_LEVELS = {
    90: "critical",
    75: "high",
    50: "medium",
    25: "low",
    5: "informational",
}

def _risk_level(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 75:
        return "high"
    if score >= 50:
        return "medium"
    if score >= 25:
        return "low"
    return "informational"

def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    return "D"

def enrich_finding_risk(
    finding: dict | None = None,
    *,
    normalized: dict | None = None,
    correlated: dict | None = None,
    validation: dict | None = None,
    provenance: dict | None = None,
    asset: dict | None = None,
) -> dict[str, Any]:
    """
    Deterministic risk enrichment for a single finding.
    Never downgrades original severity, never changes validation state, never fabricates unavailable signals.
    """
    # Use provided normalized or derive minimal
    norm = normalized or {}
    # Severity contribution
    severity = None
    if finding and isinstance(finding, dict):
        severity = str(finding.get("severity") or norm.get("severity") or "info").lower()
    elif norm:
        severity = str(norm.get("severity") or "info").lower()
    else:
        severity = "info"
    if severity not in SEVERITY_SCORES:
        severity = "info"
    severity_score = SEVERITY_SCORES[severity]
    severity_contrib = SEVERITY_CONTRIBUTION.get(severity, 0)

    # Confidence contribution from validation
    confidence_score = 0
    confidence_level = "low"
    if isinstance(validation, dict):
        confidence_score = int(validation.get("confidence_score") or 0)
        confidence_level = str(validation.get("confidence_level") or "low")

    # Corroboration contribution
    scanner_count = 1
    scanners = []
    if isinstance(validation, dict):
        scanner_count = int(validation.get("scanner_count") or validation.get("signals", {}).get("scanner_count", 1) if isinstance(validation.get("signals"), dict) else 1)
        scanners = validation.get("scanners") or validation.get("signals", {}).get("scanners", []) if isinstance(validation.get("signals"), dict) else []
    elif isinstance(correlated, dict):
        scanner_count = int(correlated.get("scanner_count") or 1)
        scanners = correlated.get("scanners") or []
    # Clamp
    if scanner_count < 1:
        scanner_count = 1
    if scanner_count == 1:
        corroboration_contrib = 0
    elif scanner_count == 2:
        corroboration_contrib = 10
    else:
        corroboration_contrib = 15

    # Evidence/provenance quality
    provenance_quality = 0
    evidence_count = 0
    if isinstance(provenance, dict):
        provenance_quality = int(provenance.get("provenance_quality_score") or 0)
        evidence_count = int(provenance.get("evidence_count") or 0)
    elif isinstance(validation, dict) and isinstance(validation.get("signals"), dict):
        # Fallback from validation signals
        provenance_quality = int(validation.get("signals", {}).get("provenance_quality_score") or 0)

    # External/exposed asset signal
    exposed = False
    has_asset = False
    # Check asset, correlated, normalized, provenance
    if isinstance(asset, dict) and asset:
        has_asset = True
    if isinstance(correlated, dict) and correlated.get("asset_id"):
        has_asset = True
    if isinstance(provenance, dict) and provenance.get("coverage", {}).get("has_asset"):
        has_asset = True
    # Check for internet_facing / exposed
    if isinstance(provenance, dict):
        cov = provenance.get("coverage") or {}
        if cov.get("has_url") or cov.get("has_ip") or cov.get("has_hostname"):
            # Use finding's exposure if available via normalized
            pass
    # Use normalized hostname/url/ip as proxy for exposed
    exposed_signals = []
    if isinstance(normalized := norm, dict):
        if normalized.get("hostname") or normalized.get("url") or normalized.get("ip"):
            exposed_signals.append("has_location")
    if isinstance(provenance, dict) and provenance.get("coverage", {}).get("has_url"):
        exposed = True
    if isinstance(provenance, dict) and provenance.get("coverage", {}).get("has_ip"):
        exposed = True

    # CVE/CWE/rule presence
    has_cve = False
    has_cwe = False
    has_rule = False
    if isinstance(normalized, dict):
        has_cve = bool(normalized.get("cve"))
        has_cwe = bool(normalized.get("cwe"))
        has_rule = bool(normalized.get("rule_id"))
    if isinstance(correlated, dict):
        has_cve = has_cve or bool(correlated.get("cve"))
        has_cwe = has_cwe or bool(correlated.get("cwe"))
        has_rule = has_rule or bool(correlated.get("rule_id"))
    if isinstance(provenance, dict):
        cov = provenance.get("coverage") or {}
        has_cve = has_cve or bool(cov.get("has_cve"))
        has_cwe = has_cwe or bool(cov.get("has_cwe"))
        has_rule = has_rule or bool(cov.get("has_rule_id"))

    # Build signals list
    signals: list[str] = []
    available: list[str] = []
    unavailable: list[str] = []

    # Severity always available
    signals.append(f"severity:{severity}")
    available.append("severity")
    # Score
    signals.append(f"score:{severity_score}")
    available.append("score")
    # Confidence
    if isinstance(validation, dict) and "confidence_score" in validation:
        signals.append(f"confidence:{confidence_score}")
        available.append("confidence")
    else:
        unavailable.append("confidence")
    # Corroboration
    signals.append(f"corroboration:count={scanner_count}")
    available.append("corroboration")
    # Evidence quality
    if isinstance(provenance, dict) and "provenance_quality_score" in provenance:
        signals.append(f"provenance_quality:{provenance_quality}")
        available.append("provenance_quality")
    else:
        unavailable.append("provenance_quality")
    # Exposed
    if exposed or has_asset:
        signals.append("exposed_asset" if exposed else "asset")
        available.append("exposure")
    else:
        unavailable.append("exposure")
    # CVE/CWE/rule
    if has_cve:
        signals.append("cve")
        available.append("cve")
    else:
        unavailable.append("cve")
    if has_cwe:
        signals.append("cwe")
        available.append("cwe")
    else:
        unavailable.append("cwe")
    if has_rule:
        signals.append("rule")
        available.append("rule")
    else:
        unavailable.append("rule")
    # Unavailable business signals (never fabricated)
    for sig in ["exploitability", "epss", "kev", "business_criticality", "asset_criticality"]:
        unavailable.append(sig)

    # Deduplicate available/unavailable
    available = sorted(set(available))
    unavailable = sorted(set(unavailable))

    # Calculate risk_score (0-100) deterministic, additive
    # Start with severity contribution as base, then add bounded contributions
    risk_score = severity_contrib
    # Confidence contribution: map confidence_score 0-100 to 0-15
    risk_score += int(confidence_score / 100 * 15)
    # Corroboration
    risk_score += corroboration_contrib
    # Evidence quality: provenance_quality /10
    risk_score += int(provenance_quality / 10)
    # Exposed: +10 if exposed
    if exposed:
        risk_score += 10
    # CVE/CWE/rule: +5 each capped
    if has_cve:
        risk_score += 5
    if has_cwe:
        risk_score += 3
    if has_rule:
        risk_score += 2
    # Clamp 0-100
    if risk_score > 100:
        risk_score = 100
    if risk_score < 0:
        risk_score = 0

    risk_level = _risk_level(risk_score)
    grade = _grade(risk_score)

    # Reasons deterministic, bounded
    reasons: list[str] = []
    reasons.append(f"Severity {severity} contributes {severity_contrib} points.")
    reasons.append(f"Confidence {confidence_level} ({confidence_score}) contributes {int(confidence_score/100*15)} points.")
    if scanner_count >= 2:
        reasons.append(f"Corroborated by {scanner_count} scanners contributes {corroboration_contrib} points.")
    if has_cve:
        reasons.append("CVE presence contributes 5 points.")
    if has_cwe:
        reasons.append("CWE presence contributes 3 points.")
    if has_rule:
        reasons.append("Rule ID presence contributes 2 points.")
    if exposed:
        reasons.append("Exposed asset contributes 10 points.")
    if provenance_quality:
        reasons.append(f"Provenance quality {provenance_quality} contributes {int(provenance_quality/10)} points.")

    # Bounded
    reasons = reasons[:20]

    # Never downgrade original severity - preserve it
    original_severity = None
    if isinstance(finding, dict):
        original_severity = finding.get("severity")

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "grade": grade,
        "signals": sorted(signals),
        "reasons": reasons,
        "available_signals": available,
        "unavailable_signals": unavailable,
        "severity": severity,
        "original_severity": original_severity,
        "confidence_score": confidence_score,
        "confidence_level": confidence_level,
        "scanner_count": scanner_count,
        "scanners": sorted(set(scanners))[:20] if isinstance(scanners, list) else [],
        "evidence_count": evidence_count,
        "provenance_quality": provenance_quality,
    }

def enrich_findings_risk(findings: list[dict]) -> list[dict]:
    """Batch O(N) enrichment for list of findings (each may be dict with finding+normalized+correlated+validation+provenance)."""
    if not findings:
        return []
    result = []
    for item in findings:
        # Allow item to be a dict with keys finding, normalized, correlated, validation, provenance, asset
        if isinstance(item, dict) and "finding" in item:
            enriched = enrich_finding_risk(
                finding=item.get("finding"),
                normalized=item.get("normalized"),
                correlated=item.get("correlated"),
                validation=item.get("validation"),
                provenance=item.get("provenance"),
                asset=item.get("asset"),
            )
            # Preserve original finding fields
            enriched["finding"] = item.get("finding")
            result.append(enriched)
        else:
            # Assume item is already a finding dict
            enriched = enrich_finding_risk(finding=item)
            enriched["finding"] = item
            result.append(enriched)
    # Deterministic ordering
    result.sort(key=lambda x: (x.get("risk_score", 0), str(x.get("finding", {}).get("title") if isinstance(x.get("finding"), dict) else "")))
    return result

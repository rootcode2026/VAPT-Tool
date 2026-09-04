"""
S4.3 Finding Validation Lifecycle & Confidence Foundation
Deterministic, no DB, no network, no LLM, no active validation.
"""

from __future__ import annotations

from typing import Any

# Validation states
STATE_DETECTED = "detected"
STATE_CORROBORATED = "corroborated"
STATE_NEEDS_REVIEW = "needs_review"
STATE_CONFIRMED = "confirmed"
STATE_FALSE_POSITIVE = "false_positive"
STATE_ACCEPTED_RISK = "accepted_risk"
STATE_REMEDIATED = "remediated"
STATE_REOPENED = "reopened"

VALID_STATES = {
    STATE_DETECTED,
    STATE_CORROBORATED,
    STATE_NEEDS_REVIEW,
    STATE_CONFIRMED,
    STATE_FALSE_POSITIVE,
    STATE_ACCEPTED_RISK,
    STATE_REMEDIATED,
    STATE_REOPENED,
}

# Valid transitions (in-memory only)
VALID_TRANSITIONS: dict[str, set[str]] = {
    STATE_DETECTED: {STATE_CORROBORATED, STATE_NEEDS_REVIEW, STATE_CONFIRMED, STATE_FALSE_POSITIVE, STATE_ACCEPTED_RISK},
    STATE_CORROBORATED: {STATE_NEEDS_REVIEW, STATE_CONFIRMED, STATE_FALSE_POSITIVE, STATE_ACCEPTED_RISK},
    STATE_NEEDS_REVIEW: {STATE_CONFIRMED, STATE_FALSE_POSITIVE, STATE_ACCEPTED_RISK},
    STATE_CONFIRMED: {STATE_REMEDIATED, STATE_REOPENED},
    STATE_ACCEPTED_RISK: {STATE_REOPENED},
    STATE_FALSE_POSITIVE: {STATE_REOPENED},
    STATE_REMEDIATED: {STATE_REOPENED},
    STATE_REOPENED: {STATE_DETECTED, STATE_CORROBORATED, STATE_NEEDS_REVIEW},
}

def transition_validation_state(current_state: str, requested_state: str) -> str:
    """
    Deterministic in-memory state transition helper.
    Raises ValueError for invalid transitions.
    """
    if current_state not in VALID_STATES:
        raise ValueError(f"Invalid current state: {current_state}")
    if requested_state not in VALID_STATES:
        raise ValueError(f"Invalid requested state: {requested_state}")
    allowed = VALID_TRANSITIONS.get(current_state, set())
    if requested_state not in allowed:
        raise ValueError(f"Invalid transition: {current_state} -> {requested_state}")
    return requested_state

def _confidence_level(score: int) -> str:
    if score >= 90:
        return "very_high"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"

def evaluate_finding_validation(correlated_finding: dict[str, Any] | None) -> dict[str, Any]:
    """
    Evaluate validation for a correlated finding.
    Never automatically returns confirmed/false_positive/accepted_risk/remediated/reopened unless explicitly via transition helper.
    Only returns detected or corroborated (or needs_review if logic decides, but per spec default is detected/corroborated).
    """
    if correlated_finding is None or not isinstance(correlated_finding, dict):
        raise ValueError("Invalid correlated finding")
    # Preserve original (no mutation) - work on copy of relevant fields
    # Extract signals
    scanner_count = int(correlated_finding.get("scanner_count") or 0)
    scanners = correlated_finding.get("scanners") or []
    if not isinstance(scanners, list):
        scanners = []
    scanners_sorted = sorted([str(s).lower() for s in scanners if s])
    evidence = correlated_finding.get("evidence") or []
    if not isinstance(evidence, list):
        evidence = []
    evidence_count = len(evidence)

    # Normalized location signals - use correlated_finding fields directly
    has_asset = bool(correlated_finding.get("asset_id"))
    # has_location: any of hostname, url, ip, port, file, parameter
    has_location = any(
        bool(correlated_finding.get(k))
        for k in ("hostname", "url", "ip", "port", "file", "parameter")
    )
    # Also check url/hostname from original if needed
    has_cve = bool(correlated_finding.get("cve") or (correlated_finding.get("cves") and any(correlated_finding.get("cves"))))
    # Check cves list
    if not has_cve and correlated_finding.get("cves"):
        cves = correlated_finding.get("cves")
        if isinstance(cves, list) and any(cves):
            has_cve = True
    has_cwe = bool(correlated_finding.get("cwe") or (correlated_finding.get("cwes") and any(correlated_finding.get("cwes"))))
    if not has_cwe and correlated_finding.get("cwes"):
        cwes = correlated_finding.get("cwes")
        if isinstance(cwes, list) and any(cwes):
            has_cwe = True
    has_rule_id = bool(correlated_finding.get("rule_id") or (correlated_finding.get("rule_ids") and any(correlated_finding.get("rule_ids"))))
    if not has_rule_id and correlated_finding.get("rule_ids"):
        rule_ids = correlated_finding.get("rule_ids")
        if isinstance(rule_ids, list) and any(rule_ids):
            has_rule_id = True

    # Confidence scoring
    if scanner_count >= 3:
        base = 85
    elif scanner_count == 2:
        base = 70
    elif scanner_count == 1:
        base = 40
    else:
        base = 0

    score = base
    if has_asset:
        score += 5
    if has_location:
        score += 5
    if has_cve:
        score += 5
    if has_cwe or has_rule_id:
        score += 5
    if score > 100:
        score = 100
    if score < 0:
        score = 0

    level = _confidence_level(score)

    # State: detected or corroborated (never confirmed etc.)
    if scanner_count >= 2:
        state = STATE_CORROBORATED
    else:
        state = STATE_DETECTED

    # Signals bounded
    signals = {
        "scanner_count": scanner_count,
        "scanners": scanners_sorted,
        "has_asset": has_asset,
        "has_location": has_location,
        "has_cve": has_cve,
        "has_cwe": has_cwe,
        "has_rule_id": has_rule_id,
        "evidence_count": evidence_count,
    }

    # Reasons deterministic, sorted, bounded
    reasons: list[str] = []
    if scanner_count == 1:
        reasons.append("Detected by one scanner.")
    elif scanner_count >= 2:
        reasons.append("Corroborated by multiple scanners.")
    if has_asset:
        reasons.append("Finding has a normalized affected asset.")
    if has_location:
        # Prefer specific
        if correlated_finding.get("url"):
            reasons.append("Finding has a normalized affected URL.")
        elif correlated_finding.get("hostname"):
            reasons.append("Finding has a normalized affected hostname.")
        elif correlated_finding.get("ip"):
            reasons.append("Finding has a normalized affected IP.")
        elif correlated_finding.get("file"):
            reasons.append("Finding has a normalized affected file.")
        else:
            reasons.append("Finding has a normalized affected location.")
    if has_cve:
        reasons.append("Finding references a CVE.")
    if has_cwe:
        reasons.append("Finding references a CWE.")
    if has_rule_id and not has_cwe:
        # Only add rule reason if not already covered by CWE? But spec says CWE or rule
        reasons.append("Finding references a rule ID.")
    elif has_rule_id and has_cwe:
        # Still add rule for completeness, but keep bounded
        reasons.append("Finding references a rule ID.")
    # Ensure deterministic sorted? But spec says sorted or fixed order - we generate in fixed order above, which is deterministic
    # Deduplicate and keep order
    seen = set()
    deduped_reasons = []
    for r in reasons:
        if r not in seen:
            seen.add(r)
            deduped_reasons.append(r)

    # Human review flag
    requires_human_review = True
    # For detected/corroborated, always true per spec 10
    # For other states (not auto), would be false, but S4.3 never auto returns those

    return {
        "state": state,
        "confidence_score": score,
        "confidence_level": level,
        "signals": signals,
        "reasons": deduped_reasons,
        "scanner_count": scanner_count,
        "scanners": scanners_sorted,
        "evidence_count": evidence_count,
        "requires_human_review": requires_human_review,
    }

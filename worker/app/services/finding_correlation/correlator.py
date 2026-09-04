"""
S4.2 Finding Correlation — deterministic cross-scanner grouping.
Uses S4.1 fingerprint as primary identity, correlation_key as secondary signal (not sufficient alone).
Conservative, project-isolated, no DB, no network.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict, Counter
from typing import Any

from app.services.finding_correlation.normalizer import (
    normalize_finding,
    fingerprint_finding,
    correlation_key,
)

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

def _highest_severity(severities: list[str]) -> str:
    best = "info"
    best_rank = 0
    for s in severities:
        rank = SEVERITY_RANK.get(s, 0)
        if rank > best_rank:
            best_rank = rank
            best = s
    return best

def _deterministic_title(findings: list[dict], severities: list[str]) -> str | None:
    # Prefer title from highest severity, then lexical
    max_rank = max((SEVERITY_RANK.get(s, 0) for s in severities), default=0)
    candidates = [f for f, s in zip(findings, severities) if SEVERITY_RANK.get(s, 0) == max_rank]
    titles = [f.get("title") for f in candidates if f.get("title")]
    if not titles:
        titles = [f.get("title") for f in findings if f.get("title")]
    if not titles:
        return None
    # Deterministic lexical
    return sorted(set(titles))[0]

def _collect_unique(values: list[Any]) -> list[Any]:
    uniq2 = []
    seen2 = set()
    for v in values:
        if v is None:
            continue
        s = str(v).strip()
        if not s:
            continue
        # For CVE/CWE, use upper
        lower = s
        if isinstance(v, str) and v.upper().startswith("CVE"):
            lower = v.upper()
        elif isinstance(v, str) and v.upper().startswith("CWE"):
            lower = v.upper()
        else:
            lower = s.lower() if isinstance(v, str) else s
        if lower not in seen2:
            seen2.add(lower)
            uniq2.append(v)
    return sorted(uniq2, key=lambda x: str(x))

def correlate_findings(findings: list[dict]) -> dict[str, Any]:
    """
    Correlate findings deterministically.

    Returns:
    {
        "correlated_findings": [...],
        "total_input_findings": int,
        "total_correlated_findings": int,
        "duplicate_count": int,
        "scanner_correlation_count": int,
        "stats": {...}
    }
    """
    total_input = len(findings) if findings else 0
    if not findings:
        return {
            "correlated_findings": [],
            "total_input_findings": 0,
            "total_correlated_findings": 0,
            "duplicate_count": 0,
            "scanner_correlation_count": 0,
            "stats": {"by_scanner_count": {}},
        }

    # Normalize once, compute fingerprint and correlation_key
    normalized_entries: list[dict] = []
    for idx, f in enumerate(findings):
        # Preserve original index for deterministic ordering
        try:
            norm = normalize_finding(f)
            fp = fingerprint_finding(f)
            ck = correlation_key(f)
        except Exception:
            # If normalization fails, treat as unique
            norm = {"normalized_title": str(f.get("title") or ""), "severity": "info"}
            fp = hashlib.sha256(f"fallback-{idx}-{json.dumps(f, sort_keys=True)}".encode()).hexdigest()
            ck = fp
        # Project isolation: extract project_id if present
        project_id = None
        # Check various places
        for k in ("project_id", "projectId"):
            if k in f and f[k]:
                project_id = str(f[k])
                break
            meta = f.get("metadata") or {}
            if isinstance(meta, dict) and k in meta and meta[k]:
                project_id = str(meta[k])
                break
            norm_project = norm.get("normalized_metadata", {}).get(k) if isinstance(norm.get("normalized_metadata"), dict) else None
            if norm_project:
                project_id = str(norm_project)
                break
        # Also check finding.get("project_id")
        if not project_id and f.get("project_id"):
            project_id = str(f.get("project_id"))
        normalized_entries.append({
            "original": f,
            "original_index": idx,
            "normalized": norm,
            "fingerprint": fp,
            "correlation_key": ck,
            "project_id": project_id,
        })

    # Group by (project_id, fingerprint) — primary identity
    # Use project_id as part of key to ensure isolation
    groups: dict[tuple[str | None, str], list[dict]] = defaultdict(list)
    for entry in normalized_entries:
        key = (entry["project_id"], entry["fingerprint"])
        groups[key].append(entry)

    correlated_findings: list[dict] = []

    for (proj, fp), members in groups.items():
        # Sort members deterministically for aggregation
        members_sorted = sorted(members, key=lambda x: (x["original"].get("scanner", ""), x["fingerprint"], x["original_index"]))

        # Aggregate
        severities = [m["normalized"].get("severity") or "info" for m in members_sorted]
        scores = [m["normalized"].get("score") for m in members_sorted if m["normalized"].get("score") is not None]
        highest_sev = _highest_severity(severities)
        highest_score = max(scores) if scores else None

        # Title
        title = _deterministic_title([m["original"] for m in members_sorted], severities)

        # CVE/CWE/rule
        cves = _collect_unique([m["normalized"].get("cve") for m in members_sorted])
        cwes = _collect_unique([m["normalized"].get("cwe") for m in members_sorted])
        rule_ids = _collect_unique([m["normalized"].get("rule_id") for m in members_sorted])

        # Choose primary cve/cwe/rule (first deterministic)
        primary_cve = cves[0] if cves else None
        primary_cwe = cwes[0] if cwes else None
        primary_rule = rule_ids[0] if rule_ids else None

        # Scanners
        scanners = sorted({str(m["original"].get("scanner") or m["normalized"].get("scanner") or "").lower() for m in members_sorted if m["original"].get("scanner") or m["normalized"].get("scanner")})
        scanners = [s for s in scanners if s]
        scanner_count = len(scanners)
        finding_count = len(members_sorted)

        # Asset/location: choose most common or first deterministic
        # For asset, take first non-None
        asset_id = next((m["normalized"].get("asset_id") for m in members_sorted if m["normalized"].get("asset_id")), None)
        asset_type = next((m["normalized"].get("asset_type") for m in members_sorted if m["normalized"].get("asset_type")), None)
        asset_value = next((m["normalized"].get("asset_value") for m in members_sorted if m["normalized"].get("asset_value")), None)
        hostname = next((m["normalized"].get("hostname") for m in members_sorted if m["normalized"].get("hostname")), None)
        url = next((m["normalized"].get("url") for m in members_sorted if m["normalized"].get("url")), None)
        ip = next((m["normalized"].get("ip") for m in members_sorted if m["normalized"].get("ip")), None)
        port = next((m["normalized"].get("port") for m in members_sorted if m["normalized"].get("port")), None)
        parameter = next((m["normalized"].get("parameter") for m in members_sorted if m["normalized"].get("parameter")), None)
        file = next((m["normalized"].get("file") for m in members_sorted if m["normalized"].get("file")), None)
        line = next((m["normalized"].get("line") for m in members_sorted if m["normalized"].get("line") is not None), None)

        # Evidence aggregation: preserve scanner + evidence, dedup, bounded, sorted
        evidence_items: list[dict] = []
        seen_ev: set[str] = set()
        for m in members_sorted:
            ev = m["normalized"].get("normalized_evidence") or m["original"].get("evidence")
            if ev is None:
                continue
            # Normalize evidence for dedup
            ev_norm = str(ev).strip()
            if not ev_norm:
                continue
            key = f"{m['original'].get('scanner')}:{ev_norm}"
            if key in seen_ev:
                continue
            seen_ev.add(key)
            evidence_items.append({
                "scanner": str(m["original"].get("scanner") or m["normalized"].get("scanner") or "").lower(),
                "evidence": ev_norm[:500],
                "fingerprint": m["fingerprint"],
            })
        # Deterministic ordering
        evidence_items.sort(key=lambda x: (x["scanner"], x["fingerprint"], x["evidence"]))

        # Source findings references (bounded)
        source_findings = []
        for m in members_sorted:
            source_findings.append({
                "scanner": str(m["original"].get("scanner") or m["normalized"].get("scanner") or "").lower(),
                "fingerprint": m["fingerprint"],
                "correlation_key": m["correlation_key"],
            })
        source_findings.sort(key=lambda x: (x["scanner"], x["fingerprint"]))

        # Build correlated finding
        # Use first member's normalized as base for other fields
        base_norm = members_sorted[0]["normalized"]
        correlated = {
            "fingerprint": fp,
            "correlation_key": members_sorted[0]["correlation_key"],
            "title": title,
            "normalized_title": base_norm.get("normalized_title"),
            "severity": highest_sev,
            "score": highest_score,
            "cve": primary_cve,
            "cves": cves,
            "cwe": primary_cwe,
            "cwes": cwes,
            "rule_id": primary_rule,
            "rule_ids": rule_ids,
            "asset_id": asset_id,
            "asset_type": asset_type,
            "asset_value": asset_value,
            "hostname": hostname,
            "url": url,
            "ip": ip,
            "port": port,
            "parameter": parameter,
            "file": file,
            "line": line,
            "scanner_count": scanner_count,
            "scanners": scanners,
            "finding_count": finding_count,
            "evidence": evidence_items,
            "source_findings": source_findings,
            "project_id": proj,
        }
        correlated_findings.append(correlated)

    # Deterministic ordering of correlated findings
    correlated_findings.sort(key=lambda x: x["fingerprint"])

    total_correlated = len(correlated_findings)
    duplicate_count = total_input - total_correlated

    # Stats: by scanner count
    scanner_counts = Counter(cf["scanner_count"] for cf in correlated_findings)
    # scanner_correlation_count: number with >=2 scanners
    scanner_correlation_count = sum(1 for cf in correlated_findings if cf["scanner_count"] >= 2)

    stats = {
        "by_scanner_count": dict(scanner_counts),
    }

    return {
        "correlated_findings": correlated_findings,
        "total_input_findings": total_input,
        "total_correlated_findings": total_correlated,
        "duplicate_count": duplicate_count,
        "scanner_correlation_count": scanner_correlation_count,
        "stats": stats,
    }

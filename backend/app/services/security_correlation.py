"""E12 Unified Security Signal Correlation — on-read, deterministic, bounded, no AI."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlparse
from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding

# Bounds
MAX_FINDINGS = 500
MAX_ASSETS = 500
MAX_GROUPS = 200
MAX_MEMBERS = 20
MAX_RELATIONSHIPS = 500

VALID_TYPES = {
    "DUPLICATE",
    "RELATED",
    "SAME_ROOT_CAUSE",
    "SAME_ASSET",
    "SAME_VULNERABILITY",
    "SAME_EXPOSURE",
    "ATTACK_PATH_RELATED",
    "CSPM_RELATED",
}
VALID_CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}

# Scanner compatibility matrix (which scanner pairs can correlate)
# Keep simple: allow all cross-scanner except same scanner duplicate is allowed
# But we will filter: same scanner same asset duplicate is still duplicate if same rule
COMPATIBLE = {
    # web
    "nuclei": {"zap", "nikto", "http_fingerprint", "nuclei", "zap", "api"},
    "zap": {"nuclei", "nikto", "http_fingerprint", "zap"},
    "nikto": {"nuclei", "zap", "nikto"},
    "http_fingerprint": {"nuclei", "zap", "nikto", "http_fingerprint"},
    "api": {"nuclei", "zap", "api"},
    # network
    "nmap": {"tls", "nmap", "nuclei"},
    "tls": {"nmap", "tls"},
    "dns": {"dns", "subdomain"},
    "subdomain": {"dns", "subdomain"},
    # code
    "sast": {"sca", "secrets", "sast"},
    "sca": {"sast", "container", "sca"},
    "secrets": {"secrets", "sast"},
    "container": {"sca", "container"},
    "iac": {"iac", "container"},
    # cloud
    "cloud": {"cloud", "cspm"},
    "cspm": {"cloud"},
}

def _is_compatible(a: str, b: str) -> bool:
    a = a.lower()
    b = b.lower()
    if a == b:
        return True
    return b in COMPATIBLE.get(a, set()) or a in COMPATIBLE.get(b, set())

def _normalize_url(url: str | None) -> str:
    if not url:
        return ""
    try:
        u = url.strip()
        parsed = urlparse(u if "://" in u else f"http://{u}")
        host = parsed.hostname or ""
        host = host.lower().strip()
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or ""
        # Remove trailing slash for root only
        if path == "/":
            path = ""
        # Keep path and query (do not over-normalize)
        query = f"?{parsed.query}" if parsed.query else ""
        # Reconstruct without scheme for bucketing (scheme normalized)
        return f"{host}{port}{path}{query}".lower().rstrip("/")
    except Exception:
        return url.lower().strip().rstrip("/")

def _normalize_hostname(h: str | None) -> str:
    if not h:
        return ""
    return h.strip().lower().rstrip(".")

def _normalize_package(pkg: str | None) -> str:
    if not pkg:
        return ""
    return pkg.strip().lower()

def _normalize_file(f: str | None) -> str:
    if not f:
        return ""
    return f.strip().lower().replace("\\", "/")

def _sanitize(text: str) -> str:
    if not text:
        return ""
    lower = text.lower()
    if any(k in lower for k in ("secret", "private_key", "credential", "token", "password", "api_key")):
        return "[REDACTED]"
    return text[:300]

def _canonical_fingerprint(project_id: str, asset_id: str | None, rule_id: str | None, cve: str | None, cwe: str | None, location: str | None) -> str:
    parts = [
        project_id,
        (asset_id or "").lower(),
        (rule_id or "").lower(),
        (cve or "").lower(),
        (cwe or "").lower(),
        (location or "").lower(),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def _confidence_and_score(exact_match: bool, same_asset: bool, same_cve: bool, same_location: bool, compatible: bool) -> tuple[str, int]:
    score = 0
    if exact_match:
        score += 40
    if same_asset:
        score += 20
    if same_cve:
        score += 20
    if same_location:
        score += 10
    if compatible:
        score += 10
    score = max(0, min(100, score))
    if score >= 80:
        conf = "HIGH"
    elif score >= 50:
        conf = "MEDIUM"
    else:
        conf = "LOW"
    return conf, score

def _group_id(project_id: str, ctype: str, canonical_key: str) -> str:
    raw = f"{project_id}|{ctype}|{canonical_key}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def get_correlations(
    project_id: str,
    db: Session,
    ctype: str | None = None,
    confidence: str | None = None,
    scanner: str | None = None,
    asset_id: str | None = None,
    finding_id: str | None = None,
    limit: int = 50,
) -> list[dict]:
    if ctype and ctype.upper() not in VALID_TYPES:
        raise ValueError(f"Invalid type: {ctype}")
    if confidence and confidence.upper() not in VALID_CONFIDENCES:
        raise ValueError(f"Invalid confidence: {confidence}")
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100

    # Bounded batch retrieval
    assets = db.query(Asset).filter(Asset.project_id == project_id).limit(MAX_ASSETS).all()
    assets_by_id = {a.id: a for a in assets}
    findings = db.query(Finding).filter(Finding.asset_id.in_(list(assets_by_id.keys())) if assets_by_id else False).limit(MAX_FINDINGS).all() if assets_by_id else []
    # Also include findings without asset but with project via target? For simplicity, fallback to direct project via asset join if no assets
    if not findings and not assets_by_id:
        # Try via Finding with asset project join
        try:
            findings = db.query(Finding).join(Asset, Asset.id == Finding.asset_id).filter(Asset.project_id == project_id).limit(MAX_FINDINGS).all()
            assets = db.query(Asset).filter(Asset.project_id == project_id).limit(MAX_ASSETS).all()
            assets_by_id = {a.id: a for a in assets}
        except Exception:
            findings = []

    if not findings:
        return []

    # Filter early if finding_id/asset_id/scanner filters
    if finding_id:
        findings = [f for f in findings if f.id == finding_id]
    if asset_id:
        findings = [f for f in findings if f.asset_id == asset_id]
    if scanner:
        findings = [f for f in findings if f.scanner.lower() == scanner.lower()]

    # Build candidate buckets
    buckets: dict[str, list[Finding]] = defaultdict(list)
    # Also track fingerprint map for duplicate
    fingerprint_map: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        asset = f.asset_id or ""
        rule = str((f.extra_data or {}).get("rule_id") or f.extra_data.get("ruleId") or "").strip().lower()
        cve = str(f.cve or "").strip().lower()
        cwe = str(f.cwe or "").strip().lower()
        # location: URL or file or package
        url = _normalize_url(str((f.extra_data or {}).get("url") or (f.extra_data or {}).get("location") or ""))
        file_loc = _normalize_file(str((f.extra_data or {}).get("file") or (f.extra_data or {}).get("path") or ""))
        pkg = _normalize_package(str((f.extra_data or {}).get("package") or (f.extra_data or {}).get("package_name") or ""))
        # Buckets
        if asset:
            buckets[f"asset:{asset}"].append(f)
        if rule:
            buckets[f"rule:{rule}"].append(f)
        if cve:
            buckets[f"cve:{cve}"].append(f)
        if cwe:
            buckets[f"cwe:{cwe}"].append(f)
        if url:
            buckets[f"url:{url}"].append(f)
        if file_loc:
            buckets[f"file:{file_loc}"].append(f)
        if pkg:
            buckets[f"pkg:{pkg}"].append(f)
        # Composite duplicate fingerprint: asset+rule+cve+cwe+location
        location = url or file_loc or pkg or ""
        fp = _canonical_fingerprint(project_id, asset, rule, cve, cwe, location)
        fingerprint_map[fp].append(f)

    groups: dict[str, dict] = {}
    seen_group_keys: set[str] = set()

    def _add_group(ctype: str, canonical_key: str, members: list[Finding], explanation: str, extra: dict | None = None):
        if len(members) < 2:
            return
        if len(members) > MAX_MEMBERS:
            members = members[:MAX_MEMBERS]
        # Limit groups
        if len(groups) >= MAX_GROUPS:
            return
        # Determine confidence/score based on members
        # For this group, check exact match etc.
        exact = False
        same_asset = len({m.asset_id for m in members}) == 1
        same_cve = len({(m.cve or "").lower() for m in members if m.cve}) == 1 and any(m.cve for m in members)
        same_location = False
        # Check if all have same normalized URL/file
        locs = set()
        for m in members:
            loc = _normalize_url(str((m.extra_data or {}).get("url") or "")) or _normalize_file(str((m.extra_data or {}).get("file") or "")) or _normalize_package(str((m.extra_data or {}).get("package") or ""))
            if loc:
                locs.add(loc)
        if len(locs) == 1 and locs:
            same_location = True
        # Check fingerprint exact
        fps = { _canonical_fingerprint(project_id, m.asset_id, str((m.extra_data or {}).get("rule_id") or "").lower(), str(m.cve or "").lower(), str(m.cwe or "").lower(), _normalize_url(str((m.extra_data or {}).get("url") or "")) ) for m in members }
        if len(fps) == 1:
            exact = True
        # Compatible scanners?
        scanners = [m.scanner for m in members]
        compatible = all(_is_compatible(scanners[0], s) for s in scanners[1:]) if len(scanners) > 1 else True
        conf, score = _confidence_and_score(exact, same_asset, same_cve, same_location, compatible)
        if confidence and conf != confidence.upper():
            return
        gid = _group_id(project_id, ctype, canonical_key)
        if gid in seen_group_keys:
            return
        seen_group_keys.add(gid)
        # Filter by scanner if requested (already filtered findings, but groups may contain mixed)
        if scanner and not any(m.scanner.lower() == scanner.lower() for m in members):
            return
        # Build title
        asset_example = assets_by_id.get(members[0].asset_id) if members[0].asset_id else None
        asset_val = asset_example.value[:60] if asset_example else (members[0].asset_id or "unknown")
        title = f"{ctype.replace('_',' ').title()} on {asset_val}"
        # Limit evidence
        group = {
            "id": gid,
            "project_id": project_id,
            "correlation_type": ctype,
            "canonical_key": canonical_key,
            "confidence": conf,
            "score": score,
            "title": _sanitize(title),
            "explanation": explanation,
            "created_at": members[0].created_at.isoformat() if hasattr(members[0], "created_at") and members[0].created_at else None,
            "updated_at": members[-1].created_at.isoformat() if hasattr(members[-1], "created_at") and members[-1].created_at else None,
            "finding_count": len(members),
            "scanner_count": len({m.scanner for m in members}),
            "asset_count": len({m.asset_id for m in members}),
            "members": [
                {
                    "finding_id": m.id,
                    "asset_id": m.asset_id,
                    "scanner": m.scanner,
                    "severity": m.severity,
                    "title": _sanitize(m.title),
                    "cve": m.cve,
                    "cwe": m.cwe,
                    "role": "primary" if i == 0 else "corroborating",
                }
                for i, m in enumerate(members)
            ],
            "finding_ids": [m.id for m in members],
            "asset_ids": list({m.asset_id for m in members if m.asset_id}),
            "scanners": sorted({m.scanner for m in members}),
        }
        if extra:
            group.update(extra)
        groups[gid] = group

    # 1. DUPLICATE via exact fingerprint
    for fp, members in fingerprint_map.items():
        if len(members) >= 2:
            # Check different scanners or same scanner but same location — still duplicate if same asset+rule
            # Only if same asset
            if len({m.asset_id for m in members}) == 1:
                _add_group("DUPLICATE", fp, members, "Same canonical fingerprint and same asset.")

    # 2. SAME_ASSET
    for key, members in buckets.items():
        if key.startswith("asset:") and len(members) >= 2 and len(members) <= MAX_MEMBERS:
            # Avoid duplicate with already created duplicate groups (same members)
            _add_group("SAME_ASSET", key, members, "Findings affect the same canonical asset.")

    # 3. SAME_VULNERABILITY via CVE
    for key, members in buckets.items():
        if key.startswith("cve:") and len(members) >= 2:
            # If same CVE but different assets → SAME_VULNERABILITY, not DUPLICATE
            if len({m.asset_id for m in members}) > 1:
                _add_group("SAME_VULNERABILITY", key, members, "Same CVE affects multiple assets.")

    # 4. SAME_EXPOSURE via URL
    for key, members in buckets.items():
        if key.startswith("url:") and len(members) >= 2:
            _add_group("SAME_EXPOSURE", key, members, "Same normalized URL endpoint.")

    # 5. SAME_ROOT_CAUSE via package or file
    for key, members in buckets.items():
        if (key.startswith("pkg:") or key.startswith("file:")) and len(members) >= 2:
            # Check cross-scanner like sca/container/sast
            scanners = {m.scanner.lower() for m in members}
            if len(scanners) > 1:
                _add_group("SAME_ROOT_CAUSE", key, members, "Same package/file across scanners indicates common root cause.")

    # 6. RELATED via rule_id (same rule across assets)
    for key, members in buckets.items():
        if key.startswith("rule:") and len(members) >= 2:
            if len({m.asset_id for m in members}) > 1:
                # Already might be duplicate, but for different assets it's RELATED
                _add_group("RELATED", key, members, "Same rule ID across multiple assets.")

    # 7. ATTACK_PATH_RELATED — reuse E9
    try:
        from app.services.cloud_attack_paths import build_cloud_attack_paths
        paths = build_cloud_attack_paths(project_id, db, limit=20)
        if paths:
            # Map asset_id -> path_ids
            asset_to_paths: dict[str, list[str]] = defaultdict(list)
            for p in paths:
                for aid in p.get("asset_ids", []):
                    asset_to_paths[aid].append(p.get("id") or p.get("fingerprint"))
            for asset_id, members in buckets.items():
                if not asset_id.startswith("asset:"):
                    continue
                aid = asset_id.split(":", 1)[1]
                if aid in asset_to_paths:
                    # Create group for findings on this asset that are on attack path
                    relevant = [m for m in members if m.asset_id == aid]
                    if len(relevant) >= 1:
                        # Need at least one finding on path — create group with all findings on that asset plus path
                        for f in relevant:
                            _add_group("ATTACK_PATH_RELATED", f"attack_path:{aid}", [f], "Finding appears on existing cloud attack path.", extra={"attack_path_ids": asset_to_paths[aid][:5]})
    except Exception:
        pass

    # 8. CSPM_RELATED — via E8
    try:
        from app.services.cspm import evaluate_cspm
        cspm_data = evaluate_cspm(project_id, db)
        failed = [r for r in cspm_data.get("results", []) if r.get("status") == "FAIL"]
        if failed:
            # Map rule_id -> control
            cspm_rules = set()
            for ctrl in failed:
                for prov_rules in ctrl.get("mappings", {}).values():
                    for rid in prov_rules:
                        cspm_rules.add(rid.upper())
            for f in findings:
                rid = str((f.extra_data or {}).get("rule_id") or "").upper()
                if rid in cspm_rules:
                    _add_group("CSPM_RELATED", f"cspm:{rid}", [f], "Cloud finding maps to CSPM control.", extra={"cspm_control_ids": [c["control_id"] for c in failed if rid in [r.upper() for rules in c.get("mappings", {}).values() for r in rules]]})
    except Exception:
        pass

    # Filter by ctype if requested
    result = list(groups.values())
    if ctype:
        result = [g for g in result if g["correlation_type"] == ctype.upper()]
    # Sort deterministic: score desc, confidence rank, type, id
    rank_conf = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    result.sort(key=lambda g: (-g["score"], rank_conf.get(g["confidence"], 99), g["correlation_type"], g["id"]))
    return result[:limit]

def get_correlation_detail(project_id: str, db: Session, correlation_id: str) -> dict | None:
    groups = get_correlations(project_id, db, limit=MAX_GROUPS)
    for g in groups:
        if g["id"] == correlation_id:
            return g
    return None

def get_correlation_summary(project_id: str, db: Session) -> dict:
    groups = get_correlations(project_id, db, limit=MAX_GROUPS)
    by_type: dict[str, int] = {}
    by_scanner: dict[str, int] = {}
    by_asset: dict[str, int] = {}
    for g in groups:
        by_type[g["correlation_type"]] = by_type.get(g["correlation_type"], 0) + 1
        for s in g.get("scanners", []):
            by_scanner[s] = by_scanner.get(s, 0) + 1
        for aid in g.get("asset_ids", []):
            by_asset[aid] = by_asset.get(aid, 0) + 1
    return {
        "project_id": project_id,
        "total_groups": len(groups),
        "duplicates": len([g for g in groups if g["correlation_type"] == "DUPLICATE"]),
        "related": len([g for g in groups if g["correlation_type"] == "RELATED"]),
        "root_causes": len([g for g in groups if g["correlation_type"] == "SAME_ROOT_CAUSE"]),
        "attack_path_related": len([g for g in groups if g["correlation_type"] == "ATTACK_PATH_RELATED"]),
        "cspm_related": len([g for g in groups if g["correlation_type"] == "CSPM_RELATED"]),
        "by_type": by_type,
        "by_scanner": by_scanner,
        "by_asset_count": len(by_asset),
        "groups": groups[:10],
    }

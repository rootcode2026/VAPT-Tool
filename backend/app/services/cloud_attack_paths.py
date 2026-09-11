"""E9 Cloud Attack Paths — provider-neutral, deterministic, bounded, on-read.

Reuses existing cloud assets/relationships/findings/CSPM. No new discovery, no new checks,
no graph DB. Relational -> bounded in-memory graph -> BFS -> validation -> scoring.
Terminology: evidence-backed / potential attack path (not confirmed exploitation).
"""

from __future__ import annotations

import hashlib
from collections import deque
from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.finding import Finding

# Bounded traversal defaults (reuse S5.3 where appropriate, but cloud-specific)
MAX_PATH_DEPTH = 6
MAX_PATHS = 100
MAX_NODES_PER_GRAPH = 500
MAX_EDGES_PER_GRAPH = 1000
MAX_PATH_EVIDENCE = 20
MAX_API_LIMIT = 100

# Normalized taxonomy — only types actually supported by existing evidence
VALID_PATH_TYPES = {
    "INTERNET_TO_RESOURCE",
    "INTERNET_TO_VULNERABLE_RESOURCE",
    "PUBLIC_RESOURCE_TO_INTERNAL_RESOURCE",
    "IDENTITY_TO_PRIVILEGED_RESOURCE",
    "EXTERNAL_TRUST_TO_PRIVILEGED_RESOURCE",
    "NETWORK_TO_SENSITIVE_RESOURCE",
}

VALID_PROVIDERS = {"aws", "gcp", "azure"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
VALID_CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}

# Provider-neutral severity weights (reuse existing)
SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 1}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Sensitive resource type hints (from existing cloud discovery metadata.resource_type)
SENSITIVE_TYPES = {
    "aws_rds_instance", "aws_s3_bucket", "aws_ebs_volume", "aws_ebs_snapshot", "aws_efs_filesystem",
    "gcp_storage_bucket", "gcp_compute_instance", "gcp_sql_instance",
    "azure_storage_account", "azure_vm", "azure_sql_database",
    "aws_iam_role", "aws_iam_user", "gcp_iam_policy", "azure_rbac_assignment",
}

# Entry point rule_ids that imply internet/external exposure (from existing checks)
ENTRY_RULE_IDS = {
    "AWS-EC2-002", "AWS-NET-002", "AWS-NET-003", "AWS-NET-004", "AWS-NET-005", "AWS-NET-007",
    "AWS-S3-003", "AWS-S3-005", "AWS-RDS-001",
    "GCP-NET-001", "GCP-NET-002", "GCP-NET-003", "GCP-NET-004", "GCP-GCS-001", "GCP-COMPUTE-002",
    "AZURE-NET-001", "AZURE-NET-002", "AZURE-NET-003", "AZURE-NET-004", "AZURE-STORAGE-001", "AZURE-NET-006",
}

# Identity/privilege rule_ids
PRIVILEGE_RULE_IDS = {
    "AWS-IAM-001", "AWS-IAM-002", "AWS-IAM-003", "AWS-IAM-004", "AWS-IAM-005",
    "GCP-IAM-001", "GCP-IAM-002", "GCP-IAM-003",
    "AZURE-IAM-001", "AZURE-IAM-002", "AZURE-IAM-003",
}


def _extract_provider(asset: Asset) -> str:
    """Derive provider from asset value or metadata; fallback unknown."""
    try:
        val = str(asset.value or "")
        # value like cloud_resource:aws:account:region:type:id or cloud_account:aws:...
        parts = val.split(":")
        if len(parts) >= 3 and parts[1].lower() in VALID_PROVIDERS:
            return parts[1].lower()
        meta = asset.extra_data if isinstance(asset.extra_data, dict) else {}
        prov = str(meta.get("provider") or meta.get("resource_type") or "").lower()
        for p in VALID_PROVIDERS:
            if p in prov or p in val.lower():
                return p
    except Exception:
        pass
    # Fallback by value prefix
    for p in VALID_PROVIDERS:
        if f":{p}:" in str(asset.value or "").lower():
            return p
    return "unknown"


def _is_entry_asset(asset: Asset, findings_by_asset: dict[str, list]) -> bool:
    """Evidence-backed entry point: public metadata or exposure finding."""
    meta = asset.extra_data if isinstance(asset.extra_data, dict) else {}
    # Explicit public metadata
    if meta.get("public") is True or str(meta.get("public_ip") or "").strip():
        return True
    if str(meta.get("exposure") or "").upper() in ("INTERNET_EXPOSED", "PUBLIC"):
        return True
    if str(meta.get("scheme") or "").lower() == "internet-facing":
        return True
    if meta.get("allow_blob_public_access") is True or meta.get("is_public") is True:
        return True
    # Check findings attached to this asset that are entry-related
    for f in findings_by_asset.get(asset.id, []):
        rid = str((f.extra_data or {}).get("rule_id") or "").upper()
        if rid in ENTRY_RULE_IDS:
            return True
        # Generic public hint in title
        if "public" in str(f.title or "").lower() and f.severity in ("high", "critical"):
            return True
    # Asset type internet gateway / public IP etc via value
    if "internet_gateway" in str(meta.get("resource_type") or "").lower():
        return True
    return False


def _is_sensitive_target(asset: Asset, findings_by_asset: dict[str, list]) -> bool:
    meta = asset.extra_data if isinstance(asset.extra_data, dict) else {}
    rtype = str(meta.get("resource_type") or "").lower()
    if rtype in SENSITIVE_TYPES:
        return True
    # Has high/critical finding
    for f in findings_by_asset.get(asset.id, []):
        if str(f.severity).lower() in ("critical", "high"):
            return True
        rid = str((f.extra_data or {}).get("rule_id") or "").upper()
        if rid in PRIVILEGE_RULE_IDS or rid in ("AWS-RDS-001", "AWS-S3-003", "GCP-GCS-001", "AZURE-STORAGE-001"):
            return True
    return False


def _provider_for_path(assets_by_id: dict[str, Asset], asset_ids: list[str]) -> str:
    providers = {_extract_provider(assets_by_id[aid]) for aid in asset_ids if aid in assets_by_id}
    providers.discard("unknown")
    if len(providers) == 1:
        return list(providers)[0]
    if len(providers) > 1:
        return "multi"
    return "unknown"


def _path_type_for(entry_asset: Asset | None, target_asset: Asset | None, findings_on_path: list, has_identity: bool) -> str:
    if has_identity:
        # Check if external trust (look at findings for IAM-004/005 external trust)
        for f in findings_on_path:
            rid = str((f.extra_data or {}).get("rule_id") or "").upper()
            if rid in ("AWS-IAM-004", "AWS-IAM-005", "GCP-IAM-001"):
                return "EXTERNAL_TRUST_TO_PRIVILEGED_RESOURCE"
        return "IDENTITY_TO_PRIVILEGED_RESOURCE"
    if entry_asset and target_asset:
        e_is_entry = _is_entry_asset(entry_asset, {})
        t_sensitive = _is_sensitive_target(target_asset, {})
        # If target has finding, it's vulnerable
        if findings_on_path:
            return "INTERNET_TO_VULNERABLE_RESOURCE"
        if t_sensitive:
            return "NETWORK_TO_SENSITIVE_RESOURCE"
        return "INTERNET_TO_RESOURCE"
    return "INTERNET_TO_VULNERABLE_RESOURCE"


def _score_path(entry_exposure: bool, findings_on_path: list, privilege_count: int, sensitive: bool, path_len: int) -> int:
    """Deterministic priority score 0-100. Documented formula."""
    # Base 30
    score = 30
    if entry_exposure:
        score += 20  # exposure weight
    if privilege_count > 0:
        score += 15 + min(privilege_count, 2) * 5  # privilege weight
    # critical finding weight
    has_critical = any(str(f.severity).lower() == "critical" for f in findings_on_path)
    has_high = any(str(f.severity).lower() == "high" for f in findings_on_path)
    if has_critical:
        score += 20
    elif has_high:
        score += 10
    elif findings_on_path:
        score += 5
    if sensitive:
        score += 10  # sensitive target weight
    # path length penalty: longer paths are less direct (2 per hop beyond 2)
    if path_len > 3:
        score -= (path_len - 3) * 2
    # CSPM-like weight: add average severity weight capped
    total_w = sum(SEVERITY_WEIGHTS.get(str(f.severity).lower(), 1) for f in findings_on_path)
    score += min(total_w // 4, 10)
    return max(0, min(100, score))


def _severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _confidence_for_path(edge_count: int, finding_count: int, inferred_edges: int) -> str:
    if inferred_edges == 0 and finding_count >= 1:
        return "HIGH"
    if inferred_edges == 0:
        return "MEDIUM"
    if inferred_edges == 1 and finding_count >= 1:
        return "MEDIUM"
    return "LOW"


def _canonical_fingerprint(project_id: str, path_type: str, provider: str, asset_ids: list[str]) -> str:
    raw = f"{project_id}|{path_type}|{provider}|{'->'.join(sorted(asset_ids))}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def _sanitize_evidence(evidence: list[dict]) -> list[dict]:
    out = []
    for e in evidence[:MAX_PATH_EVIDENCE]:
        safe = {
            "rule_id": str(e.get("rule_id") or "")[:64],
            "finding_id": str(e.get("finding_id") or "")[:64],
            "asset_id": str(e.get("asset_id") or "")[:64],
            "severity": str(e.get("severity") or "").lower()[:20],
            "title": str(e.get("title") or "")[:300],
        }
        lower = safe["title"].lower()
        if any(k in lower for k in ("secret", "private_key", "credential", "token")):
            safe["title"] = "[REDACTED]"
        out.append(safe)
    return out


def build_cloud_attack_paths(project_id: str, db: Session, limit: int = MAX_PATHS, provider_filter: str | None = None, severity_filter: str | None = None, confidence_filter: str | None = None, path_type_filter: str | None = None, max_depth: int = MAX_PATH_DEPTH) -> list[dict]:
    """Core engine: bounded graph, deterministic BFS, validation, scoring."""
    # Validate filters
    if provider_filter and provider_filter.lower() not in VALID_PROVIDERS:
        raise ValueError(f"Invalid provider: {provider_filter}")
    if severity_filter and severity_filter.lower() not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity: {severity_filter}")
    if confidence_filter and confidence_filter.upper() not in VALID_CONFIDENCES:
        raise ValueError(f"Invalid confidence: {confidence_filter}")
    if path_type_filter and path_type_filter.upper() not in VALID_PATH_TYPES:
        raise ValueError(f"Invalid path_type: {path_type_filter}")
    if limit < 1:
        limit = 1
    if limit > MAX_API_LIMIT:
        limit = MAX_API_LIMIT
    if max_depth < 1:
        max_depth = 1
    if max_depth > 10:
        max_depth = 10

    # Bounded batch retrieval — no N+1
    assets = db.query(Asset).filter(Asset.project_id == project_id).limit(MAX_NODES_PER_GRAPH).all()
    # Only cloud assets matter
    cloud_assets = [a for a in assets if a.asset_type in ("cloud_account", "cloud_resource")]
    if not cloud_assets:
        return []

    assets_by_id = {a.id: a for a in cloud_assets}

    relationships = db.query(AssetRelationship).filter(AssetRelationship.project_id == project_id).limit(MAX_EDGES_PER_GRAPH).all()
    # Filter to cloud-relevant relationships only (both ends in cloud_assets)
    rels = [r for r in relationships if r.source_asset_id in assets_by_id and r.target_asset_id in assets_by_id]

    findings = db.query(Finding).join(Asset, Asset.id == Finding.asset_id).filter(Asset.project_id == project_id, Finding.scanner == "cloud").limit(500).all()

    findings_by_asset: dict[str, list] = {}
    for f in findings:
        if f.asset_id and f.asset_id in assets_by_id:
            findings_by_asset.setdefault(f.asset_id, []).append(f)

    # Build adjacency deterministic
    rels_sorted = sorted(rels, key=lambda r: (r.source_asset_id, r.target_asset_id, r.relationship_type, r.id))
    adj: dict[str, list[tuple[str, AssetRelationship]]] = {aid: [] for aid in assets_by_id}
    for rel in rels_sorted:
        adj[rel.source_asset_id].append((rel.target_asset_id, rel))

    # Entry points
    entry_ids = [aid for aid, a in assets_by_id.items() if _is_entry_asset(a, findings_by_asset)]
    entry_ids.sort()
    if not entry_ids:
        return []

    # Sensitive/vulnerable targets
    # Target is sensitive OR has finding
    target_ids = set()
    for aid, a in assets_by_id.items():
        if _is_sensitive_target(a, findings_by_asset) or findings_by_asset.get(aid):
            # Must not be same as entry unless entry also has finding (allow)
            target_ids.add(aid)

    # If no explicit sensitive, use any asset that has high/critical finding as target
    # Already covered via findings_by_asset
    if not target_ids:
        return []

    # BFS from each entry
    paths: list[dict] = []
    seen_fingerprints: set[str] = set()

    for entry_id in entry_ids:
        if len(paths) >= limit:
            break
        entry_asset = assets_by_id[entry_id]
        queue = deque()
        queue.append(([entry_id], [], []))  # asset_ids, rel_ids, rel_objects
        # visited per path to prevent cycles
        while queue and len(paths) < limit:
            cur_asset_ids, cur_rel_ids, cur_rels = queue.popleft()
            cur_asset_id = cur_asset_ids[-1]
            cur_depth = len(cur_rel_ids)
            if cur_depth >= max_depth:
                continue
            for target_id, rel in adj.get(cur_asset_id, []):
                if target_id in cur_asset_ids:
                    continue  # cycle prevention

                new_asset_ids = cur_asset_ids + [target_id]
                new_rel_ids = cur_rel_ids + [rel.id]
                new_rels = cur_rels + [rel]

                # Validate path contains meaningful security condition: target has finding or sensitive
                is_target = target_id in target_ids
                findings_on_path = []
                for aid in new_asset_ids:
                    findings_on_path.extend(findings_by_asset.get(aid, []))

                privilege_count = sum(1 for f in findings_on_path if str((f.extra_data or {}).get("rule_id") or "").upper() in PRIVILEGE_RULE_IDS)
                has_identity = privilege_count > 0

                # Only emit paths that end at a target with finding or are multi-hop to sensitive
                if is_target and findings_on_path:
                    provider = _provider_for_path(assets_by_id, new_asset_ids)
                    if provider_filter and provider not in (provider_filter.lower(), "multi"):
                        # If provider filter, skip non-matching providers (multi counts for all)
                        if provider != provider_filter.lower() and provider != "multi":
                            # Also check if any asset matches provider
                            prov_assets = [_extract_provider(assets_by_id[aid]) for aid in new_asset_ids]
                            if provider_filter.lower() not in prov_assets:
                                pass  # will filter later but still generate; skip now for efficiency
                                # Don't skip fully — let filter later
                                pass
                    path_type = _path_type_for(entry_asset, assets_by_id.get(target_id), findings_on_path, has_identity)
                    if path_type_filter and path_type != path_type_filter.upper():
                        pass
                    else:
                        # Provider neutrality via normalized path
                        fingerprint = _canonical_fingerprint(project_id, path_type, provider, new_asset_ids)
                        if fingerprint not in seen_fingerprints:
                            seen_fingerprints.add(fingerprint)
                            # Score and confidence
                            sensitive = _is_sensitive_target(assets_by_id[target_id], findings_by_asset)
                            entry_exposure = True
                            score = _score_path(entry_exposure, findings_on_path, privilege_count, sensitive, len(new_asset_ids))
                            severity = _severity_from_score(score)
                            if severity_filter and severity != severity_filter.lower():
                                pass
                            else:
                                confidence = _confidence_for_path(len(new_rels), len(findings_on_path), 0)
                                if confidence_filter and confidence != confidence_filter.upper():
                                    pass
                                else:
                                    # Evidence bounded
                                    evidence = []
                                    for f in findings_on_path[:MAX_PATH_EVIDENCE]:
                                        evidence.append({
                                            "rule_id": str((f.extra_data or {}).get("rule_id") or ""),
                                            "finding_id": f.id,
                                            "asset_id": f.asset_id,
                                            "severity": f.severity,
                                            "title": f.title,
                                        })
                                    evidence = _sanitize_evidence(evidence)

                                    # Relationship evidence
                                    rel_evidence = [
                                        {"id": r.id, "source_asset_id": r.source_asset_id, "target_asset_id": r.target_asset_id, "relationship_type": r.relationship_type}
                                        for r in new_rels
                                    ]

                                    # Nodes for UI chain
                                    nodes = [
                                        {"asset_id": aid, "value": assets_by_id[aid].value, "asset_type": assets_by_id[aid].asset_type, "provider": _extract_provider(assets_by_id[aid]), "metadata": {}}
                                        for aid in new_asset_ids
                                    ]

                                    paths.append({
                                        "id": fingerprint,
                                        "fingerprint": fingerprint,
                                        "project_id": project_id,
                                        "provider": provider,
                                        "path_type": path_type,
                                        "severity": severity,
                                        "priority_score": score,
                                        "confidence": confidence,
                                        "entry_asset_id": entry_id,
                                        "target_asset_id": target_id,
                                        "asset_ids": new_asset_ids,
                                        "nodes": nodes,
                                        "relationships": rel_evidence,
                                        "findings": evidence,
                                        "finding_count": len(evidence),
                                        "evidence": evidence,
                                        "affected_resources": list(dict.fromkeys(new_asset_ids))[:MAX_PATH_EVIDENCE],
                                        "status": "ACTIVE",
                                        "explanation": f"Evidence-backed potential attack path: {path_type.replace('_',' ').lower()} via {len(new_asset_ids)} resources with {len(findings_on_path)} finding(s).",
                                    })
                # Enqueue for further expansion
                if len(new_rel_ids) < max_depth and len(paths) < limit:
                    queue.append((new_asset_ids, new_rel_ids, new_rels))

    # Deduplicate already via fingerprint, sort by priority_score desc
    # Apply post-filters for provider/severity/confidence/path_type that were deferred
    if provider_filter:
        paths = [p for p in paths if p["provider"] in (provider_filter.lower(), "multi") or any(_extract_provider(assets_by_id[aid]) == provider_filter.lower() for aid in p["asset_ids"])]
    if severity_filter:
        paths = [p for p in paths if p["severity"] == severity_filter.lower()]
    if confidence_filter:
        paths = [p for p in paths if p["confidence"] == confidence_filter.upper()]
    if path_type_filter:
        paths = [p for p in paths if p["path_type"] == path_type_filter.upper()]

    # Sort deterministic: priority_score desc, severity rank, length, fingerprint
    paths.sort(key=lambda p: (-p["priority_score"], SEVERITY_RANK.get(p["severity"], 99), len(p["asset_ids"]), p["fingerprint"]))

    return paths[:limit]


def get_attack_path_detail(project_id: str, db: Session, path_id: str) -> dict | None:
    paths = build_cloud_attack_paths(project_id, db, limit=MAX_API_LIMIT, max_depth=MAX_PATH_DEPTH)
    for p in paths:
        if p["id"] == path_id or p["fingerprint"] == path_id:
            return p
    return None

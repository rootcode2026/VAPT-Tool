"""
D5 — Attack Path Foundation.

Deterministic bounded BFS over persisted AssetRelationships.
Project-scoped, in-memory adjacency, no graph DB, no live scans.
Reuses D2/D3/D4 signals for entry/target/priority.
"""

from __future__ import annotations

import hashlib
from collections import deque
from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.services.asset_contextual_risk import aggregate_contextual_risk_for_assets

MAX_DEPTH = 5
MAX_PATHS = 100

# Priority rank for ordering (0 highest)
PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _build_security_context(entry_asset: Asset | None, target_signals: dict, target_contextual: dict) -> dict:
    """D6.1 security context — deterministic, reused D3/D4 signals."""
    target_vuln = bool(target_contextual.get("context", {}).get("vulnerability_context", {}).get("vulnerable"))
    target_highest_severity = target_contextual.get("context", {}).get("vulnerability_context", {}).get("highest_severity")
    # D3 finding_signal also has highest_score
    target_highest_score = None
    sig = target_contextual.get("signals", {})
    if sig:
        target_highest_score = sig.get("finding_signal", {}).get("highest_score")
        if target_highest_severity is None:
            target_highest_severity = sig.get("finding_signal", {}).get("highest_severity")
    # Fallback to signals_by_asset if contextual missing
    if target_highest_severity is None and target_signals:
        target_highest_severity = target_signals.get("finding_signal", {}).get("highest_severity")
        target_highest_score = target_signals.get("finding_signal", {}).get("highest_score")
    return {
        "entry_internet_facing": True,  # entry is always internet_facing by selection
        "entry_asset_type": entry_asset.asset_type if entry_asset else "unknown",
        "target_vulnerable": target_vuln,
        "target_highest_severity": target_highest_severity,
        "target_highest_score": target_highest_score,
        "target_contextual_priority": target_contextual.get("priority", "informational"),
        "target_recently_changed": bool(target_contextual.get("context", {}).get("change_context", {}).get("recently_changed")),
        "target_potentially_sensitive": bool(target_contextual.get("context", {}).get("sensitivity_context", {}).get("potentially_sensitive")),
    }


def _build_flags(entry_internet_facing: bool, target_signals: dict, target_contextual: dict) -> dict:
    """D6.1 path-level flags — descriptive, not exploitability."""
    findings = target_signals.get("finding_signal", {}) if target_signals else {}
    sens = target_contextual.get("context", {}).get("sensitivity_context", {}) if target_contextual else {}
    change = target_contextual.get("context", {}).get("change_context", {}) if target_contextual else {}
    posture = target_contextual.get("context", {}) if False else {}  # placeholder
    # Use signals for vulnerable etc
    vulnerable = bool(findings.get("total", 0) > 0) or bool(target_contextual.get("context", {}).get("vulnerability_context", {}).get("vulnerable"))
    highest = findings.get("highest_severity") or target_contextual.get("context", {}).get("vulnerability_context", {}).get("highest_severity")
    return {
        "internet_exposed": bool(entry_internet_facing),
        "vulnerable_target": bool(vulnerable),
        "critical_target": highest == "critical",
        "high_target": highest in ("critical", "high"),
        "sensitive_target": bool(sens.get("potentially_sensitive")),
        "recently_changed_target": bool(change.get("recently_changed")),
    }


def _build_evidence(entry_asset_id: str, target_asset_id: str, relationships: list) -> dict:
    """D6.1 evidence — unique sorted relationship types, counts."""
    types = sorted({r["relationship_type"] if isinstance(r, dict) else r.relationship_type for r in relationships})
    return {
        "entry_asset_id": entry_asset_id,
        "target_asset_id": target_asset_id,
        "relationship_count": len(relationships),
        "asset_count": len({entry_asset_id, target_asset_id} | {r["target_asset_id"] for r in relationships if isinstance(r, dict)} | {r["source_asset_id"] for r in relationships if isinstance(r, dict)}),
        "relationship_types": types,
    }


def _build_d61_explanation(entry_internet_facing: bool, target_signals: dict, target_contextual: dict, priority: str) -> str:
    """D6.1 deterministic explanation priority order (no AI)."""
    # Order per spec: 1 critical exposed, 2 sensitive exposed, 3 changed vulnerable, 4 exposed vulnerable, 5 vulnerable, 6 generic
    vuln = target_contextual.get("context", {}).get("vulnerability_context", {}).get("vulnerable") if target_contextual else False
    critical = (target_signals.get("finding_signal", {}).get("critical", 0) > 0) if target_signals else False
    sensitive = bool(target_contextual.get("context", {}).get("sensitivity_context", {}).get("potentially_sensitive")) if target_contextual else False
    recently = bool(target_contextual.get("context", {}).get("change_context", {}).get("recently_changed")) if target_contextual else False
    if critical and entry_internet_facing:
        return "Observed path from an internet-facing asset to a critical vulnerable asset."
    if sensitive and entry_internet_facing:
        return "Observed path reaches a potentially sensitive vulnerable asset."
    if recently and vuln:
        return "Observed path reaches a recently changed vulnerable asset."
    if vuln and entry_internet_facing:
        return "Observed path from an internet-facing asset to a vulnerable asset."
    if vuln:
        return "Observed relationship chain reaches a vulnerable asset."
    if entry_internet_facing:
        return "Observed path from an internet-facing asset."
    return "Observed relationship path."


def _canonical_path_id(project_id: str, asset_ids: list[str], rel_ids: list[str]) -> str:
    raw = f"{project_id}|{','.join(asset_ids)}|{','.join(rel_ids)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_attack_paths_for_project(
    db: Session,
    project_id: str,
    max_depth: int = MAX_DEPTH,
    max_paths: int = MAX_PATHS,
    asset_id: str | None = None,
) -> dict[str, Any]:
    """
    Deterministic bounded BFS.

    Steps (bulk queries, no N+1):
    1. Load project assets (1 query)
    2. Load project relationships (1 query)
    3. D4 batch for entry/target/priority (reuses D3 batch internally)
    4. In-memory BFS

    Returns {"paths": [...], "total": int, "truncated": bool}
    """
    if max_depth < 1:
        max_depth = 1
    if max_depth > 10:
        max_depth = 10
    if max_paths < 1:
        max_paths = 1
    if max_paths > 500:
        max_paths = 500

    assets = db.query(Asset).filter(Asset.project_id == project_id).all()
    if not assets:
        return {"paths": [], "total": 0, "truncated": False}

    asset_map = {a.id: a for a in assets}
    asset_ids = [a.id for a in assets]

    # Optional filter: if asset_id provided, ensure it belongs to project
    if asset_id is not None and asset_id not in asset_map:
        return {"paths": [], "total": 0, "truncated": False}

    relationships = (
        db.query(AssetRelationship)
        .filter(AssetRelationship.project_id == project_id)
        .all()
    )

    # Build adjacency: source -> list[(target_id, relationship)]
    # Sort relationships deterministically for BFS order
    relationships_sorted = sorted(relationships, key=lambda r: (r.source_asset_id, r.target_asset_id, r.relationship_type, r.id))
    adj: dict[str, list[tuple[str, AssetRelationship]]] = {aid: [] for aid in asset_ids}
    for rel in relationships_sorted:
        if rel.source_asset_id in adj:
            adj[rel.source_asset_id].append((rel.target_asset_id, rel))
        # Ensure target also in map even if not source (for completeness)
        if rel.target_asset_id not in adj:
            adj[rel.target_asset_id] = []

    # D4 batch for contextual priority (also gives finding/vuln)
    # This internally does D3 batch (finding, tech, change) + D2 batch
    contextual_by_asset = aggregate_contextual_risk_for_assets(db, assets)
    # Also need D3 signals for highest_severity/score etc — available inside contextual_by_asset["signals"]
    # But keep reference for enrichment
    # Build quick map for signals (reuse contextual's signals)
    signals_by_asset: dict[str, dict] = {}
    for aid, art in contextual_by_asset.items():
        signals_by_asset[aid] = art.get("signals", {})

    # Entry points: internet_facing == true
    # Target: vulnerable == true (from D3 posture via contextual signals)
    entry_ids = []
    target_ids = set()
    for aid, art in contextual_by_asset.items():
        ctx = art.get("context", {})
        exp = ctx.get("exposure_context", {})
        vuln = ctx.get("vulnerability_context", {})
        if exp.get("internet_facing"):
            entry_ids.append(aid)
        if vuln.get("vulnerable"):
            target_ids.add(aid)

    if not entry_ids or not target_ids:
        return {"paths": [], "total": 0, "truncated": False}

    entry_ids.sort()  # deterministic

    # BFS from each entry
    paths: list[dict] = []
    seen_path_keys: set[str] = set()
    truncated = False

    # To ensure deterministic ordering across entries, we will BFS per entry in sorted order
    # and use a queue with deterministic neighbor ordering (already sorted)
    for entry_id in entry_ids:
        if len(paths) >= max_paths:
            truncated = True
            break
        # BFS queue: (current_asset_id, path_asset_ids, path_rel_ids, path_rels, visited_set)
        queue = deque()
        queue.append(([entry_id], [], []))  # asset_ids, rel_ids, rel_objects
        visited_paths = set()  # to avoid revisiting same asset in current path (cycle)

        while queue and len(paths) < max_paths:
            cur_asset_ids, cur_rel_ids, cur_rels = queue.popleft()
            cur_asset_id = cur_asset_ids[-1]
            cur_depth = len(cur_rel_ids)  # edges
            if cur_depth >= max_depth:
                continue
            # Explore neighbors deterministically
            neighbors = adj.get(cur_asset_id, [])
            # Already sorted
            for target_id, rel in neighbors:
                if target_id in cur_asset_ids:
                    continue  # cycle protection: do not revisit asset in current path
                new_asset_ids = cur_asset_ids + [target_id]
                new_rel_ids = cur_rel_ids + [rel.id]
                new_rels = cur_rels + [rel]

                # Check if target is vulnerable -> record path
                if target_id in target_ids:
                    # Valid path must have at least one edge (already) and entry internet_facing
                    # Build canonical key
                    key = f"{project_id}|{'->'.join(new_asset_ids)}|{'->'.join(new_rel_ids)}"
                    if key not in seen_path_keys:
                        seen_path_keys.add(key)
                        # Deduplication already via key
                        # Build path object
                        path_id = _canonical_path_id(project_id, new_asset_ids, new_rel_ids)
                        # Priority from target contextual
                        target_ctx = contextual_by_asset.get(target_id, {})
                        priority = target_ctx.get("priority", "medium")
                        # Confidence always observed
                        confidence = "observed"
                        # Explanation deterministic
                        exp = target_ctx.get("context", {}).get("change_context", {}).get("recently_changed")
                        if exp and target_ctx.get("context", {}).get("vulnerability_context", {}).get("vulnerable"):
                            explanation = "Observed internet-facing path reaches a recently changed vulnerable asset."
                        elif target_ctx.get("context", {}).get("vulnerability_context", {}).get("critical_findings", 0) > 0:
                            explanation = "Observed relationship chain reaches an asset with a critical finding."
                        else:
                            explanation = "Observed path from an internet-facing asset to a vulnerable asset."
                        # Filter by asset_id if provided
                        if asset_id is not None and asset_id not in new_asset_ids:
                            # Do not add this path if filter not satisfied
                            pass
                        else:
                            paths.append({
                                "path_id": path_id,
                                "project_id": project_id,
                                "entry_asset_id": entry_id,
                                "target_asset_id": target_id,
                                "asset_ids": new_asset_ids,
                                "relationships": [
                                    {
                                        "id": r.id,
                                        "source_asset_id": r.source_asset_id,
                                        "target_asset_id": r.target_asset_id,
                                        "relationship_type": r.relationship_type,
                                        "metadata": r.extra_data or {},
                                    }
                                    for r in new_rels
                                ],
                                "length": len(new_asset_ids),
                                "entry_type": "internet_facing",
                                "target_type": "vulnerable",
                                "priority": priority,
                                "confidence": confidence,
                                "explanation": explanation,
                                # Expose target contextual for D4 integration
                                "target_contextual_priority": priority,
                                "target_risk_factors": target_ctx.get("risk_factors", []),
                            })
                            if len(paths) >= max_paths:
                                truncated = True
                                break
                # Enqueue for further expansion if depth allows
                if len(new_rel_ids) < max_depth and len(paths) < max_paths:
                    # Avoid enqueue if target already vulnerable? Still explore beyond? For now explore beyond to find longer paths to other vulnerable nodes
                    queue.append((new_asset_ids, new_rel_ids, new_rels))
            if truncated:
                break

    # D6.1 enrichment — pure Python, no extra DB queries, reuse already loaded asset_map + contextual/signals
    enriched_paths: list[dict] = []
    for p in paths:
        entry_asset = asset_map.get(p["entry_asset_id"])
        target_id = p["target_asset_id"]
        target_ctx = contextual_by_asset.get(target_id, {})
        target_sig = signals_by_asset.get(target_id, {})
        # Security context
        sec_ctx = _build_security_context(entry_asset, target_sig, target_ctx)
        # Flags
        flags = _build_flags(True, target_sig, target_ctx)
        # Evidence
        evidence = _build_evidence(p["entry_asset_id"], p["target_asset_id"], p["relationships"])
        # Improve explanation deterministically (D6.1 priority order)
        explanation = _build_d61_explanation(True, target_sig, target_ctx, p["priority"])
        enriched = {
            **p,
            "security_context": sec_ctx,
            "flags": flags,
            "evidence": evidence,
            "explanation": explanation,
        }
        enriched_paths.append(enriched)
    paths = enriched_paths

    # Deterministic ordering: priority rank, length, entry_id, target_id, canonical asset sequence
    def sort_key(p):
        return (
            PRIORITY_RANK.get(p["priority"], 99),
            p["length"],
            p["entry_asset_id"],
            p["target_asset_id"],
            ",".join(p["asset_ids"]),
        )

    paths.sort(key=sort_key)

    # Deduplicate again after sort (should already be deduped) and enforce max_paths after sorting
    if len(paths) > max_paths:
        paths = paths[:max_paths]
        truncated = True

    return {"paths": paths, "total": len(paths), "truncated": truncated}

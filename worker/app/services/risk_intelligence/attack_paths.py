"""
S5.3 Attack-Path Intelligence — deterministic discovery layer.

Sits above Asset Intelligence:
  Asset Intelligence -> Relationships -> Finding Associations -> Attack-Path Discovery

- No DB / network / AI
- Deterministic, project-isolated, bounded traversal
- Uses existing RELATIONSHIP_TYPES; does not invent types
- Findings are associated only via explicit asset_id
"""

from __future__ import annotations

import hashlib
import ipaddress
from typing import Any

try:
    from app.asset_intel.types import RELATIONSHIP_TYPES
except ImportError:
    RELATIONSHIP_TYPES = frozenset({
        "contains", "resolves_to", "points_to", "exposes",
        "runs", "serves", "uses", "observed_on",
    })

DEFAULT_MAX_PATH_LENGTH = 6
DEFAULT_MAX_PATHS = 100

# Controlled vocabulary — small set, reused if arch has better terms
PATH_TYPES = (
    "network_exposure",
    "web_exposure",
    "domain_to_service",
    "technology_exposure",
    "finding_path",
    "observed_relationship_path",
)

# Confidence reflects structural quality only, not exploitability
CONFIDENCE_LEVELS = ("high", "medium", "low")

# Words that would claim exploitability — must never appear in description
FORBIDDEN_DESCRIPTION_SUBSTRINGS = (
    "confirmed attack chain",
    "exploitable",
    "confirmed exploitable",
    "verified exploit",
    "successfully exploited",
)

def _norm_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()

def _asset_id(asset: dict) -> str | None:
    if not isinstance(asset, dict):
        return None
    for k in ("id", "asset_id", "_id"):
        v = asset.get(k)
        if v not in (None, ""):
            s = _norm_str(v)
            if s:
                return s
    return None

def _asset_type(asset: dict) -> str:
    if not isinstance(asset, dict):
        return "unknown"
    for k in ("asset_type", "type"):
        v = asset.get(k)
        if v not in (None, ""):
            return _norm_str(v).lower() or "unknown"
    return "unknown"

def _asset_value(asset: dict) -> str:
    if not isinstance(asset, dict):
        return ""
    for k in ("value", "asset_value", "name"):
        v = asset.get(k)
        if v not in (None, ""):
            return _norm_str(v)
    return ""

def _project_id(obj: dict) -> str | None:
    if not isinstance(obj, dict):
        return None
    for k in ("project_id", "projectId"):
        if k in obj and obj[k] not in (None, ""):
            s = _norm_str(obj[k])
            if s:
                return s
    # also check metadata.project_id for findings
    md = obj.get("metadata")
    if isinstance(md, dict) and md.get("project_id") not in (None, ""):
        s = _norm_str(md.get("project_id"))
        if s:
            return s
    return None

def _finding_id(finding: dict) -> str | None:
    if not isinstance(finding, dict):
        return None
    for k in ("id", "finding_id", "_id"):
        v = finding.get(k)
        if v not in (None, ""):
            return _norm_str(v)
    return None

def _finding_asset_id(finding: dict) -> str | None:
    if not isinstance(finding, dict):
        return None
    for k in ("asset_id", "assetId"):
        v = finding.get(k)
        if v not in (None, ""):
            return _norm_str(v)
    return None

def _is_public_ip(value: str) -> bool | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if hasattr(ip, "is_global"):
        return bool(ip.is_global)
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)

def _is_entry_candidate(asset: dict) -> bool:
    """Plausible entry-point signal without assuming every domain/URL is exposed."""
    if not isinstance(asset, dict):
        return False
    atype = _asset_type(asset)
    value = _asset_value(asset)
    if atype in ("ip", "ipv6"):
        pub = _is_public_ip(value)
        if pub is True:
            return True
        return False
    if atype in ("url", "web_site", "web_host"):
        if value.startswith("http://") or value.startswith("https://"):
            return True
        # url assets are considered externally reachable only if http(s)
        return False
    # For other types, do not assume entry. Relationships will drive exposure.
    return False

def _classify_path_type(node_types: list[str], rel_types: list[str], has_finding: bool) -> str:
    nt = set(node_types)
    rt = set(rel_types)
    if has_finding:
        # If finding present, prefer more specific when possible
        if "url" in nt and "serves" in rt:
            return "web_exposure"
        if "technology" in nt:
            return "technology_exposure"
        if "exposes" in rt and "runs" in rt:
            return "network_exposure"
        if "exposes" in rt:
            return "network_exposure"
        if "resolves_to" in rt:
            return "domain_to_service"
        return "finding_path"
    # No finding
    if "url" in nt and "serves" in rt:
        return "web_exposure"
    if "technology" in nt and "serves" in rt:
        return "technology_exposure"
    if "exposes" in rt and "runs" in rt:
        return "network_exposure"
    if "exposes" in rt:
        return "network_exposure"
    if "resolves_to" in rt or "contains" in rt:
        return "domain_to_service"
    return "observed_relationship_path"

def _confidence(node_count: int, has_finding: bool, rel_count: int) -> str:
    # Structural quality only
    if has_finding and node_count >= 3 and rel_count >= 2:
        return "high"
    if has_finding and node_count >= 2:
        return "medium"
    if node_count >= 3:
        return "medium"
    return "low"

def _build_description(nodes: list[dict], rels: list[dict], finding_ids: list[str], path_type: str, confidence: str) -> str:
    # Deterministic, never claims exploitability
    parts: list[str] = []
    # Opening prefix uses observed language
    prefix = "Observed relationship path"
    if finding_ids:
        prefix = "Potential attack path based on observed asset relationships"
    parts.append(prefix + ": ")
    # Chain
    chain_parts: list[str] = []
    for idx, node in enumerate(nodes):
        ntype = _asset_type(node)
        nval = _asset_value(node)
        chain_parts.append(f"{ntype}:{nval}")
        if idx < len(rels):
            rtype = _norm_str(rels[idx].get("relationship_type") or rels[idx].get("type") or "").lower() or "related_to"
            # Arrow
            chain_parts.append(f"--{rtype}-->")
    chain = " ".join(chain_parts)
    parts.append(chain)
    if finding_ids:
        parts.append(f" associated with finding(s) {', '.join(sorted(finding_ids))}")
    parts.append(f" [{path_type}, confidence={confidence}].")
    parts.append(" Not confirmed exploitable; based solely on observed asset relationships and finding associations.")
    desc = "".join(parts)
    # Ensure we never use forbidden wording
    low = desc.lower()
    for bad in FORBIDDEN_DESCRIPTION_SUBSTRINGS:
        if bad in low:
            # Should not happen; replace
            desc = desc.replace(bad, "observed")
    return desc

def _canonical_path_id(project_id: str | None, node_ids: list[str], rel_types: list[str], finding_ids: list[str]) -> str:
    pid = _norm_str(project_id) if project_id else "default"
    canonical = "|".join([
        pid,
        "->".join(node_ids),
        "->".join(rel_types),
        ",".join(sorted(finding_ids)),
    ])
    h = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"path-{h[:16]}"

def _normalize_relationship(rel: dict, asset_value_index: dict[tuple[str, str], str], asset_id_set: set[str]) -> tuple[str | None, str | None, str | None, str | None]:
    """Return (source_id, target_id, rel_type, project_id) or (None,None,None,None) if invalid.

    Supports both id-based and type/value-based relationship representations.
    """
    if not isinstance(rel, dict):
        return None, None, None, None
    rel_type = _norm_str(rel.get("relationship_type") or rel.get("type") or "").lower()
    if rel_type not in RELATIONSHIP_TYPES:
        return None, None, None, None
    project_id = _project_id(rel)
    src_id = None
    tgt_id = None
    # Priority: explicit asset ids
    for k in ("source_asset_id", "source_id", "sourceAssetId"):
        if rel.get(k) not in (None, ""):
            src_id = _norm_str(rel.get(k))
            break
    for k in ("target_asset_id", "target_id", "targetAssetId"):
        if rel.get(k) not in (None, ""):
            tgt_id = _norm_str(rel.get(k))
            break
    # Fallback: type/value
    if not src_id:
        stype = _norm_str(rel.get("source_type") or "").lower()
        svalue = _norm_str(rel.get("source_value") or "")
        if stype and svalue:
            # need normalized canonical? Use lower for type, raw trimmed value
            # attempt to resolve via asset_value_index (which stores (type,value.lower()) maybe)
            # Build lookup with exact value and lowered value
            key = (stype, svalue.lower())
            # also try value as-is lower
            src_id = asset_value_index.get(key)
            if not src_id:
                # try without lower for value case sensitivity for urls?
                src_id = asset_value_index.get((stype, svalue))
            if not src_id:
                # hostname alias handling: try domain/subdomain/hostname aliases
                for alias in ("domain", "subdomain", "hostname"):
                    cand = asset_value_index.get((alias, svalue.lower()))
                    if cand:
                        src_id = cand
                        break
    if not tgt_id:
        ttype = _norm_str(rel.get("target_type") or "").lower()
        tvalue = _norm_str(rel.get("target_value") or "")
        if ttype and tvalue:
            key = (ttype, tvalue.lower())
            tgt_id = asset_value_index.get(key)
            if not tgt_id:
                tgt_id = asset_value_index.get((ttype, tvalue))
            if not tgt_id:
                for alias in ("domain", "subdomain", "hostname"):
                    cand = asset_value_index.get((alias, tvalue.lower()))
                    if cand:
                        tgt_id = cand
                        break
            if not tgt_id:
                for alias in ("url", "web_site"):
                    cand = asset_value_index.get((alias, tvalue.lower()))
                    if cand:
                        tgt_id = cand
                        break
    if not src_id or not tgt_id:
        return None, None, None, None
    if src_id == tgt_id:
        return None, None, None, None
    if src_id not in asset_id_set or tgt_id not in asset_id_set:
        return None, None, None, None
    return src_id, tgt_id, rel_type, project_id

def discover_attack_paths(
    assets: list[dict] | None = None,
    relationships: list[dict] | None = None,
    findings: list[dict] | None = None,
    *,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
    max_paths: int = DEFAULT_MAX_PATHS,
    project_id: str | None = None,
) -> list[dict]:
    """
    Deterministic attack-path discovery.

    Traversal: DFS with deterministic ordering, cycle prevention, bounded length/count.

    Args:
        assets: list of asset dicts (id, asset_type/type, value, project_id)
        relationships: list of relationship dicts (source_asset_id/target_asset_id/relationship_type/project_id
                       or source_type/source_value/target_type/target_value)
        findings: list of finding dicts (id, asset_id, project_id)
        max_path_length: maximum nodes per path (bounded, default 6)
        max_paths: maximum total paths returned (bounded, default 100)
        project_id: optional hard filter; if set, only this project considered

    Returns:
        list of path dicts with keys:
        path_id, project_id, entry_asset, target_asset, nodes, relationships,
        finding_ids, path_length, path_type, confidence, description, human_readable
    """
    assets = assets if isinstance(assets, list) else []
    relationships = relationships if isinstance(relationships, list) else []
    findings = findings if isinstance(findings, list) else []

    # Clamp bounds safely
    try:
        max_path_length = int(max_path_length)
    except (TypeError, ValueError):
        max_path_length = DEFAULT_MAX_PATH_LENGTH
    if max_path_length < 2:
        max_path_length = 2
    if max_path_length > 12:
        max_path_length = 12
    try:
        max_paths = int(max_paths)
    except (TypeError, ValueError):
        max_paths = DEFAULT_MAX_PATHS
    if max_paths < 1:
        max_paths = 1
    if max_paths > 500:
        max_paths = 500

    # Shallow copies to avoid mutating callers (tests check unchanged)
    # Build asset index детерминистически
    # Deterministic ordering: sort assets by id for indexing, but retain original order for retrieval? We sort.
    cleaned_assets: list[dict] = []
    for a in assets:
        if not isinstance(a, dict):
            continue
        aid = _asset_id(a)
        if not aid:
            continue
        # project isolation pre-filter if project_id param set
        a_proj = _project_id(a)
        if project_id is not None and a_proj is not None and _norm_str(project_id) != a_proj:
            continue
        # Also need asset_type/value? Not required for indexing but keep
        cleaned_assets.append(dict(a))  # shallow copy

    # Deterministic sort of assets by id
    cleaned_assets.sort(key=lambda x: _asset_id(x) or "")

    asset_by_id: dict[str, dict] = {}
    asset_value_index: dict[tuple[str, str], str] = {}
    asset_proj_by_id: dict[str, str | None] = {}
    for a in cleaned_assets:
        aid = _asset_id(a)
        if not aid or aid in asset_by_id:
            # duplicate asset id — keep first deterministically (sorted order)
            continue
        asset_by_id[aid] = a
        asset_proj_by_id[aid] = _project_id(a)
        atype = _asset_type(a)
        aval = _asset_value(a)
        # index for type/value resolution — use lowered value for hostname-like
        # Store both original lower and exact to be safe
        if aval:
            # Use lower for case-insensitive types
            key_lower = (atype, aval.lower())
            if key_lower not in asset_value_index:
                asset_value_index[key_lower] = aid
            key_exact = (atype, aval)
            if key_exact not in asset_value_index:
                asset_value_index[key_exact] = aid

    asset_id_set = set(asset_by_id.keys())
    if not asset_by_id:
        return []

    # Findings index: asset_id -> sorted list of finding ids, plus project check
    # Keep original findings unmutated
    finding_by_asset: dict[str, list[str]] = {}
    finding_proj_by_id: dict[str, str | None] = {}
    finding_id_set: set[str] = set()
    valid_findings: list[dict] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = _finding_id(f)
        # Need at least fid? But some findings may not have id — use index fallback
        # For deduplication we use fid if present else hash title? But spec says finding_ids list
        # If no fid, skip? However we need to handle missing id finding without crashing
        # Use fid or generate deterministic fallback from content but don't invent; skip if no id
        if not fid:
            # Try to use title+severity hash as id? Safer to skip without id because cannot reference
            continue
        if fid in finding_id_set:
            continue
        finding_id_set.add(fid)
        valid_findings.append(dict(f))
        finding_proj_by_id[fid] = _project_id(f)

    # Sort findings deterministically by id
    valid_findings.sort(key=lambda x: _finding_id(x) or "")

    # Build mapping asset_id -> findings (filtered by project isolation later per path)
    for f in valid_findings:
        fid = _finding_id(f)
        faid = _finding_asset_id(f)
        if not faid:
            # Finding without asset_id — not attached to any path (spec: don't invent)
            continue
        if faid not in asset_id_set:
            # Orphaned finding — skip
            continue
        # Project isolation for finding->asset: only if both have explicit projects and differ, skip
        f_proj = _project_id(f)
        a_proj = asset_proj_by_id.get(faid)
        if f_proj is not None and a_proj is not None and f_proj != a_proj:
            continue
        # Also if project_id param filter set, skip findings not matching
        if project_id is not None and f_proj is not None and _norm_str(project_id) != f_proj:
            continue
        finding_by_asset.setdefault(faid, []).append(fid)

    # Deterministically sort finding lists per asset
    for k in finding_by_asset:
        finding_by_asset[k] = sorted(set(finding_by_asset[k]))

    # Relationships: normalize, deduplicate, project-isolate, sort
    # Use dict to dedup by (src, tgt, rel_type)
    rel_dedup: dict[tuple[str, str, str], dict] = {}
    # First, sort relationships deterministically by stringified content to make dedup stable
    def _rel_sort_key(r: dict):
        src = _norm_str(r.get("source_asset_id") or r.get("source_id") or r.get("source_value") or "")
        tgt = _norm_str(r.get("target_asset_id") or r.get("target_id") or r.get("target_value") or "")
        rtype = _norm_str(r.get("relationship_type") or r.get("type") or "")
        return (src.lower(), tgt.lower(), rtype.lower(), _norm_str(r.get("project_id") or ""))

    sorted_rels_input = sorted(
        [r for r in relationships if isinstance(r, dict)],
        key=_rel_sort_key
    )

    for rel in sorted_rels_input:
        # Shallow copy
        rel_copy = dict(rel)
        src_id, tgt_id, rtype, r_proj = _normalize_relationship(rel_copy, asset_value_index, asset_id_set)
        if not src_id:
            continue
        # Project isolation: relationship project must match both endpoints if all have explicit projects
        s_proj = asset_proj_by_id.get(src_id)
        t_proj = asset_proj_by_id.get(tgt_id)
        # If any explicit project mismatch among source/target, skip edge
        if s_proj is not None and t_proj is not None and s_proj != t_proj:
            continue
        # Relationship project must match endpoints
        if r_proj is not None:
            if s_proj is not None and r_proj != s_proj:
                continue
            if t_proj is not None and r_proj != t_proj:
                continue
            if project_id is not None and r_proj != _norm_str(project_id):
                continue
        else:
            # If relationship has no project but endpoints have project, still allow if endpoints share project
            pass
        # If global project_id filter set, ensure endpoints belong to that project (if they have project)
        if project_id is not None:
            pid_str = _norm_str(project_id)
            # If endpoints have explicit project that mismatches filter, they were already filtered, but also ensure at least one endpoint matches filter if endpoints have project
            if s_proj is not None and s_proj != pid_str:
                continue
            if t_proj is not None and t_proj != pid_str:
                continue

        key = (src_id, tgt_id, rtype)
        if key in rel_dedup:
            # Merge metadata deterministically not needed for traversal, but keep first
            continue
        # Build normalized relationship record for output/traversal
        norm_rel = {
            "source_asset_id": src_id,
            "target_asset_id": tgt_id,
            "relationship_type": rtype,
        }
        # Preserve project_id for path grouping
        effective_proj = r_proj or s_proj or t_proj
        if effective_proj:
            norm_rel["project_id"] = effective_proj
        # Preserve metadata if present (copy, not mutate)
        if isinstance(rel.get("metadata"), dict):
            norm_rel["metadata"] = dict(rel.get("metadata"))
        elif isinstance(rel.get("metadata"), str):
            norm_rel["metadata"] = rel.get("metadata")
        rel_dedup[key] = norm_rel

    # Adjacency list deterministic
    adj: dict[str, list[dict]] = {aid: [] for aid in asset_by_id}
    for (src, tgt, rtype), rel in rel_dedup.items():
        adj[src].append(rel)
    # Sort each adjacency list by (target_id, relationship_type)
    for src in adj:
        adj[src].sort(key=lambda e: (e["target_asset_id"], e["relationship_type"]))

    # Discover paths via DFS from each start node
    # Start nodes: all nodes that have outgoing edges, sorted deterministically
    start_nodes = sorted([aid for aid, lst in adj.items() if lst])

    # If graph has isolated nodes with incoming but no outgoing, they won't be starts, but paths that start later
    # will still be discovered as prefixes. That's correct; we want all simple paths.
    # However to also capture paths that are only incoming chains, they will be discovered when starting from predecessors.
    # So starting from outgoing nodes is sufficient to enumerate all paths of length >=2.

    all_paths: list[dict] = []
    seen_canonical: set[str] = set()

    # For deterministic traversal, use iterative DFS with explicit stack
    # We enumerate DFS from each start, limiting depth and cycling.
    # Use recursion with visited set per path.
    def dfs(current_id: str, path_nodes: list[str], path_rels: list[dict], visited: set[str]):
        # Emit path if length >=2 (at least one edge)
        if len(path_nodes) >= 2:
            # Build path data
            # Project is determined by first node's project (all share due to filtering)
            proj = asset_proj_by_id.get(path_nodes[0])
            # Validate all nodes share same project (should hold)
            # Collect finding_ids for any node in path (spec: associated findings)
            fids: list[str] = []
            for nid in path_nodes:
                lst = finding_by_asset.get(nid, [])
                for fid in lst:
                    # Project isolation per finding vs path project
                    f_proj = finding_proj_by_id.get(fid)
                    if proj is not None and f_proj is not None and proj != f_proj:
                        continue
                    if fid not in fids:
                        fids.append(fid)
            fids_sorted = sorted(fids)
            rel_types = [r["relationship_type"] for r in path_rels]
            node_types = [_asset_type(asset_by_id[n]) for n in path_nodes]

            # Deduplication key
            canonical_key = f"{proj or 'default'}|{'->'.join(path_nodes)}|{'->'.join(rel_types)}|{','.join(fids_sorted)}"
            if canonical_key not in seen_canonical:
                seen_canonical.add(canonical_key)
                # Classify
                path_type = _classify_path_type(node_types, rel_types, bool(fids_sorted))
                conf = _confidence(len(path_nodes), bool(fids_sorted), len(path_rels))
                nodes_data = [dict(asset_by_id[n]) for n in path_nodes]
                rels_data = [dict(r) for r in path_rels]
                # Build deterministic path_id
                pid_hash = _canonical_path_id(proj, path_nodes, rel_types, fids_sorted)
                # Entry/target
                entry_asset = dict(asset_by_id[path_nodes[0]])
                target_asset = dict(asset_by_id[path_nodes[-1]])
                # Description
                desc = _build_description(nodes_data, rels_data, fids_sorted, path_type, conf)
                path_obj = {
                    "path_id": pid_hash,
                    "project_id": proj,
                    "entry_asset": entry_asset,
                    "target_asset": target_asset,
                    "nodes": nodes_data,
                    "relationships": rels_data,
                    "finding_ids": fids_sorted,
                    "path_length": len(path_nodes),
                    "path_type": path_type,
                    "confidence": conf,
                    "description": desc,
                    # human_readable alias for spec example
                    "human_readable": desc,
                }
                all_paths.append(path_obj)
                if len(all_paths) >= max_paths:
                    return True  # signal to stop

        if len(path_nodes) >= max_path_length:
            return False
        # Explore neighbors deterministically
        for edge in adj.get(current_id, []):
            tgt = edge["target_asset_id"]
            if tgt in visited:
                continue  # cycle prevention
            # Also enforce project consistency (should already be filtered)
            # Extend
            path_nodes.append(tgt)
            path_rels.append(edge)
            visited.add(tgt)
            should_stop = dfs(tgt, path_nodes, path_rels, visited)
            # backtrack
            visited.remove(tgt)
            path_nodes.pop()
            path_rels.pop()
            if should_stop:
                return True
        return False

    for start in start_nodes:
        if len(all_paths) >= max_paths:
            break
        # Start path includes start node
        dfs(start, [start], [], {start})

    # Deterministic ordering of final paths: sort by canonical components
    def _path_sort_key(p: dict):
        # Use node ids, rel types, finding_ids, project_id
        node_ids = [ _asset_id(n) or "" for n in p.get("nodes", []) ]
        rel_types = [ _norm_str(r.get("relationship_type") or "") for r in p.get("relationships", []) ]
        return (
            _norm_str(p.get("project_id") or ""),
            tuple(node_ids),
            tuple(rel_types),
            tuple(p.get("finding_ids", [])),
            p.get("path_id") or "",
        )

    all_paths.sort(key=_path_sort_key)

    # Truncate to max_paths deterministically (already bounded during DFS, but sort may change order)
    if len(all_paths) > max_paths:
        all_paths = all_paths[:max_paths]

    # Re-sort after truncation? Already sorted; truncated preserves order.
    return all_paths

# Public API alias for compatibility
discover_attack_paths = discover_attack_paths

# Re-export prioritizer for evaluator import flexibility
try:
    from app.services.risk_intelligence.prioritizer import prioritize_attack_paths  # noqa: F401
except ImportError:
    pass

"""
S5.4 Attack-Path Risk Prioritization — additive, deterministic, no DB/network/AI.

Takes S5.3 paths + S5.1/S5.2 signals and calculates explainable priority.

Reuses S5.1 terminology and scoring conventions.
"""

from __future__ import annotations

import copy
import ipaddress
from typing import Any

try:
    from app.asset_intel.types import RELATIONSHIP_TYPES  # noqa: F401
except ImportError:
    pass

# Reuse severity weights/levels from enricher / RiskAssessmentEngine
SEVERITY_SCORES = {"critical": 90, "high": 75, "medium": 50, "low": 25, "info": 5}
SEVERITY_CONTRIBUTION = {"critical": 35, "high": 20, "medium": 10, "low": 3, "info": 0}
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

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

def _norm_str(v: Any) -> str:
    if v is None:
        return ""
    return str(v).strip()

def _project_id(obj: dict) -> str | None:
    if not isinstance(obj, dict):
        return None
    for k in ("project_id", "projectId"):
        if k in obj and obj[k] not in (None, ""):
            s = _norm_str(obj[k])
            if s:
                return s
    md = obj.get("metadata")
    if isinstance(md, dict) and md.get("project_id") not in (None, ""):
        s = _norm_str(md.get("project_id"))
        if s:
            return s
    return None

def _finding_id(f: dict) -> str | None:
    if not isinstance(f, dict):
        return None
    for k in ("id", "finding_id", "_id"):
        if f.get(k) not in (None, ""):
            s = _norm_str(f.get(k))
            if s:
                return s
    return None

def _asset_id(a: dict) -> str | None:
    if not isinstance(a, dict):
        return None
    for k in ("id", "asset_id", "_id"):
        if a.get(k) not in (None, ""):
            return _norm_str(a.get(k))
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

def _exposure_from_asset(asset: dict | None) -> tuple[bool | None, str | None]:
    if not asset or not isinstance(asset, dict):
        return None, None
    atype = str(asset.get("asset_type") or asset.get("type") or "").lower()
    value = str(asset.get("value") or asset.get("asset_value") or "").strip()
    if atype in ("url", "web_site", "web_host"):
        if value.startswith("http://") or value.startswith("https://"):
            return True, "url_asset"
    if atype in ("ip", "ipv6"):
        pub = _is_public_ip(value)
        if pub is True:
            return True, "public_ip"
        if pub is False:
            return False, "private_ip"
    rels = asset.get("relationships") or asset.get("asset_relationships") or []
    if isinstance(rels, list) and rels:
        for rel in rels:
            if not isinstance(rel, dict):
                continue
            rtype = str(rel.get("relationship_type") or rel.get("type") or "").lower()
            if rtype in ("exposes", "resolves_to", "serves"):
                return True, f"relationship_{rtype}"
    if atype in ("domain", "subdomain", "hostname"):
        return None, None
    return None, None

def _extract_enriched_lookup(enriched_findings) -> dict[str, dict]:
    """Build fid -> enriched dict lookup deterministically."""
    lookup: dict[str, dict] = {}
    if enriched_findings is None:
        return lookup
    if isinstance(enriched_findings, dict):
        # dict mapping id -> enriched
        for k, v in enriched_findings.items():
            if isinstance(v, dict):
                fid = _norm_str(k)
                if fid and fid not in lookup:
                    lookup[fid] = dict(v)
            # also possible enriched_findings is single enriched dict with risk_score?
        # If dict looks like single enriched result (has risk_score), treat as not mapping
        if "risk_score" in enriched_findings and "severity" in enriched_findings:
            # single enriched, try to extract fid from finding inside
            maybe_fid = None
            if isinstance(enriched_findings.get("finding"), dict):
                maybe_fid = _finding_id(enriched_findings.get("finding"))
            if maybe_fid and maybe_fid not in lookup:
                lookup[maybe_fid] = dict(enriched_findings)
        return lookup
    if isinstance(enriched_findings, list):
        for item in enriched_findings:
            if not isinstance(item, dict):
                continue
            # item may be enriched with "finding" key
            fid = None
            if "finding" in item and isinstance(item["finding"], dict):
                fid = _finding_id(item["finding"])
            if not fid:
                fid = _finding_id(item)
            # also check if item has risk_score and finding id derived from item's id?
            if not fid and item.get("id"):
                fid = _norm_str(item.get("id"))
            if fid and fid not in lookup:
                # store shallow copy
                lookup[fid] = dict(item)
        return lookup
    return lookup

def _build_finding_lookup(findings) -> dict[str, dict]:
    lookup: dict[str, dict] = {}
    if not isinstance(findings, list):
        return lookup
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = _finding_id(f)
        if not fid:
            continue
        if fid not in lookup:
            lookup[fid] = dict(f)
    return lookup

def _build_asset_lookup(assets) -> dict[str, dict]:
    lookup: dict[str, dict] = {}
    if not isinstance(assets, list):
        return lookup
    for a in assets:
        if not isinstance(a, dict):
            continue
        aid = _asset_id(a)
        if not aid:
            continue
        if aid not in lookup:
            lookup[aid] = dict(a)
    return lookup

def _build_asset_context_lookup(asset_contexts) -> dict[str, dict]:
    lookup: dict[str, dict] = {}
    if asset_contexts is None:
        return lookup
    if isinstance(asset_contexts, dict):
        # Could be mapping asset_id -> context dict OR single context?
        # Heuristic: if keys look like asset ids and values have asset_context
        for k, v in asset_contexts.items():
            if isinstance(v, dict):
                # v may be context wrapper from S5.2: {asset_id, asset_context, ...}
                # extract asset_id
                aid = _norm_str(k)
                if aid:
                    lookup[aid] = dict(v)
                # also if v contains asset_id field
                inner_aid = v.get("asset_id") or v.get("id")
                if inner_aid:
                    ia = _norm_str(inner_aid)
                    if ia and ia not in lookup:
                        lookup[ia] = dict(v)
        # If dict is single asset_context result (has asset_context key)
        if "asset_context" in asset_contexts and "asset_id" in asset_contexts:
            aid = _norm_str(asset_contexts.get("asset_id"))
            if aid and aid not in lookup:
                lookup[aid] = dict(asset_contexts)
        return lookup
    if isinstance(asset_contexts, list):
        for item in asset_contexts:
            if not isinstance(item, dict):
                continue
            aid = item.get("asset_id") or item.get("id") or item.get("assetId")
            if aid:
                aid_s = _norm_str(aid)
                if aid_s and aid_s not in lookup:
                    lookup[aid_s] = dict(item)
            # also handle wrapper with asset_context
            if "asset_context" in item:
                inner_aid = item.get("asset_id")
                if inner_aid:
                    ia = _norm_str(inner_aid)
                    if ia and ia not in lookup:
                        lookup[ia] = dict(item)
        return lookup
    return lookup

def prioritize_attack_paths(
    paths: list[dict] | None = None,
    findings: list[dict] | None = None,
    *,
    enriched_findings: list[dict] | dict | None = None,
    asset_contexts: list[dict] | dict | None = None,
    assets: list[dict] | None = None,
    project_id: str | None = None,
    max_paths: int | None = None,
) -> list[dict]:
    """
    Deterministic attack-path prioritization.

    Preserves original path information and adds:
      priority_score (0-100), priority_level, priority_grade,
      contributing_signals, reasons, available_signals, unavailable_signals

    Project-isolated, bounded, explainable.

    Args:
        paths: list from discover_attack_paths (S5.3)
        findings: raw findings list (for severity/title etc)
        enriched_findings: optional S5.1 enriched results (list or dict mapping id->enriched)
        asset_contexts: optional S5.2 asset_context results (list or dict mapping asset_id -> context)
        assets: optional raw assets for exposure fallback
        project_id: optional hard filter (if set, only paths for this project)
        max_paths: optional truncation

    Returns:
        list of prioritized path dicts sorted by priority_score descending then deterministic tie-breakers.
        Each output contains copy of original path fields plus priority fields.
    """
    paths = paths if isinstance(paths, list) else []
    findings = findings if isinstance(findings, list) else []

    # max_paths clamp if provided
    if max_paths is not None:
        try:
            max_paths = int(max_paths)
        except (TypeError, ValueError):
            max_paths = None
        if isinstance(max_paths, int):
            if max_paths < 1:
                max_paths = 1
            if max_paths > 500:
                max_paths = 500

    # Build lookups without mutating callers
    finding_by_id = _build_finding_lookup(findings)
    enriched_by_id = _extract_enriched_lookup(enriched_findings)
    # If enriched_findings not provided but findings contain enriched fields (risk_score etc), treat findings as enriched?
    # We'll fallback to finding_by_id for signals

    asset_by_id = _build_asset_lookup(assets)
    asset_ctx_by_id = _build_asset_context_lookup(asset_contexts)

    # Also need to handle case where findings themselves are enriched (contain risk_score)
    # For convenience, if finding has risk_score, treat as enriched entry
    for fid, f in list(finding_by_id.items()):
        if "risk_score" in f and fid not in enriched_by_id:
            enriched_by_id[fid] = dict(f)

    result: list[dict] = []

    for p in paths:
        if not isinstance(p, dict):
            continue
        # Defensive copy of original path for preservation check
        orig = copy.deepcopy(p)

        # Extract core path fields deterministically, handle missing
        path_id = _norm_str(p.get("path_id") or p.get("id") or "")
        path_project = _project_id(p) or p.get("project_id")
        # Respect global project_id filter
        if project_id is not None and path_project is not None and _norm_str(project_id) != _norm_str(path_project):
            continue
        if project_id is not None and path_project is None:
            # If path has no project but filter set, skip? Keep isolated
            continue

        # Nodes/relationships/finding_ids
        nodes = p.get("nodes") if isinstance(p.get("nodes"), list) else []
        relationships = p.get("relationships") if isinstance(p.get("relationships"), list) else []
        finding_ids = p.get("finding_ids") if isinstance(p.get("finding_ids"), list) else []
        # Also support findings field
        if not finding_ids and isinstance(p.get("findings"), list):
            finding_ids = [_finding_id(x) or _norm_str(x) for x in p.get("findings") if x]

        # Clean finding_ids: only strings, dedup sorted for internal, but preserve original order for determinism? For scoring we use sorted unique
        clean_fids: list[str] = []
        for fid in finding_ids:
            if fid is None:
                continue
            s = _norm_str(fid)
            if s and s not in clean_fids:
                clean_fids.append(s)
        # Filter by project isolation: only keep findings where finding project matches path project (if both explicit)
        filtered_fids: list[str] = []
        for fid in clean_fids:
            f_proj = None
            if fid in finding_by_id:
                f_proj = _project_id(finding_by_id[fid])
            elif fid in enriched_by_id:
                ef = enriched_by_id[fid]
                # enriched may have finding inside
                if isinstance(ef.get("finding"), dict):
                    f_proj = _project_id(ef.get("finding"))
                else:
                    f_proj = _project_id(ef)
            # If both have explicit projects and differ, skip
            if path_project is not None and f_proj is not None and _norm_str(path_project) != _norm_str(f_proj):
                continue
            filtered_fids.append(fid)
        clean_fids = sorted(set(filtered_fids))

        # Determine signals from findings on this path
        # Collect per-finding attributes
        severities: list[str] = []
        risk_scores: list[int] = []
        confidence_scores: list[int] = []
        confidence_levels: list[str] = []
        scanner_counts: list[int] = []
        provenance_qualities: list[int] = []
        evidence_counts: list[int] = []

        has_cve = False
        has_cwe = False
        has_rule = False

        for fid in clean_fids:
            # Prefer enriched
            enriched = enriched_by_id.get(fid)
            raw = finding_by_id.get(fid)

            # Severity
            sev = None
            if enriched and isinstance(enriched, dict):
                sev = str(enriched.get("severity") or "").lower()
                if not sev and isinstance(enriched.get("finding"), dict):
                    sev = str(enriched["finding"].get("severity") or "").lower()
            if not sev and raw:
                sev = str(raw.get("severity") or "").lower()
            if sev not in SEVERITY_SCORES:
                if sev:
                    sev = "info" if sev not in SEVERITY_SCORES else sev
                else:
                    sev = None
            if sev:
                severities.append(sev)

            # risk_score
            if enriched and "risk_score" in enriched:
                try:
                    rs = int(enriched.get("risk_score"))
                    risk_scores.append(rs)
                except (TypeError, ValueError):
                    pass
            elif raw and "risk_score" in raw:
                try:
                    rs = int(raw.get("risk_score"))
                    risk_scores.append(rs)
                except (TypeError, ValueError):
                    pass

            # confidence
            if enriched and "confidence_score" in enriched:
                try:
                    cs = int(enriched.get("confidence_score"))
                    confidence_scores.append(cs)
                    lvl = str(enriched.get("confidence_level") or "low").lower()
                    confidence_levels.append(lvl)
                except (TypeError, ValueError):
                    pass
            elif enriched and isinstance(enriched.get("validation"), dict):
                try:
                    cs = int(enriched["validation"].get("confidence_score") or 0)
                    confidence_scores.append(cs)
                except (TypeError, ValueError):
                    pass
            elif raw and "confidence_score" in raw:
                try:
                    cs = int(raw.get("confidence_score"))
                    confidence_scores.append(cs)
                except (TypeError, ValueError):
                    pass

            # scanner_count / corroboration
            sc = None
            if enriched and "scanner_count" in enriched:
                try:
                    sc = int(enriched.get("scanner_count"))
                    scanner_counts.append(sc)
                except (TypeError, ValueError):
                    pass
            elif enriched and isinstance(enriched.get("validation"), dict):
                try:
                    sc = int(enriched["validation"].get("scanner_count") or 1)
                    scanner_counts.append(sc)
                except (TypeError, ValueError):
                    pass
            elif raw and "scanner_count" in raw:
                try:
                    sc = int(raw.get("scanner_count"))
                    scanner_counts.append(sc)
                except (TypeError, ValueError):
                    pass
            elif raw and isinstance(raw.get("metadata"), dict) and raw["metadata"].get("scanner_count"):
                try:
                    sc = int(raw["metadata"].get("scanner_count"))
                    scanner_counts.append(sc)
                except (TypeError, ValueError):
                    pass

            # provenance_quality
            if enriched and "provenance_quality" in enriched:
                try:
                    pq = int(enriched.get("provenance_quality"))
                    provenance_qualities.append(pq)
                except (TypeError, ValueError):
                    pass
            elif enriched and "provenance_quality_score" in enriched:
                try:
                    pq = int(enriched.get("provenance_quality_score"))
                    provenance_qualities.append(pq)
                except (TypeError, ValueError):
                    pass
            elif enriched and isinstance(enriched.get("provenance"), dict):
                try:
                    pq = int(enriched["provenance"].get("provenance_quality_score") or 0)
                    provenance_qualities.append(pq)
                except (TypeError, ValueError):
                    pass
            elif raw and "provenance_quality" in raw:
                try:
                    pq = int(raw.get("provenance_quality"))
                    provenance_qualities.append(pq)
                except (TypeError, ValueError):
                    pass

            if enriched and "evidence_count" in enriched:
                try:
                    ec = int(enriched.get("evidence_count"))
                    evidence_counts.append(ec)
                except (TypeError, ValueError):
                    pass

            # cve/cwe/rule presence
            # Check normalized/enriched fields
            check_sources = []
            if enriched:
                check_sources.append(enriched)
                if isinstance(enriched.get("finding"), dict):
                    check_sources.append(enriched["finding"])
                if isinstance(enriched.get("normalized"), dict):
                    check_sources.append(enriched["normalized"])
            if raw:
                check_sources.append(raw)
                if isinstance(raw.get("metadata"), dict):
                    check_sources.append(raw["metadata"])
            for src in check_sources:
                if not isinstance(src, dict):
                    continue
                if src.get("cve"):
                    has_cve = True
                if src.get("cwe"):
                    has_cwe = True
                if src.get("rule_id") or src.get("ruleId"):
                    has_rule = True

        # Determine highest severity
        highest_sev = None
        highest_order = -1
        for s in severities:
            o = SEVERITY_ORDER.get(s, -1)
            if o > highest_order:
                highest_order = o
                highest_sev = s
        if not highest_sev and clean_fids:
            highest_sev = "info"
            highest_order = 0
        elif not highest_sev:
            highest_sev = None

        severity_contrib = SEVERITY_CONTRIBUTION.get(highest_sev, 0) if highest_sev else 0

        # Confidence
        best_conf_score = max(confidence_scores) if confidence_scores else 0
        confidence_contrib = int(best_conf_score / 100 * 15) if confidence_scores else 0
        # Determine if confidence signal available
        has_confidence = bool(confidence_scores)

        # Corroboration
        best_scanner = max(scanner_counts) if scanner_counts else 1
        if best_scanner < 1:
            best_scanner = 1
        if best_scanner == 1:
            corroboration_contrib = 0
        elif best_scanner == 2:
            corroboration_contrib = 10
        else:
            corroboration_contrib = 15
        has_corroboration = bool(scanner_counts) or bool(clean_fids) # we at least have count 1 if findings exist; but mark unavailable if no findings

        # Provenance
        best_pq = max(provenance_qualities) if provenance_qualities else 0
        provenance_contrib = int(best_pq / 10) if provenance_qualities else 0
        has_provenance = bool(provenance_qualities)

        # Exposure and asset modifier from asset_contexts / assets
        exposed = False
        exposure_signal = None
        has_exposure_signal = False
        asset_modifier = 0
        has_asset_modifier = False

        # Build node asset_ids for exposure lookup
        node_ids: list[str] = []
        for n in nodes:
            if isinstance(n, dict):
                aid = _asset_id(n) or _norm_str(n.get("value") or "")
                # For prioritizer, nodes are dicts with id, try to get id
                nid = _asset_id(n)
                if nid:
                    node_ids.append(nid)
                else:
                    # fallback to value key? but need to match asset_by_id keys which are ids, so use value as fallback not ideal
                    pass

        # If nodes don't have ids (should have), fallback to path's nodes values
        # Check asset contexts
        for nid in node_ids:
            ctx = asset_ctx_by_id.get(nid)
            if ctx and isinstance(ctx, dict):
                # ctx could be S5.2 wrapper: {asset_context: {is_externally_exposed, asset_risk_modifier}}
                inner = ctx.get("asset_context") if isinstance(ctx.get("asset_context"), dict) else ctx
                if isinstance(inner, dict):
                    if "is_externally_exposed" in inner:
                        has_exposure_signal = True
                        if inner.get("is_externally_exposed") is True:
                            exposed = True
                            exposure_signal = inner.get("exposure_signal") or "exposed"
                    if "asset_risk_modifier" in inner:
                        try:
                            mod = int(inner.get("asset_risk_modifier"))
                            # Take max modifier
                            if not has_asset_modifier or mod > asset_modifier:
                                asset_modifier = mod
                            has_asset_modifier = True
                        except (TypeError, ValueError):
                            pass
                    # also check direct is_externally_exposed
                if "is_externally_exposed" in ctx and not has_exposure_signal:
                    has_exposure_signal = True
                    if ctx.get("is_externally_exposed") is True:
                        exposed = True
            # fallback to raw asset
            asset_obj = asset_by_id.get(nid)
            if asset_obj:
                exp, sig = _exposure_from_asset(asset_obj)
                if exp is not None:
                    has_exposure_signal = True
                    if exp is True:
                        exposed = True
                        exposure_signal = sig

        # Also check if any node asset is url/ip public even without context
        if not has_exposure_signal:
            for nid in node_ids:
                a = asset_by_id.get(nid)
                if a:
                    exp, _ = _exposure_from_asset(a)
                    if exp is not None:
                        has_exposure_signal = True
                        if exp:
                            exposed = True
                        break
            # If still no signal, check nodes themselves directly (they are asset dicts)
            if not has_exposure_signal:
                for n in nodes:
                    if isinstance(n, dict):
                        exp, _ = _exposure_from_asset(n)
                        if exp is not None:
                            has_exposure_signal = True
                            if exp:
                                exposed = True
                            break

        # Exposure contrib bounded
        exposure_contrib = 10 if exposed else 0

        # Asset modifier contribution: clamp already -10 to 15, use directly
        # has_asset_modifier already
        # If no modifier available, 0

        # Path completeness
        has_finding = bool(clean_fids)
        path_len = len(nodes) if nodes else int(p.get("path_length") or 0)
        rel_len = len(relationships)
        if has_finding and path_len >= 3 and rel_len >= 2:
            completeness_contrib = 5
            completeness_label = "complete"
        elif has_finding and path_len >= 2:
            completeness_contrib = 2
            completeness_label = "partial"
        else:
            completeness_contrib = 0
            completeness_label = "incomplete"

        # Path length contrib small, capped
        if path_len <= 2:
            length_contrib = 0
        elif path_len == 3:
            length_contrib = 1
        elif path_len == 4:
            length_contrib = 2
        else:
            length_contrib = 3

        # Calculate priority_score
        priority_score = 0
        priority_score += severity_contrib
        priority_score += confidence_contrib
        priority_score += corroboration_contrib if has_finding else 0
        priority_score += provenance_contrib
        priority_score += exposure_contrib
        priority_score += asset_modifier  # can be negative
        priority_score += completeness_contrib
        priority_score += length_contrib

        # Clamp 0-100
        if priority_score > 100:
            priority_score = 100
        if priority_score < 0:
            priority_score = 0

        priority_level = _risk_level(priority_score)
        priority_grade = _grade(priority_score)

        # Build signals
        signals: list[str] = []
        available: list[str] = []
        unavailable: list[str] = []

        if highest_sev:
            signals.append(f"severity:{highest_sev}")
            available.append("severity")
            available.append("risk_score")  # severity implies risk
        else:
            unavailable.append("severity")
            unavailable.append("risk_score")

        if has_confidence:
            signals.append(f"confidence:{best_conf_score}")
            available.append("confidence")
        else:
            unavailable.append("confidence")

        if has_finding and scanner_counts:
            signals.append(f"corroboration:count={best_scanner}")
            available.append("corroboration")
        elif has_finding:
            # at least count 1 available if findings exist
            signals.append(f"corroboration:count=1")
            available.append("corroboration")
        else:
            unavailable.append("corroboration")

        if has_provenance:
            signals.append(f"provenance_quality:{best_pq}")
            available.append("provenance_quality")
            available.append("evidence")
        else:
            unavailable.append("provenance_quality")
            unavailable.append("evidence")

        if has_exposure_signal:
            signals.append("exposure:externally_exposed" if exposed else "exposure:internal")
            available.append("exposure")
        else:
            unavailable.append("exposure")

        if has_asset_modifier:
            signals.append(f"asset_modifier:{asset_modifier}")
            available.append("asset_modifier")
            available.append("asset_context")
        else:
            unavailable.append("asset_modifier")
            # asset_context unavailable if no context
            if not has_asset_modifier:
                unavailable.append("asset_context")

        # completeness and length always available from path
        signals.append(f"completeness:{completeness_label}")
        available.append("completeness")
        signals.append(f"path_length:{path_len}")
        available.append("path_length")

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

        # Never fabricated signals
        for sig in ["exploitability", "epss", "kev", "business_criticality", "asset_criticality"]:
            if sig not in unavailable:
                unavailable.append(sig)
            if sig in available:
                available.remove(sig)

        available = sorted(set(available))
        unavailable = sorted(set(unavailable))
        signals = sorted(set(signals))

        # Reasons deterministic, bounded
        reasons: list[str] = []
        if highest_sev:
            reasons.append(f"Highest severity {highest_sev} contributes {severity_contrib} points.")
        else:
            reasons.append("No finding severity available; 0 points.")
        if has_confidence:
            reasons.append(f"Confidence {best_conf_score} contributes {confidence_contrib} points.")
        else:
            reasons.append("No confidence signal; 0 points.")
        if has_finding:
            if best_scanner >= 2:
                reasons.append(f"Corroborated by {best_scanner} scanners contributes {corroboration_contrib} points.")
            else:
                reasons.append("Single scanner detection; 0 corroboration points.")
        if has_provenance and best_pq:
            reasons.append(f"Provenance quality {best_pq} contributes {provenance_contrib} points.")
        if exposed:
            reasons.append("Externally exposed asset contributes 10 points.")
        elif has_exposure_signal and not exposed:
            reasons.append("Internal asset does not add exposure points.")
        if has_asset_modifier and asset_modifier != 0:
            reasons.append(f"Asset risk modifier {asset_modifier} applied.")
        if completeness_contrib:
            reasons.append(f"Path {completeness_label} contributes {completeness_contrib} points.")
        if length_contrib:
            reasons.append(f"Path length {path_len} contributes {length_contrib} points.")
        if has_cve:
            reasons.append("CVE presence noted.")
        # Ensure deterministic sorted? Keep order as added but bounded
        reasons = reasons[:20]

        # Build prioritized path: copy original fields plus priority fields
        # Must not mutate original p
        prioritized = copy.deepcopy(p)
        # Ensure original fields preserved; then add priority fields
        prioritized["priority_score"] = priority_score
        prioritized["priority_level"] = priority_level
        prioritized["priority_grade"] = priority_grade
        prioritized["contributing_signals"] = signals
        prioritized["reasons"] = reasons
        prioritized["available_signals"] = available
        prioritized["unavailable_signals"] = unavailable
        # Also expose explicit components for debugging/verification (not required but helpful)
        prioritized["priority_signals"] = {
            "severity": highest_sev,
            "severity_contrib": severity_contrib,
            "confidence_score": best_conf_score if has_confidence else None,
            "confidence_contrib": confidence_contrib,
            "scanner_count": best_scanner if has_finding else None,
            "corroboration_contrib": corroboration_contrib if has_finding else 0,
            "provenance_quality": best_pq if has_provenance else None,
            "provenance_contrib": provenance_contrib,
            "exposed": exposed,
            "exposure_contrib": exposure_contrib,
            "asset_modifier": asset_modifier if has_asset_modifier else 0,
            "completeness": completeness_label,
            "completeness_contrib": completeness_contrib,
            "path_length": path_len,
            "length_contrib": length_contrib,
        }

        # Preserve path_id for sorting; ensure it exists
        if not prioritized.get("path_id"):
            prioritized["path_id"] = path_id or f"path-{hash(str(prioritized)) % 100000}"

        result.append(prioritized)

    # Deterministic ordering: sort by priority_score descending, then priority_level, then path_id, then finding_ids
    def _sort_key(x: dict):
        # Negative score for descending
        return (
            -int(x.get("priority_score", 0)),
            _norm_str(x.get("priority_level") or ""),
            _norm_str(x.get("path_id") or ""),
            tuple(x.get("finding_ids") or []),
            _norm_str(x.get("project_id") or ""),
        )

    result.sort(key=_sort_key)

    if max_paths is not None and len(result) > max_paths:
        result = result[:max_paths]

    return result

# Alias for conceptual API
prioritize_attack_paths = prioritize_attack_paths

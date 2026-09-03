"""Evidence-based cross-scanner asset correlation.

Operates on already-parsed/enriched observations. Canonical identity
comes from E2.1. This module does not invent DNS, reverse-DNS, or
URL-to-IP links.
"""

from app.asset_intel.enrich import enrich_parsed_output
from app.asset_intel.normalize import (
    canonical_value,
    infer_asset_type,
    infer_asset_value,
)
from app.asset_intel.provenance import (
    attach_relationship_provenance,
    merge_relationship_metadata,
)
from app.asset_intel.types import HOSTNAME_TYPES, RELATIONSHIP_TYPES


def correlate_parsed_bundle(
    scanner: str,
    assets: list,
    findings: list | None = None,
    existing_assets: list | None = None,
) -> dict:
    enriched = enrich_parsed_output(scanner, assets, findings)
    return correlate_assets(
        {
            "scanner": scanner,
            "assets": enriched["assets"],
            "relationships": enriched["relationships"],
            "findings": findings or [],
        },
        existing_assets=existing_assets,
    )


def correlate_assets(
    parsed_result: dict,
    existing_assets: list | None = None,
) -> dict:
    scanner = str(parsed_result.get("scanner") or "").strip().lower() or None
    collected: dict[tuple[str, str], dict] = {}

    for asset in existing_assets or []:
        if isinstance(asset, dict):
            _index_asset(collected, asset, scanner=None)

    for asset in parsed_result.get("assets") or []:
        if isinstance(asset, dict):
            _index_asset(collected, asset, scanner=scanner)

    relationships = []

    for relationship in parsed_result.get("relationships") or []:
        if not isinstance(relationship, dict):
            continue

        normalized = _normalize_relationship(relationship, collected)
        if not normalized:
            continue

        if not _relationship_allowed(normalized):
            continue

        normalized["metadata"] = attach_relationship_provenance(
            normalized,
            scanner,
        )

        key = (
            normalized["source_type"],
            normalized["source_value"],
            normalized["target_type"],
            normalized["target_value"],
            normalized["relationship_type"],
        )

        existing_rel = next(
            (
                item
                for item in relationships
                if (
                    item["source_type"],
                    item["source_value"],
                    item["target_type"],
                    item["target_value"],
                    item["relationship_type"],
                ) == key
            ),
            None,
        )
        if existing_rel:
            existing_rel["metadata"] = merge_relationship_metadata(
                existing_rel.get("metadata"),
                normalized["metadata"],
                scanner,
            )
            continue

        relationships.append(normalized)

    return {
        "scanner": parsed_result.get("scanner"),
        "assets": list(collected.values()),
        "relationships": relationships,
        "findings": list(parsed_result.get("findings") or []),
    }


def _index_asset(collected: dict, asset: dict, scanner: str | None) -> dict | None:
    asset_type = infer_asset_type(asset)
    value = infer_asset_value(asset) or canonical_value(
        asset_type,
        asset.get("value"),
    )

    if not value:
        return None

    key = (asset_type, value)
    metadata = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
    extra = dict(metadata)

    if scanner:
        sources = list(extra.get("sources") or [])
        if scanner not in sources:
            sources.append(scanner)
        extra["sources"] = sources

    existing = collected.get(key)

    if existing is None:
        item = {
            "type": asset_type,
            "value": value,
            "metadata": extra,
        }
        if asset.get("id"):
            item["id"] = asset["id"]
        collected[key] = item
        return item

    merged = dict(existing.get("metadata") or {})
    for field, item in extra.items():
        if field == "sources":
            continue
        if field not in merged or merged[field] in (None, "", [], {}):
            merged[field] = item
        elif isinstance(merged[field], dict) and isinstance(item, dict):
            merged[field] = {**merged[field], **item}
        else:
            merged[field] = item

    sources = list(merged.get("sources") or [])
    for source in extra.get("sources") or []:
        if source and source not in sources:
            sources.append(source)
    if sources:
        merged["sources"] = sources

    existing["metadata"] = merged
    if asset.get("id") and not existing.get("id"):
        existing["id"] = asset["id"]
    return existing


def _normalize_relationship(relationship: dict, collected: dict) -> dict | None:
    rel_type = str(relationship.get("relationship_type") or "").strip()
    if rel_type not in RELATIONSHIP_TYPES:
        return None

    source = _resolve_endpoint(
        collected,
        relationship.get("source_type"),
        relationship.get("source_value"),
    )
    target = _resolve_endpoint(
        collected,
        relationship.get("target_type"),
        relationship.get("target_value"),
    )

    if not source or not target:
        return None

    if source["type"] == target["type"] and source["value"] == target["value"]:
        return None

    metadata = relationship.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    return {
        "source_type": source["type"],
        "source_value": source["value"],
        "target_type": target["type"],
        "target_value": target["value"],
        "relationship_type": rel_type,
        "metadata": dict(metadata),
    }


def _resolve_endpoint(collected: dict, asset_type, value) -> dict | None:
    kind = str(asset_type or "").strip().lower()
    canonical = canonical_value(kind, value)
    if not canonical:
        return None

    found = collected.get((kind, canonical))
    if found:
        return found

    if kind in HOSTNAME_TYPES:
        for alias in ("domain", "subdomain", "hostname"):
            found = collected.get((alias, canonical))
            if found:
                return found

    if kind in {"url", "web_site"}:
        for alias in ("url", "web_site"):
            found = collected.get((alias, canonical))
            if found:
                return found

    return None


def _record_type(metadata: dict) -> str:
    evidence = metadata.get("evidence")
    if isinstance(evidence, dict) and evidence.get("record_type"):
        return str(evidence["record_type"]).upper()
    return str(metadata.get("record") or "").upper()


def _relationship_allowed(relationship: dict) -> bool:
    rel_type = relationship["relationship_type"]
    metadata = relationship.get("metadata") or {}
    source_type = relationship["source_type"]
    source_value = relationship["source_value"]
    target_value = relationship["target_value"]
    evidence = metadata.get("evidence") if isinstance(metadata.get("evidence"), dict) else {}

    if rel_type == "resolves_to":
        record = _record_type(metadata)
        if record in {"A", "AAAA"}:
            return True
        if metadata.get("evidence") == "resolved_ip":
            return True
        if evidence.get("kind") == "resolved_ip":
            return True
        return False

    if rel_type == "points_to":
        return _record_type(metadata) in {"CNAME", "MX", "NS"}

    if rel_type == "contains":
        return _is_immediate_child(target_value, source_value)

    if rel_type == "exposes":
        return source_type in {"ip", "ipv6", "web_site", "web_host", "host"}

    if rel_type == "runs":
        return source_type == "port"

    if rel_type == "serves":
        return source_type in {"url", "web_site"}

    if rel_type == "uses":
        return True

    if rel_type == "observed_on":
        return True

    return False


def _is_immediate_child(child: str, parent: str) -> bool:
    if not child or not parent or child == parent:
        return False

    suffix = "." + parent
    if not child.endswith(suffix):
        return False

    extra = child[: -len(suffix)]
    return extra != "" and "." not in extra

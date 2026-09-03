"""Relationship provenance, confidence, and validation.

Uses the existing JSONB metadata column. No extra tables.
"""

from __future__ import annotations

import json

from app.asset_intel.types import RELATIONSHIP_TYPES

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

CONFIDENCE_RANK = {
    CONFIDENCE_LOW: 0,
    CONFIDENCE_MEDIUM: 1,
    CONFIDENCE_HIGH: 2,
}

HIGH_CONFIDENCE_TYPES = frozenset(
    {
        "resolves_to",
        "points_to",
        "exposes",
        "runs",
        "serves",
        "uses",
    }
)

RELATIONSHIP_SEMANTICS = {
    "contains": "Parent asset contains an observed child hostname.",
    "resolves_to": "Hostname or domain resolves to an IP address.",
    "points_to": "DNS hostname points to another hostname (CNAME, MX, or NS).",
    "exposes": "Host or IP exposes a network port.",
    "runs": "Port runs a network service.",
    "serves": "URL serves an application technology.",
    "uses": "Hostname uses a TLS endpoint.",
    "observed_on": "An asset or finding was observed on a host or URL.",
}


class RelationshipValidationError(ValueError):
    """Raised when a relationship cannot be persisted."""


def relationship_confidence(relationship_type: str, evidence: dict | None = None) -> str:
    if relationship_type in HIGH_CONFIDENCE_TYPES:
        return CONFIDENCE_HIGH
    if relationship_type in RELATIONSHIP_TYPES:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_LOW


def attach_relationship_provenance(
    relationship: dict,
    scanner: str | None,
) -> dict:
    metadata = relationship.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}

    evidence = _extract_evidence(relationship, metadata)
    sources = _unique_sources(metadata.get("sources"), scanner)
    confidence = metadata.get("confidence")
    if confidence not in CONFIDENCE_RANK:
        confidence = relationship_confidence(
            relationship.get("relationship_type") or "",
            evidence,
        )

    provenance = {
        "sources": sources,
        "confidence": confidence,
        "evidence": evidence,
    }

    for key, value in metadata.items():
        if key in {"sources", "confidence", "evidence", "record"}:
            continue
        if key in {"protocol", "priority", "state", "product", "version"}:
            continue
        provenance[key] = value

    return provenance


def merge_relationship_metadata(
    existing,
    incoming,
    scanner: str | None = None,
) -> dict:
    base = existing if isinstance(existing, dict) else {}
    update = incoming if isinstance(incoming, dict) else {}

    merged = {
        key: item
        for key, item in base.items()
        if key not in {"sources", "evidence", "confidence"}
    }

    for key, item in update.items():
        if key in {"sources", "evidence", "confidence"}:
            continue
        if key not in merged or merged[key] in (None, "", [], {}):
            merged[key] = item
        elif isinstance(merged[key], dict) and isinstance(item, dict):
            merged[key] = {**merged[key], **item}
        else:
            merged[key] = item

    merged["evidence"] = {
        **_extract_evidence({"target_value": "", "metadata": base}, base),
        **_extract_evidence({"target_value": "", "metadata": update}, update),
    }
    merged["sources"] = _unique_sources(
        list(base.get("sources") or []) + list(update.get("sources") or []),
        scanner,
    )
    merged["confidence"] = _higher_confidence(
        base.get("confidence"),
        update.get("confidence"),
        relationship_confidence(
            str(update.get("relationship_type") or "")
        ),
    )

    json.dumps(merged, default=str)
    return merged


def validate_relationship(
    *,
    project_id: str,
    relationship_type: str,
    source_asset: dict | None,
    target_asset: dict | None,
    metadata=None,
) -> None:
    rel_type = str(relationship_type or "").strip()
    if rel_type not in RELATIONSHIP_TYPES:
        raise RelationshipValidationError(
            f"Unsupported relationship type '{relationship_type}'."
        )

    if not source_asset:
        raise RelationshipValidationError("Source asset is missing.")

    if not target_asset:
        raise RelationshipValidationError("Target asset is missing.")

    source_id = source_asset.get("id")
    target_id = target_asset.get("id")
    if not source_id or not target_id:
        raise RelationshipValidationError("Relationship endpoints must have asset ids.")

    if source_id == target_id:
        raise RelationshipValidationError(
            "Relationship source and target cannot be the same asset."
        )

    source_project = source_asset.get("project_id")
    target_project = target_asset.get("project_id")
    if source_project and source_project != project_id:
        raise RelationshipValidationError(
            "Source asset does not belong to the relationship project."
        )
    if target_project and target_project != project_id:
        raise RelationshipValidationError(
            "Target asset does not belong to the relationship project."
        )

    try:
        json.dumps(metadata if metadata is not None else {})
    except (TypeError, ValueError) as exc:
        raise RelationshipValidationError(
            "Relationship metadata must be JSON serializable."
        ) from exc


def _extract_evidence(relationship: dict, metadata: dict) -> dict:
    evidence = metadata.get("evidence")
    if isinstance(evidence, dict):
        extracted = dict(evidence)
    elif isinstance(evidence, str) and evidence:
        extracted = {"kind": evidence}
    else:
        extracted = {}

    record = metadata.get("record") or extracted.get("record_type")
    if record:
        extracted.setdefault("record_type", str(record).upper())

    for key in ("protocol", "priority", "state", "product", "version"):
        if metadata.get(key) not in (None, ""):
            extracted.setdefault(key, metadata.get(key))

    observed = (
        extracted.get("observed_value")
        or relationship.get("target_value")
        or metadata.get("observed_value")
    )
    if observed:
        extracted.setdefault("observed_value", observed)

    return extracted


def _unique_sources(values, scanner: str | None = None) -> list:
    sources = []
    for item in list(values or []):
        name = str(item).strip()
        if name and name not in sources:
            sources.append(name)
    if scanner:
        name = str(scanner).strip()
        if name and name not in sources:
            sources.append(name)
    return sources


def _higher_confidence(*values) -> str:
    best = CONFIDENCE_MEDIUM
    best_rank = CONFIDENCE_RANK[best]
    for value in values:
        rank = CONFIDENCE_RANK.get(value)
        if rank is not None and rank > best_rank:
            best = value
            best_rank = rank
    return best

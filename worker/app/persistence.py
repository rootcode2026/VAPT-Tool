"""Asset persistence: identity, provenance, timestamps, relationships."""

import json
import re
from datetime import datetime, timezone
import uuid

from sqlalchemy import text

from app.asset_intel.correlate import correlate_parsed_bundle
from app.asset_intel.normalize import infer_asset_type, infer_asset_value
from app.asset_intel.provenance import (
    RelationshipValidationError,
    merge_relationship_metadata,
    validate_relationship,
)
from app.asset_intel.types import RELATIONSHIP_TYPES


SECRET_KEY_FRAGMENTS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "jwt",
    "private_key",
    "access_key",
)

BLOCKED_METADATA_KEYS = {
    "raw_output",
    "logs",
    "command",
    "credentials",
    "env",
    "environment",
}

MAX_METADATA_BYTES = 16384

SCANNER_ASSET_PREFERENCE = {
    "nmap": ("port", "service", "ip", "ipv6", "host"),
    "zap": ("url", "web_site", "domain", "hostname"),
    "nikto": ("url", "web_host", "hostname", "ip"),
    "tls": ("tls_endpoint", "hostname", "domain", "url", "ip"),
    "nuclei": ("url", "domain", "hostname", "ip", "ipv6"),
    "http_fingerprint": ("url", "technology"),
    "dns": ("domain", "subdomain", "ip", "ipv6"),
    "subdomain": ("subdomain", "domain"),
}


def sanitize_metadata(value) -> dict:
    if not isinstance(value, dict):
        return {}

    cleaned = _sanitize_value(value)

    if not isinstance(cleaned, dict):
        return {}

    encoded = json.dumps(cleaned, default=str)

    if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
        return {
            key: cleaned[key]
            for key in ("sources",)
            if key in cleaned
        }

    return cleaned


def _sanitize_value(value):
    if isinstance(value, dict):
        result = {}

        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()

            if key_text in BLOCKED_METADATA_KEYS:
                continue

            if any(fragment in lowered for fragment in SECRET_KEY_FRAGMENTS):
                continue

            sanitized_item = _sanitize_value(item)

            if sanitized_item is not None:
                result[key_text] = sanitized_item

        return result

    if isinstance(value, list):
        return [
            _sanitize_value(item)
            for item in value[:100]
            if _sanitize_value(item) is not None
        ]

    if isinstance(value, (str, int, float, bool)) or value is None:
        if isinstance(value, str) and len(value) > 4000:
            return value[:4000]

        return value

    return str(value)


def merge_metadata(existing, incoming, scanner: str | None = None) -> dict:
    base = existing if isinstance(existing, dict) else {}
    update = incoming if isinstance(incoming, dict) else {}
    merged = dict(base)

    for key, item in update.items():
        if key == "sources":
            continue

        if key not in merged or merged[key] in (None, "", [], {}):
            merged[key] = item
        elif isinstance(merged[key], dict) and isinstance(item, dict):
            merged[key] = {**merged[key], **item}
        else:
            merged[key] = item

    sources = []
    for value in list(base.get("sources") or []) + list(update.get("sources") or []):
        if value and value not in sources:
            sources.append(value)

    if scanner and scanner not in sources:
        sources.append(scanner)

    if sources:
        merged["sources"] = sources

    return sanitize_metadata(merged)


def _parse_dt(val) -> datetime | None:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val)
        except ValueError:
            return None
    return None


def observation_timestamps(
    existing_first_seen,
    existing_last_seen=None,
    existing_last_scan_id: str | None = None,
    observed_at: datetime | None = None,
    incoming_scan_id: str | None = None,
):
    if existing_last_scan_id is None and observed_at is None and incoming_scan_id is None:
        now = _parse_dt(existing_last_seen)
        efs = _parse_dt(existing_first_seen)
        if efs is None:
            return now, now
        return efs, now

    efs = _parse_dt(existing_first_seen)
    els = _parse_dt(existing_last_seen)

    if observed_at.tzinfo is None:
        observed_at = observed_at.replace(tzinfo=timezone.utc)

    if efs is not None and efs.tzinfo is None:
        efs = efs.replace(tzinfo=timezone.utc)

    if els is not None and els.tzinfo is None:
        els = els.replace(tzinfo=timezone.utc)

    if efs is None:
        final_first_seen = observed_at
    else:
        final_first_seen = min(efs, observed_at)

    if els is None:
        final_last_seen = observed_at
        final_last_scan_id = incoming_scan_id
    elif observed_at >= els:
        final_last_seen = observed_at
        final_last_scan_id = incoming_scan_id
    else:
        final_last_seen = els
        final_last_scan_id = existing_last_scan_id

    return final_first_seen, final_last_seen, final_last_scan_id


def asset_metadata(asset: dict) -> dict:
    nested = asset.get("metadata")

    if isinstance(nested, dict):
        return sanitize_metadata(nested)

    ignored = {
        "type",
        "value",
        "name",
        "url",
        "final_url",
        "host",
        "ip",
    }

    remainder = {
        key: item
        for key, item in asset.items()
        if key not in ignored
    }

    return sanitize_metadata(remainder)


def match_asset_id(
    finding: dict,
    assets: list[dict],
    scanner: str | None = None,
) -> str | None:
    if not assets:
        return None

    if len(assets) == 1:
        return assets[0]["id"]

    scanner_name = (
        scanner
        or str(finding.get("scanner") or "")
    ).strip().lower()

    needles = _finding_needles(finding)

    exact = []
    for asset in assets:
        value = str(asset.get("value") or "").strip().lower()
        if value and value in needles:
            exact.append(asset)

    preferred = _prefer_assets(exact or [], scanner_name, finding)
    if len(preferred) == 1:
        return preferred[0]["id"]
    if len(preferred) > 1:
        return None

    if exact:
        preferred = _prefer_assets(exact, scanner_name, finding)
        if len(preferred) == 1:
            return preferred[0]["id"]
        return None

    partial = []
    for asset in assets:
        value = str(asset.get("value") or "").strip().lower()
        if not value or len(value) < 3:
            continue
        for needle in needles:
            if needle and (value in needle or needle in value):
                partial.append(asset)
                break

    unique = {asset["id"]: asset for asset in partial}
    preferred = _prefer_assets(list(unique.values()), scanner_name, finding)

    if len(preferred) == 1:
        return preferred[0]["id"]

    return None


def _finding_needles(finding: dict) -> set[str]:
    metadata = finding.get("metadata") or {}
    values = [
        metadata.get("uri"),
        metadata.get("url"),
        metadata.get("matched_at"),
        metadata.get("host"),
        metadata.get("ip"),
        metadata.get("site"),
        finding.get("evidence"),
    ]

    needles = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip().lower()
        if text:
            needles.add(text)
            if "://" in text:
                from app.asset_intel.normalize import normalize_url, normalize_hostname
                url_value = normalize_url(text)
                if url_value:
                    needles.add(url_value.lower())
                host = normalize_hostname(text)
                if host:
                    needles.add(host)
            # Reuse canonical utilities for host/IP evidence (project-scoped deterministic matching)
            try:
                from app.asset_intel.normalize import normalize_hostname as _nh, normalize_ip as _nip, normalize_url as _nu
                # bare hostname / domain
                hn = _nh(text, extract_url=True)
                if hn and hn != text:
                    needles.add(hn.lower())
                # url without scheme but still normalize attempt
                if "." in text and " " not in text:
                    # IP canonicalization for IPv4/IPv6
                    _t, _v = _nip(text)
                    if _v:
                        needles.add(_v.lower())
            except Exception:
                pass

    evidence = str(finding.get("evidence") or "")
    for token in re.split(r"[\s/:]+", evidence):
        cleaned = token.strip().lower()
        if len(cleaned) >= 3 or cleaned.isdigit():
            needles.add(cleaned)
            # normalize IP tokens for IPv4/IPv6 canonical matching
            try:
                from app.asset_intel.normalize import normalize_ip as _nip2
                _t, _v = _nip2(cleaned)
                if _v:
                    needles.add(_v.lower())
            except Exception:
                pass

    port = metadata.get("port")
    if port not in (None, ""):
        needles.add(str(port).strip().lower())

    expanded = set()
    for text in list(needles):
        if "/" in text:
            for part in text.split("/"):
                if part:
                    expanded.add(part)
    needles.update(expanded)

    return {item for item in needles if item}


def _prefer_assets(assets: list[dict], scanner: str, finding: dict) -> list[dict]:
    if not assets:
        return []

    if len(assets) == 1:
        return assets

    order = SCANNER_ASSET_PREFERENCE.get(scanner, ())
    for asset_type in order:
        matches = [
            asset
            for asset in assets
            if asset.get("asset_type") == asset_type or asset.get("type") == asset_type
        ]
        if len(matches) == 1:
            return matches
        if len(matches) > 1 and asset_type == "port":
            port_hits = _port_matches(matches, finding)
            if len(port_hits) == 1:
                return port_hits

    return assets


def _port_matches(assets: list[dict], finding: dict) -> list[dict]:
    needles = _finding_needles(finding)
    return [
        asset
        for asset in assets
        if str(asset.get("value") or "") in needles
    ]


def get_project_id(db, target_id: str) -> str:
    row = db.execute(
        text(
            """
            SELECT project_id
            FROM targets
            WHERE id = :target_id
            """
        ),
        {"target_id": target_id},
    ).fetchone()

    if row is None:
        raise ValueError(
            f"Target '{target_id}' was not found."
        )

    return row[0]


def persist_parsed_bundle(
    db,
    *,
    project_id: str,
    scan_id: str,
    scanner: str,
    assets: list,
    findings: list,
    now: datetime | None = None,
) -> list[dict]:
    from app.asset_intel.change_detection import (
        detect_asset_changes,
        persist_change_events,
    )

    observed_at = now or datetime.now(timezone.utc)
    correlated = correlate_parsed_bundle(
        scanner,
        assets,
        findings,
    )

    target_identities = [
        (infer_asset_type(a), infer_asset_value(a))
        for a in (correlated.get("assets") or [])
        if isinstance(a, dict) and infer_asset_value(a)
    ]
    previous_map = _load_target_assets_pre_mutation(db, project_id, target_identities)

    change_events = detect_asset_changes(
        db,
        project_id=project_id,
        scan_id=scan_id,
        scanner=scanner,
        current_assets=correlated.get("assets") or [],
        current_relationships=correlated.get("relationships") or [],
        previous_assets_map=previous_map,
        observed_at=observed_at,
    )

    persisted = upsert_assets(
        db,
        project_id=project_id,
        scan_id=scan_id,
        assets=correlated["assets"],
        scanner=scanner,
        now=observed_at,
    )
    upsert_relationships(
        db,
        project_id=project_id,
        relationships=correlated["relationships"],
        persisted_assets=persisted,
        scanner=scanner,
        now=observed_at,
    )
    # Change events carry asset_id, which is a FK to assets.id. The assets
    # referenced by 'new_asset' / attribute events must already exist before
    # the event rows are written, otherwise the insert aborts the transaction
    # (surfacing later as a masking InFailedSqlTransaction on the asset upsert).
    persist_change_events(db, change_events)
    return persisted


def _load_target_assets_pre_mutation(
    db,
    project_id: str,
    identities: list[tuple[str, str]],
) -> dict[tuple[str, str], dict]:
    if not identities:
        return {}

    sorted_identities = sorted(list(set(identities)))
    if not sorted_identities:
        return {}
    # Single database-side, project-scoped candidate lookup (no loading all assets)
    # Build a single query with OR clauses to avoid N round-trips
    clauses = []
    params: dict = {"project_id": project_id}
    for idx, (asset_type, val) in enumerate(sorted_identities):
        t_key = f"t{idx}"
        v_key = f"v{idx}"
        clauses.append(f"(asset_type = :{t_key} AND value = :{v_key})")
        params[t_key] = asset_type
        params[v_key] = val

    where = " OR ".join(clauses)
    rows = db.execute(
        text(
            f"""
                SELECT id, asset_type, value, metadata, first_seen_at, last_seen_at, status
                FROM assets
                WHERE project_id = :project_id
                  AND ({where})
                """
        ),
        params,
    ).fetchall()

    results = {}
    for row in rows:
        raw_meta = row[3]
        if isinstance(raw_meta, str):
            try:
                meta = json.loads(raw_meta)
            except Exception:
                meta = {}
        elif isinstance(raw_meta, dict):
            meta = raw_meta
        else:
            meta = {}

        results[(row[1], row[2])] = {
            "id": row[0],
            "asset_type": row[1],
            "value": row[2],
            "metadata": meta,
            "first_seen_at": row[4],
            "last_seen_at": row[5],
            "status": row[6] if len(row) > 6 else "active",
        }
    return results


def upsert_assets(
    db,
    *,
    project_id: str,
    scan_id: str,
    assets: list,
    scanner: str | None = None,
    now: datetime | None = None,
) -> list[dict]:
    from app.asset_intel.change_detection import compute_asset_lifecycle_status

    persisted = []
    observed_at = now or datetime.now(timezone.utc)

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        asset_type = infer_asset_type(asset)
        value = infer_asset_value(asset)

        if not value:
            continue

        metadata = asset_metadata(asset)
        if scanner:
            metadata = merge_metadata(metadata, {}, scanner)

        new_id = asset.get("id") or str(uuid.uuid4())

        row = db.execute(
            text(
                """
                INSERT INTO assets (
                    id,
                    project_id,
                    first_seen_scan_id,
                    last_seen_scan_id,
                    asset_type,
                    value,
                    status,
                    metadata,
                    first_seen_at,
                    last_seen_at,
                    created_at,
                    updated_at
                )
                VALUES (
                    :id,
                    :project_id,
                    :scan_id,
                    :scan_id,
                    :asset_type,
                    :value,
                    :status,
                    :metadata,
                    :observed_at,
                    :observed_at,
                    :observed_at,
                    :observed_at
                )
                ON CONFLICT (project_id, asset_type, value)
                DO UPDATE SET
                    updated_at = EXCLUDED.updated_at
                RETURNING id, metadata, first_seen_at, last_seen_at, last_seen_scan_id
                """
            ),
            {
                "id": new_id,
                "project_id": project_id,
                "scan_id": scan_id,
                "asset_type": asset_type,
                "value": value,
                "status": "active",
                "metadata": json.dumps(metadata),
                "observed_at": observed_at,
            },
        ).fetchone()

        if row is None:
            continue

        asset_id, existing_metadata_raw, existing_first_seen, existing_last_seen, existing_last_scan_id = (
            row[0],
            row[1],
            row[2],
            row[3],
            row[4],
        )

        if isinstance(existing_metadata_raw, str):
            try:
                existing_metadata = json.loads(existing_metadata_raw)
            except (json.JSONDecodeError, TypeError):
                existing_metadata = {}
        elif isinstance(existing_metadata_raw, dict):
            existing_metadata = existing_metadata_raw
        else:
            existing_metadata = {}

        merged = merge_metadata(existing_metadata, metadata, scanner)
        final_first_seen, final_last_seen, final_last_scan_id = observation_timestamps(
            existing_first_seen,
            existing_last_seen,
            existing_last_scan_id,
            observed_at,
            scan_id,
        )
        status = compute_asset_lifecycle_status(final_last_seen, reference_time=observed_at)

        db.execute(
            text(
                """
                UPDATE assets
                SET
                    metadata = :metadata,
                    first_seen_at = :first_seen_at,
                    last_seen_at = :last_seen_at,
                    last_seen_scan_id = :last_seen_scan_id,
                    status = :status,
                    updated_at = :updated_at
                WHERE id = :id
                """
            ),
            {
                "id": asset_id,
                "metadata": json.dumps(merged),
                "first_seen_at": final_first_seen,
                "last_seen_at": final_last_seen,
                "last_seen_scan_id": final_last_scan_id,
                "status": status,
                "updated_at": observed_at,
            },
        )

        persisted.append(
            {
                "id": asset_id,
                "asset_type": asset_type,
                "value": value,
            }
        )

    return persisted


def upsert_relationships(
    db,
    *,
    project_id: str,
    relationships: list,
    persisted_assets: list[dict],
    scanner: str | None = None,
    now: datetime | None = None,
) -> list[dict]:
    observed_at = now or datetime.now(timezone.utc)
    index = {
        (item["asset_type"], item["value"]): item["id"]
        for item in persisted_assets
    }
    stored = []

    for relationship in relationships:
        if not isinstance(relationship, dict):
            continue

        rel_type = str(relationship.get("relationship_type") or "").strip()
        source_id = index.get(
            (
                relationship.get("source_type"),
                relationship.get("source_value"),
            )
        )
        target_id = index.get(
            (
                relationship.get("target_type"),
                relationship.get("target_value"),
            )
        )

        if not source_id or not target_id or rel_type not in RELATIONSHIP_TYPES:
            continue

        endpoints = _load_relationship_assets(db, [source_id, target_id])
        source_asset = endpoints.get(source_id)
        target_asset = endpoints.get(target_id)
        metadata = sanitize_metadata(relationship.get("metadata"))

        try:
            validate_relationship(
                project_id=project_id,
                relationship_type=rel_type,
                source_asset=source_asset,
                target_asset=target_asset,
                metadata=metadata,
            )
        except RelationshipValidationError:
            continue

        new_id = str(uuid.uuid4())

        row = db.execute(
            text(
                """
                INSERT INTO asset_relationships (
                    id,
                    project_id,
                    source_asset_id,
                    target_asset_id,
                    relationship_type,
                    metadata,
                    created_at,
                    updated_at
                )
                VALUES (
                    :id,
                    :project_id,
                    :source_asset_id,
                    :target_asset_id,
                    :relationship_type,
                    :metadata,
                    :observed_at,
                    :observed_at
                )
                ON CONFLICT (project_id, source_asset_id, target_asset_id, relationship_type)
                DO UPDATE SET
                    updated_at = EXCLUDED.updated_at
                RETURNING id, metadata, created_at
                """
            ),
            {
                "id": new_id,
                "project_id": project_id,
                "source_asset_id": source_id,
                "target_asset_id": target_id,
                "relationship_type": rel_type,
                "metadata": json.dumps(metadata),
                "observed_at": observed_at,
            },
        ).fetchone()

        if row is None:
            continue

        rel_id, existing_metadata_raw = row[0], row[1]

        if isinstance(existing_metadata_raw, str):
            try:
                existing_metadata = json.loads(existing_metadata_raw)
            except (json.JSONDecodeError, TypeError):
                existing_metadata = {}
        elif isinstance(existing_metadata_raw, dict):
            existing_metadata = existing_metadata_raw
        else:
            existing_metadata = {}

        merged = sanitize_metadata(
            merge_relationship_metadata(
                existing_metadata,
                metadata,
                scanner,
            )
        )

        db.execute(
            text(
                """
                UPDATE asset_relationships
                SET
                    metadata = :metadata,
                    updated_at = :updated_at
                WHERE id = :id
                """
            ),
            {
                "id": rel_id,
                "metadata": json.dumps(merged),
                "updated_at": observed_at,
            },
        )
        stored.append({"id": rel_id})

    return stored


def _load_relationship_assets(db, asset_ids: list[str]) -> dict[str, dict]:
    found = {}
    for asset_id in asset_ids:
        row = db.execute(
            text(
                """
                SELECT id, project_id, asset_type, value
                FROM assets
                WHERE id = :asset_id
                """
            ),
            {"asset_id": asset_id},
        ).fetchone()
        if row is None:
            continue
        found[row[0]] = {
            "id": row[0],
            "project_id": row[1],
            "asset_type": row[2],
            "value": row[3],
        }
    return found

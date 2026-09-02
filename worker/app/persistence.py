"""
Asset identity and metadata sanitization.

Identity strategy
-----------------
An asset is uniquely identified within a project by:

    (project_id, asset_type, value)

where:

* asset_type is asset["type"] when present, otherwise inferred
  from generic fields (url → "url", addresses/ports → "host",
  host → "host", otherwise "unknown")
* value is a lowercase, trimmed canonical string taken from the
  first available generic field:
  name, url, host[:port], ip, or the first addresses[].address

This is not cross-scanner correlation. A ZAP web_site named
"https://host" and an Nmap host "10.0.0.8" remain separate
records even if they refer to the same system.

Repeated observations of the same (project, type, value) update
last_seen_scan_id and replace metadata with the latest snapshot.
"""

import json
from datetime import datetime, timezone
import uuid

from sqlalchemy import text


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


def sanitize_metadata(value) -> dict:
    if not isinstance(value, dict):
        return {}

    cleaned = _sanitize_value(value)

    if not isinstance(cleaned, dict):
        return {}

    encoded = json.dumps(cleaned, default=str)

    if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
        return {}

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


def infer_asset_type(asset: dict) -> str:
    declared = asset.get("type")

    if declared:
        return str(declared).strip().lower() or "unknown"

    if asset.get("url") or asset.get("final_url"):
        return "url"

    if asset.get("addresses") or asset.get("ports"):
        return "host"

    if asset.get("host"):
        return "host"

    return "unknown"


def infer_asset_value(asset: dict) -> str | None:
    candidates = [
        asset.get("value"),
        asset.get("name"),
        asset.get("url"),
        asset.get("final_url"),
    ]

    host = asset.get("host")
    port = asset.get("port")

    if host and port not in (None, ""):
        candidates.append(f"{host}:{port}")
    else:
        candidates.append(host)

    candidates.append(asset.get("ip"))

    addresses = asset.get("addresses")

    if isinstance(addresses, list) and addresses:
        first = addresses[0]

        if isinstance(first, dict):
            candidates.append(first.get("address"))
        else:
            candidates.append(first)

    for candidate in candidates:
        if candidate is None:
            continue

        value = str(candidate).strip().lower()

        if value:
            return value[:1024]

    return None


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
) -> str | None:
    if not assets:
        return None

    if len(assets) == 1:
        return assets[0]["id"]

    metadata = finding.get("metadata") or {}
    needles = [
        str(metadata.get("uri") or "").lower(),
        str(metadata.get("url") or "").lower(),
        str(metadata.get("host") or "").lower(),
        str(metadata.get("ip") or "").lower(),
        str(finding.get("evidence") or "").lower(),
    ]

    for asset in assets:
        value = str(asset.get("value") or "").lower()

        if not value:
            continue

        for needle in needles:
            if needle and (value in needle or needle in value):
                return asset["id"]

    return None


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


def upsert_assets(
    db,
    *,
    project_id: str,
    scan_id: str,
    assets: list,
) -> list[dict]:
    persisted = []
    now = datetime.now(timezone.utc)

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        asset_type = infer_asset_type(asset)
        value = infer_asset_value(asset)

        if not value:
            continue

        metadata = asset_metadata(asset)
        asset_id = str(uuid.uuid4())

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
                    metadata,
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
                    CAST(:metadata AS JSONB),
                    :created_at,
                    :updated_at
                )
                ON CONFLICT (project_id, asset_type, value)
                DO UPDATE SET
                    last_seen_scan_id = EXCLUDED.last_seen_scan_id,
                    metadata = EXCLUDED.metadata,
                    updated_at = EXCLUDED.updated_at
                RETURNING id, asset_type, value
                """
            ),
            {
                "id": asset_id,
                "project_id": project_id,
                "scan_id": scan_id,
                "asset_type": asset_type,
                "value": value,
                "metadata": json.dumps(metadata),
                "created_at": now,
                "updated_at": now,
            },
        ).fetchone()

        persisted.append(
            {
                "id": row[0],
                "asset_type": row[1],
                "value": row[2],
            }
        )

    return persisted

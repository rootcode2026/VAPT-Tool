"""
Stage B — Meaningful Change Detection and Asset Lifecycle Module.

Authoritative Capability Matrix per scanner:
- dns: domain, subdomain, ip, ipv6, dns_cname, dns_mx, dns_ns, dns_txt, dns_soa
- subdomain: subdomain, domain
- nmap: ip, ipv6, port, service, host
- http_fingerprint: url, technology
- zap / nikto: url, web_site, web_host
- tls: tls_endpoint
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import uuid
from sqlalchemy import text

ASSET_STALE_AFTER_DAYS = 7
ASSET_INACTIVE_AFTER_DAYS = 30

SCANNER_AUTHORITATIVE_ASSETS = {
    "dns": {"domain", "subdomain", "ip", "ipv6", "dns_cname", "dns_mx", "dns_ns", "dns_txt", "dns_soa"},
    "subdomain": {"subdomain", "domain"},
    "nmap": {"ip", "ipv6", "port", "service", "host"},
    "http_fingerprint": {"url", "technology"},
    "zap": {"url", "web_site", "web_host"},
    "nikto": {"url", "web_host"},
    "tls": {"tls_endpoint"},
    "nuclei": {"url", "domain", "hostname", "ip", "ipv6"},
}

VOLATILE_METADATA_KEYS = frozenset(
    {
        "created_at",
        "updated_at",
        "first_seen_at",
        "last_seen_at",
        "first_seen_scan_id",
        "last_seen_scan_id",
        "sources",
        "id",
        "project_id",
        "scan_id",
    }
)


def compute_asset_lifecycle_status(
    last_seen_at: datetime | str | None,
    reference_time: datetime | None = None,
    stale_days: int = ASSET_STALE_AFTER_DAYS,
    inactive_days: int = ASSET_INACTIVE_AFTER_DAYS,
) -> str:
    if last_seen_at is None:
        return "active"

    ref = reference_time or datetime.now(timezone.utc)

    if isinstance(last_seen_at, str):
        try:
            last_seen_at = datetime.fromisoformat(last_seen_at)
        except ValueError:
            return "active"

    if last_seen_at.tzinfo is None:
        last_seen_at = last_seen_at.replace(tzinfo=timezone.utc)
    if ref.tzinfo is None:
        ref = ref.replace(tzinfo=timezone.utc)

    age_days = (ref - last_seen_at).total_seconds() / 86400.0

    if age_days >= inactive_days:
        return "inactive"
    if age_days >= stale_days:
        return "stale"
    return "active"


def detect_asset_changes(
    db,
    *,
    project_id: str,
    scan_id: str,
    scanner: str,
    current_assets: list[dict],
    current_relationships: list[dict],
    previous_assets_map: dict[tuple[str, str], dict],
    observed_at: datetime | None = None,
) -> list[dict]:
    now = observed_at or datetime.now(timezone.utc)
    scanner_name = str(scanner or "").strip().lower()
    authoritative_types = SCANNER_AUTHORITATIVE_ASSETS.get(scanner_name, set())

    events = []

    for asset in current_assets:
        if not isinstance(asset, dict):
            continue
        asset_type = asset.get("asset_type") or asset.get("type")
        value = asset.get("value")
        if not asset_type or not value:
            continue

        key = (asset_type, value)
        prev = previous_assets_map.get(key)
        curr_id = asset.get("id")
        if not curr_id:
            if prev and prev.get("id"):
                curr_id = prev.get("id")
                asset["id"] = curr_id
            else:
                curr_id = str(uuid.uuid4())
                asset["id"] = curr_id

        if prev is None:
            events.append(
                _create_event(
                    project_id=project_id,
                    asset_id=curr_id,
                    scan_id=scan_id,
                    change_type="new_asset",
                    previous_state=None,
                    current_state={
                        "type": asset_type,
                        "value": value,
                        "status": "active",
                    },
                    detected_at=now,
                )
            )
        else:
            prev_status = prev.get("status") or compute_asset_lifecycle_status(
                prev.get("last_seen_at"),
                reference_time=now,
            )

            if prev_status in {"stale", "inactive"}:
                events.append(
                    _create_event(
                        project_id=project_id,
                        asset_id=curr_id,
                        scan_id=scan_id,
                        change_type="asset_reappeared",
                        previous_state={"status": prev_status},
                        current_state={"status": "active"},
                        detected_at=now,
                    )
                )

            _check_attribute_changes(
                events=events,
                project_id=project_id,
                asset_id=curr_id,
                scan_id=scan_id,
                prev=prev,
                curr=asset,
                detected_at=now,
            )

    if authoritative_types:
        curr_keys = {
            (item.get("asset_type") or item.get("type"), item.get("value"))
            for item in current_assets
            if isinstance(item, dict)
        }

        for key, prev_asset in previous_assets_map.items():
            prev_type, prev_value = key
            if prev_type not in authoritative_types:
                continue

            if key not in curr_keys:
                prev_last_seen = prev_asset.get("last_seen_at")
                if isinstance(prev_last_seen, str):
                    try:
                        prev_last_seen = datetime.fromisoformat(prev_last_seen)
                    except ValueError:
                        prev_last_seen = None

                if prev_last_seen and prev_last_seen.tzinfo is None:
                    prev_last_seen = prev_last_seen.replace(tzinfo=timezone.utc)

                if prev_last_seen and now < prev_last_seen:
                    continue

                prev_status = prev_asset.get("status") or compute_asset_lifecycle_status(
                    prev_last_seen,
                    reference_time=now,
                )

                if prev_status in {"active", "stale"}:
                    events.append(
                        _create_event(
                            project_id=project_id,
                            asset_id=prev_asset["id"],
                            scan_id=scan_id,
                            change_type="asset_disappeared",
                            previous_state={
                                "type": prev_type,
                                "value": prev_value,
                                "status": prev_status,
                            },
                            current_state={"status": "disappeared"},
                            detected_at=now,
                        )
                    )

    return events


def _check_attribute_changes(
    *,
    events: list[dict],
    project_id: str,
    asset_id: str,
    scan_id: str,
    prev: dict,
    curr: dict,
    detected_at: datetime,
) -> None:
    prev_meta = prev.get("metadata") or {}
    curr_meta = curr.get("metadata") or {}
    if not isinstance(prev_meta, dict):
        prev_meta = {}
    if not isinstance(curr_meta, dict):
        curr_meta = {}

    prev_ports = sorted(list(prev_meta.get("ports") or []))
    curr_ports = sorted(list(curr_meta.get("ports") or []))
    if prev_ports and curr_ports and prev_ports != curr_ports:
        events.append(
            _create_event(
                project_id=project_id,
                asset_id=asset_id,
                scan_id=scan_id,
                change_type="port_changed",
                previous_state={"ports": prev_ports},
                current_state={"ports": curr_ports},
                detected_at=detected_at,
            )
        )

    prev_tech = sorted(list(prev_meta.get("technologies") or []))
    curr_tech = sorted(list(curr_meta.get("technologies") or []))
    if prev_tech and curr_tech and prev_tech != curr_tech:
        events.append(
            _create_event(
                project_id=project_id,
                asset_id=asset_id,
                scan_id=scan_id,
                change_type="technology_changed",
                previous_state={"technologies": prev_tech},
                current_state={"technologies": curr_tech},
                detected_at=detected_at,
            )
        )

    prev_ip = prev_meta.get("resolved_ip") or prev_meta.get("ip")
    curr_ip = curr_meta.get("resolved_ip") or curr_meta.get("ip")
    if prev_ip and curr_ip and prev_ip != curr_ip:
        events.append(
            _create_event(
                project_id=project_id,
                asset_id=asset_id,
                scan_id=scan_id,
                change_type="ip_changed",
                previous_state={"ip": prev_ip},
                current_state={"ip": curr_ip},
                detected_at=detected_at,
            )
        )

    prev_url = prev_meta.get("url") or prev_meta.get("final_url")
    curr_url = curr_meta.get("url") or curr_meta.get("final_url")
    if prev_url and curr_url and prev_url != curr_url:
        events.append(
            _create_event(
                project_id=project_id,
                asset_id=asset_id,
                scan_id=scan_id,
                change_type="url_changed",
                previous_state={"url": prev_url},
                current_state={"url": curr_url},
                detected_at=detected_at,
            )
        )

    clean_prev = {k: v for k, v in prev_meta.items() if k not in VOLATILE_METADATA_KEYS and k not in {"ports", "technologies", "ip", "resolved_ip", "url", "final_url"}}
    clean_curr = {k: v for k, v in curr_meta.items() if k not in VOLATILE_METADATA_KEYS and k not in {"ports", "technologies", "ip", "resolved_ip", "url", "final_url"}}
    if clean_prev and clean_curr and clean_prev != clean_curr:
        events.append(
            _create_event(
                project_id=project_id,
                asset_id=asset_id,
                scan_id=scan_id,
                change_type="metadata_changed",
                previous_state=clean_prev,
                current_state=clean_curr,
                detected_at=detected_at,
            )
        )


def _create_event(
    *,
    project_id: str,
    asset_id: str,
    scan_id: str,
    change_type: str,
    previous_state: dict | None,
    current_state: dict | None,
    detected_at: datetime,
) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "project_id": project_id,
        "asset_id": asset_id,
        "scan_id": scan_id,
        "change_type": change_type,
        "previous_state": previous_state,
        "current_state": current_state,
        "detected_at": detected_at,
        "metadata": {},
    }


def persist_change_events(db, events: list[dict]) -> list[dict]:
    persisted = []
    for event in events or []:
        if not isinstance(event, dict):
            continue
        try:
            db.execute(
                text(
                    """
                    INSERT INTO asset_change_events (
                        id,
                        project_id,
                        asset_id,
                        scan_id,
                        change_type,
                        previous_state,
                        current_state,
                        detected_at,
                        metadata
                    )
                    VALUES (
                        :id,
                        :project_id,
                        :asset_id,
                        :scan_id,
                        :change_type,
                        :previous_state,
                        :current_state,
                        :detected_at,
                        :metadata
                    )
                    ON CONFLICT (scan_id, asset_id, change_type)
                    DO NOTHING
                    """
                ),
                {
                    "id": event.get("id") or str(uuid.uuid4()),
                    "project_id": event["project_id"],
                    "asset_id": event["asset_id"],
                    "scan_id": event["scan_id"],
                    "change_type": event["change_type"],
                    "previous_state": json.dumps(event.get("previous_state")),
                    "current_state": json.dumps(event.get("current_state")),
                    "detected_at": event.get("detected_at") or datetime.now(timezone.utc),
                    "metadata": json.dumps(event.get("metadata") or {}),
                },
            )
            persisted.append(event)
        except Exception:
            pass
    return persisted

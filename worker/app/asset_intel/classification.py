"""
D2 — Worker-side Attack Surface Classification (mirrors backend logic).

Deterministic, project-scoped, derived from persisted assets/relationships/findings.
Reuse canonical normalization and ipaddress.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

SENSITIVE_KEYWORDS = frozenset({
    "admin", "login", "auth", "authentication", "internal",
    "staging", "dev", "test", "database", "db", "management", "vpn", "api",
})

WEB_ASSET_TYPES = frozenset({"url", "web_site", "web_host"})
WEB_PORTS = frozenset({"80", "443", "8080", "8443", "8000", "9000"})

RECENT_DAYS = 7


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    return bool(ip.is_global)


def _parse_hostname(value: str) -> str | None:
    try:
        parsed = urlparse(value)
        if parsed.hostname:
            return parsed.hostname
        return None
    except Exception:
        return None


def is_sensitive_value(value: str) -> bool:
    if not value:
        return False
    tokens = re.split(r'[^a-z0-9]+', value.lower())
    return any(t in SENSITIVE_KEYWORDS for t in tokens if t)


def classify_assets_maps(
    assets: list[dict],
    relationships: list[dict],
    findings_by_asset: dict[str, list],
    change_events_by_asset: dict[str, list],
    now: datetime | None = None,
) -> dict[str, dict]:
    """
    Pure-python classification for tests/offline — no DB.
    assets: list of {id, asset_type, value, project_id, extra_data, last_seen_at, updated_at}
    relationships: list of {source_asset_id, target_asset_id, relationship_type, project_id}
    findings_by_asset: asset_id -> list
    change_events_by_asset: asset_id -> list of {detected_at}
    """
    now = now or datetime.now(timezone.utc)
    window = now - timedelta(days=RECENT_DAYS)

    # index relationships by source/target
    out_map: dict[str, list] = {}
    in_map: dict[str, list] = {}
    # need asset map to resolve target types/values for public IP checks
    asset_by_id = {a["id"]: a for a in assets if isinstance(a, dict) and a.get("id")}
    for rel in relationships:
        sid = rel.get("source_asset_id")
        tid = rel.get("target_asset_id")
        if sid:
            out_map.setdefault(sid, []).append(rel)
        if tid:
            in_map.setdefault(tid, []).append(rel)

    result: dict[str, dict] = {}
    for asset in assets:
        aid = asset.get("id")
        if not aid:
            continue
        atype = asset.get("asset_type") or asset.get("type")
        value = asset.get("value") or ""
        outgoing = out_map.get(aid, [])
        incoming = in_map.get(aid, [])
        all_rels = outgoing + incoming

        # internet_facing
        internet_facing = False
        if atype in ("ip", "ipv6"):
            internet_facing = is_public_ip(value)
        elif atype in ("url", "web_site", "web_host"):
            host = _parse_hostname(value) or value
            if is_public_ip(host):
                internet_facing = True
            else:
                for rel in outgoing:
                    if rel.get("relationship_type") == "resolves_to":
                        tid = rel.get("target_asset_id")
                        tgt = asset_by_id.get(tid)
                        if tgt and tgt.get("asset_type") in ("ip", "ipv6") and is_public_ip(tgt.get("value") or ""):
                            internet_facing = True
                            break
        else:
            for rel in outgoing:
                if rel.get("relationship_type") in ("resolves_to", "points_to"):
                    tid = rel.get("target_asset_id")
                    tgt = asset_by_id.get(tid)
                    if tgt and is_public_ip(tgt.get("value") or ""):
                        internet_facing = True
                        break

        externally_resolvable = any(r.get("relationship_type") in ("resolves_to", "points_to") for r in outgoing)
        web_application = atype in WEB_ASSET_TYPES
        if not web_application:
            for rel in outgoing:
                if rel.get("relationship_type") == "serves":
                    # need target type check
                    tid = rel.get("target_asset_id")
                    tgt = asset_by_id.get(tid)
                    if tgt and tgt.get("asset_type") == "technology":
                        web_application = True
                        break
                if rel.get("relationship_type") == "observed_on":
                    web_application = True
                    break
            if not web_application:
                for rel in incoming:
                    if rel.get("relationship_type") == "observed_on":
                        web_application = True
                        break
            if not web_application and atype == "port" and value in WEB_PORTS and all_rels:
                web_application = True

        exposed_service = any(r.get("relationship_type") in ("exposes", "runs") for r in all_rels)
        if not exposed_service and atype in ("port", "service") and all_rels:
            exposed_service = True

        technology_bearing = False
        for rel in outgoing:
            if rel.get("relationship_type") in ("serves", "uses"):
                tid = rel.get("target_asset_id")
                tgt = asset_by_id.get(tid)
                if tgt and tgt.get("asset_type") == "technology":
                    technology_bearing = True
                    break

        vulnerable = bool(findings_by_asset.get(aid))
        # recently_changed
        recently_changed = False
        for ts in (asset.get("last_seen_at"), asset.get("updated_at"), asset.get("created_at")):
            if ts is None:
                continue
            aware = ts
            if isinstance(aware, str):
                try:
                    aware = datetime.fromisoformat(aware)
                except ValueError:
                    continue
            if aware.tzinfo is None:
                aware = aware.replace(tzinfo=timezone.utc)
            if aware >= window:
                recently_changed = True
                break
        if not recently_changed and change_events_by_asset.get(aid):
            for ev in change_events_by_asset[aid]:
                det = ev.get("detected_at") if isinstance(ev, dict) else ev
                if isinstance(det, str):
                    try:
                        det = datetime.fromisoformat(det)
                    except ValueError:
                        continue
                if det and det.tzinfo is None:
                    det = det.replace(tzinfo=timezone.utc)
                if det and det >= window:
                    recently_changed = True
                    break

        potentially_sensitive = is_sensitive_value(value)

        result[aid] = {
            "internet_facing": internet_facing,
            "externally_resolvable": externally_resolvable,
            "web_application": web_application,
            "exposed_service": exposed_service,
            "technology_bearing": technology_bearing,
            "vulnerable": vulnerable,
            "recently_changed": recently_changed,
            "potentially_sensitive": potentially_sensitive,
        }
    return result

"""
D2 — Attack Surface Classification Engine.

Deterministic, project-scoped, derived from persisted evidence (assets,
relationships, findings, change events). No live DNS, no external calls.
All IP checks use Python's ipaddress (RFC1918, loopback, link-local, etc.).
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.asset_change_event import AssetChangeEvent
from app.models.asset_relationship import AssetRelationship
from app.models.finding import Finding

# Conservative sensitive keywords — exact token match, not substring.
# Tokens are split on non-alphanumeric boundaries.
SENSITIVE_KEYWORDS = frozenset({
    "admin", "login", "auth", "authentication", "internal",
    "staging", "dev", "test", "database", "db", "management", "vpn", "api",
})

# Asset types that are web-related
WEB_ASSET_TYPES = frozenset({"url", "web_site", "web_host"})
WEB_SERVICES = frozenset({"http", "https", "http_alt", "https_alt"})
WEB_PORTS = frozenset({"80", "443", "8080", "8443", "8000", "9000"})

# For batch queries we reuse 7-day window from Stage B / D1
RECENT_DAYS = 7


def is_public_ip(value: str) -> bool:
    """Return True iff value is a public (global) IP per ipaddress.

    Private, loopback, link-local, multicast, unspecified, reserved
    all return False. Uses ipaddress.is_global where available.
    """
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    # is_global is the most reliable for "public internet" in modern Python
    # Fallback: ensure not private/reserved/etc.
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return False
    # ip.is_global is True only for public routable addresses
    return bool(ip.is_global)


def _parse_hostname_from_url(value: str) -> str | None:
    """Extract hostname from URL asset value if possible."""
    try:
        parsed = urlparse(value)
        host = parsed.hostname
        if host:
            return host
        # fallback: try as plain host
        return None
    except Exception:
        return None


def _is_sensitive_value(value: str, metadata: dict | None = None) -> bool:
    """
    Conservative sensitive detection:
    - Split value on non-alphanumeric (., -, _, /, :, etc.)
    - Exact token match against SENSITIVE_KEYWORDS (lowercased)
    - Does NOT match substrings (e.g., "adventure" does not match "dev")
    - Generic hosts like example.com / www.example.com → not sensitive
    """
    if not value:
        return False
    tokens = re.split(r'[^a-z0-9]+', value.lower())
    tokens = [t for t in tokens if t]
    for tok in tokens:
        if tok in SENSITIVE_KEYWORDS:
            return True
    # Also check metadata string values conservatively (same token rule)
    if isinstance(metadata, dict):
        for v in metadata.values():
            if isinstance(v, str):
                toks = re.split(r'[^a-z0-9]+', v.lower())
                for tok in toks:
                    if tok in SENSITIVE_KEYWORDS:
                        # Only count if metadata key suggests sensitive context?
                        # Keep conservative: require value also has hint,
                        # but for now metadata alone not enough unless value already hinted
                        # We return True only if metadata value token matches and value contains related term
                        # For simplicity, not marking metadata-only as sensitive to avoid false positives
                        pass
    return False


def _get_recent_window() -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=RECENT_DAYS)


# ---------------------------------------------------------------------------
# Single-asset classification (bounded queries, for detail endpoint)
# ---------------------------------------------------------------------------

def classify_asset(db: Session, asset: Asset) -> dict[str, Any]:
    """Classify a single asset with bounded queries (no N+1)."""
    return classify_assets_batch(db, [asset]).get(asset.id, _default_classifications())


def _default_classifications() -> dict[str, bool]:
    return {
        "internet_facing": False,
        "externally_resolvable": False,
        "web_application": False,
        "exposed_service": False,
        "technology_bearing": False,
        "vulnerable": False,
        "recently_changed": False,
        "potentially_sensitive": False,
    }


def classify_assets_batch(db: Session, assets: list[Asset]) -> dict[str, dict[str, bool]]:
    """
    Batch classification for multiple assets in the same project.
    Uses grouped/database-side queries to avoid N+1.
    All queries are project-scoped: they filter by project_id and asset ids.
    """
    if not assets:
        return {}

    # Group by project to enforce isolation (should be same project for detail batch,
    # but support mixed for safety — we query per project)
    by_project: dict[str, list[Asset]] = {}
    for a in assets:
        by_project.setdefault(a.project_id, []).append(a)

    result: dict[str, dict[str, bool]] = {}

    for project_id, proj_assets in by_project.items():
        asset_ids = [a.id for a in proj_assets]
        asset_map = {a.id: a for a in proj_assets}

        # --- Batch queries ---
        # Relationships where source or target is in set
        rel_rows = (
            db.query(AssetRelationship, Asset)
            .join(Asset, Asset.id == AssetRelationship.target_asset_id)
            .filter(
                AssetRelationship.project_id == project_id,
                AssetRelationship.source_asset_id.in_(asset_ids),
            )
            .all()
        )
        # Need also incoming relationships (target in ids) with source asset join
        # For simplicity, fetch both directions separately and merge
        incoming_rows = (
            db.query(AssetRelationship, Asset)
            .join(Asset, Asset.id == AssetRelationship.source_asset_id)
            .filter(
                AssetRelationship.project_id == project_id,
                AssetRelationship.target_asset_id.in_(asset_ids),
            )
            .all()
        )

        # Build maps: source_id -> list[(rel, target_asset)], target_id -> list[(rel, source_asset)]
        outgoing_map: dict[str, list] = {aid: [] for aid in asset_ids}
        incoming_map: dict[str, list] = {aid: [] for aid in asset_ids}
        for rel, tgt in rel_rows:
            if rel.source_asset_id in outgoing_map:
                outgoing_map[rel.source_asset_id].append((rel, tgt))
        for rel, src in incoming_rows:
            if rel.target_asset_id in incoming_map:
                incoming_map[rel.target_asset_id].append((rel, src))

        # Findings counts per asset
        finding_rows = (
            db.query(Finding.asset_id, Finding.severity, func.count(Finding.id))
            .filter(Finding.asset_id.in_(asset_ids))
            .group_by(Finding.asset_id, Finding.severity)
            .all()
        )
        findings_by_asset: dict[str, dict[str, int]] = {aid: {} for aid in asset_ids}
        total_by_asset: dict[str, int] = {aid: 0 for aid in asset_ids}
        for aid, sev, cnt in finding_rows:
            findings_by_asset[aid][sev] = cnt
            total_by_asset[aid] += cnt

        # Change events recent
        window = _get_recent_window()
        # Recent by timestamps (we have assets already, check python side) and by change events
        # Batch change events: one query
        recent_event_ids = set(
            r[0]
            for r in db.query(AssetChangeEvent.asset_id)
            .filter(
                AssetChangeEvent.project_id == project_id,
                AssetChangeEvent.asset_id.in_(asset_ids),
                AssetChangeEvent.detected_at >= window,
            )
            .all()
        )

        # For each asset compute classifications
        for aid, asset in asset_map.items():
            outgoing = outgoing_map.get(aid, [])
            incoming = incoming_map.get(aid, [])
            all_rels = outgoing + incoming

            # internet_facing
            internet_facing = False
            if asset.asset_type in ("ip", "ipv6"):
                internet_facing = is_public_ip(asset.value)
            elif asset.asset_type in ("url", "web_site", "web_host"):
                host = _parse_hostname_from_url(asset.value) or asset.value
                # If host is IP and public
                if is_public_ip(host):
                    internet_facing = True
                else:
                    # Check resolves_to to public IP via outgoing relationships
                    for rel, tgt in outgoing:
                        if rel.relationship_type == "resolves_to" and tgt.asset_type in ("ip", "ipv6") and is_public_ip(tgt.value):
                            internet_facing = True
                            break
                    # Also check target IP asset exposed via url observed_on?
                    if not internet_facing:
                        for rel, tgt in outgoing:
                            if tgt.asset_type in ("ip", "ipv6") and is_public_ip(tgt.value):
                                internet_facing = True
                                break
            else:  # domain / subdomain / hostname / etc
                for rel, tgt in outgoing:
                    if rel.relationship_type in ("resolves_to", "points_to") and tgt.asset_type in ("ip", "ipv6") and is_public_ip(tgt.value):
                        internet_facing = True
                        break
                # Also if asset value itself is public IP (host blob)
                if not internet_facing and asset.asset_type in ("host",) and is_public_ip(asset.value):
                    internet_facing = True

            # externally_resolvable
            externally_resolvable = False
            for rel, tgt in outgoing:
                if rel.relationship_type in ("resolves_to", "points_to"):
                    externally_resolvable = True
                    break

            # web_application
            web_application = False
            if asset.asset_type in WEB_ASSET_TYPES:
                web_application = True
            else:
                # Check serves technology
                for rel, tgt in outgoing:
                    if rel.relationship_type == "serves" and tgt.asset_type == "technology":
                        web_application = True
                        break
                    if rel.relationship_type == "observed_on":
                        # outgoing observed_on from this asset to url/host suggests web
                        if tgt.asset_type in WEB_ASSET_TYPES or tgt.asset_type == "url":
                            web_application = True
                            break
                if not web_application:
                    for rel, src in incoming:
                        if rel.relationship_type == "observed_on" and src.asset_type in WEB_ASSET_TYPES:
                            web_application = True
                            break
                # Check exposes -> runs http/https
                if not web_application:
                    # outgoing exposes to port that runs http/https
                    for rel, tgt in outgoing:
                        if rel.relationship_type == "exposes" and tgt.asset_type == "port":
                            # need to check if that port runs web service — look for second hop via port's outgoing runs
                            # For batch we would need to fetch port's relationships, but we can approximate by port value
                            if tgt.value in WEB_PORTS:
                                web_application = True
                                break
                            # Also if any incoming runs to http service for this asset's exposed port
                            # We can check if asset has incoming exposes? Already covered
                            pass
                    # If asset is port and value is web port, it's part of web app (the port itself)
                    if not web_application and asset.asset_type == "port" and asset.value in WEB_PORTS:
                        # Only consider port as web_application if it has exposes incoming or runs outgoing
                        if all_rels:
                            web_application = True

            # exposed_service
            exposed_service = False
            # Any exposes or runs relationship involving this asset
            for rel, other in all_rels:
                if rel.relationship_type in ("exposes", "runs"):
                    exposed_service = True
                    break
            # Also asset_type port/service with any relationship qualifies already
            if not exposed_service and asset.asset_type in ("port", "service") and all_rels:
                exposed_service = True
            # IP/domain that exposes at least one port
            # Already covered via outgoing exposes check

            # technology_bearing
            technology_bearing = False
            for rel, tgt in outgoing:
                if rel.relationship_type in ("serves", "uses") and tgt.asset_type == "technology":
                    technology_bearing = True
                    break
            for rel, src in incoming:
                if rel.relationship_type == "serves" and src.asset_type in WEB_ASSET_TYPES:
                    # This asset is technology being served, not bearer
                    pass

            # vulnerable (reuse finding counts, project-scoped)
            total = total_by_asset.get(aid, 0)
            vulnerable = total > 0

            # recently_changed (reuse Stage B 7-day window)
            recently_changed = False
            # check timestamps
            for ts in (asset.last_seen_at, asset.updated_at, asset.created_at):
                if ts is None:
                    continue
                aware = ts
                if aware.tzinfo is None:
                    aware = aware.replace(tzinfo=timezone.utc)
                if aware >= window:
                    recently_changed = True
                    break
            if not recently_changed and aid in recent_event_ids:
                recently_changed = True

            # potentially_sensitive (conservative keyword exact token)
            potentially_sensitive = _is_sensitive_value(asset.value, asset.extra_data if isinstance(asset.extra_data, dict) else {})

            # Unknown vs false: we use false for insufficient evidence (never true when unknown)
            result[aid] = {
                "internet_facing": bool(internet_facing),
                "externally_resolvable": bool(externally_resolvable),
                "web_application": bool(web_application),
                "exposed_service": bool(exposed_service),
                "technology_bearing": bool(technology_bearing),
                "vulnerable": bool(vulnerable),
                "recently_changed": bool(recently_changed),
                "potentially_sensitive": bool(potentially_sensitive),
            }

    return result

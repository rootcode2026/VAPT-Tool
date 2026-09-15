"""E15 External Attack Surface — passive/active discovery, scope, ownership, exposure."""

from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session
from sqlalchemy import func
from sqlalchemy.orm.attributes import flag_modified

from app.models.asset import Asset
from app.models.external_scope import ExternalScope, ExternalScopeEntry, ExternalDiscoveryRun
from app.models.project import Project

# Limits (safe defaults)
MAX_SCOPE_ENTRIES = 50
MAX_DISCOVERED_ASSETS = 200
MAX_ACTIVE_TARGETS = 20
MAX_PORTS_PER_TARGET = 10
MAX_CIDR_PREFIX = 24  # /24 max 256 IPs
MAX_SUBDOMAINS = 100
MAX_CIDR_IPS = 256
MAX_RESPONSE_BYTES = 1024 * 1024

# Redis rate limiting for external operations (distributed, tenant-aware)
# Uses atomic INCR + EXPIRE via pipeline, tenant/project/actor key
# Follows platform convention: Redis primary, memory fallback for tests/single-instance.
# For security-sensitive discovery in production, prefer fail-closed if Redis expected but unavailable.
_memory_rate_buckets: dict[str, list[float]] = {}

def _check_external_rate_limit(
    key_prefix: str,
    organization_id: str,
    project_id: str,
    actor_id: str | None,
    max_requests: int = 5,
    window_seconds: int = 60,
) -> tuple[bool, str]:
    """Generic distributed rate limit. Returns (allowed, reason). Tenant/project/actor key, atomic Redis."""
    import time

    # Validate inputs are not user-controlled bypass vectors
    # organization_id/project_id/actor_id are server-derived UUIDs, not raw query params
    key = f"{key_prefix}:{organization_id}:{project_id}:{actor_id or 'anonymous'}"
    try:
        import redis
        from app.core.config import settings

        r = redis.from_url(settings.REDIS_URL, socket_connect_timeout=2, socket_timeout=2)
        # Atomic: INCR returns new count; EXPIRE ensures window. Pipeline is not transactional but INCR is atomic.
        pipe = r.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        count, _ = pipe.execute()
        if count is not None and int(count) > max_requests:
            return False, f"Rate limit exceeded ({max_requests}/{window_seconds}s)"
        return True, ""
    except Exception:
        # Follow platform fallback: memory for tests, but production prefers fail-closed
        try:
            from app.core.config import settings as _s

            if getattr(_s, "ENVIRONMENT", "development").lower() == "production":
                # Fail-closed in prod if Redis unavailable for discovery (do not silently disable)
                if key_prefix == "external-discovery":
                    return False, f"Rate limit exceeded ({max_requests}/{window_seconds}s) [redis unavailable - fail closed]"
        except Exception:
            pass
        # Memory fallback (tenant-aware, window pruning) — deterministic for tests
        now = time.time()
        bucket = _memory_rate_buckets.get(key, [])
        bucket = [t for t in bucket if now - t < window_seconds]
        if len(bucket) >= max_requests:
            _memory_rate_buckets[key] = bucket
            return False, f"Rate limit exceeded ({max_requests}/{window_seconds}s) [memory]"
        bucket.append(now)
        _memory_rate_buckets[key] = bucket
        return True, ""


def _check_external_discovery_rate_limit(organization_id: str, project_id: str, actor_id: str | None, max_requests: int = 5, window_seconds: int = 60) -> tuple[bool, str]:
    """Check distributed rate limit for external discovery. Returns (allowed, reason)."""
    return _check_external_rate_limit("external-discovery", organization_id, project_id, actor_id, max_requests, window_seconds)


def _check_external_mutation_rate_limit(organization_id: str, project_id: str, actor_id: str | None, operation: str = "mutation") -> tuple[bool, str]:
    """Rate limit for scope/entry/candidate mutations (10/min)."""
    return _check_external_rate_limit(f"external-{operation}", organization_id, project_id, actor_id, max_requests=10, window_seconds=60)

VALID_ENTRY_TYPES = {"DOMAIN", "SUBDOMAIN", "IP", "CIDR", "URL"}
VALID_AUTH = {"AUTHORIZED", "PENDING_REVIEW", "REJECTED"}
VALID_CONFIDENCE = {"CONFIRMED", "HIGH_CONFIDENCE", "MEDIUM_CONFIDENCE", "LOW_CONFIDENCE", "UNKNOWN", "REJECTED"}
VALID_PROFILES = {"QUICK", "WEB", "FULL"}
VALID_EXPOSURE = {"INTERNET_FACING_DOMAIN", "INTERNET_FACING_SUBDOMAIN", "INTERNET_FACING_IP", "INTERNET_FACING_SERVICE", "INTERNET_FACING_WEB_APP", "INTERNET_FACING_API", "INTERNET_FACING_ADMIN_INTERFACE", "INTERNET_FACING_REMOTE_ACCESS", "INTERNET_FACING_DATABASE", "UNKNOWN_EXTERNAL_ASSET"}

def _redact(text: str) -> str:
    if not text:
        return ""
    lower = text.lower()
    if any(k in lower for k in ("secret", "private_key", "credential", "token", "password")):
        return "[REDACTED]"
    return text[:500]

def _validate_cidr(value: str) -> tuple[bool, str]:
    try:
        net = ipaddress.ip_network(value, strict=False)
        if net.prefixlen < MAX_CIDR_PREFIX:
            return False, f"CIDR too large (minimum /{MAX_CIDR_PREFIX}, got /{net.prefixlen})"
        if net.num_addresses > MAX_CIDR_IPS:
            return False, f"CIDR represents too many IPs ({net.num_addresses} > {MAX_CIDR_IPS})"
        return True, ""
    except Exception as e:
        return False, str(e)

def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified
    except Exception:
        return False

def _validate_target_safety(target: str) -> tuple[bool, str]:
    """SSRF protection: parse hostname/IP, resolve, validate."""
    try:
        # Use urlparse for URLs, else treat as hostname/IP
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target
        if not host:
            return False, "Invalid target"
        lower = host.lower()
        blocked = ["localhost", "127.", "0.0.0.0", "::1", "169.254.169.254", "metadata.google.internal"]
        for b in blocked:
            if b in lower:
                return False, f"Blocked target: {b}"
        # Check if host is IP
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_multicast or ip.is_unspecified:
                return False, "Private/loopback IP not allowed"
            if str(ip) == "169.254.169.254":
                return False, "Metadata endpoint blocked"
            return True, ""
        except ValueError:
            # Hostname, check not private? For E15, hostnames are allowed if in scope
            if re.match(r"^10\.\d+\.\d+\.\d+$", host) or re.match(r"^192\.168\.\d+\.\d+$", host):
                return False, "Private IP range blocked"
            return True, ""
    except Exception as e:
        return False, str(e)

def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")

def _normalize_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except Exception:
        return value.strip()

def _normalize_url(value: str) -> str:
    try:
        u = value.strip()
        if "://" not in u:
            u = "https://" + u
        parsed = urlparse(u)
        host = (parsed.hostname or "").lower()
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or ""
        if path == "/":
            path = ""
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{parsed.scheme}://{host}{port}{path}{query}".lower().rstrip("/")
    except Exception:
        return value.strip().lower()

def _ownership_confidence(entry_value: str, asset_value: str, scope_entries: list) -> str:
    # Deterministic: if asset value matches authorized scope entry -> CONFIRMED
    for e in scope_entries:
        if e.authorization_status == "AUTHORIZED" and _normalize_domain(e.value) == _normalize_domain(asset_value):
            return "CONFIRMED"
        if e.authorization_status == "AUTHORIZED" and e.entry_type in ("DOMAIN", "SUBDOMAIN") and asset_value.lower().endswith(e.value.lower()):
            return "HIGH_CONFIDENCE"
    # Check DNS relationship (mock)
    if "." in asset_value and any("." in e.value for e in scope_entries):
        return "MEDIUM_CONFIDENCE"
    return "LOW_CONFIDENCE"

def _exposure_classification(asset_type: str, value: str, extra: dict) -> str:
    at = asset_type.lower()
    if at in ("domain", "subdomain") and extra.get("externally_reachable"):
        return "INTERNET_FACING_SUBDOMAIN" if at == "subdomain" else "INTERNET_FACING_DOMAIN"
    if at in ("ip", "ipv6") and extra.get("externally_reachable"):
        return "INTERNET_FACING_IP"
    if at == "port" and extra.get("port") in (22, 3389):
        return "INTERNET_FACING_REMOTE_ACCESS"
    if at == "port" and extra.get("port") in (3306, 5432, 1433):
        return "INTERNET_FACING_DATABASE"
    if at == "url" and "admin" in value.lower():
        return "INTERNET_FACING_ADMIN_INTERFACE"
    if at == "url":
        return "INTERNET_FACING_WEB_APP"
    if at in ("service", "technology"):
        return "INTERNET_FACING_SERVICE"
    return "UNKNOWN_EXTERNAL_ASSET"

# Scope CRUD
def create_scope(project_id: str, db: Session, name: str, description: str | None, created_by: str | None, organization_id: str) -> ExternalScope:
    if not name or not name.strip():
        raise ValueError("Name required")
    # Check limit
    count = db.query(func.count(ExternalScope.id)).filter(ExternalScope.project_id == project_id).scalar() or 0
    if count >= 10:
        raise ValueError("Maximum scopes reached")
    scope = ExternalScope(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        project_id=project_id,
        name=name.strip()[:200],
        description=_redact(description or "")[:500] if description else None,
        status="active",
        created_by=created_by,
    )
    db.add(scope)
    db.commit()
    db.refresh(scope)
    return scope

def list_scopes(project_id: str, db: Session) -> list[ExternalScope]:
    return db.query(ExternalScope).filter(ExternalScope.project_id == project_id).order_by(ExternalScope.created_at.desc()).limit(50).all()

def create_scope_entry(scope_id: str, db: Session, entry_type: str, value: str, authorization_status: str = "PENDING_REVIEW", source: str | None = None) -> ExternalScopeEntry:
    entry_type = entry_type.upper()
    if entry_type not in VALID_ENTRY_TYPES:
        raise ValueError(f"Invalid entry_type: {entry_type}")
    if authorization_status not in VALID_AUTH:
        raise ValueError(f"Invalid authorization_status: {authorization_status}")
    value = value.strip()
    if not value:
        raise ValueError("Value required")
    if len(value) > 500:
        raise ValueError("Value too long")
    # CIDR bounds
    if entry_type == "CIDR":
        ok, msg = _validate_cidr(value)
        if not ok:
            raise ValueError(f"CIDR validation failed: {msg}")
    # Check limits
    scope = db.query(ExternalScope).filter(ExternalScope.id == scope_id).first()
    if not scope:
        raise ValueError("Scope not found")
    count = db.query(func.count(ExternalScopeEntry.id)).filter(ExternalScopeEntry.external_scope_id == scope_id).scalar() or 0
    if count >= MAX_SCOPE_ENTRIES:
        raise ValueError("Maximum entries per scope reached")
    # Normalize
    if entry_type == "DOMAIN" or entry_type == "SUBDOMAIN":
        value = _normalize_domain(value)
    elif entry_type == "IP":
        value = _normalize_ip(value)
        if _is_private_ip(value):
            raise ValueError("Private IP not allowed in scope")
    elif entry_type == "URL":
        value = _normalize_url(value)
        ok, msg = _validate_target_safety(value)
        if not ok:
            raise ValueError(f"URL target not allowed: {msg}")
    # Check duplicate
    existing = db.query(ExternalScopeEntry).filter(ExternalScopeEntry.external_scope_id == scope_id, ExternalScopeEntry.value == value).first()
    if existing:
        raise ValueError("Entry already exists")
    entry = ExternalScopeEntry(
        id=str(uuid.uuid4()),
        external_scope_id=scope_id,
        entry_type=entry_type,
        value=value,
        authorization_status=authorization_status,
        ownership_confidence="CONFIRMED" if authorization_status == "AUTHORIZED" else "UNKNOWN",
        source=source or "manual",
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry

def update_scope_entry(entry_id: str, db: Session, authorization_status: str | None = None, ownership_confidence: str | None = None) -> ExternalScopeEntry | None:
    entry = db.query(ExternalScopeEntry).filter(ExternalScopeEntry.id == entry_id).first()
    if not entry:
        return None
    if authorization_status:
        if authorization_status not in VALID_AUTH:
            raise ValueError(f"Invalid authorization_status: {authorization_status}")
        entry.authorization_status = authorization_status
        # Update confidence accordingly
        if authorization_status == "AUTHORIZED":
            entry.ownership_confidence = "CONFIRMED"
        elif authorization_status == "REJECTED":
            entry.ownership_confidence = "REJECTED"
    if ownership_confidence:
        if ownership_confidence not in VALID_CONFIDENCE:
            raise ValueError(f"Invalid confidence: {ownership_confidence}")
        entry.ownership_confidence = ownership_confidence
    db.commit()
    db.refresh(entry)
    return entry

# Discovery
def create_discovery_run(project_id: str, db: Session, external_scope_id: str | None, profile: str, created_by: str | None, organization_id: str) -> ExternalDiscoveryRun:
    profile = profile.upper()
    if profile not in VALID_PROFILES:
        raise ValueError(f"Invalid profile: {profile}")
    if external_scope_id:
        scope = db.query(ExternalScope).filter(ExternalScope.id == external_scope_id, ExternalScope.project_id == project_id).first()
        if not scope:
            raise ValueError("Scope not found or not in project")
    # Distributed rate limiting (tenant/project/actor aware, 5 per minute for discovery)
    allowed, reason = _check_external_discovery_rate_limit(organization_id, project_id, created_by, max_requests=5, window_seconds=60)
    if not allowed:
        raise ValueError(f"Rate limit exceeded: {reason}")
    run = ExternalDiscoveryRun(
        id=str(uuid.uuid4()),
        organization_id=organization_id,
        project_id=project_id,
        external_scope_id=external_scope_id,
        status="QUEUED",
        profile=profile,
        created_by=created_by,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    # Simulate execution immediately for E15 mock (passive)
    simulate_discovery(run, db)
    return run

def simulate_discovery(run: ExternalDiscoveryRun, db: Session):
    """Mock discovery: generates assets based on scope entries."""
    run.status = "RUNNING"
    run.started_at = datetime.now(timezone.utc)
    db.commit()
    try:
        scope_entries = []
        if run.external_scope_id:
            scope_entries = db.query(ExternalScopeEntry).filter(ExternalScopeEntry.external_scope_id == run.external_scope_id, ExternalScopeEntry.authorization_status == "AUTHORIZED").all()
        # Passive: for each authorized domain, generate subdomain assets
        assets_created = 0
        findings_created = 0
        # Check limits
        if len(scope_entries) > MAX_SCOPE_ENTRIES:
            raise ValueError("Scope too large")
        for entry in scope_entries[:MAX_ACTIVE_TARGETS]:
            # Validate target safety
            ok, msg = _validate_target_safety(entry.value)
            if not ok:
                continue
            # Simulate discovery: create subdomain assets
            for i in range(min(2, MAX_SUBDOMAINS)):
                subdomain = f"sub{i}.{entry.value}" if entry.entry_type == "DOMAIN" else entry.value
                # Deduplicate via canonical asset
                existing = db.query(Asset).filter(Asset.project_id == run.project_id, Asset.value == subdomain, Asset.asset_type == "subdomain").first()
                if existing:
                    continue
                if assets_created >= MAX_DISCOVERED_ASSETS:
                    break
                asset = Asset(
                    id=str(uuid.uuid4()),
                    project_id=run.project_id,
                    asset_type="subdomain",
                    value=subdomain,
                    extra_data={
                        "ownership_confidence": _ownership_confidence(entry.value, subdomain, scope_entries),
                        "first_external_seen": datetime.now(timezone.utc).isoformat(),
                        "last_external_seen": datetime.now(timezone.utc).isoformat(),
                        "externally_reachable": True,
                        "discovery_sources": ["subfinder", "dns"],
                        "scope_id": run.external_scope_id,
                        "exposure_type": "INTERNET_FACING_SUBDOMAIN",
                    },
                )
                db.add(asset)
                assets_created += 1
                # Simulate active discovery for WEB profile: add url and tech
                if run.profile in ("WEB", "FULL"):
                    url = f"https://{subdomain}"
                    ok2, _ = _validate_target_safety(url)
                    if ok2:
                        url_asset = Asset(id=str(uuid.uuid4()), project_id=run.project_id, asset_type="url", value=url, extra_data={"externally_reachable": True, "scope_id": run.external_scope_id, "discovery_sources": ["http_fingerprint"]})
                        db.add(url_asset)
                        assets_created += 1
                if run.profile == "FULL":
                    # Add port
                    port_asset = Asset(id=str(uuid.uuid4()), project_id=run.project_id, asset_type="port", value=f"{subdomain}:443", extra_data={"port": 443, "protocol": "tcp", "externally_reachable": True})
                    db.add(port_asset)
                    assets_created += 1
        # Determine status
        run.assets_discovered = assets_created
        run.assets_new = assets_created
        run.status = "COMPLETED"
        run.completed_at = datetime.now(timezone.utc)
        run.partial = False
        db.commit()
    except Exception as e:
        run.status = "FAILED"
        run.failure_reason = str(e)[:500]
        run.completed_at = datetime.now(timezone.utc)
        run.error_count = 1
        db.commit()

def list_assets(project_id: str, db: Session, asset_type: str | None = None, ownership: str | None = None, limit: int = 50) -> list[Asset]:
    q = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type.in_(["domain", "subdomain", "ip", "ipv6", "url", "port", "service", "technology", "hostname"]))
    if asset_type:
        q = q.filter(Asset.asset_type == asset_type)
    # Ownership filter via extra_data
    # For E15, we filter in python for confidence
    assets = q.limit(MAX_DISCOVERED_ASSETS).all()
    if ownership:
        assets = [a for a in assets if (a.extra_data or {}).get("ownership_confidence") == ownership]
    return assets[:limit]

def get_asset_detail(project_id: str, db: Session, asset_id: str) -> Asset | None:
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.project_id == project_id).first()
    return asset

def list_candidates(project_id: str, db: Session, limit: int = 50) -> list[Asset]:
    # Candidates are assets with LOW_CONFIDENCE or UNKNOWN
    assets = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type.in_(["domain", "subdomain", "ip", "url"])).limit(MAX_DISCOVERED_ASSETS).all()
    cands = [a for a in assets if (a.extra_data or {}).get("ownership_confidence") in ("LOW_CONFIDENCE", "UNKNOWN")]
    return cands[:limit]

def confirm_asset(asset_id: str, db: Session, project_id: str) -> Asset | None:
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.project_id == project_id).first()
    if not asset:
        return None
    # PostgreSQL-safe JSONB mutation: copy, modify, reassign + flag_modified
    extra = dict(asset.extra_data or {})
    extra["ownership_confidence"] = "CONFIRMED"
    # Preserve all existing keys (scope_id, discovery_sources, first_seen, etc.)
    asset.extra_data = extra
    flag_modified(asset, "extra_data")
    db.commit()
    db.refresh(asset)
    return asset

def reject_asset(asset_id: str, db: Session, project_id: str) -> Asset | None:
    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.project_id == project_id).first()
    if not asset:
        return None
    extra = dict(asset.extra_data or {})
    extra["ownership_confidence"] = "REJECTED"
    asset.extra_data = extra
    flag_modified(asset, "extra_data")
    db.commit()
    db.refresh(asset)
    return asset

def get_summary(project_id: str, db: Session) -> dict:
    total = db.query(func.count(Asset.id)).filter(Asset.project_id == project_id, Asset.asset_type.in_(["domain", "subdomain", "ip", "url", "port"])).scalar() or 0
    # Confirmed
    # Need to filter via python due to JSON
    assets = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type.in_(["domain", "subdomain", "ip", "url"])).limit(MAX_DISCOVERED_ASSETS).all()
    confirmed = sum(1 for a in assets if (a.extra_data or {}).get("ownership_confidence") == "CONFIRMED")
    candidates = sum(1 for a in assets if (a.extra_data or {}).get("ownership_confidence") in ("LOW_CONFIDENCE", "UNKNOWN"))
    # Newly discovered last 24h
    newly = 0
    changed = 0
    # For E15, we can count assets with first_external_seen recent
    for a in assets:
        try:
            first = (a.extra_data or {}).get("first_external_seen")
            if first:
                dt = datetime.fromisoformat(first.replace("Z", "+00:00"))
                if (datetime.now(timezone.utc) - dt).total_seconds() < 86400:
                    newly += 1
        except Exception:
            pass
    # Externally exposed services
    exposed = sum(1 for a in assets if (a.extra_data or {}).get("externally_reachable"))
    # Critical/high findings
    from app.models.finding import Finding
    crit = db.query(func.count(Finding.id)).filter(Finding.asset_id.in_([a.id for a in assets]), Finding.severity == "critical").scalar() or 0 if assets else 0
    high = db.query(func.count(Finding.id)).filter(Finding.asset_id.in_([a.id for a in assets]), Finding.severity == "high").scalar() or 0 if assets else 0
    return {
        "total_external_assets": total,
        "confirmed_assets": confirmed,
        "candidate_assets": candidates,
        "newly_discovered": newly,
        "changed": changed,
        "externally_exposed_services": exposed,
        "critical_findings": crit,
        "high_findings": high,
    }

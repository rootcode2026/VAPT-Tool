"""GCP discovery — bounded, deterministic, mocked, read-only.

Reuses AWS discovery patterns: bounded pagination, sanitized errors, secret filtering.
No network, no real GCP calls in tests (injected client factory).
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any, Callable

from .aws_discovery import (
    MAX_TOTAL_RESOURCES,
    MAX_ITEMS_PER_SERVICE_CALL,
    MAX_REGIONS,
    PERMISSION_CODES,
    THROTTLE_CODES,
    SECRET_KEY_RE,
    _bounded_extra,
    _paginate,
    _resource,
    _tags_as_dict,
    _warning_for,
    sanitize_aws_error as sanitize_gcp_error,
    classify_aws_error,
    call_with_retry,
)

MAX_GCP_RESOURCES = MAX_TOTAL_RESOURCES
MAX_FIREWALL_RULES = 50
MAX_IAM_BINDINGS = 50

def _build_gcp_service(service_name: str, credentials, project_id: str | None = None):
    """Build real GCP service via googleapiclient (production) or return mock."""
    try:
        from googleapiclient.discovery import build as _build
        # For compute, storage, etc.
        if service_name == "compute":
            return _build("compute", "v1", credentials=credentials, cache_discovery=False)
        if service_name == "storage":
            return _build("storage", "v1", credentials=credentials, cache_discovery=False)
        if service_name == "iam":
            return _build("iam", "v1", credentials=credentials, cache_discovery=False)
        if service_name == "resource_manager":
            return _build("cloudresourcemanager", "v1", credentials=credentials, cache_discovery=False)
    except ImportError:
        return None
    except Exception:
        return None
    return None

def _gcp_paginate_real(service, method: str, items_key: str, limit: int = 50, **kwargs):
    """Bounded pagination for real GCP clients (nextPageToken)."""
    items: list[dict] = []
    try:
        # service.instances().list etc.
        # For simplicity, handle via getattr
        resource = getattr(service, method.split(".")[0])() if "." in method else service
        # This is simplified; real calls would be e.g., service.instances().list(...)
        # For E6, we keep mocked path as primary; real path is documented boundary
        pass
    except Exception:
        pass
    return items

def _sanitize(val: str) -> str:
    return str(val or "")[:500]

# ---------------------------------------------------------------------------
# GCP per-resource discoverers: (client, project_id, location) -> (resources, warning)
# ---------------------------------------------------------------------------

def discover_gcp_project(client, project_id: str):
    resources, warning = [], None
    try:
        # In real GCP, would call projects.get
        # Mock: single project asset
        resources.append(_resource("gcp", "gcp_project", project_id, "global", project_id,
                                   name=project_id, extra={"project_id": project_id, "lifecycle_state": "ACTIVE"}))
    except Exception as exc:
        warning = _warning_for("gcp_project", exc)
    return resources, warning

def discover_gcp_compute_instances(client, project_id: str, zone: str = "us-central1-a"):
    resources, warning = [], None
    try:
        for inst in _paginate(client, "list_instances", "items", limit=50):
            name = inst.get("name") or inst.get("id")
            if not name:
                continue
            # Network interfaces
            nics = inst.get("networkInterfaces") or []
            ext_ip = None
            int_ip = None
            network = None
            subnet = None
            for nic in nics[:2]:
                if isinstance(nic, dict):
                    network = nic.get("network")
                    subnet = nic.get("subnetwork")
                    for cfg in (nic.get("accessConfigs") or [])[:2]:
                        if isinstance(cfg, dict) and cfg.get("natIP"):
                            ext_ip = str(cfg.get("natIP"))[:64]
                    if nic.get("networkIP"):
                        int_ip = str(nic.get("networkIP"))[:64]
            disks = inst.get("disks") or []
            attached_disks = [str(d.get("source") or "")[:256] for d in disks[:5] if isinstance(d, dict)]
            svc_acc = (inst.get("serviceAccounts") or [{}])[0].get("email") if inst.get("serviceAccounts") else None
            shielded = inst.get("shieldedInstanceConfig") or {}
            # Tags for firewall target matching
            tags = inst.get("tags") or {}
            tag_items = [str(t)[:64] for t in (tags.get("items") or [])[:20]] if isinstance(tags, dict) else []
            resources.append(_resource("gcp", "gcp_compute_instance", str(inst.get("id") or name), zone, project_id,
                                       name=name, extra={
                                           "machine_type": str(inst.get("machineType") or "")[:100],
                                           "zone": zone,
                                           "network": str(network or "")[:256] or None,
                                           "subnet": str(subnet or "")[:256] or None,
                                           "external_ip": ext_ip,
                                           "internal_ip": int_ip,
                                           "service_account": str(svc_acc or "")[:256] or None,
                                           "shielded_vm": bool(shielded.get("enableSecureBoot")) if shielded else None,
                                           "status": str(inst.get("status") or "")[:20] or None,
                                           "attached_disks": attached_disks,
                                           "tags": tag_items,
                                       }))
    except Exception as exc:
        warning = _warning_for("gcp_compute", exc)
    return resources, warning

def discover_gcp_disks(client, project_id: str, zone: str = "us-central1-a"):
    resources, warning = [], None
    try:
        for disk in _paginate(client, "list_disks", "items", limit=50):
            name = disk.get("name")
            if not name:
                continue
            resources.append(_resource("gcp", "gcp_disk", name, zone, project_id,
                                       name=name, extra={
                                           "size_gb": disk.get("sizeGb"),
                                           "zone": zone,
                                           "encrypted": disk.get("encrypted"),  # mock field
                                           "disk_encryption_key": str(disk.get("diskEncryptionKey") or "")[:256] or None,
                                       }))
    except Exception as exc:
        warning = _warning_for("gcp_disk", exc)
    return resources, warning

def discover_gcp_vpc(client, project_id: str):
    resources, warning = [], None
    try:
        for net in _paginate(client, "list_networks", "items", limit=20):
            name = net.get("name")
            if not name:
                continue
            resources.append(_resource("gcp", "gcp_vpc", name, "global", project_id,
                                       name=name, extra={
                                           "auto_create_subnetworks": net.get("autoCreateSubnetworks"),
                                           "routing_mode": str(net.get("routingConfig", {}).get("routingMode") or "")[:20] or None,
                                       }))
    except Exception as exc:
        warning = _warning_for("gcp_vpc", exc)
    return resources, warning

def discover_gcp_subnets(client, project_id: str, region: str = "us-central1"):
    resources, warning = [], None
    try:
        for subnet in _paginate(client, "list_subnetworks", "items", limit=50):
            name = subnet.get("name")
            if not name:
                continue
            resources.append(_resource("gcp", "gcp_subnet", name, region, project_id,
                                       name=name, extra={
                                           "network": str(subnet.get("network") or "")[:256] or None,
                                           "cidr": str(subnet.get("ipCidrRange") or "")[:64] or None,
                                           "region": region,
                                           "private_ip_google_access": subnet.get("privateIpGoogleAccess"),
                                       }))
    except Exception as exc:
        warning = _warning_for("gcp_subnet", exc)
    return resources, warning

def discover_gcp_firewalls(client, project_id: str):
    resources, warning = [], None
    try:
        for fw in _paginate(client, "list_firewalls", "items", limit=MAX_FIREWALL_RULES):
            name = fw.get("name")
            if not name:
                continue
            # Normalize firewall rule
            direction = str(fw.get("direction") or "INGRESS")[:20]
            priority = fw.get("priority")
            source_ranges = [str(s)[:64] for s in (fw.get("sourceRanges") or [])[:10]]
            dest_ranges = [str(s)[:64] for s in (fw.get("destinationRanges") or [])[:10]]
            allowed = []
            for allow in (fw.get("allowed") or [])[:10]:
                if isinstance(allow, dict):
                    proto = str(allow.get("IPProtocol") or "")[:10]
                    ports = [str(p)[:20] for p in (allow.get("ports") or [])[:20]]
                    allowed.append({"protocol": proto, "ports": ports})
            denied = []
            for deny in (fw.get("denied") or [])[:10]:
                if isinstance(deny, dict):
                    proto = str(deny.get("IPProtocol") or "")[:10]
                    ports = [str(p)[:20] for p in (deny.get("ports") or [])[:20]]
                    denied.append({"protocol": proto, "ports": ports})
            target_tags = [str(t)[:64] for t in (fw.get("targetTags") or [])[:10]]
            target_sas = [str(s)[:256] for s in (fw.get("targetServiceAccounts") or [])[:10]]
            resources.append(_resource("gcp", "gcp_firewall", name, "global", project_id,
                                       name=name, extra={
                                           "network": str(fw.get("network") or "")[:256] or None,
                                           "direction": direction,
                                           "priority": priority,
                                           "source_ranges": source_ranges,
                                           "destination_ranges": dest_ranges,
                                           "allowed": allowed,
                                           "denied": denied,
                                           "target_tags": target_tags,
                                           "target_service_accounts": target_sas,
                                           "disabled": fw.get("disabled"),
                                       }))
    except Exception as exc:
        warning = _warning_for("gcp_firewall", exc)
    return resources, warning

def discover_gcp_storage_buckets(client, project_id: str):
    resources, warning = [], None
    try:
        for bucket in _paginate(client, "list_buckets", "items", limit=50):
            name = bucket.get("name")
            if not name:
                continue
            # IAM policy / uniform access
            iam_members = []
            for binding in (bucket.get("iamBindings") or [])[:20]:
                if isinstance(binding, dict):
                    role = str(binding.get("role") or "")[:100]
                    for member in (binding.get("members") or [])[:20]:
                        iam_members.append({"role": role, "member": str(member)[:256]})
            resources.append(_resource("gcp", "gcp_storage_bucket", name, bucket.get("location") or "us", project_id,
                                       name=name, extra={
                                           "location": str(bucket.get("location") or "")[:64] or None,
                                           "storage_class": str(bucket.get("storageClass") or "")[:20] or None,
                                           "uniform_bucket_level_access": bucket.get("uniformBucketLevelAccess", {}).get("enabled") if isinstance(bucket.get("uniformBucketLevelAccess"), dict) else bucket.get("uniformBucketLevelAccess"),
                                           "public_iam_members": iam_members[:20],
                                           "versioning": str(bucket.get("versioning", {}).get("enabled") or "")[:20] or None if isinstance(bucket.get("versioning"), dict) else str(bucket.get("versioning") or "")[:20] or None,
                                           "encryption": bucket.get("encryption", {}).get("defaultKmsKeyName") if isinstance(bucket.get("encryption"), dict) else bucket.get("encryption"),
                                           "logging": bucket.get("logging"),
                                       }))
    except Exception as exc:
        warning = _warning_for("gcp_storage", exc)
    return resources, warning

def discover_gcp_iam_bindings(client, project_id: str):
    resources, warning = [], None
    try:
        bindings = []
        for page in _paginate(client, "get_iam_policy", "bindings", limit=MAX_IAM_BINDINGS):
            # _paginate expects dict key, but get_iam_policy returns {"bindings": [...]}
            # Handle both
            if isinstance(page, dict) and "role" in page:
                bindings.append(page)
            elif isinstance(page, dict):
                for b in (page.get("bindings") or []):
                    bindings.append(b)
            else:
                bindings.append(page)
        # Normalize: if client returns directly bindings list via get_iam_policy, handle
        if not bindings:
            # Try direct call
            try:
                pol = call_with_retry(lambda: client.get_iam_policy(project=project_id), sleep=lambda _: None) or {}
                bindings = pol.get("bindings") or []
            except Exception:
                bindings = []
        normalized = []
        for b in bindings[:MAX_IAM_BINDINGS]:
            if not isinstance(b, dict):
                continue
            role = str(b.get("role") or "")[:100]
            members = [str(m)[:256] for m in (b.get("members") or [])[:20]]
            normalized.append({"role": role, "members": members})
        if normalized:
            resources.append(_resource("gcp", "gcp_iam_policy", f"{project_id}-iam", "global", project_id,
                                       name=f"{project_id}-iam", extra={"bindings": normalized}))
    except Exception as exc:
        warning = _warning_for("gcp_iam", exc)
    return resources, warning

def discover_gcp_service_accounts(client, project_id: str):
    resources, warning = [], None
    try:
        for sa in _paginate(client, "list_service_accounts", "accounts", limit=50):
            email = sa.get("email")
            if not email:
                continue
            # Keys metadata (no private material)
            keys = []
            for key in (sa.get("keys") or [])[:10]:
                if isinstance(key, dict):
                    keys.append({"key_id": str(key.get("name") or "")[:100], "valid_after": str(key.get("validAfterTime") or "")[:32] or None, "valid_before": str(key.get("validBeforeTime") or "")[:32] or None})
            resources.append(_resource("gcp", "gcp_service_account", email, "global", project_id,
                                       name=email, extra={
                                           "display_name": str(sa.get("displayName") or "")[:100] or None,
                                           "disabled": sa.get("disabled"),
                                           "keys": keys,
                                       }))
    except Exception as exc:
        warning = _warning_for("gcp_service_account", exc)
    return resources, warning

GCP_REGIONAL_DISCOVERERS = (
    ("compute", discover_gcp_compute_instances),
    ("disk", discover_gcp_disks),
)

GCP_GLOBAL_DISCOVERERS = (
    ("project", discover_gcp_project),
    ("vpc", discover_gcp_vpc),
    ("subnet", discover_gcp_subnets),
    ("firewall", discover_gcp_firewalls),
    ("storage", discover_gcp_storage_buckets),
    ("iam", discover_gcp_iam_bindings),
    ("service_account", discover_gcp_service_accounts),
)

GCP_SERVICE_CLIENTS = {
    "compute": "compute",
    "disk": "compute",
    "project": "resource_manager",
    "vpc": "compute",
    "subnet": "compute",
    "firewall": "compute",
    "storage": "storage",
    "iam": "iam",
    "service_account": "iam",
}

def discover_gcp_region(session_factory, project_id: str, zone: str, max_total: int) -> dict:
    resources: list[dict] = []
    warnings: list[dict] = []
    ok = 0
    fail = 0
    for key, discoverer in GCP_REGIONAL_DISCOVERERS:
        if len(resources) >= max_total:
            break
        try:
            client = session_factory(GCP_SERVICE_CLIENTS[key], zone)
            found, warning = discoverer(client, project_id, zone)
            resources.extend(found[:max_total - len(resources)])
            if warning:
                warnings.append(warning)
                fail += 1
            else:
                ok += 1
        except Exception as exc:
            warnings.append(_warning_for(key, exc) or {"service": key, "reason": "service_error", "detail": sanitize_gcp_error(exc)})
            fail += 1
    return {"resources": resources, "warnings": warnings, "services_ok": ok, "services_failed": fail}

def discover_gcp_global(session_factory, project_id: str, max_total: int) -> dict:
    resources: list[dict] = []
    warnings: list[dict] = []
    for key, discoverer in GCP_GLOBAL_DISCOVERERS:
        if len(resources) >= max_total:
            break
        try:
            client = session_factory(GCP_SERVICE_CLIENTS[key], "global")
            found, warning = discoverer(client, project_id)
            resources.extend(found[:max_total - len(resources)])
            if warning:
                warnings.append(warning)
        except Exception as exc:
            warnings.append(_warning_for(key, exc) or {"service": key, "reason": "service_error", "detail": sanitize_gcp_error(exc)})
    return {"resources": resources, "warnings": warnings}

def discover_gcp_account(session_factory, project_id: str, zones: list[str], max_total: int = MAX_GCP_RESOURCES) -> dict:
    all_resources: list[dict] = []
    warnings: list[dict] = []
    attempted = succeeded = failed = 0
    remaining = max(0, int(max_total or MAX_GCP_RESOURCES))
    # Global first
    attempted += 1
    try:
        outcome = discover_gcp_global(session_factory, project_id, remaining)
        all_resources.extend(outcome["resources"])
        warnings.extend(outcome["warnings"])
        succeeded += 1
        remaining = max(0, remaining - len(outcome["resources"]))
    except Exception as exc:
        failed += 1
        warnings.append({"service": "global", "reason": "service_error", "detail": sanitize_gcp_error(exc)})
    # Regional per zone
    for zone in (zones or [])[:5]:
        attempted += 1
        try:
            outcome = discover_gcp_region(session_factory, project_id, zone, remaining)
            all_resources.extend(outcome["resources"])
            warnings.extend(outcome["warnings"])
            succeeded += 1
            remaining = max(0, remaining - len(outcome["resources"]))
        except Exception as exc:
            failed += 1
            warnings.append({"service": "zone", "zone": zone, "reason": "service_error", "detail": sanitize_gcp_error(exc)})
    if attempted and failed == attempted:
        status = "failed"
    elif failed:
        status = "partial"
    else:
        status = "completed"
    counts: dict[str, int] = {}
    for r in all_resources:
        k = str(r.get("resource_type") or "unknown")
        counts[k] = counts.get(k, 0) + 1
    return {"status": status, "regions_attempted": attempted, "regions_succeeded": succeeded, "regions_failed": failed,
            "resources": all_resources, "warnings": warnings[:50], "resource_counts": counts}

def gcp_canonical_value(resource: dict) -> str:
    arn = (resource.get("arn") or "").strip()
    if arn.startswith("gcp:"):
        return arn[:1024]
    project = str(resource.get("account_id") or "").strip()
    region = str(resource.get("region") or "global").strip().lower()
    rtype = str(resource.get("resource_type") or "unknown").strip().lower()
    rid = str(resource.get("resource_id") or "").strip()
    return f"cloud_resource:gcp:{project}:{region}:{rtype}:{rid}"[:1024]

def gcp_to_asset_inputs(resources: list[dict], project_id: str, observed_at: str) -> list[dict]:
    assets: list[dict] = []
    seen: set[tuple[str, str]] = set()
    account_value = f"cloud_account:gcp:{project_id}:global"
    assets.append({"type": "cloud_account", "value": account_value, "metadata": {"provider": "gcp", "account_id": project_id, "region": "global", "sources": ["gcp-discovery"], "observed_at": observed_at}})
    seen.add(("cloud_account", account_value))
    for resource in resources:
        value = gcp_canonical_value(resource)
        key = ("cloud_resource", value)
        if key in seen or not value:
            continue
        seen.add(key)
        extra = _bounded_extra(resource.get("extra") if isinstance(resource.get("extra"), dict) else {})
        assets.append({"type": "cloud_resource", "value": value, "metadata": {"provider": "gcp", "service": resource.get("service"), "resource_type": resource.get("resource_type"), "resource_id": str(resource.get("resource_id") or "")[:500], "arn": (resource.get("arn") or "")[:1024] or None, "region": resource.get("region"), "account_id": project_id, "name": (resource.get("name") or "")[:255] or None, "tags": _tags_as_dict(resource.get("tags")), "extra": extra, "sources": ["gcp-discovery"], "observed_at": observed_at}})
    return assets

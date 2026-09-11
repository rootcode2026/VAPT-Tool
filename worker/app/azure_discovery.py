"""Azure discovery — bounded, deterministic, mocked, read-only.

Reuses AWS discovery patterns: bounded pagination, sanitized errors, secret filtering.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from .aws_discovery import (
    MAX_TOTAL_RESOURCES,
    SECRET_KEY_RE,
    _bounded_extra,
    _paginate,
    _resource,
    _tags_as_dict,
    _warning_for,
    sanitize_aws_error as sanitize_azure_error,
    classify_aws_error,
    call_with_retry,
)

MAX_AZURE_RESOURCES = MAX_TOTAL_RESOURCES
MAX_NSG_RULES = 50
MAX_RBAC_ASSIGNMENTS = 100

def _sanitize(val: str) -> str:
    return str(val or "")[:500]

def discover_azure_subscription(client, subscription_id: str):
    resources, warning = [], None
    try:
        # Mock: single subscription
        resources.append(_resource("azure", "azure_subscription", subscription_id, "global", subscription_id,
                                   name=subscription_id, extra={"subscription_id": subscription_id, "state": "Enabled"}))
    except Exception as exc:
        warning = _warning_for("azure_subscription", exc)
    return resources, warning

def discover_azure_resource_groups(client, subscription_id: str):
    resources, warning = [], None
    try:
        for rg in _paginate(client, "list_resource_groups", "value", limit=50):
            name = rg.get("name")
            if not name:
                continue
            resources.append(_resource("azure", "azure_resource_group", name, rg.get("location") or "eastus", subscription_id,
                                       name=name, extra={"location": str(rg.get("location") or "")[:64] or None, "tags": _tags_as_dict(rg.get("tags"))}))
    except Exception as exc:
        warning = _warning_for("azure_resource_group", exc)
    return resources, warning

def discover_azure_vms(client, subscription_id: str):
    resources, warning = [], None
    try:
        for vm in _paginate(client, "list_virtual_machines", "value", limit=50):
            name = vm.get("name")
            if not name:
                continue
            props = vm.get("properties") or vm
            rg = str(vm.get("resourceGroup") or props.get("resourceGroup") or vm.get("id", "").split("/")[4] if "/resourceGroups/" in str(vm.get("id") or "") else "")[:64] or None
            location = str(vm.get("location") or props.get("location") or "")[:64] or None
            # Network interfaces
            nics = (props.get("networkProfile", {}) or vm.get("networkProfile", {})).get("networkInterfaces") or []
            nic_ids = [str(nic.get("id") or "")[:256] for nic in nics[:5] if isinstance(nic, dict)]
            # Public IP via network interfaces (mock)
            public_ip = None
            private_ip = None
            for nic in nics[:2]:
                if isinstance(nic, dict):
                    pass
            # Disks
            disks = (props.get("storageProfile", {}) or vm.get("storageProfile", {})).get("dataDisks") or []
            managed_disks = [str(d.get("managedDisk", {}).get("id") or "")[:256] for d in disks[:5] if isinstance(d, dict)]
            # Security profile
            sec_profile = props.get("securityProfile") or vm.get("securityProfile") or {}
            uefi = sec_profile.get("uefiSettings") or {}
            # hardwareProfile
            hw = props.get("hardwareProfile") or vm.get("hardwareProfile") or {}
            resources.append(_resource("azure", "azure_vm", vm.get("id") or name, location or "eastus", subscription_id,
                                       name=name, extra={
                                           "resource_group": rg,
                                           "location": location,
                                           "vm_size": str(hw.get("vmSize") or "")[:64] or None,
                                           "os_type": str((props.get("storageProfile") or {}).get("osDisk", {}).get("osType") or vm.get("storageProfile", {}).get("osDisk", {}).get("osType") or "")[:20] or None,
                                           "network_interfaces": nic_ids,
                                           "public_ip": public_ip,
                                           "private_ip": private_ip,
                                           "managed_disks": managed_disks,
                                           "secure_boot": uefi.get("secureBootEnabled"),
                                           "vtpm_enabled": uefi.get("vTpmEnabled"),
                                           "identity": (props.get("identity") or vm.get("identity") or {}).get("type") if isinstance(props.get("identity") or vm.get("identity"), dict) else None,
                                       }))
    except Exception as exc:
        warning = _warning_for("azure_vm", exc)
    return resources, warning

def discover_azure_disks(client, subscription_id: str):
    resources, warning = [], None
    try:
        for disk in _paginate(client, "list_disks", "value", limit=50):
            name = disk.get("name")
            if not name:
                continue
            resources.append(_resource("azure", "azure_disk", disk.get("id") or name, disk.get("location") or "eastus", subscription_id,
                                       name=name, extra={
                                           "location": str(disk.get("location") or "")[:64] or None,
                                           "disk_size_gb": disk.get("diskSizeGb"),
                                           "encryption": disk.get("encryption", {}).get("type") if isinstance(disk.get("encryption"), dict) else disk.get("encryption"),
                                           "managed_by": str(disk.get("managedBy") or "")[:256] or None,
                                       }))
    except Exception as exc:
        warning = _warning_for("azure_disk", exc)
    return resources, warning

def discover_azure_vnets(client, subscription_id: str):
    resources, warning = [], None
    try:
        for vnet in _paginate(client, "list_virtual_networks", "value", limit=20):
            name = vnet.get("name")
            if not name:
                continue
            resources.append(_resource("azure", "azure_vnet", vnet.get("id") or name, vnet.get("location") or "eastus", subscription_id,
                                       name=name, extra={"location": str(vnet.get("location") or "")[:64] or None, "address_space": str((vnet.get("addressSpace", {}).get("addressPrefixes") or [""])[0])[:64] or None}))
    except Exception as exc:
        warning = _warning_for("azure_vnet", exc)
    return resources, warning

def discover_azure_subnets(client, subscription_id: str):
    resources, warning = [], None
    try:
        for subnet in _paginate(client, "list_subnets", "value", limit=50):
            name = subnet.get("name")
            if not name:
                continue
            resources.append(_resource("azure", "azure_subnet", subnet.get("id") or name, subnet.get("location") or "eastus", subscription_id,
                                       name=name, extra={"vnet": str(subnet.get("virtualNetwork") or "")[:256] or None, "address_prefix": str(subnet.get("addressPrefix") or "")[:64] or None, "nsg_id": str(subnet.get("networkSecurityGroup", {}).get("id") or "")[:256] or None}))
    except Exception as exc:
        warning = _warning_for("azure_subnet", exc)
    return resources, warning

def discover_azure_nsgs(client, subscription_id: str):
    resources, warning = [], None
    try:
        for nsg in _paginate(client, "list_network_security_groups", "value", limit=50):
            name = nsg.get("name")
            if not name:
                continue
            props_nsg = nsg.get("properties") or nsg
            rules = []
            for rule in (props_nsg.get("securityRules") or nsg.get("securityRules") or [])[:MAX_NSG_RULES]:
                if not isinstance(rule, dict):
                    continue
                props = rule.get("properties") or rule
                rules.append({
                    "name": str(rule.get("name") or props.get("name") or "")[:64] or None,
                    "direction": str(props.get("direction") or "")[:20] or None,
                    "access": str(props.get("access") or "")[:20] or None,
                    "protocol": str(props.get("protocol") or "")[:10] or None,
                    "source_prefix": str(props.get("sourceAddressPrefix") or props.get("sourceAddressPrefixes") or "")[:64] or None,
                    "source_port": str(props.get("sourcePortRange") or props.get("sourcePortRanges") or "")[:64] or None,
                    "dest_prefix": str(props.get("destinationAddressPrefix") or props.get("destinationAddressPrefixes") or "")[:64] or None,
                    "dest_port": str(props.get("destinationPortRange") or props.get("destinationPortRanges") or "")[:64] or None,
                    "priority": props.get("priority"),
                })
            resources.append(_resource("azure", "azure_nsg", nsg.get("id") or name, nsg.get("location") or "eastus", subscription_id,
                                       name=name, extra={"location": str(nsg.get("location") or "")[:64] or None, "rules": rules, "associated_subnets": [], "associated_nics": []}))
    except Exception as exc:
        warning = _warning_for("azure_nsg", exc)
    return resources, warning

def discover_azure_public_ips(client, subscription_id: str):
    resources, warning = [], None
    try:
        for pip in _paginate(client, "list_public_ip_addresses", "value", limit=50):
            name = pip.get("name")
            if not name:
                continue
            props = pip.get("properties") or {}
            resources.append(_resource("azure", "azure_public_ip", pip.get("id") or name, pip.get("location") or "eastus", subscription_id,
                                       name=name, extra={"location": str(pip.get("location") or "")[:64] or None, "ip_address": str(props.get("ipAddress") or "")[:64] or None, "allocation_method": str(props.get("publicIPAllocationMethod") or "")[:20] or None, "associated_nic": str(props.get("ipConfiguration", {}).get("id") or "")[:256] or None}))
    except Exception as exc:
        warning = _warning_for("azure_public_ip", exc)
    return resources, warning

def discover_azure_storage_accounts(client, subscription_id: str):
    resources, warning = [], None
    try:
        for account in _paginate(client, "list_storage_accounts", "value", limit=50):
            name = account.get("name")
            if not name:
                continue
            props = account.get("properties") or {}
            resources.append(_resource("azure", "azure_storage_account", account.get("id") or name, account.get("location") or "eastus", subscription_id,
                                       name=name, extra={
                                           "location": str(account.get("location") or "")[:64] or None,
                                           "kind": str(account.get("kind") or "")[:20] or None,
                                           "sku": str((account.get("sku", {}) or {}).get("name") or "")[:20] or None,
                                           "https_only": props.get("supportsHttpsTrafficOnly"),
                                           "minimum_tls": str(props.get("minimumTlsVersion") or "")[:10] or None,
                                           "public_network_access": str(props.get("publicNetworkAccess") or "")[:20] or None,
                                           "allow_blob_public_access": props.get("allowBlobPublicAccess"),
                                           "encryption": props.get("encryption", {}).get("keySource") if isinstance(props.get("encryption"), dict) else props.get("encryption"),
                                           "infrastructure_encryption": str((props.get("encryption", {}) or {}).get("requireInfrastructureEncryption") or "")[:10] or None if isinstance(props.get("encryption"), dict) else None,
                                       }))
    except Exception as exc:
        warning = _warning_for("azure_storage_account", exc)
    return resources, warning

def discover_azure_rbac(client, subscription_id: str):
    resources, warning = [], None
    try:
        for assignment in _paginate(client, "list_role_assignments", "value", limit=MAX_RBAC_ASSIGNMENTS):
            name = assignment.get("name") or assignment.get("id")
            if not name:
                continue
            props = assignment.get("properties") or {}
            resources.append(_resource("azure", "azure_rbac_assignment", assignment.get("id") or name, "global", subscription_id,
                                       name=name, extra={
                                           "role_definition_id": str(props.get("roleDefinitionId") or "")[:256] or None,
                                           "principal_id": str(props.get("principalId") or "")[:64] or None,
                                           "principal_type": str(props.get("principalType") or "")[:20] or None,
                                           "scope": str(props.get("scope") or "")[:256] or None,
                                           "role_name": str(props.get("roleDefinitionId", "").split("/")[-1])[:64] or None,
                                       }))
    except Exception as exc:
        warning = _warning_for("azure_rbac", exc)
    return resources, warning

AZURE_GLOBAL_DISCOVERERS = (
    ("subscription", discover_azure_subscription),
    ("resource_group", discover_azure_resource_groups),
    ("rbac", discover_azure_rbac),
)

AZURE_REGIONAL_DISCOVERERS = (
    ("vnet", discover_azure_vnets),
    ("subnet", discover_azure_subnets),
    ("nsg", discover_azure_nsgs),
    ("public_ip", discover_azure_public_ips),
    ("vm", discover_azure_vms),
    ("disk", discover_azure_disks),
    ("storage", discover_azure_storage_accounts),
)

AZURE_SERVICE_CLIENTS = {
    "subscription": "resource",
    "resource_group": "resource",
    "rbac": "authorization",
    "vnet": "network",
    "subnet": "network",
    "nsg": "network",
    "public_ip": "network",
    "vm": "compute",
    "disk": "compute",
    "storage": "storage",
}

def discover_azure_account(session_factory, subscription_id: str, regions: list[str], max_total: int = MAX_AZURE_RESOURCES) -> dict:
    all_resources: list[dict] = []
    warnings: list[dict] = []
    attempted = succeeded = failed = 0
    remaining = max(0, int(max_total or MAX_AZURE_RESOURCES))
    # Global
    attempted += 1
    try:
        global_res = []
        global_warn = []
        for key, disc in AZURE_GLOBAL_DISCOVERERS:
            if len(global_res) >= remaining:
                break
            try:
                client = session_factory(AZURE_SERVICE_CLIENTS[key], "global")
                found, warning = disc(client, subscription_id)
                global_res.extend(found[:remaining - len(global_res)])
                if warning:
                    global_warn.append(warning)
            except Exception as exc:
                global_warn.append(_warning_for(key, exc) or {"service": key, "reason": "service_error", "detail": sanitize_azure_error(exc)})
        all_resources.extend(global_res)
        warnings.extend(global_warn)
        succeeded += 1
        remaining = max(0, remaining - len(global_res))
    except Exception as exc:
        failed += 1
        warnings.append({"service": "global", "reason": "service_error", "detail": sanitize_azure_error(exc)})
    # Regional per location
    for region in (regions or ["eastus"])[:5]:
        attempted += 1
        try:
            regional_res = []
            regional_warn = []
            for key, disc in AZURE_REGIONAL_DISCOVERERS:
                if len(regional_res) >= remaining:
                    break
                try:
                    client = session_factory(AZURE_SERVICE_CLIENTS[key], region)
                    found, warning = disc(client, subscription_id)
                    # Filter by location if needed
                    regional_res.extend(found[:remaining - len(regional_res)])
                    if warning:
                        regional_warn.append(warning)
                except Exception as exc:
                    regional_warn.append(_warning_for(key, exc) or {"service": key, "reason": "service_error", "detail": sanitize_azure_error(exc)})
            all_resources.extend(regional_res)
            warnings.extend(regional_warn)
            succeeded += 1
            remaining = max(0, remaining - len(regional_res))
        except Exception as exc:
            failed += 1
            warnings.append({"service": "region", "region": region, "reason": "service_error", "detail": sanitize_azure_error(exc)})
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
    return {"status": status, "regions_attempted": attempted, "regions_succeeded": succeeded, "regions_failed": failed, "resources": all_resources, "warnings": warnings[:50], "resource_counts": counts}

def azure_canonical_value(resource: dict) -> str:
    arn = (resource.get("arn") or "").strip()
    if arn.startswith("azure:"):
        return arn[:1024]
    sub = str(resource.get("account_id") or "").strip()
    region = str(resource.get("region") or "global").strip().lower()
    rtype = str(resource.get("resource_type") or "unknown").strip().lower()
    rid = str(resource.get("resource_id") or "").strip()
    return f"cloud_resource:azure:{sub}:{region}:{rtype}:{rid}"[:1024]

def azure_to_asset_inputs(resources: list[dict], subscription_id: str, observed_at: str) -> list[dict]:
    assets: list[dict] = []
    seen: set[tuple[str, str]] = set()
    account_value = f"cloud_account:azure:{subscription_id}:global"
    assets.append({"type": "cloud_account", "value": account_value, "metadata": {"provider": "azure", "account_id": subscription_id, "region": "global", "sources": ["azure-discovery"], "observed_at": observed_at}})
    seen.add(("cloud_account", account_value))
    for resource in resources:
        value = azure_canonical_value(resource)
        key = ("cloud_resource", value)
        if key in seen or not value:
            continue
        seen.add(key)
        extra = _bounded_extra(resource.get("extra") if isinstance(resource.get("extra"), dict) else {})
        assets.append({"type": "cloud_resource", "value": value, "metadata": {"provider": "azure", "service": resource.get("service"), "resource_type": resource.get("resource_type"), "resource_id": str(resource.get("resource_id") or "")[:500], "arn": (resource.get("arn") or "")[:1024] or None, "region": resource.get("region"), "account_id": subscription_id, "name": (resource.get("name") or "")[:255] or None, "tags": _tags_as_dict(resource.get("tags")), "extra": extra, "sources": ["azure-discovery"], "observed_at": observed_at}})
    return assets

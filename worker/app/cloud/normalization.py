"""Cloud identity normalization — deterministic, provider-aware, project-scoped."""

import re
import hashlib

MAX_VALUE = 1024

def normalize_account_value(provider: str, account_id: str, region: str) -> str:
    provider = str(provider or "").strip().lower()
    account_id = str(account_id or "").strip()
    region = str(region or "global").strip().lower()
    # AWS account is 12 digits, GCP project is lower, Azure sub is UUID
    # Keep as is, just normalize case for region/provider, truncate
    value = f"cloud_account:{provider}:{account_id}:{region}"
    if len(value) > MAX_VALUE:
        h = hashlib.sha256(value.encode()).hexdigest()[:12]
        value = f"cloud_account:{provider}:{account_id[:100]}:{region}:{h}"
    return value[:MAX_VALUE]

def normalize_resource_value(provider: str, account_id: str, region: str, resource_type: str, resource_id: str) -> str:
    provider = str(provider or "").strip().lower()
    account_id = str(account_id or "").strip()
    region = str(region or "global").strip().lower()
    resource_type = str(resource_type or "").strip().lower()
    resource_id = str(resource_id or "").strip()
    # Resource_id is canonical identifier (ARN, selfLink, etc.) — keep as is but lower region/provider
    value = f"cloud_resource:{provider}:{account_id}:{region}:{resource_type}:{resource_id}"
    if len(value) > MAX_VALUE:
        h = hashlib.sha256(value.encode()).hexdigest()[:12]
        value = f"cloud_resource:{provider}:{account_id}:{region}:{resource_type}:{h}"
    return value[:MAX_VALUE]

def sanitize_cloud_metadata(metadata: dict) -> dict:
    """Remove secret-bearing keys from cloud metadata."""
    if not isinstance(metadata, dict):
        return {}
    cleaned = {}
    for k, v in metadata.items():
        low = str(k).lower()
        if any(s in low for s in ("secret", "token", "key", "password", "private", "credential")):
            continue
        if isinstance(v, str) and len(v) > 500:
            cleaned[k] = v[:500]
        else:
            cleaned[k] = v
    return cleaned

def validate_provider(provider: str) -> str:
    pid = str(provider or "").strip().lower()
    if pid not in ("aws", "gcp", "azure"):
        raise ValueError(f"Unsupported provider: {provider}")
    return pid

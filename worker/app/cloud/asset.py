"""Cloud asset helpers — convert CloudAccount/CloudResource to canonical Asset dicts."""

from typing import List, Dict
from .models import CloudAccount, CloudResource

def cloud_account_to_asset(account: CloudAccount) -> Dict:
    """Convert CloudAccount to Asset dict (cloud_account)."""
    return {
        "type": "cloud_account",
        "value": account.canonical_value(),
        "metadata": {
            "provider": account.provider,
            "region": account.region or "global",
            "display_name": (account.display_name or account.canonical_value())[:200],
            "account_id": (account.aws_account_id or account.gcp_project_id or account.azure_subscription_id or "")[:100],
            "project_id": account.project_id or "",
            "sources": ["cloud_discovery"],
            **{k: str(v)[:200] for k, v in (account.metadata or {}).items() if k not in ("secret", "token", "key", "password")},
        },
    }

def cloud_resource_to_asset(resource: CloudResource) -> Dict:
    """Convert CloudResource to Asset dict (cloud_resource)."""
    return resource.to_asset_dict()

def build_cloud_relationships(account: CloudAccount, resources: List[CloudResource]) -> List[Dict]:
    """Build deterministic cloud relationships: account contains resource, plus resource uses."""
    rels = []
    seen = set()
    acct_val = account.canonical_value()
    for res in resources:
        key = ("cloud_account", acct_val, "cloud_resource", res.canonical_value(), "contains")
        if key not in seen:
            seen.add(key)
            rels.append({
                "source_type": "cloud_account",
                "source_value": acct_val,
                "target_type": "cloud_resource",
                "target_value": res.canonical_value(),
                "relationship_type": "contains",
                "metadata": {"sources": ["cloud_discovery"]},
            })
    # Add deterministic resource-to-resource uses for first two
    if len(resources) >= 2:
        key = ("cloud_resource", resources[0].canonical_value(), "cloud_resource", resources[1].canonical_value(), "uses")
        if key not in seen:
            rels.append({
                "source_type": "cloud_resource",
                "source_value": resources[0].canonical_value(),
                "target_type": "cloud_resource",
                "target_value": resources[1].canonical_value(),
                "relationship_type": "uses",
                "metadata": {"sources": ["cloud_discovery"]},
            })
    return rels

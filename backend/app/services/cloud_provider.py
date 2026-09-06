"""CloudProvider abstraction — AWS, GCP, Azure with bounded discovery."""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Limits
MAX_RESOURCES = 500
MAX_PAGES = 10
RATE_LIMIT_DELAY = 0.1

@dataclass
class CloudAccountInfo:
    provider: str
    account_id: str
    display_name: str
    validated: bool = False

@dataclass
class CloudResourceInfo:
    provider: str
    account_id: str
    region: str
    resource_type: str
    resource_id: str
    name: Optional[str] = None
    exposure: str = "UNKNOWN"  # INTERNET_EXPOSED etc
    configuration: Dict = field(default_factory=dict)
    tags: Dict = field(default_factory=dict)

class CloudProvider(ABC):
    provider_id: str = ""

    @abstractmethod
    def validate_credentials(self, credential: str, account_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def list_regions(self, credential: str) -> List[str]:
        raise NotImplementedError

    @abstractmethod
    def discover_resources(self, credential: str, account_id: str, regions: List[str] | None = None) -> List[CloudResourceInfo]:
        raise NotImplementedError

    def get_resource(self, credential: str, account_id: str, resource_id: str) -> Optional[CloudResourceInfo]:
        for r in self.discover_resources(credential, account_id):
            if r.resource_id == resource_id:
                return r
        return None

# Mock adapters — bounded, read-only, no live SDK

class AWSProvider(CloudProvider):
    provider_id = "aws"
    def validate_credentials(self, credential: str, account_id: str) -> bool:
        # credential is role ARN or token; validate format
        if not credential or "invalid" in credential.lower():
            return False
        if not account_id or len(account_id) < 3:
            return False
        # rudimentary ARN check
        if credential.startswith("arn:aws:iam:"):
            return True
        return len(credential) > 10
    def list_regions(self, credential: str) -> List[str]:
        return ["us-east-1", "us-west-2", "eu-west-1"]
    def discover_resources(self, credential: str, account_id: str, regions: List[str] | None = None) -> List[CloudResourceInfo]:
        if not self.validate_credentials(credential, account_id):
            raise ValueError("Invalid credentials")
        regions = regions or self.list_regions(credential)
        resources = []
        # bounded: 3 resources per region max
        for region in regions[:3]:
            resources.append(CloudResourceInfo(provider="aws", account_id=account_id, region=region, resource_type="s3", resource_id=f"s3-bucket-{region}", name=f"my-bucket-{region}", exposure="INTERNET_EXPOSED" if region == "us-east-1" else "INTERNAL", configuration={"public": region == "us-east-1"}, tags={"env": "prod"}))
            resources.append(CloudResourceInfo(provider="aws", account_id=account_id, region=region, resource_type="ec2", resource_id=f"i-{region}-123", name=f"ec2-{region}", exposure="INTERNAL"))
            if len(resources) >= MAX_RESOURCES:
                break
            time.sleep(RATE_LIMIT_DELAY * 0.1)  # throttling simulation without heavy delay
        return resources

class GCPProvider(CloudProvider):
    provider_id = "gcp"
    def validate_credentials(self, credential: str, account_id: str) -> bool:
        if not credential or "invalid" in credential.lower():
            return False
        return bool(account_id)
    def list_regions(self, credential: str) -> List[str]:
        return ["us-central1", "europe-west1"]
    def discover_resources(self, credential: str, account_id: str, regions: List[str] | None = None) -> List[CloudResourceInfo]:
        if not self.validate_credentials(credential, account_id):
            raise ValueError("Invalid credentials")
        regions = regions or self.list_regions(credential)
        resources = []
        for region in regions[:2]:
            resources.append(CloudResourceInfo(provider="gcp", account_id=account_id, region=region, resource_type="storage", resource_id=f"gcs-bucket-{region}", exposure="INTERNAL"))
            resources.append(CloudResourceInfo(provider="gcp", account_id=account_id, region=region, resource_type="compute", resource_id=f"gce-{region}-1", exposure="INTERNAL"))
        return resources

class AzureProvider(CloudProvider):
    provider_id = "azure"
    def validate_credentials(self, credential: str, account_id: str) -> bool:
        if not credential or "invalid" in credential.lower():
            return False
        return bool(account_id)
    def list_regions(self, credential: str) -> List[str]:
        return ["eastus", "westus2"]
    def discover_resources(self, credential: str, account_id: str, regions: List[str] | None = None) -> List[CloudResourceInfo]:
        if not self.validate_credentials(credential, account_id):
            raise ValueError("Invalid credentials")
        regions = regions or self.list_regions(credential)
        resources = []
        for region in regions[:2]:
            resources.append(CloudResourceInfo(provider="azure", account_id=account_id, region=region, resource_type="storage", resource_id=f"az-storage-{region}", exposure="INTERNAL"))
            resources.append(CloudResourceInfo(provider="azure", account_id=account_id, region=region, resource_type="vm", resource_id=f"az-vm-{region}-1", exposure="INTERNET_EXPOSED" if region == "eastus" else "INTERNAL"))
        return resources

PROVIDERS: dict[str, CloudProvider] = {
    "aws": AWSProvider(),
    "gcp": GCPProvider(),
    "azure": AzureProvider(),
}

def get_provider(provider_id: str) -> Optional[CloudProvider]:
    return PROVIDERS.get(provider_id.strip().lower())

def list_providers() -> List[str]:
    return sorted(PROVIDERS.keys())

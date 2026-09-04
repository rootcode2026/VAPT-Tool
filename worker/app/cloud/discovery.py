"""Cloud discovery abstraction — provider-neutral, mock for tests, no network."""

import time
from typing import Dict, List
from .models import CloudAccount, CloudResource, CloudDiscoveryResult
from .provider import get_provider


class CloudDiscoveryAdapter:
    """Abstract adapter — future providers implement discover()."""

    provider_id: str = ""

    def discover(self, account: CloudAccount) -> CloudDiscoveryResult:
        raise NotImplementedError

    def capabilities(self) -> Dict:
        provider = get_provider(self.provider_id)
        if provider:
            return provider.capabilities.to_dict()
        return {}


class MockCloudDiscoveryAdapter(CloudDiscoveryAdapter):
    """Safe mock adapter for tests — deterministic, no network, no credentials."""

    provider_id = "mock"

    def __init__(self, provider_id: str = "aws", resource_count: int = 3):
        self.provider_id = provider_id
        self.resource_count = resource_count

    def discover(self, account: CloudAccount) -> CloudDiscoveryResult:
        start = time.monotonic()
        provider = str(account.provider or self.provider_id).strip().lower()
        # Validate provider
        from .provider import is_supported_provider
        if not is_supported_provider(provider):
            return CloudDiscoveryResult(
                provider=provider,
                account=account,
                resources=[],
                relationships=[],
                duration_ms=int((time.monotonic() - start) * 1000),
                status="failed",
                error_category="unsupported_provider",
                error_message=f"Unsupported provider: {provider}",
            )

        # Deterministic resources based on account + provider
        resources = []
        for i in range(self.resource_count):
            rid = f"{provider}-resource-{i+1}"
            # Use account's region or default
            region = account.region or "us-east-1"
            # Account id for identity
            acct_id = account.aws_account_id or account.gcp_project_id or account.azure_subscription_id or f"account-{i}"
            resources.append(
                CloudResource(
                    provider=provider,
                    resource_type="ec2" if provider == "aws" else "compute" if provider == "gcp" else "vm",
                    resource_id=rid,
                    region=region,
                    service="ec2" if provider == "aws" else "compute",
                    name=f"test-resource-{i+1}",
                    account_id=acct_id,
                    tags={"env": "test", "index": str(i)},
                    metadata={"discovery_source": "mock", "mock": True},
                    project_id=account.project_id,
                )
            )

        # Deterministic relationships: account contains each resource
        relationships = []
        for res in resources:
            relationships.append({
                "source_type": "cloud_account",
                "source_value": account.canonical_value(),
                "target_type": "cloud_resource",
                "target_value": res.canonical_value(),
                "relationship_type": "contains",
                "metadata": {"sources": ["mock_discovery"]},
            })

        # Add a deterministic resource-to-resource relationship (first contains second if enough resources)
        if len(resources) >= 2:
            relationships.append({
                "source_type": "cloud_resource",
                "source_value": resources[0].canonical_value(),
                "target_type": "cloud_resource",
                "target_value": resources[1].canonical_value(),
                "relationship_type": "uses",
                "metadata": {"sources": ["mock_discovery"]},
            })

        duration_ms = int((time.monotonic() - start) * 1000)
        return CloudDiscoveryResult(
            provider=provider,
            account=account,
            resources=resources,
            relationships=relationships,
            duration_ms=duration_ms,
            status="completed",
        )


# Provider-specific mock adapters (thin wrappers for registry clarity)
class MockAWSAdapter(MockCloudDiscoveryAdapter):
    def __init__(self, resource_count: int = 3):
        super().__init__(provider_id="aws", resource_count=resource_count)
        self.provider_id = "aws"

class MockGCPAdapter(MockCloudDiscoveryAdapter):
    def __init__(self, resource_count: int = 3):
        super().__init__(provider_id="gcp", resource_count=resource_count)
        self.provider_id = "gcp"

class MockAzureAdapter(MockCloudDiscoveryAdapter):
    def __init__(self, resource_count: int = 3):
        super().__init__(provider_id="azure", resource_count=resource_count)
        self.provider_id = "azure"

"""Cloud provider abstraction — registry and capability model."""

from dataclasses import dataclass, field
from typing import Dict, List, Set


# Provider identifiers — canonical, lowercase
SUPPORTED_PROVIDERS = frozenset({"aws", "gcp", "azure"})


@dataclass
class CloudProviderCapabilities:
    resource_discovery: bool = False
    regions: bool = False
    identity_discovery: bool = False
    network_discovery: bool = False
    storage_discovery: bool = False
    container_discovery: bool = False
    serverless_discovery: bool = False
    iam_discovery: bool = False

    def to_dict(self) -> Dict[str, bool]:
        return {
            "resource_discovery": self.resource_discovery,
            "regions": self.regions,
            "identity_discovery": self.identity_discovery,
            "network_discovery": self.network_discovery,
            "storage_discovery": self.storage_discovery,
            "container_discovery": self.container_discovery,
            "serverless_discovery": self.serverless_discovery,
            "iam_discovery": self.iam_discovery,
        }


@dataclass
class CloudProvider:
    """Provider-neutral descriptor — no SDK, no network, no credentials."""

    provider_id: str  # aws, gcp, azure
    display_name: str
    description: str
    capabilities: CloudProviderCapabilities = field(default_factory=CloudProviderCapabilities)
    regions: List[str] = field(default_factory=list)  # capability declaration only, not full DB
    supported_services: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "provider_id": self.provider_id,
            "display_name": self.display_name,
            "description": self.description,
            "capabilities": self.capabilities.to_dict(),
            "regions": sorted(self.regions)[:50],
            "supported_services": sorted(self.supported_services)[:50],
        }


# Registry — deterministic, no network
_PROVIDER_REGISTRY: Dict[str, CloudProvider] = {}


def _init_default_providers():
    # AWS
    _PROVIDER_REGISTRY["aws"] = CloudProvider(
        provider_id="aws",
        display_name="Amazon Web Services",
        description="Provider-neutral AWS account/region/resource model",
        capabilities=CloudProviderCapabilities(
            resource_discovery=True,
            regions=True,
            identity_discovery=True,
            network_discovery=True,
            storage_discovery=True,
            container_discovery=True,
            serverless_discovery=True,
            iam_discovery=True,
        ),
        regions=["us-east-1", "us-west-2", "eu-west-1", "ap-south-1"],  # sample, not exhaustive
        supported_services=["ec2", "s3", "rds", "lambda", "eks", "iam"],
    )
    # GCP
    _PROVIDER_REGISTRY["gcp"] = CloudProvider(
        provider_id="gcp",
        display_name="Google Cloud Platform",
        description="Provider-neutral GCP project/region/resource model",
        capabilities=CloudProviderCapabilities(
            resource_discovery=True,
            regions=True,
            identity_discovery=True,
            network_discovery=True,
            storage_discovery=True,
            container_discovery=True,
            serverless_discovery=True,
            iam_discovery=True,
        ),
        regions=["us-central1", "europe-west1", "asia-east1"],
        supported_services=["compute", "storage", "sql", "functions", "gke", "iam"],
    )
    # Azure
    _PROVIDER_REGISTRY["azure"] = CloudProvider(
        provider_id="azure",
        display_name="Microsoft Azure",
        description="Provider-neutral Azure subscription/resource-group/region model",
        capabilities=CloudProviderCapabilities(
            resource_discovery=True,
            regions=True,
            identity_discovery=True,
            network_discovery=True,
            storage_discovery=True,
            container_discovery=True,
            serverless_discovery=True,
            iam_discovery=True,
        ),
        regions=["eastus", "westus2", "westeurope", "southeastasia"],
        supported_services=["vm", "storage", "sql", "functions", "aks", "iam"],
    )


_init_default_providers()


def register_provider(provider: CloudProvider) -> None:
    pid = str(provider.provider_id or "").strip().lower()
    if not pid:
        raise ValueError("provider_id required")
    if pid not in SUPPORTED_PROVIDERS and pid not in _PROVIDER_REGISTRY:
        # Allow custom but warn — for P12.1 only allow aws/gcp/azure
        raise ValueError(f"Unsupported provider: {pid}")
    _PROVIDER_REGISTRY[pid] = provider


def get_provider(provider_id: str) -> CloudProvider | None:
    pid = str(provider_id or "").strip().lower()
    return _PROVIDER_REGISTRY.get(pid)


def list_providers() -> List[CloudProvider]:
    return sorted(_PROVIDER_REGISTRY.values(), key=lambda p: p.provider_id)


def is_supported_provider(provider_id: str) -> bool:
    return str(provider_id or "").strip().lower() in SUPPORTED_PROVIDERS

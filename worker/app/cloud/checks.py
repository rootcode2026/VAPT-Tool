"""Cloud security check abstraction — provider-neutral, future extensible."""

from typing import List
from .models import CloudSecurityCheck, CloudCheckResult, CloudResource

# Minimal safe checks for foundation — not hundreds, just architecture
DEFAULT_CHECKS = [
    CloudSecurityCheck(
        check_id="CLOUD-001",
        title="Cloud resource should have tags",
        description="Resources should be tagged for ownership and environment",
        provider="aws",
        resource_type="ec2",
        severity="low",
        remediation="Add tags owner and env",
        references=["https://docs.aws.amazon.com/tagging"],
    ),
    CloudSecurityCheck(
        check_id="CLOUD-002",
        title="Storage should not be publicly accessible",
        description="Storage resources should not allow public read",
        provider="aws",
        resource_type="s3",
        severity="high",
        remediation="Enable block public access",
        references=["https://docs.aws.amazon.com/s3"],
    ),
    CloudSecurityCheck(
        check_id="CLOUD-003",
        title="GCP resource should be in allowed region",
        description="Resources should be in approved regions",
        provider="gcp",
        resource_type="compute",
        severity="medium",
        remediation="Move to allowed region",
        references=["https://cloud.google.com/compute"],
    ),
]


def get_checks_for_provider(provider: str) -> List[CloudSecurityCheck]:
    provider = str(provider or "").strip().lower()
    return [c for c in DEFAULT_CHECKS if c.provider == provider]


def run_checks_for_resource(resource: CloudResource, checks: List[CloudSecurityCheck] = None) -> List[CloudCheckResult]:
    """Run checks deterministically — for P12.1, synthetic: one check per resource type match."""
    if checks is None:
        checks = get_checks_for_provider(resource.provider)
    results = []
    for check in checks:
        if check.resource_type.lower() == str(resource.resource_type or "").lower():
            # Deterministic: fail first resource, pass second, etc. For mock, always fail to produce finding
            # For foundation, we produce a synthetic finding for every matching resource
            results.append(
                CloudCheckResult(
                    check=check,
                    resource=resource,
                    passed=False,
                    evidence=f"Resource {resource.resource_id} failed check {check.check_id}",
                    metadata={"mock": True, "resource_id": resource.resource_id},
                )
            )
    return results

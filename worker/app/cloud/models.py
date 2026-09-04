"""Cloud models — provider-neutral, project-scoped, no credentials."""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import time
import hashlib

# Safe defaults
MAX_RESOURCE_ID_LENGTH = 1024
MAX_TAG_KEYS = 20


@dataclass
class CloudRegion:
    provider: str
    region: str
    zone: Optional[str] = None  # for GCP zone

    def to_dict(self) -> Dict:
        d = {"provider": self.provider, "region": self.region}
        if self.zone:
            d["zone"] = self.zone
        return d


@dataclass
class CloudAccount:
    """Normalized cloud account/project/subscription — provider-neutral.

    Never stores credentials. Credential reference is external.
    """
    provider: str  # aws, gcp, azure
    # Provider-specific identity — only one will be set, others None
    aws_account_id: Optional[str] = None  # 12-digit
    gcp_project_id: Optional[str] = None
    azure_subscription_id: Optional[str] = None
    azure_resource_group: Optional[str] = None
    region: Optional[str] = None
    # Common
    display_name: Optional[str] = None
    credential_reference: Optional[str] = None  # opaque reference, never plaintext
    metadata: Dict[str, Any] = field(default_factory=dict)
    project_id: Optional[str] = None  # VAPT project_id for isolation

    def canonical_value(self) -> str:
        """Deterministic identity for asset value: provider:account:region"""
        provider = str(self.provider or "").strip().lower()
        if provider == "aws":
            acct = str(self.aws_account_id or "").strip()
            region = str(self.region or "global").strip().lower()
            return f"cloud_account:aws:{acct}:{region}"[:MAX_RESOURCE_ID_LENGTH]
        elif provider == "gcp":
            proj = str(self.gcp_project_id or "").strip()
            region = str(self.region or "global").strip().lower()
            return f"cloud_account:gcp:{proj}:{region}"[:MAX_RESOURCE_ID_LENGTH]
        elif provider == "azure":
            sub = str(self.azure_subscription_id or "").strip()
            region = str(self.region or "global").strip().lower()
            # Include resource group if present for more specificity, but keep identity stable
            return f"cloud_account:azure:{sub}:{region}"[:MAX_RESOURCE_ID_LENGTH]
        else:
            # Generic fallback
            ident = str(self.aws_account_id or self.gcp_project_id or self.azure_subscription_id or "unknown").strip()
            region = str(self.region or "global").strip().lower()
            return f"cloud_account:{provider}:{ident}:{region}"[:MAX_RESOURCE_ID_LENGTH]

    def to_dict(self) -> Dict:
        d = {
            "provider": self.provider,
            "region": self.region,
            "display_name": self.display_name,
            "credential_reference": self.credential_reference,
            "project_id": self.project_id,
            "metadata": dict(self.metadata),
        }
        if self.aws_account_id:
            d["aws_account_id"] = self.aws_account_id
        if self.gcp_project_id:
            d["gcp_project_id"] = self.gcp_project_id
        if self.azure_subscription_id:
            d["azure_subscription_id"] = self.azure_subscription_id
        if self.azure_resource_group:
            d["azure_resource_group"] = self.azure_resource_group
        return d

    def to_safe_dict(self) -> Dict:
        """Sanitized for API/logs — no credentials."""
        d = self.to_dict()
        # Never expose credential_reference value beyond reference id
        # Ensure no secret leakage
        for k in list(d.keys()):
            low = k.lower()
            if any(s in low for s in ("secret", "token", "key", "password", "credential")):
                # Keep reference but truncate, never raw
                if d[k]:
                    d[k] = str(d[k])[:100]
        # Remove metadata secrets
        meta = d.get("metadata", {})
        if isinstance(meta, dict):
            for mk in list(meta.keys()):
                if any(s in mk.lower() for s in ("secret", "token", "password", "key")):
                    del meta[mk]
        return d


@dataclass
class CloudResource:
    """Provider-neutral cloud resource — no secrets."""
    provider: str
    resource_type: str  # e.g., ec2, s3, sql, vm, storage
    resource_id: str  # canonical identifier (ARN, selfLink, resourceId etc.)
    region: Optional[str] = None
    service: Optional[str] = None
    name: Optional[str] = None
    account_id: Optional[str] = None  # AWS account or GCP project or Azure subscription, for identity
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    project_id: Optional[str] = None

    def canonical_value(self) -> str:
        """Deterministic identity: provider:account:region:resource_type:resource_id"""
        provider = str(self.provider or "").strip().lower()
        acct = str(self.account_id or "").strip()
        region = str(self.region or "global").strip().lower()
        rtype = str(self.resource_type or "").strip().lower()
        rid = str(self.resource_id or "").strip()
        # Normalize: lower, truncate, hash if too long
        value = f"cloud_resource:{provider}:{acct}:{region}:{rtype}:{rid}"
        if len(value) > MAX_RESOURCE_ID_LENGTH:
            h = hashlib.sha256(value.encode()).hexdigest()[:12]
            value = f"cloud_resource:{provider}:{acct}:{region}:{rtype}:{h}"
        return value[:MAX_RESOURCE_ID_LENGTH]

    def to_dict(self) -> Dict:
        d = {
            "provider": self.provider,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "region": self.region,
            "service": self.service,
            "name": self.name,
            "account_id": self.account_id,
            "tags": dict(self.tags),
            "metadata": dict(self.metadata),
            "project_id": self.project_id,
        }
        return d

    def to_safe_dict(self) -> Dict:
        d = self.to_dict()
        # Sanitize tags/metadata
        for k in list(d.get("tags", {}).keys()):
            if any(s in k.lower() for s in ("secret", "token", "password")):
                d["tags"].pop(k, None)
        meta = d.get("metadata", {})
        if isinstance(meta, dict):
            for mk in list(meta.keys()):
                if any(s in mk.lower() for s in ("secret", "token", "password", "key", "private")):
                    del meta[mk]
        return d

    def to_asset_dict(self) -> Dict:
        """Convert to canonical Asset dict for persistence."""
        return {
            "type": "cloud_resource",
            "value": self.canonical_value(),
            "metadata": {
                "provider": self.provider,
                "resource_type": self.resource_type,
                "resource_id": self.resource_id[:500],
                "region": self.region or "global",
                "service": (self.service or self.resource_type)[:100],
                "name": (self.name or self.resource_id)[:200],
                "account_id": (self.account_id or "")[:100],
                "tags": {k: v[:200] for k, v in list(self.tags.items())[:MAX_TAG_KEYS]},
                "project_id": self.project_id,
                "sources": ["cloud_discovery"],
            },
        }


@dataclass
class CloudDiscoveryResult:
    """Result of discovery — structured resources and relationships."""

    provider: str
    account: CloudAccount
    resources: List[CloudResource] = field(default_factory=list)
    relationships: List[Dict] = field(default_factory=list)  # AssetRelationship dicts
    duration_ms: int = 0
    status: str = "completed"  # completed, failed, partial
    error_category: Optional[str] = None
    error_message: Optional[str] = None
    timestamp: float = field(default_factory=lambda: time.time())

    def to_safe_dict(self) -> Dict:
        return {
            "provider": self.provider,
            "account": self.account.to_safe_dict(),
            "resource_count": len(self.resources),
            "relationship_count": len(self.relationships),
            "duration_ms": self.duration_ms,
            "status": self.status,
            "error_category": self.error_category,
            "error_message": (self.error_message or "")[:500] if self.error_message else None,
        }


@dataclass
class CloudSecurityCheck:
    """Provider-neutral security check definition."""

    check_id: str
    title: str
    description: str
    provider: str
    resource_type: str
    severity: str  # critical, high, medium, low, info
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "provider": self.provider,
            "resource_type": self.resource_type,
            "severity": self.severity,
            "remediation": self.remediation,
            "references": list(self.references)[:10],
            "metadata": dict(self.metadata),
        }


@dataclass
class CloudCheckResult:
    """Result of a security check against a resource."""

    check: CloudSecurityCheck
    resource: CloudResource
    passed: bool
    evidence: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_finding_dict(self) -> Dict:
        """Convert to standardized finding for FindingEngine."""
        severity = str(self.check.severity or "medium").lower()
        if severity not in ("critical", "high", "medium", "low", "info"):
            severity = "medium"
        return {
            "scanner": "cloud",
            "title": f"{self.check.check_id}: {self.check.title}",
            "description": self.check.description,
            "severity": severity,
            "score": None,
            "status": "open",
            "evidence": self.evidence[:500] if self.evidence else self.check.title[:500],
            "remediation": self.check.remediation[:2000] if self.check.remediation else "",
            "cve": None,
            "cwe": None,
            "metadata": {
                "check_id": self.check.check_id,
                "rule_id": self.check.check_id,
                "provider": self.check.provider,
                "resource_type": self.check.resource_type,
                "resource_id": self.resource.resource_id[:500],
                "region": self.resource.region or "global",
                "account_id": self.resource.account_id or "",
                "evidence": self.evidence[:500] if self.evidence else "",
                "execution_engine": "cloud_check",
                "execution_mode": "mock" if self.metadata.get("mock") else "discovery",
                **{k: str(v)[:200] for k, v in self.metadata.items() if k not in ("mock",)},
            },
            "rule_id": self.check.check_id,
        }

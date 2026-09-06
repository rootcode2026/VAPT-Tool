from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field


class AssetRelationshipResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: str
    extra_data: dict[str, Any] = Field(default_factory=dict, exclude=True)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @computed_field
    @property
    def metadata(self) -> dict[str, Any]:
        return self.extra_data or {}


class AssetSecuritySummary(BaseModel):
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    highest_severity: str | None = None
    highest_score: int | None = None
    has_findings: bool = False
    has_critical: bool = False
    has_high: bool = False
    externally_exposed: bool = False
    recently_changed: bool = False


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    asset_type: str
    value: str
    status: str = "active"
    criticality: str = "unknown"
    owner_user_id: str | None = None
    first_seen_scan_id: str | None = None
    last_seen_scan_id: str | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    extra_data: dict[str, Any] = Field(default_factory=dict, exclude=True)
    created_at: datetime | None = None
    updated_at: datetime | None = None

    @computed_field
    @property
    def metadata(self) -> dict[str, Any]:
        return self.extra_data or {}


class AssetNeighborResponse(BaseModel):
    direction: str
    relationship_type: str
    relationship_id: str
    asset: AssetResponse
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_asset_id: str | None = None
    target_asset_id: str | None = None
    source_asset: AssetResponse | None = None
    target_asset: AssetResponse | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class AssetClassifications(BaseModel):
    """
    D2 — Attack Surface Classifications (deterministic, derived).

    Semantics (when evidence insufficient → false, never silently true):
    - internet_facing: true only if public IP or URL/domain resolves_to public IP via persisted relationship; private/loopback/link-local → false
    - externally_resolvable: true if asset has outgoing resolves_to/points_to relationship (persisted)
    - web_application: true if asset_type in {url,web_site,web_host} or serves technology / observed_on URL
    - exposed_service: true if asset participates in exposes/runs graph (IP→port→service)
    - technology_bearing: true if asset serves/uses technology (url serves nginx)
    - vulnerable: true if findings exist (reuse D1 security_summary)
    - recently_changed: true if timestamps or AssetChangeEvent within 7 days (reuse Stage B)
    - potentially_sensitive: true only if value token exactly matches conservative keywords (admin, login, etc.); generic domains false
    """
    internet_facing: bool = Field(default=False, description="Public internet reachable")
    externally_resolvable: bool = Field(default=False, description="Has resolves_to/points_to relationship")
    web_application: bool = Field(default=False, description="URL/web_site/web_host or serves/observed_on web evidence")
    exposed_service: bool = Field(default=False, description="Participates in exposes/runs graph")
    technology_bearing: bool = Field(default=False, description="Serves/uses technology")
    vulnerable: bool = Field(default=False, description="Has findings")
    recently_changed: bool = Field(default=False, description="Changed within 7 days (Stage B)")
    potentially_sensitive: bool = Field(default=False, description="Value token matches sensitive keywords")


class FindingSignal(BaseModel):
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    highest_severity: str | None = None
    highest_score: int | None = None


class ExposureSignal(BaseModel):
    internet_facing: bool = False
    externally_resolvable: bool = False
    web_application: bool = False
    exposed_service: bool = False


class TechnologySignal(BaseModel):
    technology_bearing: bool = False
    technology_count: int = 0


class ChangeSignal(BaseModel):
    recently_changed: bool = False
    recent_change_count: int = 0


class SensitivitySignal(BaseModel):
    potentially_sensitive: bool = False


class LifecycleSignal(BaseModel):
    status: str = "active"


class SecurityPostureFlags(BaseModel):
    vulnerable: bool = False
    critical_exposure: bool = False
    exposed_vulnerable: bool = False
    sensitive_exposed: bool = False
    changed_and_vulnerable: bool = False


class AssetSecuritySignals(BaseModel):
    finding_signal: FindingSignal = Field(default_factory=FindingSignal)
    exposure_signal: ExposureSignal = Field(default_factory=ExposureSignal)
    technology_signal: TechnologySignal = Field(default_factory=TechnologySignal)
    change_signal: ChangeSignal = Field(default_factory=ChangeSignal)
    sensitivity_signal: SensitivitySignal = Field(default_factory=SensitivitySignal)
    lifecycle_signal: LifecycleSignal = Field(default_factory=LifecycleSignal)
    posture: SecurityPostureFlags = Field(default_factory=SecurityPostureFlags)


class ProjectSecuritySummary(BaseModel):
    total_assets: int = 0
    internet_facing_assets: int = 0
    web_applications: int = 0
    exposed_services: int = 0
    vulnerable_assets: int = 0
    critical_assets: int = 0
    sensitive_assets: int = 0
    recently_changed_assets: int = 0
    stale_assets: int = 0
    inactive_assets: int = 0


class ProjectSecurityIntelligenceSummary(BaseModel):
    total_assets: int = 0
    internet_facing_assets: int = 0
    externally_resolvable_assets: int = 0
    web_application_assets: int = 0
    exposed_service_assets: int = 0
    vulnerable_assets: int = 0
    critical_assets: int = 0
    high_assets: int = 0
    medium_assets: int = 0
    low_assets: int = 0
    technology_bearing_assets: int = 0
    sensitive_assets: int = 0
    recently_changed_assets: int = 0
    stale_assets: int = 0
    inactive_assets: int = 0
    critical_exposure_assets: int = 0
    exposed_vulnerable_assets: int = 0
    sensitive_exposed_assets: int = 0
    changed_vulnerable_assets: int = 0
    attack_path_count: int = 0
    attack_paths_truncated: bool = False
    highest_contextual_priority: str | None = None
    # Backward-compat aliases for existing /summary clients
    web_applications: int = 0
    exposed_services: int = 0


class ExposureContext(BaseModel):
    internet_facing: bool = False
    externally_resolvable: bool = False
    web_application: bool = False
    exposed_service: bool = False


class VulnerabilityContext(BaseModel):
    vulnerable: bool = False
    critical_findings: int = 0
    high_findings: int = 0
    highest_severity: str | None = None
    highest_score: int | None = None


class ChangeContext(BaseModel):
    recently_changed: bool = False
    recent_change_count: int = 0


class SensitivityContext(BaseModel):
    potentially_sensitive: bool = False


class TechnologyContext(BaseModel):
    technology_bearing: bool = False
    technology_count: int = 0


class LifecycleContext(BaseModel):
    status: str = "active"


class ContextualRiskContext(BaseModel):
    exposure_context: ExposureContext = Field(default_factory=ExposureContext)
    vulnerability_context: VulnerabilityContext = Field(default_factory=VulnerabilityContext)
    change_context: ChangeContext = Field(default_factory=ChangeContext)
    sensitivity_context: SensitivityContext = Field(default_factory=SensitivityContext)
    technology_context: TechnologyContext = Field(default_factory=TechnologyContext)
    lifecycle_context: LifecycleContext = Field(default_factory=LifecycleContext)


class RiskFactor(BaseModel):
    code: str
    severity: str
    description: str


class ContextualRisk(BaseModel):
    priority: str = Field(default="informational", description="critical|high|medium|low|informational")
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    explanation: str = Field(default="No significant contextual risk signals.")
    context: ContextualRiskContext = Field(default_factory=ContextualRiskContext)


class AttackPathRelationship(BaseModel):
    id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AttackPathSecurityContext(BaseModel):
    entry_internet_facing: bool = False
    entry_asset_type: str = "unknown"
    target_vulnerable: bool = False
    target_highest_severity: str | None = None
    target_highest_score: int | float | None = None
    target_contextual_priority: str = "informational"
    target_recently_changed: bool = False
    target_potentially_sensitive: bool = False


class AttackPathFlags(BaseModel):
    internet_exposed: bool = False
    vulnerable_target: bool = False
    critical_target: bool = False
    high_target: bool = False
    sensitive_target: bool = False
    recently_changed_target: bool = False


class AttackPathEvidence(BaseModel):
    entry_asset_id: str = ""
    target_asset_id: str = ""
    relationship_count: int = 0
    asset_count: int = 0
    relationship_types: list[str] = Field(default_factory=list)


class AttackPath(BaseModel):
    path_id: str
    project_id: str
    entry_asset_id: str
    target_asset_id: str
    asset_ids: list[str]
    relationships: list[AttackPathRelationship]
    length: int
    entry_type: str = "internet_facing"
    target_type: str = "vulnerable"
    priority: str
    confidence: str = "observed"
    explanation: str
    target_contextual_priority: str | None = None
    target_risk_factors: list[RiskFactor] = Field(default_factory=list)
    # D6.1 enrichment — additive, deterministic, no new DB queries
    security_context: AttackPathSecurityContext = Field(default_factory=AttackPathSecurityContext)
    flags: AttackPathFlags = Field(default_factory=AttackPathFlags)
    evidence: AttackPathEvidence = Field(default_factory=AttackPathEvidence)


class AttackPathsResponse(BaseModel):
    paths: list[AttackPath] = Field(default_factory=list)
    total: int = 0
    truncated: bool = False


class AssetDetailResponse(AssetResponse):
    relationships: list[AssetNeighborResponse] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    security_summary: AssetSecuritySummary = Field(default_factory=AssetSecuritySummary)
    classifications: AssetClassifications = Field(default_factory=AssetClassifications)
    security_signals: AssetSecuritySignals = Field(default_factory=AssetSecuritySignals)
    contextual_risk: ContextualRisk = Field(default_factory=ContextualRisk)

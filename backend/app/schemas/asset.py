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


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    asset_type: str
    value: str
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


class AssetDetailResponse(AssetResponse):
    relationships: list[AssetNeighborResponse] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)

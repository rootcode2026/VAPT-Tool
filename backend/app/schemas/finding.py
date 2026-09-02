from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    target_id: str
    scanner: str
    title: str
    description: str | None = None
    severity: str
    score: int | None = None
    status: str
    evidence: str | None = None
    remediation: str | None = None
    cve: str | None = None
    cwe: str | None = None
    asset_id: str | None = None
    extra_data: dict[str, Any] = Field(
        default_factory=dict,
        exclude=True,
    )

    @computed_field
    @property
    def metadata(self) -> dict[str, Any]:
        return self.extra_data or {}

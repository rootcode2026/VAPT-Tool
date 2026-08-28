from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    target_id: str = Field(min_length=1)
    profile: str = Field(min_length=1, max_length=50)


class ScanResponse(BaseModel):
    id: str
    target_id: str
    profile: str
    status: str
    phase: str

    risk_score: int | None = None
    risk_grade: str | None = None
    risk_level: str | None = None

    class Config:
        from_attributes = True


class ScanHistoryResponse(BaseModel):
    id: str
    target_id: str
    target: str

    profile: str
    status: str

    risk_score: int | None = None
    risk_grade: str | None = None
    risk_level: str | None = None

    findings_count: int

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
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

    class Config:
        from_attributes = True


class ScanDetailsResponse(BaseModel):
    scan: ScanResponse
    findings: list[FindingResponse]
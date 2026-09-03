from pydantic import BaseModel, Field

from app.schemas.finding import FindingResponse


class ScanCreate(BaseModel):
    target_id: str = Field(min_length=1)
    profile: str = Field(min_length=1, max_length=50)


class ScannerExecutionSummary(BaseModel):
    status: str
    attempt: int | None = None
    duration_ms: int | None = None
    findings_count: int | None = None
    assets_count: int | None = None
    error_type: str | None = None
    error_message: str | None = None
    error: str | None = None
    error_phase: str | None = None
    retryable: bool | None = None


class ScanResponse(BaseModel):
    id: str
    target_id: str
    profile: str
    status: str
    phase: str

    risk_score: int | None = None
    risk_grade: str | None = None
    risk_level: str | None = None
    progress: int | None = None
    scanners: list[str] | None = None
    scanner_summary: dict[str, ScannerExecutionSummary] | None = None

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


class ScanDetailsResponse(BaseModel):
    scan: ScanResponse
    findings: list[FindingResponse]


class ScanProgressResponse(BaseModel):
    scan_id: str
    status: str
    progress: int
    total_scanners: int
    completed: int
    failed: int
    running: int
    pending: int
    skipped: int = 0
    scanners: dict[str, ScannerExecutionSummary]
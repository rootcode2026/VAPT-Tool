from pydantic import BaseModel


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    target_id: str
    scanner: str
    title: str
    description: str | None
    severity: str
    score: int | None
    status: str
    evidence: str | None
    remediation: str | None
    cve: str | None
    cwe: str | None

    class Config:
        from_attributes = True
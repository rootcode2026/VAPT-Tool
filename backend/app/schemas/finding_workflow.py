from typing import Optional
from pydantic import BaseModel, Field


class FindingUpdate(BaseModel):
    status: Optional[str] = Field(default=None, max_length=30)
    severity_override: Optional[str] = Field(default=None, max_length=20)
    assigned_to: Optional[str] = Field(default=None, max_length=36)
    owner_user_id: Optional[str] = Field(default=None, max_length=36)
    tags: Optional[list[str]] = Field(default=None, max_length=10)
    reason: Optional[str] = Field(default=None, max_length=1000)


class FindingCommentCreate(BaseModel):
    body: str = Field(min_length=1, max_length=2000)


class FindingCommentResponse(BaseModel):
    id: str
    finding_id: str
    author_user_id: str | None = None
    body: str
    created_at: str | None = None

    class Config:
        from_attributes = True

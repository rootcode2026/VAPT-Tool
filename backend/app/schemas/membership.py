from datetime import datetime

from pydantic import BaseModel, Field


class OrganizationMemberResponse(BaseModel):
    id: str
    organization_id: str
    user_id: str
    email: str | None = None
    role: str
    status: str
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class OrganizationMemberCreate(BaseModel):
    user_id: str = Field(min_length=1, max_length=36)
    role: str = Field(min_length=1, max_length=50)
    status: str | None = Field(default="active", max_length=20)


class OrganizationMemberUpdate(BaseModel):
    role: str | None = Field(default=None, max_length=50)
    status: str | None = Field(default=None, max_length=20)


class ProjectMemberResponse(BaseModel):
    id: str
    project_id: str
    user_id: str
    email: str | None = None
    role: str
    status: str
    created_at: datetime | None = None
    updated_at: datetime | None = None

    class Config:
        from_attributes = True


class ProjectMemberCreate(BaseModel):
    user_id: str = Field(min_length=1, max_length=36)
    role: str = Field(min_length=1, max_length=50)
    status: str | None = Field(default="active", max_length=20)


class ProjectMemberUpdate(BaseModel):
    role: str | None = Field(default=None, max_length=50)
    status: str | None = Field(default=None, max_length=20)

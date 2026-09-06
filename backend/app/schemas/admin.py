from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class AdminOrganizationCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(min_length=1, max_length=100)
    status: Optional[str] = Field(default="active", max_length=20)


class AdminOrganizationUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    slug: Optional[str] = Field(default=None, min_length=1, max_length=100)
    status: Optional[str] = Field(default=None, max_length=20)


class AdminOrganizationResponse(BaseModel):
    id: str
    name: str
    slug: str
    status: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class AdminUserUpdate(BaseModel):
    status: Optional[str] = Field(default=None, max_length=20)


class AdminUserResponse(BaseModel):
    id: str
    email: str
    organization_id: str
    role: str
    status: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

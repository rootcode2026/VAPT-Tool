from pydantic import BaseModel, Field


class ProjectCreate(BaseModel):
    organization_id: str = Field(min_length=1)
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(
        default=None,
        max_length=1000,
    )


class ProjectResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str | None

    class Config:
        from_attributes = True
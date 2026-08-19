from pydantic import BaseModel, Field


class TargetCreate(BaseModel):
    project_id: str = Field(min_length=1)
    value: str = Field(min_length=1, max_length=255)
    target_type: str = Field(min_length=1, max_length=50)


class TargetResponse(BaseModel):
    id: str
    project_id: str
    value: str
    target_type: str
    is_active: bool

    class Config:
        from_attributes = True
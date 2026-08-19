from pydantic import BaseModel, Field


class ScanCreate(BaseModel):
    target_id: str = Field(min_length=1)
    profile: str = Field(min_length=1, max_length=50)


class ScanResponse(BaseModel):
    id: str
    target_id: str
    profile: str
    status: str

    class Config:
        from_attributes = True
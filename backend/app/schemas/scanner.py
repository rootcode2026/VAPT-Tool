from pydantic import BaseModel


class ScannerResponse(BaseModel):
    name: str
    category: str
    description: str
    target_types: list[str]
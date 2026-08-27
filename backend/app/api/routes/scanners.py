from fastapi import APIRouter

from app.schemas.scanner import ScannerResponse


router = APIRouter(
    prefix="/api/v1/scanners",
    tags=["Scanners"],
)


SCANNERS = [
    {
        "name": "nmap",
        "category": "recon",
        "description": "Network and service discovery",
        "target_types": ["domain", "ip"],
    },
    {
        "name": "nuclei",
        "category": "vulnerability",
        "description": (
            "Template-based vulnerability and "
            "security misconfiguration detection"
        ),
        "target_types": ["domain", "ip", "url"],
    },
]


@router.get(
    "",
    response_model=list[ScannerResponse],
)
def get_scanners():
    return SCANNERS
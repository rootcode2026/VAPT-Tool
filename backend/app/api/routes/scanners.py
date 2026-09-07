from fastapi import APIRouter, Depends

from app.api.deps import get_current_user
from app.db.database import get_db
from app.models.user import User
from app.schemas.scanner import ScannerResponse
from app.services.scanner_catalog import SCANNER_CATALOG, get_catalog
from sqlalchemy.orm import Session


router = APIRouter(
    prefix="/api/v1/scanners",
    tags=["Scanners"],
)


@router.get(
    "",
    response_model=list[dict],
)
def get_scanners(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Platform-level catalog, not tenant-isolated, but requires authentication
    # Use DB definitions if seeded, otherwise fallback to static catalog
    try:
        from app.models.scanner_fleet import ScannerDefinition

        defs = db.query(ScannerDefinition).order_by(ScannerDefinition.scanner_key.asc()).all()
        if defs:
            return [
                {
                    "name": d.scanner_key,
                    "display_name": d.display_name,
                    "category": d.category,
                    "family": d.family,
                    "description": d.description,
                    "capabilities": d.capabilities,
                    "target_types": [],
                    "supported_profiles": d.supported_profiles,
                    "requires_workspace": d.requires_workspace,
                    "execution_type": d.execution_type,
                    "timeout": d.timeout_seconds,
                    "image": d.default_image,
                    "image_digest": None,
                    "version": d.current_version,
                    "channel": "stable",
                    "enabled": d.enabled,
                    "health_state": "unknown",
                }
                for d in defs
            ]
    except Exception:
        pass
    # Fallback to static catalog
    return [
        {
            "name": s["key"],
            "display_name": s["name"],
            "category": s["category"],
            "family": s["family"],
            "description": s["description"],
            "capabilities": s["capabilities"],
            "target_types": [],
            "supported_profiles": s["profiles"],
            "requires_workspace": s["requires_workspace"],
            "execution_type": s["execution_type"],
            "timeout": s["timeout_seconds"],
            "image": s["default_image"],
            "image_digest": None,
            "version": None,
            "channel": "stable",
            "enabled": True,
            "health_state": "unknown",
        }
        for s in SCANNER_CATALOG
    ]


@router.get(
    "/{scanner_key}",
    response_model=dict,
)
def get_scanner(
    scanner_key: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    key = scanner_key.strip()
    # Try DB
    try:
        from app.models.scanner_fleet import ScannerDefinition

        d = db.query(ScannerDefinition).filter(ScannerDefinition.scanner_key == key).first()
        if d:
            return {
                "name": d.scanner_key,
                "display_name": d.display_name,
                "category": d.category,
                "family": d.family,
                "description": d.description,
                "capabilities": d.capabilities,
                "supported_profiles": d.supported_profiles,
                "requires_workspace": d.requires_workspace,
                "execution_type": d.execution_type,
                "timeout": d.timeout_seconds,
                "image": d.default_image,
                "image_digest": None,
                "version": d.current_version,
                "channel": "stable",
                "enabled": d.enabled,
                "health_state": "unknown",
                "requirements": d.requirements,
            }
    except Exception:
        pass
    # Fallback to catalog
    from app.services.scanner_catalog import get_scanner_entry

    entry = get_scanner_entry(key)
    if not entry:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Scanner not found")
    return {
        "name": entry["key"],
        "display_name": entry["name"],
        "category": entry["category"],
        "family": entry["family"],
        "description": entry["description"],
        "capabilities": entry["capabilities"],
        "supported_profiles": entry["profiles"],
        "requires_workspace": entry["requires_workspace"],
        "execution_type": entry["execution_type"],
        "timeout": entry["timeout_seconds"],
        "image": entry["default_image"],
        "image_digest": None,
        "version": None,
        "channel": "stable",
        "enabled": True,
        "health_state": "unknown",
        "requirements": [],
    }

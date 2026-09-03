from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.finding import Finding
from app.schemas.asset import (
    AssetDetailResponse,
    AssetNeighborResponse,
    AssetResponse,
)
from app.schemas.finding import FindingResponse


router = APIRouter(
    prefix="/api/v1/assets",
    tags=["Assets"],
)


@router.get(
    "",
    response_model=list[AssetResponse],
)
def get_assets(
    project: str | None = None,
    project_id: str | None = None,
    asset_type: str | None = None,
    search: str | None = None,
    value: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    query = db.query(Asset)
    selected_project = project or project_id

    if selected_project:
        query = query.filter(Asset.project_id == selected_project)

    if asset_type:
        query = query.filter(Asset.asset_type == asset_type.strip().lower())

    lookup = (search or value or "").strip()[:256]
    if lookup:
        escaped = (
            lookup.replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
        query = query.filter(Asset.value.ilike(f"%{escaped}%", escape="\\"))

    return (
        query
        .order_by(Asset.last_seen_at.desc(), Asset.created_at.desc())
        .limit(limit)
        .all()
    )


@router.get(
    "/{asset_id}",
    response_model=AssetDetailResponse,
)
def get_asset(
    asset_id: str,
    db: Session = Depends(get_db),
):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    neighbors = _load_neighbors(db, asset)
    findings = (
        db.query(Finding)
        .filter(Finding.asset_id == asset.id)
        .order_by(Finding.created_at.desc())
        .all()
    )

    payload = AssetDetailResponse.model_validate(asset)
    return payload.model_copy(
        update={
            "relationships": neighbors,
            "findings": [
                FindingResponse.model_validate(item).model_dump()
                for item in findings
            ],
        }
    )


def _load_neighbors(db: Session, asset: Asset) -> list[AssetNeighborResponse]:
    outgoing = (
        db.query(AssetRelationship, Asset)
        .join(Asset, Asset.id == AssetRelationship.target_asset_id)
        .filter(AssetRelationship.source_asset_id == asset.id)
        .all()
    )
    incoming = (
        db.query(AssetRelationship, Asset)
        .join(Asset, Asset.id == AssetRelationship.source_asset_id)
        .filter(AssetRelationship.target_asset_id == asset.id)
        .all()
    )

    neighbors = []
    current = AssetResponse.model_validate(asset)
    for relationship, related in outgoing:
        neighbor = AssetResponse.model_validate(related)
        neighbors.append(
            AssetNeighborResponse(
                direction="outgoing",
                relationship_type=relationship.relationship_type,
                relationship_id=relationship.id,
                asset=neighbor,
                metadata=relationship.extra_data or {},
                source_asset_id=asset.id,
                target_asset_id=related.id,
                source_asset=current,
                target_asset=neighbor,
                created_at=relationship.created_at,
                updated_at=relationship.updated_at,
            )
        )
    for relationship, related in incoming:
        neighbor = AssetResponse.model_validate(related)
        neighbors.append(
            AssetNeighborResponse(
                direction="incoming",
                relationship_type=relationship.relationship_type,
                relationship_id=relationship.id,
                asset=neighbor,
                metadata=relationship.extra_data or {},
                source_asset_id=related.id,
                target_asset_id=asset.id,
                source_asset=neighbor,
                target_asset=current,
                created_at=relationship.created_at,
                updated_at=relationship.updated_at,
            )
        )
    return neighbors

"""P12.1 Cloud API — project-scoped, no credentials exposed."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.user import User

router = APIRouter(prefix="/api/v1/cloud", tags=["Cloud"])


def _ensure_columns(db: Session) -> None:
    try:
        from app.services.attack_surface import ensure_asset_workflow_columns

        ensure_asset_workflow_columns(db)
    except Exception:
        pass


@router.get("/providers")
def list_providers(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Provider list is static, no DB, no project filter needed but still auth
    from worker.app.cloud.provider import list_providers as lp

    # Import via worker path — use try to avoid hard dependency
    try:
        providers = lp()
        return {"providers": [p.to_dict() for p in providers]}
    except Exception:
        # Fallback static
        return {
            "providers": [
                {"provider_id": "aws", "display_name": "Amazon Web Services"},
                {"provider_id": "gcp", "display_name": "Google Cloud Platform"},
                {"provider_id": "azure", "display_name": "Microsoft Azure"},
            ]
        }


@router.get("/accounts")
def list_cloud_accounts(
    project_id: str = Query(..., description="Project ID"),
    provider: str | None = Query(default=None, description="Filter by provider aws/gcp/azure"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _ensure_columns(db)
    q = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_account")
    if provider:
        provider = provider.strip().lower()
        if provider not in ("aws", "gcp", "azure"):
            raise HTTPException(status_code=400, detail="Unsupported provider")
        # Filter by provider in metadata or value prefix
        q = q.filter(Asset.value.like(f"cloud_account:{provider}:%"))
    assets = q.limit(100).all()
    return {
        "project_id": project_id,
        "provider": provider,
        "count": len(assets),
        "accounts": [
            {
                "id": a.id,
                "value": a.value,
                "asset_type": a.asset_type,
                "metadata": a.asset_metadata if hasattr(a, "asset_metadata") else a.metadata if hasattr(a, "metadata") else {},
                "project_id": a.project_id,
            }
            for a in assets
        ],
    }


@router.get("/assets")
def list_cloud_assets(
    project_id: str = Query(..., description="Project ID"),
    provider: str | None = Query(default=None),
    asset_type: str | None = Query(default=None, description="cloud_account or cloud_resource"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _ensure_columns(db)
    q = db.query(Asset).filter(Asset.project_id == project_id)
    if asset_type:
        if asset_type not in ("cloud_account", "cloud_resource"):
            raise HTTPException(status_code=400, detail="Invalid cloud asset type")
        q = q.filter(Asset.asset_type == asset_type)
    else:
        q = q.filter(Asset.asset_type.in_(["cloud_account", "cloud_resource"]))
    if provider:
        provider = provider.strip().lower()
        q = q.filter(Asset.value.like(f"%:{provider}:%"))
    assets = q.limit(100).all()
    return {
        "project_id": project_id,
        "count": len(assets),
        "assets": [
            {
                "id": a.id,
                "value": a.value,
                "asset_type": a.asset_type,
                "metadata": getattr(a, "asset_metadata", getattr(a, "metadata", {})),
                "project_id": a.project_id,
            }
            for a in assets
        ],
    }


@router.get("/assets/{asset_id}")
def get_cloud_asset(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_columns(db)
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    require_project_access(asset.project_id, db, current_user)
    if asset.asset_type not in ("cloud_account", "cloud_resource"):
        raise HTTPException(status_code=404, detail="Not a cloud asset")
    return {
        "id": asset.id,
        "value": asset.value,
        "asset_type": asset.asset_type,
        "metadata": getattr(asset, "asset_metadata", getattr(asset, "metadata", {})),
        "project_id": asset.project_id,
    }


@router.get("/assets/{asset_id}/related")
def get_related_assets(
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ensure_columns(db)
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    require_project_access(asset.project_id, db, current_user)
    # Find relationships where this asset is source or target
    rels = (
        db.query(AssetRelationship)
        .filter(
            AssetRelationship.project_id == asset.project_id,
            ((AssetRelationship.source_asset_id == asset_id) | (AssetRelationship.target_asset_id == asset_id)),
        )
        .limit(50)
        .all()
    )
    related_ids = set()
    for r in rels:
        if r.source_asset_id != asset_id:
            related_ids.add(r.source_asset_id)
        if r.target_asset_id != asset_id:
            related_ids.add(r.target_asset_id)
    related = []
    if related_ids:
        related_assets = db.query(Asset).filter(Asset.id.in_(list(related_ids))).all()
        for a in related_assets:
            # Ensure same project (defense)
            if a.project_id != asset.project_id:
                continue
            related.append({
                "id": a.id,
                "value": a.value,
                "asset_type": a.asset_type,
                "project_id": a.project_id,
            })
    return {
        "asset_id": asset_id,
        "count": len(related),
        "related": related,
        "relationships": [
            {
                "id": r.id,
                "source_asset_id": r.source_asset_id,
                "target_asset_id": r.target_asset_id,
                "relationship_type": r.relationship_type,
                "project_id": r.project_id,
            }
            for r in rels
        ],
    }

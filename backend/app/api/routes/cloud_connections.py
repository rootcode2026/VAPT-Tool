from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import uuid
import json
from datetime import datetime, timezone

from app.api.deps import get_current_user, require_project_access, _is_super_admin, _effective_project_role, _effective_org_role
from app.db.database import get_db
from app.models.connector import CloudConnection
from app.models.user import User
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.services.audit import AuditService
from app.services.secret_store import get_secret_store

router = APIRouter(prefix="/api/v1/projects/{project_id}/cloud", tags=["Cloud Connectors"])

ALLOWED_PROVIDERS = {"aws", "gcp", "azure"}

def _require_manage(project_id: str, db: Session, user: User):
    if _is_super_admin(user):
        return
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj and _effective_org_role(user, proj.organization_id, db) == "org_admin":
        return
    role = _effective_project_role(user, project_id, db)
    if role != "project_admin":
        raise HTTPException(status_code=403, detail="Requires project_admin")

@router.get("/connections")
def list_connections(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    rows = db.query(CloudConnection).filter(CloudConnection.project_id == project_id).all()
    return {"project_id": project_id, "count": len(rows), "connections": [
        {"id": r.id, "provider": r.provider, "account_id": r.account_id, "status": r.status, "last_validation_at": r.last_validation_at.isoformat() if r.last_validation_at else None, "last_discovery_at": r.last_discovery_at.isoformat() if r.last_discovery_at else None}
        for r in rows
    ]}

@router.post("/connections", status_code=201)
def create_connection(project_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _require_manage(project_id, db, current_user)
    provider = str(payload.get("provider", "")).strip().lower()
    if provider not in ALLOWED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Invalid provider")
    account_id = str(payload.get("account_id") or payload.get("subscription_id") or payload.get("project_id") or "").strip()[:255]
    if not account_id:
        raise HTTPException(status_code=400, detail="account_id required")
    credential = payload.get("credential") or payload.get("role_arn") or payload.get("service_account") or payload.get("client_secret")
    if not credential or not isinstance(credential, str) or len(credential) < 10:
        raise HTTPException(status_code=400, detail="Credential required")
    if len(credential) > 8192:
        raise HTTPException(status_code=400, detail="Credential too large")
    # duplicate
    existing = db.query(CloudConnection).filter(CloudConnection.project_id == project_id, CloudConnection.provider == provider, CloudConnection.account_id == account_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Connection already exists")
    store = get_secret_store(db)
    cred_ref = store.put_secret(credential)
    regions = payload.get("regions")
    regions_str = None
    if regions and isinstance(regions, list):
        regions_str = json.dumps(regions[:20])
    conn = CloudConnection(
        id=str(uuid.uuid4()),
        project_id=project_id,
        provider=provider,
        account_id=account_id,
        credential_reference=cred_ref,
        credential_type="role" if provider == "aws" else "service_account",
        regions=regions_str,
        status="active",
    )
    db.add(conn)
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type="CLOUD_CONNECTION_CREATED", action="CLOUD_CONNECTION_CREATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": provider, "account_id": account_id[:100]})
    except Exception:
        pass
    db.commit()
    db.refresh(conn)
    return {"id": conn.id, "provider": conn.provider, "account_id": conn.account_id, "status": conn.status}

@router.post("/connections/{connection_id}/validate")
def validate_connection(project_id: str, connection_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    conn = db.query(CloudConnection).filter(CloudConnection.id == connection_id, CloudConnection.project_id == project_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    store = get_secret_store(db)
    cred = store.get_secret(conn.credential_reference) if conn.credential_reference else None
    if not cred:
        raise HTTPException(status_code=400, detail="Missing credential")
    from app.services.cloud_provider import get_provider
    provider = get_provider(conn.provider)
    if not provider:
        raise HTTPException(status_code=400, detail="Unknown provider")
    try:
        valid = provider.validate_credentials(cred, conn.account_id)
    except Exception as e:
        valid = False
    conn.last_validation_at = datetime.now(timezone.utc)
    conn.status = "active" if valid else "failed"
    db.commit()
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type="CLOUD_CONNECTION_VALIDATED" if valid else "CLOUD_CONNECTION_FAILED", action="CLOUD_CONNECTION_VALIDATED" if valid else "CLOUD_CONNECTION_FAILED", result="SUCCESS" if valid else "FAILURE", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": conn.provider, "valid": valid})
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    if not valid:
        raise HTTPException(status_code=400, detail="Credential validation failed")
    return {"id": conn.id, "valid": True, "status": conn.status}

@router.post("/connections/{connection_id}/discover")
def discover_resources(project_id: str, connection_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _require_manage(project_id, db, current_user)
    conn = db.query(CloudConnection).filter(CloudConnection.id == connection_id, CloudConnection.project_id == project_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    store = get_secret_store(db)
    cred = store.get_secret(conn.credential_reference) if conn.credential_reference else None
    if not cred:
        raise HTTPException(status_code=400, detail="Missing credential")
    from app.services.cloud_provider import get_provider
    provider = get_provider(conn.provider)
    if not provider:
        raise HTTPException(status_code=400, detail="Unknown provider")
    try:
        resources = provider.discover_resources(cred, conn.account_id)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)[:500])
    # Bounded, sanitize, persist as canonical assets
    # Use deterministic identity: provider+account+resource_type+resource_id
    persisted = 0
    for r in resources[:200]:
        value = f"cloud_resource:{r.provider}:{r.account_id}:{r.region}:{r.resource_type}:{r.resource_id}"
        # check existing
        existing = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_resource", Asset.value == value).first()
        if existing:
            # update metadata
            meta = existing.extra_data if isinstance(existing.extra_data, dict) else {}
            meta.update({"provider": r.provider, "region": r.region, "resource_type": r.resource_type, "resource_id": r.resource_id, "exposure": r.exposure})
            # sanitize no secrets
            for k in list(meta.keys()):
                if "secret" in k.lower() or "private" in k.lower():
                    meta.pop(k, None)
            existing.extra_data = meta
        else:
            db.add(Asset(id=str(uuid.uuid4()), project_id=project_id, asset_type="cloud_resource", value=value, status="active", extra_data={"provider": r.provider, "region": r.region, "resource_type": r.resource_type, "resource_id": r.resource_id, "exposure": r.exposure, "tags": r.tags}))
            persisted += 1
        # relationship: cloud_account -> contains -> cloud_resource
        account_value = f"cloud_account:{r.provider}:{r.account_id}:{r.region}"
        acc = db.query(Asset).filter(Asset.project_id == project_id, Asset.asset_type == "cloud_account", Asset.value == account_value).first()
        if not acc:
            acc = Asset(id=str(uuid.uuid4()), project_id=project_id, asset_type="cloud_account", value=account_value, status="active", extra_data={"provider": r.provider, "account_id": r.account_id, "region": r.region})
            db.add(acc)
            db.flush()
        # relationship
        # avoid duplicate
        rel_exists = db.query(AssetRelationship).filter(AssetRelationship.project_id == project_id, AssetRelationship.source_asset_id == acc.id, AssetRelationship.target_asset_id == db.query(Asset).filter(Asset.project_id == project_id, Asset.value == value).first().id if db.query(Asset).filter(Asset.project_id == project_id, Asset.value == value).first() else None).first() if False else None
        # simplified: always add if not exists
        try:
            res_asset = db.query(Asset).filter(Asset.project_id == project_id, Asset.value == value).first()
            if res_asset and not db.query(AssetRelationship).filter(AssetRelationship.project_id == project_id, AssetRelationship.source_asset_id == acc.id, AssetRelationship.target_asset_id == res_asset.id).first():
                db.add(AssetRelationship(id=str(uuid.uuid4()), project_id=project_id, source_asset_id=acc.id, target_asset_id=res_asset.id, relationship_type="contains"))
        except Exception:
            pass
    conn.last_discovery_at = datetime.now(timezone.utc)
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type="CLOUD_DISCOVERY_COMPLETED", action="CLOUD_DISCOVERY_COMPLETED", result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": conn.provider, "resources": len(resources), "persisted": persisted})
    except Exception:
        pass
    db.commit()
    return {"connection_id": conn.id, "discovered": len(resources), "persisted": persisted, "provider": conn.provider}

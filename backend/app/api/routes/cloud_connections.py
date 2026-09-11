from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import uuid
import json
from datetime import datetime, timezone

from app.api.deps import get_current_user, require_project_access, _is_super_admin, _effective_project_role, _effective_org_role
from app.db.database import get_db
from app.models.connector import CloudConnection
from app.models.cloud_discovery import CloudDiscovery
from app.models.user import User
from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.services.audit import (
    EVENT_CLOUD_CONNECTION_CREATED,
    EVENT_CLOUD_CONNECTION_FAILED,
    EVENT_CLOUD_CONNECTION_UPDATED,
    EVENT_CLOUD_CONNECTION_VALIDATED,
    EVENT_CLOUD_DISCOVERY_COMPLETED,
    EVENT_CLOUD_DISCOVERY_QUEUED,
    AuditService,
)
from app.services.secret_store import get_secret_store
import os

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


def _require_discover(project_id: str, db: Session, user: User):
    """Run discovery: analyst or above (mirrors scan execution permissions)."""
    if _is_super_admin(user):
        return
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj and _effective_org_role(user, proj.organization_id, db) == "org_admin":
        return
    role = _effective_project_role(user, project_id, db)
    if role not in ("analyst", "project_admin"):
        raise HTTPException(status_code=403, detail="Requires analyst or project_admin to run discovery")

@router.get("/connections")
def list_connections(project_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    rows = db.query(CloudConnection).filter(CloudConnection.project_id == project_id).all()
    return {"project_id": project_id, "count": len(rows), "connections": [
        {"id": r.id, "provider": r.provider, "name": getattr(r, "name", None), "account_id": r.account_id,
         "role_arn": getattr(r, "role_arn", None), "has_external_id": bool(getattr(r, "external_id", None)),
         "status": r.status, "last_validation_at": r.last_validation_at.isoformat() if r.last_validation_at else None,
         "last_discovery_at": r.last_discovery_at.isoformat() if r.last_discovery_at else None}
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
    # E1 AWS cross-account role: identifiers only (ARN/external ID are not secrets).
    role_arn = str(payload.get("role_arn") or "").strip() or None
    external_id = str(payload.get("external_id") or "").strip() or None
    name = str(payload.get("name") or "").strip()[:255] or None
    if provider == "aws" and role_arn:
        from app.services.aws_connector import (
            AWSConnectorError,
            validate_account_id,
            validate_external_id,
            validate_role_arn,
        )
        try:
            account_id = validate_account_id(account_id)
            role_arn = validate_role_arn(role_arn, account_id)
            external_id = validate_external_id(external_id)
        except AWSConnectorError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        credential = None
    elif provider == "gcp":
        from app.services.gcp_connector import GCPConnectorError, validate_project_id, validate_service_account_json
        try:
            account_id = validate_project_id(account_id)
            sa_json = payload.get("service_account_json") or payload.get("service_account") or payload.get("credential")
            if sa_json and isinstance(sa_json, str) and sa_json.strip().startswith("{"):
                validate_service_account_json(sa_json)
                credential = sa_json
            elif sa_json:
                # workload or other
                credential = str(sa_json)[:8192]
                if len(credential) < 10:
                    raise GCPConnectorError("Credential too short")
            else:
                # Allow mock without credential for tests
                credential = None
                # Check workload identity alternative
                workload_provider = payload.get("workload_identity_provider")
                workload_sa = payload.get("workload_service_account")
                if workload_provider and workload_sa:
                    from app.services.gcp_connector import validate_workload_identity
                    validate_workload_identity(workload_provider, workload_sa)
                    credential = json.dumps({"workload_provider": workload_provider, "service_account": workload_sa})
        except GCPConnectorError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        # GCP does not use role_arn/external_id
        role_arn = None
        external_id = None
    else:
        credential = payload.get("credential") or payload.get("service_account") or payload.get("client_secret")
        if not credential or not isinstance(credential, str) or len(credential) < 10:
            raise HTTPException(status_code=400, detail="Credential required")
        if len(credential) > 8192:
            raise HTTPException(status_code=400, detail="Credential too large")
    # duplicate
    existing = db.query(CloudConnection).filter(CloudConnection.project_id == project_id, CloudConnection.provider == provider, CloudConnection.account_id == account_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Connection already exists")
    cred_ref = None
    if credential:
        store = get_secret_store(db)
        cred_ref = store.put_secret(credential)
    regions = payload.get("regions")
    regions_str = None
    if regions and isinstance(regions, list):
        if provider == "aws" and role_arn:
            from app.services.aws_connector import AWSConnectorError, validate_regions
            try:
                cleaned = validate_regions(regions)
                regions_str = json.dumps(cleaned) if cleaned else None
            except AWSConnectorError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        else:
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
        name=name,
        role_arn=role_arn,
        external_id=external_id,
    )
    db.add(conn)
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type=EVENT_CLOUD_CONNECTION_CREATED, action=EVENT_CLOUD_CONNECTION_CREATED, result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": provider, "account_id": account_id[:100]})
    except Exception:
        pass
    db.commit()
    db.refresh(conn)
    return {"id": conn.id, "provider": conn.provider, "name": conn.name, "account_id": conn.account_id, "role_arn": conn.role_arn, "status": conn.status}

@router.get("/connections/{connection_id}")
def get_connection(project_id: str, connection_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    conn = db.query(CloudConnection).filter(CloudConnection.id == connection_id, CloudConnection.project_id == project_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    return {"id": conn.id, "provider": conn.provider, "name": getattr(conn, "name", None),
            "account_id": conn.account_id, "role_arn": getattr(conn, "role_arn", None),
            "has_external_id": bool(getattr(conn, "external_id", None)),
            "status": conn.status,
            "last_validation_at": conn.last_validation_at.isoformat() if conn.last_validation_at else None,
            "last_discovery_at": conn.last_discovery_at.isoformat() if conn.last_discovery_at else None}


@router.patch("/connections/{connection_id}")
def update_connection(project_id: str, connection_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _require_manage(project_id, db, current_user)
    conn = db.query(CloudConnection).filter(CloudConnection.id == connection_id, CloudConnection.project_id == project_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    data = payload if isinstance(payload, dict) else {}
    if "name" in data:
        conn.name = str(data["name"] or "").strip()[:255] or None
    if "regions" in data:
        regions = data["regions"]
        if regions is None:
            conn.regions = None
        elif isinstance(regions, list):
            if conn.provider == "aws" and getattr(conn, "role_arn", None):
                from app.services.aws_connector import AWSConnectorError, validate_regions
                try:
                    cleaned = validate_regions(regions)
                    conn.regions = json.dumps(cleaned) if cleaned else None
                except AWSConnectorError as exc:
                    raise HTTPException(status_code=400, detail=str(exc))
            else:
                conn.regions = json.dumps(regions[:20])
        else:
            raise HTTPException(status_code=400, detail="regions must be a list or null")
    if "status" in data:
        status = str(data["status"] or "").strip().lower()
        if status not in ("active", "inactive"):
            raise HTTPException(status_code=400, detail="Invalid status. Use active or inactive.")
        conn.status = status
    if "role_arn" in data or "external_id" in data:
        if conn.provider != "aws":
            raise HTTPException(status_code=400, detail="Role assumption is only supported for AWS")
        from app.services.aws_connector import AWSConnectorError, validate_external_id, validate_role_arn
        role_arn = str(data.get("role_arn", getattr(conn, "role_arn", None) or "") or "").strip() or None
        external_id = data.get("external_id", getattr(conn, "external_id", None))
        try:
            conn.role_arn = validate_role_arn(role_arn, conn.account_id) if role_arn else None
            conn.external_id = validate_external_id(external_id)
        except AWSConnectorError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type=EVENT_CLOUD_CONNECTION_UPDATED, action=EVENT_CLOUD_CONNECTION_UPDATED, result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": conn.provider})
    except Exception:
        pass
    db.commit()
    db.refresh(conn)
    return {"id": conn.id, "provider": conn.provider, "name": conn.name, "account_id": conn.account_id,
            "role_arn": conn.role_arn, "status": conn.status}


@router.post("/connections/{connection_id}/validate")
def validate_connection(project_id: str, connection_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _require_manage(project_id, db, current_user)
    conn = db.query(CloudConnection).filter(CloudConnection.id == connection_id, CloudConnection.project_id == project_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    # E1 live path: cross-account role assumption + STS identity verification.
    if conn.provider == "aws" and getattr(conn, "role_arn", None):
        return _validate_aws_role_connection(project_id, conn, db, current_user)
    if conn.provider == "gcp":
        return _validate_gcp_connection(project_id, conn, db, current_user)
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
        AuditService.record(db, event_type=EVENT_CLOUD_CONNECTION_VALIDATED if valid else EVENT_CLOUD_CONNECTION_FAILED, action=EVENT_CLOUD_CONNECTION_VALIDATED if valid else EVENT_CLOUD_CONNECTION_FAILED, result="SUCCESS" if valid else "FAILURE", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": conn.provider, "valid": valid})
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    if not valid:
        raise HTTPException(status_code=400, detail="Credential validation failed")
    return {"id": conn.id, "valid": True, "status": conn.status}


def _validate_aws_role_connection(project_id: str, conn, db: Session, current_user: User):
    """Live STS identity validation. Never fakes success; sanitized failures."""
    from app.services.aws_connector import AWSConnectorError, get_account_identity
    try:
        identity = get_account_identity(conn.role_arn, getattr(conn, "external_id", None), conn.account_id)
    except AWSConnectorError as exc:
        conn.status = "failed"
        try:
            from app.models.project import Project
            proj = db.query(Project).filter(Project.id == project_id).first()
            AuditService.record(db, event_type=EVENT_CLOUD_CONNECTION_FAILED, action=EVENT_CLOUD_CONNECTION_FAILED, result="FAILURE", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": "aws"})
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        raise HTTPException(status_code=400, detail=str(exc))
    conn.last_validation_at = datetime.now(timezone.utc)
    conn.status = "active"
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type=EVENT_CLOUD_CONNECTION_VALIDATED, action=EVENT_CLOUD_CONNECTION_VALIDATED, result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": "aws", "account_id": identity["account_id"]})
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return {"id": conn.id, "valid": True, "status": conn.status, "provider": "aws",
            "account_id": identity["account_id"], "principal_arn": identity["arn"]}

def _validate_gcp_connection(project_id: str, conn, db: Session, current_user: User):
    from app.services.gcp_connector import GCPConnectorError, get_gcp_identity, validate_project_id
    try:
        validate_project_id(conn.account_id)
        # Try to get identity via stored credential if any
        sa_json = None
        if conn.credential_reference:
            try:
                from app.services.secret_store import get_secret_store
                sa_json = get_secret_store(db).get_secret(conn.credential_reference)
            except Exception:
                sa_json = None
        identity = get_gcp_identity(conn.account_id, sa_json)
    except GCPConnectorError as exc:
        conn.status = "failed"
        try:
            from app.models.project import Project
            proj = db.query(Project).filter(Project.id == project_id).first()
            AuditService.record(db, event_type=EVENT_CLOUD_CONNECTION_FAILED, action=EVENT_CLOUD_CONNECTION_FAILED, result="FAILURE", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": "gcp"})
            db.commit()
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass
        raise HTTPException(status_code=400, detail=str(exc))
    conn.last_validation_at = datetime.now(timezone.utc)
    conn.status = "active"
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type=EVENT_CLOUD_CONNECTION_VALIDATED, action=EVENT_CLOUD_CONNECTION_VALIDATED, result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": "gcp", "project_id": identity["project_id"]})
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    return {"id": conn.id, "valid": True, "status": conn.status, "provider": "gcp", "project_id": identity["project_id"]}

@router.post("/connections/{connection_id}/discover")
def discover_resources(project_id: str, connection_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _require_discover(project_id, db, current_user)
    conn = db.query(CloudConnection).filter(CloudConnection.id == connection_id, CloudConnection.project_id == project_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    if getattr(conn, "status", "active") != "active":
        raise HTTPException(status_code=400, detail="Connection is disabled")
    # E1 live path: tracked discovery run executed by the Celery worker.
    if conn.provider == "aws" and getattr(conn, "role_arn", None):
        return _start_aws_discovery_run(project_id, conn, db, current_user)
    if conn.provider == "gcp":
        return _start_gcp_discovery_run(project_id, conn, db, current_user)
    if conn.provider == "azure":
        return _start_azure_discovery_run(project_id, conn, db, current_user)
    # Async for real mode
    mode = os.getenv("CLOUD_PROVIDER_MODE", "").lower() or os.getenv("CLOUD_MODE", "").lower()
    if mode == "real":
        try:
            from app.core.celery import celery_app
            # Enqueue async discovery
            task_id = str(uuid.uuid4())
            celery_app.send_task("app.tasks.cloud_discovery.discover_cloud", args=[conn.id, project_id, conn.provider, conn.account_id])
            try:
                AuditService.record(db, event_type=EVENT_CLOUD_DISCOVERY_QUEUED, action=EVENT_CLOUD_DISCOVERY_QUEUED, result="SUCCESS", actor_user_id=current_user.id, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": conn.provider})
                db.commit()
            except Exception:
                pass
            return {"connection_id": conn.id, "status": "queued", "task_id": task_id, "provider": conn.provider}
        except Exception:
            pass
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
        AuditService.record(db, event_type=EVENT_CLOUD_DISCOVERY_COMPLETED, action=EVENT_CLOUD_DISCOVERY_COMPLETED, result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="cloud_connection", resource_id=conn.id, metadata={"provider": conn.provider, "resources": len(resources), "persisted": persisted})
    except Exception:
        pass
    db.commit()
    return {"connection_id": conn.id, "discovered": len(resources), "persisted": persisted, "provider": conn.provider}


def _start_aws_discovery_run(project_id: str, conn, db: Session, current_user: User):
    """Create a tracked E1 discovery run and enqueue the worker task."""
    from app.models.project import Project

    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj is None:
        raise HTTPException(status_code=404, detail="Project not found")
    # Idempotency: at most one queued/running run per connection.
    active = (
        db.query(CloudDiscovery)
        .filter(CloudDiscovery.connection_id == conn.id, CloudDiscovery.status.in_(["queued", "running"]))
        .first()
    )
    if active:
        raise HTTPException(status_code=409, detail="Discovery already running for this connection")
    run = CloudDiscovery(
        id=str(uuid.uuid4()),
        organization_id=proj.organization_id,
        project_id=project_id,
        connection_id=conn.id,
        provider="aws",
        status="queued",
        requested_by=current_user.id,
    )
    db.add(run)
    db.flush()
    try:
        from app.core.celery import celery_app

        celery_app.send_task("app.tasks.cloud_discovery.discover_cloud", args=[conn.id, project_id, run.id])
    except Exception as exc:
        run.status = "failed"
        run.error = f"Discovery queue unavailable: {str(exc)[:200]}"
        run.finished_at = datetime.now(timezone.utc)
        try:
            AuditService.record(db, event_type=EVENT_CLOUD_DISCOVERY_FAILED, action=EVENT_CLOUD_DISCOVERY_FAILED, result="FAILURE", actor_user_id=current_user.id, organization_id=proj.organization_id, project_id=project_id, resource_type="cloud_discovery", resource_id=run.id, metadata={"reason": "queue_failed"})
        except Exception:
            pass
        db.commit()
        db.refresh(run)
        raise HTTPException(status_code=502, detail="Discovery queue unavailable")
    try:
        AuditService.record(db, event_type=EVENT_CLOUD_DISCOVERY_QUEUED, action=EVENT_CLOUD_DISCOVERY_QUEUED, result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id, project_id=project_id, resource_type="cloud_discovery", resource_id=run.id, metadata={"provider": "aws", "connection_id": conn.id})
    except Exception:
        pass
    db.commit()
    db.refresh(run)
    return {"discovery_id": run.id, "connection_id": conn.id, "status": "queued", "provider": "aws"}


def _start_gcp_discovery_run(project_id: str, conn, db: Session, current_user: User):
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj is None:
        raise HTTPException(status_code=404, detail="Project not found")
    active = db.query(CloudDiscovery).filter(CloudDiscovery.connection_id == conn.id, CloudDiscovery.status.in_(["queued", "running"])).first()
    if active:
        raise HTTPException(status_code=409, detail="Discovery already running for this connection")
    run = CloudDiscovery(id=str(uuid.uuid4()), organization_id=proj.organization_id, project_id=project_id, connection_id=conn.id, provider="gcp", status="queued", requested_by=current_user.id)
    db.add(run)
    db.flush()
    try:
        from app.core.celery import celery_app
        celery_app.send_task("app.tasks.cloud_discovery.discover_cloud", args=[conn.id, project_id, run.id])
    except Exception as exc:
        run.status = "failed"
        run.error = f"Discovery queue unavailable: {str(exc)[:200]}"
        run.finished_at = datetime.now(timezone.utc)
        try:
            AuditService.record(db, event_type=EVENT_CLOUD_DISCOVERY_FAILED, action=EVENT_CLOUD_DISCOVERY_FAILED, result="FAILURE", actor_user_id=current_user.id, organization_id=proj.organization_id, project_id=project_id, resource_type="cloud_discovery", resource_id=run.id, metadata={"reason": "queue_failed"})
        except Exception:
            pass
        db.commit()
        db.refresh(run)
        raise HTTPException(status_code=502, detail="Discovery queue unavailable")
    try:
        AuditService.record(db, event_type=EVENT_CLOUD_DISCOVERY_QUEUED, action=EVENT_CLOUD_DISCOVERY_QUEUED, result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id, project_id=project_id, resource_type="cloud_discovery", resource_id=run.id, metadata={"provider": "gcp", "connection_id": conn.id})
    except Exception:
        pass
    db.commit()
    db.refresh(run)
    return {"discovery_id": run.id, "connection_id": conn.id, "status": "queued", "provider": "gcp"}


def _start_azure_discovery_run(project_id: str, conn, db: Session, current_user: User):
    from app.models.project import Project
    proj = db.query(Project).filter(Project.id == project_id).first()
    if proj is None:
        raise HTTPException(status_code=404, detail="Project not found")
    active = db.query(CloudDiscovery).filter(CloudDiscovery.connection_id == conn.id, CloudDiscovery.status.in_(["queued", "running"])).first()
    if active:
        raise HTTPException(status_code=409, detail="Discovery already running for this connection")
    run = CloudDiscovery(id=str(uuid.uuid4()), organization_id=proj.organization_id, project_id=project_id, connection_id=conn.id, provider="azure", status="queued", requested_by=current_user.id)
    db.add(run)
    db.flush()
    try:
        from app.core.celery import celery_app
        celery_app.send_task("app.tasks.cloud_discovery.discover_cloud", args=[conn.id, project_id, run.id])
    except Exception as exc:
        run.status = "failed"
        run.error = f"Discovery queue unavailable: {str(exc)[:200]}"
        run.finished_at = datetime.now(timezone.utc)
        try:
            AuditService.record(db, event_type=EVENT_CLOUD_DISCOVERY_FAILED, action=EVENT_CLOUD_DISCOVERY_FAILED, result="FAILURE", actor_user_id=current_user.id, organization_id=proj.organization_id, project_id=project_id, resource_type="cloud_discovery", resource_id=run.id, metadata={"reason": "queue_failed"})
        except Exception:
            pass
        db.commit()
        db.refresh(run)
        raise HTTPException(status_code=502, detail="Discovery queue unavailable")
    try:
        AuditService.record(db, event_type=EVENT_CLOUD_DISCOVERY_QUEUED, action=EVENT_CLOUD_DISCOVERY_QUEUED, result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id, project_id=project_id, resource_type="cloud_discovery", resource_id=run.id, metadata={"provider": "azure", "connection_id": conn.id})
    except Exception:
        pass
    db.commit()
    db.refresh(run)
    return {"discovery_id": run.id, "connection_id": conn.id, "status": "queued", "provider": "azure"}


def _discovery_payload(run) -> dict:
    return {
        "id": run.id,
        "connection_id": run.connection_id,
        "project_id": run.project_id,
        "provider": run.provider,
        "status": run.status,
        "regions_attempted": run.regions_attempted,
        "regions_succeeded": run.regions_succeeded,
        "regions_failed": run.regions_failed,
        "assets_discovered": run.assets_discovered,
        "relationships_discovered": run.relationships_discovered,
        "resource_counts": run.resource_counts or {},
        "region_results": (run.region_results or [])[:50],
        "warnings": (run.warnings or [])[:50],
        "error": run.error,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


@router.get("/cloud-discoveries")
def list_discoveries(
    project_id: str,
    connection_id: str | None = None,
    status: str | None = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    try:
        limit = max(1, min(int(limit), 200))
    except Exception:
        limit = 50
    q = db.query(CloudDiscovery).filter(CloudDiscovery.project_id == project_id)
    if connection_id:
        q = q.filter(CloudDiscovery.connection_id == str(connection_id).strip()[:36])
    if status:
        s = str(status).strip().lower()
        if s not in ("queued", "running", "completed", "partial", "failed"):
            raise HTTPException(status_code=400, detail="Invalid status")
        q = q.filter(CloudDiscovery.status == s)
    rows = q.order_by(CloudDiscovery.created_at.desc()).limit(limit).all()
    return {"project_id": project_id, "count": len(rows), "discoveries": [_discovery_payload(r) for r in rows]}


@router.get("/cloud-discoveries/{discovery_id}")
def get_discovery(project_id: str, discovery_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    run = db.query(CloudDiscovery).filter(CloudDiscovery.id == discovery_id, CloudDiscovery.project_id == project_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Discovery not found")
    return _discovery_payload(run)

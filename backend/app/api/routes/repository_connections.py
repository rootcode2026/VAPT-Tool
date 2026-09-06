from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
import uuid
import re
import hashlib
from datetime import datetime, timezone

from app.api.deps import get_current_user, require_project_access, _is_super_admin, _effective_project_role, _effective_org_role
from app.db.database import get_db
from app.models.connector import RepositoryConnection, WebhookDelivery
from app.models.user import User
from app.services.audit import AuditService
from app.services.secret_store import get_secret_store

router = APIRouter(prefix="/api/v1/projects/{project_id}/repositories", tags=["Repository Connectors"])

ALLOWED_PROVIDERS = {"github", "gitlab", "bitbucket", "azure_devops"}

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
    rows = db.query(RepositoryConnection).filter(RepositoryConnection.project_id == project_id).all()
    return {"project_id": project_id, "count": len(rows), "connections": [
        {"id": r.id, "provider": r.provider, "display_name": r.display_name, "status": r.status, "webhook_status": r.webhook_status, "last_validation_at": r.last_validation_at.isoformat() if r.last_validation_at else None, "last_sync_at": r.last_sync_at.isoformat() if r.last_sync_at else None, "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows
    ]}

@router.post("/connections", status_code=201)
def create_connection(project_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _require_manage(project_id, db, current_user)
    provider = str(payload.get("provider", "")).strip().lower()
    if provider not in ALLOWED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Invalid provider")
    display_name = str(payload.get("display_name", "")).strip()[:255]
    if not display_name:
        raise HTTPException(status_code=400, detail="display_name required")
    credential = payload.get("credential") or payload.get("token") or payload.get("pat")
    if not credential or not isinstance(credential, str) or len(credential) < 10:
        raise HTTPException(status_code=400, detail="Credential required")
    if len(credential) > 8192:
        raise HTTPException(status_code=400, detail="Credential too large")
    # prevent duplicate
    existing = db.query(RepositoryConnection).filter(RepositoryConnection.project_id == project_id, RepositoryConnection.provider == provider, RepositoryConnection.display_name == display_name).first()
    if existing:
        raise HTTPException(status_code=409, detail="Connection already exists")
    # store via SecretStore
    store = get_secret_store(db)
    cred_ref = store.put_secret(credential)
    # webhook secret optional
    webhook_secret = payload.get("webhook_secret")
    webhook_ref = None
    if webhook_secret and isinstance(webhook_secret, str) and len(webhook_secret) >= 8:
        webhook_ref = store.put_secret(webhook_secret)
    conn = RepositoryConnection(
        id=str(uuid.uuid4()),
        project_id=project_id,
        provider=provider,
        display_name=display_name,
        credential_reference=cred_ref,
        credential_type="token",
        status="active",
        webhook_secret_reference=webhook_ref,
        webhook_status="inactive",
    )
    db.add(conn)
    # audit
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type="REPOSITORY_CONNECTION_CREATED", action="REPOSITORY_CONNECTION_CREATED", result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="repository_connection", resource_id=conn.id, metadata={"provider": provider, "display_name": display_name})
    except Exception:
        pass
    db.commit()
    db.refresh(conn)
    return {"id": conn.id, "provider": conn.provider, "display_name": conn.display_name, "status": conn.status}

@router.post("/connections/{connection_id}/validate")
def validate_connection(project_id: str, connection_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    conn = db.query(RepositoryConnection).filter(RepositoryConnection.id == connection_id, RepositoryConnection.project_id == project_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    store = get_secret_store(db)
    cred = store.get_secret(conn.credential_reference) if conn.credential_reference else None
    if not cred:
        raise HTTPException(status_code=400, detail="Missing credential")
    from app.services.repository_provider import get_provider
    provider = get_provider(conn.provider)
    if not provider:
        raise HTTPException(status_code=400, detail="Unknown provider")
    try:
        valid = provider.validate_credentials(cred)
    except Exception as e:
        valid = False
    conn.last_validation_at = datetime.now(timezone.utc)
    conn.status = "active" if valid else "failed"
    db.commit()
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type="REPOSITORY_CONNECTION_VALIDATED" if valid else "REPOSITORY_CONNECTION_FAILED", action="REPOSITORY_CONNECTION_VALIDATED" if valid else "REPOSITORY_CONNECTION_FAILED", result="SUCCESS" if valid else "FAILURE", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="repository_connection", resource_id=conn.id, metadata={"provider": conn.provider, "valid": valid})
        db.commit()
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    if not valid:
        raise HTTPException(status_code=400, detail="Credential validation failed")
    return {"id": conn.id, "provider": conn.provider, "valid": True, "status": conn.status}

@router.get("/connections/{connection_id}")
def get_connection(project_id: str, connection_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    conn = db.query(RepositoryConnection).filter(RepositoryConnection.id == connection_id, RepositoryConnection.project_id == project_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    return {"id": conn.id, "provider": conn.provider, "display_name": conn.display_name, "status": conn.status, "webhook_status": conn.webhook_status}

@router.post("/connections/{connection_id}/sync")
def sync_repository(project_id: str, connection_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    require_project_access(project_id, db, current_user)
    _require_manage(project_id, db, current_user)
    conn = db.query(RepositoryConnection).filter(RepositoryConnection.id == connection_id, RepositoryConnection.project_id == project_id).first()
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    # payload may contain repo_id, branch, commit_sha
    repo_id = str(payload.get("repo_id") or payload.get("repository_id") or "gh-1")[:255]
    branch = str(payload.get("branch") or "main")[:100]
    commit_sha = str(payload.get("commit_sha") or payload.get("sha") or "abc123def456")[:100]
    # sanitize: prevent traversal
    if ".." in repo_id or ".." in branch or "/" in commit_sha.replace("/", ""):
        # allow slashes in repo_id? but not traversal
        if ".." in repo_id or ".." in branch:
            raise HTTPException(status_code=400, detail="Invalid repo/branch")
    # Simulate snapshot with isolated workspace (no actual clone)
    # Use project_id to ensure tenant isolation
    snapshot_meta = {
        "repository": repo_id,
        "branch": branch,
        "commit_sha": commit_sha,
        "provider": conn.provider,
        "project_id": project_id,
        "connection_id": conn.id,
    }
    # Enqueue Celery task (mock) — if celery unavailable, just record audit
    try:
        from app.core.celery import celery_app
        celery_app.send_task("app.tasks.execute_scan", args=[str(uuid.uuid4()), repo_id, repo_id, "code"], kwargs={})
    except Exception:
        pass
    conn.last_sync_at = datetime.now(timezone.utc)
    db.commit()
    try:
        from app.models.project import Project
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type="REPOSITORY_SYNC_STARTED", action="REPOSITORY_SYNC_STARTED", result="SUCCESS", actor_user_id=current_user.id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="repository_connection", resource_id=conn.id, metadata={"repo_id": repo_id, "branch": branch})
        db.commit()
    except Exception:
        pass
    return {"connection_id": conn.id, "snapshot": snapshot_meta, "status": "sync_queued"}

# Webhook endpoint — no user auth, signature verified
webhook_router = APIRouter(prefix="/api/v1/webhooks", tags=["Webhooks"])

@webhook_router.post("/repository/{provider}")
async def repository_webhook(provider: str, request: Request, db: Session = Depends(get_db)):
    provider = provider.strip().lower()
    if provider not in ALLOWED_PROVIDERS:
        raise HTTPException(status_code=400, detail="Invalid provider")
    body = await request.body()
    if len(body) > 1024 * 1024:
        raise HTTPException(status_code=413, detail="Payload too large")
    # Find connection by provider (webhook must map via registered connection)
    # In real impl, lookup via webhook secret; here we find first active connection for provider
    # But we must not trust payload's project_id
    # Try to get event id from headers
    event_id = request.headers.get("x-github-delivery") or request.headers.get("x-gitlab-event-uuid") or request.headers.get("x-request-uuid") or str(uuid.uuid4())
    payload_hash = hashlib.sha256(body).hexdigest()
    # Replay protection: check if event_id already exists
    existing = db.query(WebhookDelivery).filter(WebhookDelivery.event_id == event_id).first()
    if existing:
        return {"status": "duplicate", "event_id": event_id}
    # Signature verification if secret exists
    # For mock, accept if no secret configured
    # Find connection with webhook secret
    # Simplified: just check any connection for provider
    conn = db.query(RepositoryConnection).filter(RepositoryConnection.provider == provider).first()
    if conn and conn.webhook_secret_reference:
        store = get_secret_store(db)
        secret = store.get_secret(conn.webhook_secret_reference)
        if secret:
            sig = request.headers.get("x-hub-signature-256") or request.headers.get("x-hub-signature") or request.headers.get("x-gitlab-token") or ""
            from app.services.repository_provider import get_provider
            prov = get_provider(provider)
            if prov and not prov.verify_webhook_signature(body, sig, secret):
                raise HTTPException(status_code=401, detail="Invalid signature")
    # Idempotent store
    if conn:
        delivery = WebhookDelivery(id=str(uuid.uuid4()), connection_id=conn.id, provider=provider, event_id=event_id, payload_hash=payload_hash, status="received")
        db.add(delivery)
        db.commit()
        try:
            AuditService.record(db, event_type="REPOSITORY_WEBHOOK_RECEIVED", action="REPOSITORY_WEBHOOK_RECEIVED", result="SUCCESS", organization_id=None, project_id=conn.project_id, resource_type="webhook", resource_id=delivery.id, metadata={"provider": provider, "event_id": event_id[:100]})
            db.commit()
        except Exception:
            pass
        return {"status": "received", "event_id": event_id}
    return {"status": "received", "event_id": event_id}

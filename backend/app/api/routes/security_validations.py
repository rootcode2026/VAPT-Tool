"""E14 Security Validation API — project-scoped, bounded, safe."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.services.security_validation import (
    request_validation,
    get_validations,
    get_validation_detail,
    get_finding_validations,
)

router = APIRouter(prefix="/api/v1/projects/{project_id}/security/validations", tags=["Security Validations"])


def _set_rls(db: Session, project_id: str, user: User):
    try:
        from app.db.rls import set_tenant_context
        org_id = getattr(user, "organization_id", None)
        if org_id and str(org_id).strip():
            if db.in_transaction():
                set_tenant_context(db, organization_id=str(org_id), project_id=str(project_id), user_id=str(user.id))
    except Exception:
        pass

def _require_analyst(project_id: str, db: Session, user: User):
    from app.api.deps import _effective_project_role, _is_super_admin
    if _is_super_admin(user):
        return
    role = _effective_project_role(user, project_id, db)
    if role not in ("analyst", "project_admin"):
        raise HTTPException(status_code=403, detail="Analyst or project_admin required")


class CreateValidationRequest(BaseModel):
    finding_id: str | None = None
    validation_type: str = "SAFE_SCANNER_RECHECK"


@router.get("")
def list_validations(
    project_id: str,
    finding_id: str | None = Query(None, max_length=36),
    status: str | None = Query(None, max_length=20),
    verdict: str | None = Query(None, max_length=20),
    validation_type: str | None = Query(None, max_length=30),
    scanner: str | None = Query(None, max_length=30),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    try:
        rows = get_validations(project_id, db, finding_id=finding_id, status=status, verdict=verdict, validation_type=validation_type, scanner=scanner, limit=limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"project_id": project_id, "count": len(rows), "validations": [
        {
            "id": r.id,
            "project_id": r.project_id,
            "finding_id": r.finding_id,
            "status": r.status,
            "validation_type": r.validation_type,
            "scanner": r.scanner,
            "scanner_version": r.scanner_version,
            "scanner_digest": r.scanner_digest,
            "verdict": r.verdict,
            "confidence": r.confidence,
            "target": r.target,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in rows
    ]}


@router.get("/{validation_id}")
def get_validation(
    project_id: str,
    validation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    row = get_validation_detail(project_id, db, validation_id)
    if not row:
        raise HTTPException(status_code=404, detail="Validation not found")
    return {
        "id": row.id,
        "project_id": row.project_id,
        "finding_id": row.finding_id,
        "status": row.status,
        "validation_type": row.validation_type,
        "scanner": row.scanner,
        "scanner_version": row.scanner_version,
        "scanner_digest": row.scanner_digest,
        "target": row.target,
        "original_fingerprint": row.original_fingerprint,
        "observed_fingerprint": row.observed_fingerprint,
        "verdict": row.verdict,
        "confidence": row.confidence,
        "evidence": (row.evidence or "")[:5000],
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "duration_ms": row.duration_ms,
        "error_code": row.error_code,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.post("")
def create_validation(
    project_id: str,
    body: CreateValidationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_analyst(project_id, db, current_user)
    if not body.finding_id:
        raise HTTPException(status_code=400, detail="finding_id is required")
    try:
        val = request_validation(project_id, db, finding_id=body.finding_id, validation_type=body.validation_type, requested_by=current_user.id)
    except ValueError as exc:
        # Use 400 for invalid request, 404 if finding not found? We'll map "Finding not found" to 404
        if "Finding not found" in str(exc) or "not in project" in str(exc):
            raise HTTPException(status_code=404, detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "id": val.id,
        "project_id": val.project_id,
        "finding_id": val.finding_id,
        "status": val.status,
        "validation_type": val.validation_type,
        "scanner": val.scanner,
        "verdict": val.verdict,
        "confidence": val.confidence,
        "created_at": val.created_at.isoformat() if val.created_at else None,
    }

# Convenience endpoints under findings
finding_router = APIRouter(prefix="/api/v1/projects/{project_id}/findings", tags=["Finding Validations"])

@finding_router.post("/{finding_id}/validate")
def validate_finding(
    project_id: str,
    finding_id: str,
    body: CreateValidationRequest | None = None,
    validation_type: str = Query("SAFE_SCANNER_RECHECK", max_length=30),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    _require_analyst(project_id, db, current_user)
    vt = body.validation_type if body and body.validation_type else validation_type
    # finding_id from path takes precedence
    try:
        val = request_validation(project_id, db, finding_id=finding_id, validation_type=vt, requested_by=current_user.id)
    except ValueError as exc:
        if "Finding not found" in str(exc) or "not in project" in str(exc):
            raise HTTPException(status_code=404, detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "id": val.id,
        "project_id": val.project_id,
        "finding_id": val.finding_id,
        "status": val.status,
        "validation_type": val.validation_type,
        "verdict": val.verdict,
        "confidence": val.confidence,
    }

@finding_router.get("/{finding_id}/validations")
def list_finding_validations(
    project_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _set_rls(db, project_id, current_user)
    rows = get_finding_validations(project_id, db, finding_id)
    return {"project_id": project_id, "finding_id": finding_id, "count": len(rows), "validations": [
        {
            "id": r.id,
            "status": r.status,
            "validation_type": r.validation_type,
            "verdict": r.verdict,
            "confidence": r.confidence,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in rows
    ]}

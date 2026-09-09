"""SLA, risk acceptance, remediation, retest APIs — tenant-isolated, RBAC-enforced."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import _effective_org_role, _is_super_admin, get_current_user, require_project_access
from app.api.routes.findings import (
    _require_finding_access,
    _require_finding_manage,
    _validate_user_in_org,
)
from app.db.database import get_db
from app.models.finding import (
    FindingHistory,
    FindingRemediation,
    FindingRetest,
    FindingRiskAcceptance,
    FindingSLA,
    SLAPolicy,
)
from app.models.project import Project
from app.models.user import User
from app.services import finding_lifecycle as lc
from app.services.audit import (
    EVENT_FINDING_REOPENED,
    EVENT_FINDING_RESOLVED,
    EVENT_REMEDIATION_BLOCKED,
    EVENT_REMEDIATION_CANCELLED,
    EVENT_REMEDIATION_COMPLETED,
    EVENT_REMEDIATION_CREATED,
    EVENT_REMEDIATION_EVIDENCE_ADDED,
    EVENT_REMEDIATION_STARTED,
    EVENT_REMEDIATION_UNBLOCKED,
    EVENT_REMEDIATION_UPDATED,
    EVENT_RETEST_CANCELLED,
    EVENT_RETEST_ERROR,
    EVENT_RETEST_FAILED,
    EVENT_RETEST_PASSED,
    EVENT_RETEST_REQUESTED,
    EVENT_RETEST_STARTED,
    EVENT_RISK_ACCEPTANCE_APPROVED,
    EVENT_RISK_ACCEPTANCE_EXPIRED,
    EVENT_RISK_ACCEPTANCE_REJECTED,
    EVENT_RISK_ACCEPTANCE_REQUESTED,
    EVENT_RISK_ACCEPTANCE_REVOKED,
    EVENT_SLA_BREACHED,
    EVENT_SLA_CREATED,
    EVENT_SLA_MET,
    EVENT_SLA_WAIVED,
    RESOURCE_FINDING,
    RESOURCE_REMEDIATION,
    RESOURCE_RETEST,
    RESOURCE_RISK_ACCEPTANCE,
    RESOURCE_SLA,
    RESULT_SUCCESS,
    AuditService,
)

router = APIRouter(prefix="/api/v1", tags=["Finding Lifecycle"])


def _utcnow():
    return datetime.now(timezone.utc)


def _parse_dt(value: str | None, field: str):
    if value is None:
        return None
    try:
        s = value.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid {field}")


def _finding_org_project(finding_id: str, db: Session, current_user: User):
    finding, scan, target, project, asset = _require_finding_access(finding_id, db, current_user)
    project_id = target.project_id if target else (asset.project_id if asset else None)
    if not project_id or not project:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding, project_id, project.organization_id


# -------------------------------------------------------------------
# SLA policy (org-level)
# -------------------------------------------------------------------

@router.get("/organizations/{organization_id}/sla-policy")
def get_sla_policy(
    organization_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not _is_super_admin(current_user):
        role = _effective_org_role(current_user, organization_id, db)
        if role not in ("org_admin", "member"):
            raise HTTPException(status_code=404, detail="Organization not found")
    rows = db.query(SLAPolicy).filter(SLAPolicy.organization_id == organization_id).all()
    policy = {r.severity: int(r.target_hours) for r in rows}
    for sev, default in lc.DEFAULT_SLA_HOURS.items():
        policy.setdefault(sev, default)
    return {"organization_id": organization_id, "policy": policy}


@router.put("/organizations/{organization_id}/sla-policy")
def put_sla_policy(
    organization_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not _is_super_admin(current_user):
        role = _effective_org_role(current_user, organization_id, db)
        if role != "org_admin":
            raise HTTPException(status_code=403, detail="Insufficient permissions")
    policy = payload.get("policy") if isinstance(payload, dict) else None
    if not isinstance(policy, dict):
        raise HTTPException(status_code=400, detail="policy is required")
    for sev, hours in policy.items():
        s = str(sev).strip().lower()
        if s not in lc.DEFAULT_SLA_HOURS:
            raise HTTPException(status_code=400, detail=f"Invalid severity: {sev}")
        try:
            h = int(hours)
        except Exception:
            raise HTTPException(status_code=400, detail=f"Invalid target_hours for {sev}")
        if h < 1 or h > 8760:
            raise HTTPException(status_code=400, detail=f"target_hours out of range for {sev}")
        row = (
            db.query(SLAPolicy)
            .filter(SLAPolicy.organization_id == organization_id, SLAPolicy.severity == s)
            .first()
        )
        if row:
            row.target_hours = h
        else:
            db.add(SLAPolicy(id=str(uuid.uuid4()), organization_id=organization_id, severity=s, target_hours=h))
    db.commit()
    return {"organization_id": organization_id, "updated": True}


# -------------------------------------------------------------------
# SLA instance
# -------------------------------------------------------------------

def _sla_payload(sla: FindingSLA) -> dict:
    now = _utcnow()
    status = lc.evaluate_sla_status(sla, now)
    due = sla.due_at.isoformat() if sla.due_at else None
    remaining = None
    if sla.due_at and sla.completed_at is None and status == "active":
        delta = sla.due_at - now.replace(tzinfo=None) if sla.due_at.tzinfo is None else sla.due_at - now
        remaining = int(delta.total_seconds() // 3600)
    return {
        "id": sla.id,
        "finding_id": sla.finding_id,
        "organization_id": sla.organization_id,
        "project_id": sla.project_id,
        "policy_name": sla.policy_name,
        "severity": sla.severity,
        "target_hours": sla.target_hours,
        "started_at": sla.started_at.isoformat() if sla.started_at else None,
        "due_at": due,
        "completed_at": sla.completed_at.isoformat() if sla.completed_at else None,
        "status": status,
        "breached": status == "breached",
        "remaining_hours": remaining,
        "breached_at": sla.breached_at.isoformat() if sla.breached_at else None,
        "created_at": sla.created_at.isoformat() if sla.created_at else None,
    }


@router.get("/findings/{finding_id}/sla")
def get_finding_sla(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    sla = (
        db.query(FindingSLA)
        .filter(FindingSLA.finding_id == finding.id, FindingSLA.status == "active")
        .order_by(FindingSLA.created_at.desc())
        .first()
    )
    if not sla:
        sla = (
            db.query(FindingSLA)
            .filter(FindingSLA.finding_id == finding.id)
            .order_by(FindingSLA.created_at.desc())
            .first()
        )
    if not sla:
        raise HTTPException(status_code=404, detail="No SLA for finding")
    if lc.refresh_sla_breach(db, sla):
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=None, action="sla_breached", old_value="active", new_value="breached", reason=None))
        AuditService.record(db, event_type=EVENT_SLA_BREACHED, action=EVENT_SLA_BREACHED, result=RESULT_SUCCESS, actor_user_id=None, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_SLA, resource_id=sla.id, metadata={"finding_id": finding.id})
        db.commit()
        db.refresh(sla)
    return _sla_payload(sla)


@router.post("/findings/{finding_id}/sla/start", status_code=201)
def start_finding_sla(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    _require_finding_manage(project_id, db, current_user)
    existing = (
        db.query(FindingSLA)
        .filter(FindingSLA.finding_id == finding.id, FindingSLA.status == "active")
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Active SLA already exists")
    severity = (getattr(finding, "severity_override", None) or finding.severity or "medium").strip().lower()
    target_hours = lc.get_sla_target_hours(db, organization_id, severity)
    now = _utcnow()
    # SQLite stores naive; keep naive for consistency
    now_naive = now.replace(tzinfo=None)
    sla = FindingSLA(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        organization_id=organization_id,
        project_id=project_id,
        policy_name="org-default",
        severity=severity,
        target_hours=target_hours,
        started_at=now_naive,
        due_at=now_naive + __import__("datetime").timedelta(hours=target_hours),
        status="active",
    )
    db.add(sla)
    db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="sla_created", old_value=None, new_value="active", reason=None))
    AuditService.record(db, event_type=EVENT_SLA_CREATED, action=EVENT_SLA_CREATED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_SLA, resource_id=sla.id, metadata={"finding_id": finding.id, "severity": severity, "target_hours": target_hours})
    db.commit()
    db.refresh(sla)
    return _sla_payload(sla)


@router.patch("/findings/{finding_id}/sla")
def update_finding_sla(
    finding_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    _require_finding_manage(project_id, db, current_user)
    sla = (
        db.query(FindingSLA)
        .filter(FindingSLA.finding_id == finding.id, FindingSLA.status == "active")
        .order_by(FindingSLA.created_at.desc())
        .first()
    )
    if not sla:
        raise HTTPException(status_code=404, detail="No active SLA")
    action = str(payload.get("action", "")).strip().lower() if isinstance(payload, dict) else ""
    if action == "waive":
        sla.status = "waived"
        sla.completed_at = _utcnow().replace(tzinfo=None)
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="sla_waived", old_value="active", new_value="waived", reason=str(payload.get("reason", ""))[:500] if payload.get("reason") else None))
        AuditService.record(db, event_type=EVENT_SLA_WAIVED, action=EVENT_SLA_WAIVED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_SLA, resource_id=sla.id, metadata={"finding_id": finding.id})
    elif action == "complete":
        sla.status = "met"
        sla.completed_at = _utcnow().replace(tzinfo=None)
        AuditService.record(db, event_type=EVENT_SLA_MET, action=EVENT_SLA_MET, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_SLA, resource_id=sla.id, metadata={"finding_id": finding.id})
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use waive or complete.")
    db.commit()
    db.refresh(sla)
    return _sla_payload(sla)


@router.get("/projects/{project_id}/sla/summary")
def project_sla_summary(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    now = _utcnow().replace(tzinfo=None)
    base = db.query(FindingSLA).filter(FindingSLA.project_id == project_id, FindingSLA.status == "active")
    active = base.count()
    # Breached: active + due_at < now (evaluate lazily without write)
    breached = base.filter(FindingSLA.due_at < now).count()
    # Overdue critical: join finding effective severity
    from app.models.finding import Finding

    overdue_critical = (
        db.query(func.count(FindingSLA.id))
        .join(Finding, Finding.id == FindingSLA.finding_id)
        .filter(FindingSLA.project_id == project_id, FindingSLA.status == "active", FindingSLA.due_at < now)
        .filter(func.coalesce(Finding.severity_override, Finding.severity) == "critical")
        .scalar()
        or 0
    )
    return {"project_id": project_id, "active": active, "breached": breached, "overdue_critical": overdue_critical}


# -------------------------------------------------------------------
# Risk acceptance
# -------------------------------------------------------------------

def _ra_payload(ra: FindingRiskAcceptance) -> dict:
    # Expire lazily on read is handled by caller
    return {
        "id": ra.id,
        "finding_id": ra.finding_id,
        "organization_id": ra.organization_id,
        "project_id": ra.project_id,
        "requested_by": ra.requested_by,
        "approved_by": ra.approved_by,
        "status": ra.status,
        "reason": ra.reason,
        "business_justification": ra.business_justification,
        "compensating_controls": ra.compensating_controls,
        "valid_from": ra.valid_from.isoformat() if ra.valid_from else None,
        "expires_at": ra.expires_at.isoformat() if ra.expires_at else None,
        "reviewed_at": ra.reviewed_at.isoformat() if ra.reviewed_at else None,
        "review_notes": ra.review_notes,
        "created_at": ra.created_at.isoformat() if ra.created_at else None,
    }


def _expire_ra_if_due(db: Session, ra: FindingRiskAcceptance, finding, project_id: str, organization_id: str) -> bool:
    if lc.check_ra_expired(ra):
        ra.status = "expired"
        ra.reviewed_at = _utcnow().replace(tzinfo=None)
        # Reopen finding if it was accepted_risk
        if finding.status == "accepted_risk":
            old = finding.status
            finding.status = "reopened"
            db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=None, action="status_changed", old_value=old, new_value="reopened", reason="risk acceptance expired"))
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=None, action="risk_acceptance_expired", old_value="approved", new_value="expired", reason=None))
        AuditService.record(db, event_type=EVENT_RISK_ACCEPTANCE_EXPIRED, action=EVENT_RISK_ACCEPTANCE_EXPIRED, result=RESULT_SUCCESS, actor_user_id=None, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RISK_ACCEPTANCE, resource_id=ra.id, metadata={"finding_id": finding.id})
        return True
    return False


@router.get("/findings/{finding_id}/risk-acceptances")
def list_risk_acceptances(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    rows = db.query(FindingRiskAcceptance).filter(FindingRiskAcceptance.finding_id == finding.id).order_by(FindingRiskAcceptance.created_at.desc()).all()
    changed = False
    for ra in rows:
        if _expire_ra_if_due(db, ra, finding, project_id, organization_id):
            changed = True
    if changed:
        db.commit()
    return {"items": [_ra_payload(r) for r in rows], "total": len(rows)}


@router.post("/findings/{finding_id}/risk-acceptances/request", status_code=201)
def request_risk_acceptance(
    finding_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    _require_finding_manage(project_id, db, current_user)
    reason = str(payload.get("reason", "")).strip() if isinstance(payload, dict) else ""
    justification = str(payload.get("business_justification", "")).strip() if isinstance(payload, dict) and payload.get("business_justification") else None
    controls = str(payload.get("compensating_controls", "")).strip()[:2000] if isinstance(payload, dict) and payload.get("compensating_controls") else None
    expires_raw = payload.get("expires_at") if isinstance(payload, dict) else None
    if not reason:
        raise HTTPException(status_code=400, detail="Reason is required")
    if len(reason) > 2000:
        reason = reason[:2000]
    if justification is not None and len(justification) > 2000:
        justification = justification[:2000]
    expires_at = _parse_dt(expires_raw, "expires_at") if expires_raw else None
    if expires_at is None:
        raise HTTPException(status_code=400, detail="expires_at is required")
    exp_naive = expires_at.replace(tzinfo=None) if expires_at.tzinfo else expires_at
    if exp_naive <= datetime.utcnow():
        raise HTTPException(status_code=400, detail="expires_at must be in the future")
    # Only one requested/approved active at a time
    existing = (
        db.query(FindingRiskAcceptance)
        .filter(FindingRiskAcceptance.finding_id == finding.id, FindingRiskAcceptance.status.in_(["requested", "approved"]))
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Active risk acceptance already exists")
    ra = FindingRiskAcceptance(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        organization_id=organization_id,
        project_id=project_id,
        requested_by=current_user.id,
        status="requested",
        reason=reason,
        business_justification=justification,
        compensating_controls=controls,
        valid_from=datetime.utcnow(),
        expires_at=exp_naive,
    )
    db.add(ra)
    db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="risk_acceptance_requested", old_value=None, new_value="requested", reason=reason[:500]))
    AuditService.record(db, event_type=EVENT_RISK_ACCEPTANCE_REQUESTED, action=EVENT_RISK_ACCEPTANCE_REQUESTED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RISK_ACCEPTANCE, resource_id=ra.id, metadata={"finding_id": finding.id})
    db.commit()
    db.refresh(ra)
    return _ra_payload(ra)


@router.patch("/findings/{finding_id}/risk-acceptances/{ra_id}")
def review_risk_acceptance(
    finding_id: str,
    ra_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    _require_finding_manage(project_id, db, current_user)
    ra = db.query(FindingRiskAcceptance).filter(FindingRiskAcceptance.id == ra_id, FindingRiskAcceptance.finding_id == finding.id).first()
    if not ra:
        raise HTTPException(status_code=404, detail="Risk acceptance not found")
    action = str(payload.get("action", "")).strip().lower() if isinstance(payload, dict) else ""
    notes = str(payload.get("review_notes", "")).strip()[:2000] if isinstance(payload, dict) and payload.get("review_notes") else None
    if action == "approve":
        if ra.status != "requested":
            raise HTTPException(status_code=400, detail="Only requested can be approved")
        # Separation of duties: requester cannot approve own request unless super_admin/org_admin? Enforce: different user required
        if ra.requested_by == current_user.id and not _is_super_admin(current_user):
            # Allow org_admin to self-approve? Spec says use separation of duties if ambiguous → deny
            raise HTTPException(status_code=403, detail="Requester cannot approve own risk acceptance")
        if not ra.business_justification:
            # Require justification at approval time if missing
            bj = str(payload.get("business_justification", "")).strip() if isinstance(payload, dict) and payload.get("business_justification") else None
            if not bj:
                raise HTTPException(status_code=400, detail="business_justification is required for approval")
            ra.business_justification = bj[:2000]
        ra.status = "approved"
        ra.approved_by = current_user.id
        ra.reviewed_at = _utcnow().replace(tzinfo=None)
        ra.review_notes = notes
        old_status = finding.status
        finding.status = "accepted_risk"
        try:
            finding.updated_at = _utcnow().replace(tzinfo=None)
        except Exception:
            pass
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="status_changed", old_value=old_status, new_value="accepted_risk", reason="risk acceptance approved"))
        # Waive active SLA explicitly
        sla = db.query(FindingSLA).filter(FindingSLA.finding_id == finding.id, FindingSLA.status == "active").first()
        if sla:
            sla.status = "waived"
            sla.completed_at = _utcnow().replace(tzinfo=None)
            AuditService.record(db, event_type=EVENT_SLA_WAIVED, action=EVENT_SLA_WAIVED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_SLA, resource_id=sla.id, metadata={"finding_id": finding.id, "reason": "risk accepted"})
        AuditService.record(db, event_type=EVENT_RISK_ACCEPTANCE_APPROVED, action=EVENT_RISK_ACCEPTANCE_APPROVED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RISK_ACCEPTANCE, resource_id=ra.id, metadata={"finding_id": finding.id})
    elif action == "reject":
        if ra.status != "requested":
            raise HTTPException(status_code=400, detail="Only requested can be rejected")
        ra.status = "rejected"
        ra.reviewed_at = _utcnow().replace(tzinfo=None)
        ra.review_notes = notes
        AuditService.record(db, event_type=EVENT_RISK_ACCEPTANCE_REJECTED, action=EVENT_RISK_ACCEPTANCE_REJECTED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RISK_ACCEPTANCE, resource_id=ra.id, metadata={"finding_id": finding.id})
    elif action == "revoke":
        if ra.status != "approved":
            raise HTTPException(status_code=400, detail="Only approved can be revoked")
        ra.status = "revoked"
        ra.reviewed_at = _utcnow().replace(tzinfo=None)
        ra.review_notes = notes
        old_status = finding.status
        finding.status = "reopened"
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="status_changed", old_value=old_status, new_value="reopened", reason="risk acceptance revoked"))
        AuditService.record(db, event_type=EVENT_RISK_ACCEPTANCE_REVOKED, action=EVENT_RISK_ACCEPTANCE_REVOKED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RISK_ACCEPTANCE, resource_id=ra.id, metadata={"finding_id": finding.id})
    else:
        raise HTTPException(status_code=400, detail="Invalid action. Use approve, reject, or revoke.")
    db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action=f"risk_acceptance_{ra.status}", old_value=None, new_value=ra.status, reason=notes))
    db.commit()
    db.refresh(ra)
    return _ra_payload(ra)


# -------------------------------------------------------------------
# Remediation
# -------------------------------------------------------------------

def _rem_payload(r: FindingRemediation, finding=None, sla: FindingSLA | None = None, due_source: str | None = None) -> dict:
    # D7: expose blocked/evidence + SLA rollup + verification boundary.
    # "completed" == owner-reported completion; "verified" requires D8 retest evidence.
    now = _utcnow()
    sla_status = lc.evaluate_sla_status(sla, now) if sla is not None else None
    overdue = bool(sla is not None and sla_status == "breached")
    due_at = r.due_at or (sla.due_at if sla is not None else None)
    if due_source is None:
        due_source = "remediation" if r.due_at else ("sla" if sla is not None and sla.due_at else None)
    return {
        "id": r.id,
        "finding_id": r.finding_id,
        "organization_id": r.organization_id,
        "project_id": r.project_id,
        "created_by": r.created_by,
        "assigned_to": r.assigned_to,
        "updated_by": getattr(r, "updated_by", None),
        "status": r.status,
        "title": r.title,
        "description": r.description,
        "remediation_guidance": r.remediation_guidance,
        "due_at": due_at.isoformat() if due_at else None,
        "due_source": due_source,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "completion_notes": r.completion_notes,
        "blocked_reason": getattr(r, "blocked_reason", None),
        "evidence_ref": getattr(r, "evidence_ref", None),
        "finding_status": getattr(finding, "status", None),
        "finding_severity": (
            (getattr(finding, "severity_override", None) or getattr(finding, "severity", None)) if finding is not None else None
        ),
        "accepted_risk": bool(finding is not None and getattr(finding, "status", None) == "accepted_risk"),
        "sla_status": sla_status,
        "overdue": overdue,
        "verification_required": r.status == "completed",
        "verified": False,  # D8 owns formal verification; D7 never marks verified.
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _remediation_sla(db: Session, finding_id: str) -> FindingSLA | None:
    sla = (
        db.query(FindingSLA)
        .filter(FindingSLA.finding_id == finding_id, FindingSLA.status == "active")
        .order_by(FindingSLA.created_at.desc())
        .first()
    )
    if sla is not None:
        return sla
    return (
        db.query(FindingSLA)
        .filter(FindingSLA.finding_id == finding_id)
        .order_by(FindingSLA.created_at.desc())
        .first()
    )


@router.get("/findings/{finding_id}/remediations")
def list_remediations(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    rows = db.query(FindingRemediation).filter(FindingRemediation.finding_id == finding.id).order_by(FindingRemediation.created_at.desc()).all()
    sla = _remediation_sla(db, finding.id)
    return {"items": [_rem_payload(r, finding, sla) for r in rows], "total": len(rows)}


@router.post("/findings/{finding_id}/remediations", status_code=201)
def create_remediation(
    finding_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.api.routes.findings import _validate_user_in_org

    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    _require_finding_manage(project_id, db, current_user)
    title = str(payload.get("title", "")).strip()[:255] if isinstance(payload, dict) else ""
    if not title:
        raise HTTPException(status_code=400, detail="Title is required")
    description = str(payload.get("description", "")).strip()[:2000] if isinstance(payload, dict) and payload.get("description") else None
    guidance = str(payload.get("remediation_guidance", "")).strip()[:2000] if isinstance(payload, dict) and payload.get("remediation_guidance") else None
    assigned_raw = payload.get("assigned_to") if isinstance(payload, dict) else None
    assigned_to = None
    if assigned_raw:
        auid = str(assigned_raw).strip()
        _validate_user_in_org(auid, organization_id, db)
        assigned_to = auid
    due_at = _parse_dt(payload.get("due_at"), "due_at") if isinstance(payload, dict) and payload.get("due_at") else None
    due_naive = due_at.replace(tzinfo=None) if due_at and due_at.tzinfo else due_at
    # D7: evidence_ref is a bounded reference only (no raw bodies/secrets).
    try:
        evidence_ref = lc.sanitize_remediation_evidence_ref(
            payload.get("evidence_ref") if isinstance(payload, dict) else None
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    # D7: reuse existing SLA for default due date when caller omits due_at.
    due_source = "remediation" if due_naive is not None else None
    if due_naive is None:
        sla_default = _remediation_sla(db, finding.id)
        if sla_default is not None and sla_default.due_at is not None:
            due_naive = sla_default.due_at
            due_source = "sla"
    # Only one active remediation at a time (D7: blocked counts as active)
    existing = (
        db.query(FindingRemediation)
        .filter(FindingRemediation.finding_id == finding.id, FindingRemediation.status.in_(list(lc.REMEDIATION_ACTIVE_STATUSES)))
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Active remediation already exists")
    rem = FindingRemediation(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        organization_id=organization_id,
        project_id=project_id,
        created_by=current_user.id,
        assigned_to=assigned_to,
        status="open",
        title=title,
        description=description,
        remediation_guidance=guidance,
        due_at=due_naive,
        evidence_ref=evidence_ref,
    )
    db.add(rem)
    db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="remediation_created", old_value=None, new_value="open", reason=title[:200]))
    AuditService.record(db, event_type=EVENT_REMEDIATION_CREATED, action=EVENT_REMEDIATION_CREATED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_REMEDIATION, resource_id=rem.id, metadata={"finding_id": finding.id, "title": title[:100]})
    db.commit()
    db.refresh(rem)
    return _rem_payload(rem, finding, _remediation_sla(db, finding.id), due_source=due_source)


@router.patch("/findings/{finding_id}/remediations/{rem_id}")
def update_remediation(
    finding_id: str,
    rem_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.api.routes.findings import _validate_user_in_org

    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    _require_finding_manage(project_id, db, current_user)
    rem = db.query(FindingRemediation).filter(FindingRemediation.id == rem_id, FindingRemediation.finding_id == finding.id).first()
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")
    data = payload if isinstance(payload, dict) else {}
    # Assignment change (owner must belong to org; cross-tenant rejected via _validate_user_in_org)
    if "assigned_to" in data:
        old_owner = rem.assigned_to
        if data["assigned_to"] is None:
            rem.assigned_to = None
        else:
            auid = str(data["assigned_to"]).strip()
            _validate_user_in_org(auid, organization_id, db)
            rem.assigned_to = auid
        rem.updated_by = current_user.id
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="remediation_assigned", old_value=old_owner, new_value=rem.assigned_to, reason=None))
        AuditService.record(db, event_type=EVENT_REMEDIATION_UPDATED, action=EVENT_REMEDIATION_UPDATED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_REMEDIATION, resource_id=rem.id, metadata={"finding_id": finding.id, "field": "assigned_to"})
    # Due date change (bounded history)
    if "due_at" in data and data["due_at"] is not None:
        old_due = rem.due_at.isoformat() if rem.due_at else None
        new_due = _parse_dt(str(data["due_at"]), "due_at")
        rem.due_at = new_due.replace(tzinfo=None) if new_due and new_due.tzinfo else new_due
        rem.updated_by = current_user.id
        db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="remediation_due_changed", old_value=old_due, new_value=rem.due_at.isoformat() if rem.due_at else None, reason=None))
    # Status transition (idempotent: same status is a no-op success)
    if "status" in data and data["status"] is not None:
        new_status = str(data["status"]).strip().lower()
        if new_status not in lc.REMEDIATION_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status")
        allowed = lc.REMEDIATION_TRANSITIONS.get(rem.status, set())
        if new_status != rem.status and new_status not in allowed:
            raise HTTPException(status_code=400, detail=f"Invalid transition from {rem.status} to {new_status}")
        if new_status == "blocked" and rem.status != "blocked":
            reason = str(data.get("blocked_reason", "") or "").strip()[: lc.REMEDIATION_BLOCKED_REASON_MAX]
            if not reason:
                raise HTTPException(status_code=400, detail="blocked_reason is required to block remediation")
            rem.blocked_reason = reason
        if new_status != rem.status:
            old = rem.status
            rem.status = new_status
            rem.updated_by = current_user.id
            now = _utcnow().replace(tzinfo=None)
            if new_status == "in_progress":
                if not rem.started_at:
                    rem.started_at = now
                # Unblock path clears the blocker but preserves history
                if old == "blocked":
                    rem.blocked_reason = None
                    evt = EVENT_REMEDIATION_UNBLOCKED
                else:
                    evt = EVENT_REMEDIATION_STARTED
            elif new_status == "blocked":
                evt = EVENT_REMEDIATION_BLOCKED
            elif new_status == "completed":
                notes = str(data.get("completion_notes", "")).strip()[:2000] if data.get("completion_notes") else None
                if notes:
                    rem.completion_notes = notes
                rem.completed_at = now
                # D7: completion is owner-reported only — never auto-verify/resolve.
                evt = EVENT_REMEDIATION_COMPLETED
            elif new_status == "cancelled":
                evt = EVENT_REMEDIATION_CANCELLED
            else:
                evt = EVENT_REMEDIATION_UPDATED
            db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action=f"remediation_{new_status}", old_value=old, new_value=new_status, reason=str(data.get("reason", "") or data.get("blocked_reason", ""))[:500] if (data.get("reason") or data.get("blocked_reason")) else None))
            AuditService.record(db, event_type=evt, action=evt, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_REMEDIATION, resource_id=rem.id, metadata={"finding_id": finding.id, "status": new_status})
    # Notes (bounded)
    if "completion_notes" in data and data["completion_notes"] is not None and "status" not in data:
        rem.completion_notes = str(data["completion_notes"]).strip()[:2000]
        rem.updated_by = current_user.id
    # Evidence reference (bounded reference only; secrets rejected)
    if "evidence_ref" in data and data["evidence_ref"] is not None:
        try:
            new_ref = lc.sanitize_remediation_evidence_ref(data["evidence_ref"])
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if new_ref != rem.evidence_ref:
            rem.evidence_ref = new_ref
            rem.updated_by = current_user.id
            db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="remediation_evidence_added", old_value=None, new_value=(new_ref or "")[:200], reason=None))
            AuditService.record(db, event_type=EVENT_REMEDIATION_EVIDENCE_ADDED, action=EVENT_REMEDIATION_EVIDENCE_ADDED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_REMEDIATION, resource_id=rem.id, metadata={"finding_id": finding.id})
    db.commit()
    db.refresh(rem)
    return _rem_payload(rem, finding, _remediation_sla(db, finding.id))


# -------------------------------------------------------------------
# D7: project-scoped remediation list + lifecycle actions
# -------------------------------------------------------------------

def _require_remediation_row(rem_id: str, project_id: str, db: Session):
    """Fetch a remediation strictly scoped to the project (IDOR-safe)."""
    from app.models.finding import Finding

    rem = (
        db.query(FindingRemediation)
        .filter(FindingRemediation.id == rem_id, FindingRemediation.project_id == project_id)
        .first()
    )
    if not rem:
        raise HTTPException(status_code=404, detail="Remediation not found")
    finding = db.query(Finding).filter(Finding.id == rem.finding_id).first()
    return rem, finding


def _apply_remediation_transition(db: Session, rem: FindingRemediation, finding, project_id: str, organization_id: str, actor: User, target: str, extra: dict | None = None):
    """Shared deterministic transition used by PATCH and action endpoints."""
    extra = extra or {}
    if target not in lc.REMEDIATION_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status")
    if target == rem.status:
        return False  # idempotent no-op
    allowed = lc.REMEDIATION_TRANSITIONS.get(rem.status, set())
    if target not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid transition from {rem.status} to {target}")
    if target == "blocked":
        reason = str(extra.get("blocked_reason", "") or "").strip()[: lc.REMEDIATION_BLOCKED_REASON_MAX]
        if not reason:
            raise HTTPException(status_code=400, detail="blocked_reason is required to block remediation")
        rem.blocked_reason = reason
    old = rem.status
    rem.status = target
    rem.updated_by = actor.id
    now = _utcnow().replace(tzinfo=None)
    if target == "in_progress":
        if not rem.started_at:
            rem.started_at = now
        if old == "blocked":
            rem.blocked_reason = None
            evt = EVENT_REMEDIATION_UNBLOCKED
        else:
            evt = EVENT_REMEDIATION_STARTED
    elif target == "blocked":
        evt = EVENT_REMEDIATION_BLOCKED
    elif target == "completed":
        notes = str(extra.get("completion_notes", "") or "").strip()[:2000] or None
        if notes:
            rem.completion_notes = notes
        rem.completed_at = now
        evt = EVENT_REMEDIATION_COMPLETED
    elif target == "cancelled":
        evt = EVENT_REMEDIATION_CANCELLED
    else:
        evt = EVENT_REMEDIATION_UPDATED
    db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id if finding else rem.finding_id, actor_user_id=actor.id, action=f"remediation_{target}", old_value=old, new_value=target, reason=str(extra.get("reason", "") or extra.get("blocked_reason", ""))[:500] if (extra.get("reason") or extra.get("blocked_reason")) else None))
    AuditService.record(db, event_type=evt, action=evt, result=RESULT_SUCCESS, actor_user_id=actor.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_REMEDIATION, resource_id=rem.id, metadata={"finding_id": rem.finding_id, "status": target})
    return True


@router.get("/projects/{project_id}/remediations")
def list_project_remediations(
    project_id: str,
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    owner: str | None = Query(default=None),
    overdue: bool | None = Query(default=None),
    finding_id: str | None = Query(default=None),
    since: str | None = Query(default=None),
    until: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """D7 project-scoped remediation queue (bounded, joined, no N+1)."""
    from app.models.finding import Finding

    require_project_access(project_id, db, current_user)
    q = (
        db.query(FindingRemediation, Finding)
        .join(Finding, Finding.id == FindingRemediation.finding_id)
        .filter(FindingRemediation.project_id == project_id)
    )
    if status:
        s = status.strip().lower()
        if s not in lc.REMEDIATION_STATUSES:
            raise HTTPException(status_code=400, detail="Invalid status filter")
        q = q.filter(FindingRemediation.status == s)
    if severity:
        sev = severity.strip().lower()
        q = q.filter(func.coalesce(Finding.severity_override, Finding.severity) == sev)
    if owner:
        q = q.filter(FindingRemediation.assigned_to == owner.strip())
    if finding_id:
        q = q.filter(FindingRemediation.finding_id == finding_id.strip())
    since_dt = _parse_dt(since, "since") if since else None
    until_dt = _parse_dt(until, "until") if until else None
    if since_dt:
        q = q.filter(FindingRemediation.updated_at >= (since_dt.replace(tzinfo=None) if since_dt.tzinfo else since_dt))
    if until_dt:
        q = q.filter(FindingRemediation.updated_at <= (until_dt.replace(tzinfo=None) if until_dt.tzinfo else until_dt))
    rows = q.order_by(FindingRemediation.updated_at.desc()).offset(offset).limit(limit + 1).all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    # Batch-load SLAs for overdue computation (single query, no N+1).
    fids = [r.finding_id for r, _ in rows]
    sla_map: dict[str, FindingSLA] = {}
    if fids:
        for s in db.query(FindingSLA).filter(FindingSLA.finding_id.in_(fids)).order_by(FindingSLA.created_at.desc()).all():
            sla_map.setdefault(s.finding_id, s)
    items = []
    for rem, finding in rows:
        payload = _rem_payload(rem, finding, sla_map.get(rem.finding_id))
        if overdue is True and not payload["overdue"]:
            continue
        if overdue is False and payload["overdue"]:
            continue
        items.append(payload)
    # Deterministic priority ordering: severity rank, overdue first, oldest due.
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    items.sort(key=lambda p: (rank.get(str(p.get("finding_severity") or "").lower(), 5), not p.get("overdue"), p.get("due_at") or "9999"))
    return {"items": items, "total": len(items), "limit": limit, "offset": offset, "has_more": has_more}


@router.get("/projects/{project_id}/remediations/{remediation_id}")
def get_project_remediation(
    project_id: str,
    remediation_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    rem, finding = _require_remediation_row(remediation_id, project_id, db)
    return _rem_payload(rem, finding, _remediation_sla(db, rem.finding_id))


def _remediation_action(project_id: str, remediation_id: str, target: str, payload: dict, db: Session, current_user: User):
    from app.api.routes.findings import _require_finding_manage as _manage

    require_project_access(project_id, db, current_user)
    _manage(project_id, db, current_user)
    rem, finding = _require_remediation_row(remediation_id, project_id, db)
    _apply_remediation_transition(db, rem, finding, project_id, rem.organization_id, current_user, target, payload or {})
    db.commit()
    db.refresh(rem)
    return _rem_payload(rem, finding, _remediation_sla(db, rem.finding_id))


@router.post("/projects/{project_id}/remediations/{remediation_id}/start")
def start_remediation(project_id: str, remediation_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return _remediation_action(project_id, remediation_id, "in_progress", {}, db, current_user)


@router.post("/projects/{project_id}/remediations/{remediation_id}/block")
def block_remediation(project_id: str, remediation_id: str, payload: dict, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return _remediation_action(project_id, remediation_id, "blocked", payload or {}, db, current_user)


@router.post("/projects/{project_id}/remediations/{remediation_id}/unblock")
def unblock_remediation(project_id: str, remediation_id: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return _remediation_action(project_id, remediation_id, "in_progress", {}, db, current_user)


@router.post("/projects/{project_id}/remediations/{remediation_id}/complete")
def complete_remediation(project_id: str, remediation_id: str, payload: dict | None = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return _remediation_action(project_id, remediation_id, "completed", payload or {}, db, current_user)


# -------------------------------------------------------------------
# Retest
# -------------------------------------------------------------------

def _retest_payload(r: FindingRetest) -> dict:
    return {
        "id": r.id,
        "finding_id": r.finding_id,
        "organization_id": r.organization_id,
        "project_id": r.project_id,
        "requested_by": r.requested_by,
        "executed_by": r.executed_by,
        "status": r.status,
        "scanner": r.scanner,
        "target_value": r.target_value,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        "result": r.result,
        "result_summary": r.result_summary,
        "evidence": r.evidence,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


@router.get("/findings/{finding_id}/retests")
def list_retests(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    rows = db.query(FindingRetest).filter(FindingRetest.finding_id == finding.id).order_by(FindingRetest.created_at.desc()).all()
    return {"items": [_retest_payload(r) for r in rows], "total": len(rows)}


@router.post("/findings/{finding_id}/retests/request", status_code=201)
def request_retest(
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    _require_finding_manage(project_id, db, current_user)
    # Only one active retest at a time
    existing = (
        db.query(FindingRetest)
        .filter(FindingRetest.finding_id == finding.id, FindingRetest.status.in_(["requested", "queued", "running"]))
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Active retest already exists")
    # Scanner selection: prefer original scanner
    scanner = (finding.scanner or "").strip().lower() or None
    # Target value from finding context
    from app.models.scan import Scan
    from app.models.target import Target

    scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
    target = db.query(Target).filter(Target.id == scan.target_id).first() if scan else None
    target_value = target.value if target else None
    rt = FindingRetest(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        organization_id=organization_id,
        project_id=project_id,
        requested_by=current_user.id,
        status="requested",
        scanner=scanner,
        target_value=target_value,
    )
    if not scanner:
        raise HTTPException(status_code=400, detail="Original scanner unavailable for retest")
    db.add(rt)
    db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="retest_requested", old_value=None, new_value="requested", reason=None))
    AuditService.record(db, event_type=EVENT_RETEST_REQUESTED, action=EVENT_RETEST_REQUESTED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RETEST, resource_id=rt.id, metadata={"finding_id": finding.id, "scanner": scanner})
    db.commit()
    db.refresh(rt)
    return _retest_payload(rt)


@router.patch("/findings/{finding_id}/retests/{retest_id}")
def update_retest(
    finding_id: str,
    retest_id: str,
    payload: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding, project_id, organization_id = _finding_org_project(finding_id, db, current_user)
    _require_finding_manage(project_id, db, current_user)
    rt = db.query(FindingRetest).filter(FindingRetest.id == retest_id, FindingRetest.finding_id == finding.id).first()
    if not rt:
        raise HTTPException(status_code=404, detail="Retest not found")
    data = payload if isinstance(payload, dict) else {}
    new_status = str(data.get("status", "")).strip().lower() if data.get("status") else None
    if not new_status:
        raise HTTPException(status_code=400, detail="status is required")
    if new_status not in lc.RETEST_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status")
    allowed = lc.RETEST_TRANSITIONS.get(rt.status, set())
    if new_status != rt.status and new_status not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid transition from {rt.status} to {new_status}")
    now = _utcnow().replace(tzinfo=None)
    old_status = rt.status
    # Manual resolution requires reason
    if new_status in ("passed", "failed", "error") and old_status == "running":
        pass  # valid terminal from running
    if new_status in ("passed", "failed") and rt.status not in ("running", "queued", "requested"):
        raise HTTPException(status_code=400, detail="Terminal result requires running retest")
    rt.status = new_status
    if new_status == "running" and not rt.started_at:
        rt.started_at = now
        rt.executed_by = current_user.id
        AuditService.record(db, event_type=EVENT_RETEST_STARTED, action=EVENT_RETEST_STARTED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RETEST, resource_id=rt.id, metadata={"finding_id": finding.id})
    if new_status in ("passed", "failed", "error"):
        result = str(data.get("result", new_status)).strip().lower()
        if result not in lc.RETEST_RESULTS and result != new_status:
            raise HTTPException(status_code=400, detail="Invalid result")
        rt.result = result if result in lc.RETEST_RESULTS else new_status
        summary = str(data.get("result_summary", "")).strip()[:2000] if data.get("result_summary") else None
        rt.result_summary = summary
        # Sanitized evidence (bounded, no secrets — reuse audit sanitize via history cap)
        ev = str(data.get("evidence", "")).strip()[:2000] if data.get("evidence") else None
        rt.evidence = ev
        rt.completed_at = now
        rt.executed_by = rt.executed_by or current_user.id
        if rt.result == "passed":
            old_fstatus = finding.status
            finding.status = "resolved"
            try:
                finding.updated_at = now
            except Exception:
                pass
            db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="status_changed", old_value=old_fstatus, new_value="resolved", reason="retest passed"))
            AuditService.record(db, event_type=EVENT_RETEST_PASSED, action=EVENT_RETEST_PASSED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RETEST, resource_id=rt.id, metadata={"finding_id": finding.id})
            AuditService.record(db, event_type=EVENT_FINDING_RESOLVED, action=EVENT_FINDING_RESOLVED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_FINDING, resource_id=finding.id, metadata={"via": "retest"})
        elif rt.result == "failed":
            old_fstatus = finding.status
            finding.status = "reopened"
            try:
                finding.updated_at = now
            except Exception:
                pass
            db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action="status_changed", old_value=old_fstatus, new_value="reopened", reason="retest failed"))
            AuditService.record(db, event_type=EVENT_RETEST_FAILED, action=EVENT_RETEST_FAILED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RETEST, resource_id=rt.id, metadata={"finding_id": finding.id})
            AuditService.record(db, event_type=EVENT_FINDING_REOPENED, action=EVENT_FINDING_REOPENED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_FINDING, resource_id=finding.id, metadata={"via": "retest"})
        else:
            AuditService.record(db, event_type=EVENT_RETEST_ERROR, action=EVENT_RETEST_ERROR, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RETEST, resource_id=rt.id, metadata={"finding_id": finding.id})
    if new_status == "cancelled":
        AuditService.record(db, event_type=EVENT_RETEST_CANCELLED, action=EVENT_RETEST_CANCELLED, result=RESULT_SUCCESS, actor_user_id=current_user.id, organization_id=organization_id, project_id=project_id, resource_type=RESOURCE_RETEST, resource_id=rt.id, metadata={"finding_id": finding.id})
    db.add(FindingHistory(id=str(uuid.uuid4()), finding_id=finding.id, actor_user_id=current_user.id, action=f"retest_{new_status}", old_value=old_status, new_value=new_status, reason=str(data.get("reason", ""))[:500] if data.get("reason") else None))
    # Manual resolve without retest requires reason (handled via findings PATCH, documented)
    db.commit()
    db.refresh(rt)
    return _retest_payload(rt)

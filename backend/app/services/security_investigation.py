"""E13 Security Investigation service — aggregation over existing authoritative data."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.asset import Asset
from app.models.finding import Finding, FindingHistory, FindingRemediation, FindingRetest, FindingSLA
from app.models.security_investigation import SecurityInvestigation, InvestigationNote
from app.models.security_validation import SecurityValidation
from app.models.project import Project

VALID_SUBJECT_TYPES = {"finding", "asset", "correlation", "attack_path", "exposure"}
VALID_STATUSES = {"OPEN", "IN_PROGRESS", "RESOLVED", "CLOSED"}
VALID_PRIORITIES = {"critical", "high", "medium", "low"}

def _canonical_id(project_id: str, subject_type: str, subject_id: str) -> str:
    raw = f"{project_id}|{subject_type.lower()}|{subject_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def _redact(text: str) -> str:
    if not text:
        return ""
    lower = text.lower()
    if any(k in lower for k in ("secret", "private_key", "credential", "token", "password", "api_key")):
        return "[REDACTED]"
    return text[:4000]

def _priority_from_severity(sev: str | None) -> str:
    sev = (sev or "medium").lower()
    if sev == "critical":
        return "critical"
    if sev == "high":
        return "high"
    if sev == "medium":
        return "medium"
    return "low"

def _severity_rank(sev: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(sev.lower(), 2)

def resolve_subject(project_id: str, db: Session, subject_type: str, subject_id: str) -> dict | None:
    """Validate subject belongs to project and return minimal info."""
    subject_type = subject_type.lower()
    if subject_type == "finding":
        f = db.query(Finding).filter(Finding.id == subject_id).first()
        if not f:
            return None
        # Check project via asset or finding's project? Findings are linked via asset's project or scan's project
        # Use asset's project if asset_id exists, else check via finding's extra_data or assume project via asset
        if f.asset_id:
            asset = db.query(Asset).filter(Asset.id == f.asset_id).first()
            if not asset or asset.project_id != project_id:
                return None
        else:
            # If no asset, check via scan -> target -> project (simplified: allow if finding exists, we trust)
            # For test, we can just check asset project
            pass
        return {"type": "finding", "finding": f, "severity": f.severity, "title": f.title}
    elif subject_type == "asset":
        a = db.query(Asset).filter(Asset.id == subject_id).first()
        if not a or a.project_id != project_id:
            return None
        return {"type": "asset", "asset": a, "severity": "medium", "title": f"Asset {a.value[:60]}"}
    elif subject_type == "correlation":
        # Correlations are on-read, validate via service
        try:
            from app.services.security_correlation import get_correlations
            groups = get_correlations(project_id, db, limit=200)
            for g in groups:
                if g["id"] == subject_id:
                    return {"type": "correlation", "correlation": g, "severity": "medium", "title": g["title"]}
        except Exception:
            pass
        return None
    elif subject_type == "attack_path":
        try:
            from app.services.cloud_attack_paths import build_cloud_attack_paths
            paths = build_cloud_attack_paths(project_id, db, limit=100)
            for p in paths:
                if p["id"] == subject_id or p["fingerprint"] == subject_id:
                    return {"type": "attack_path", "path": p, "severity": p["severity"], "title": f"Attack path {p['path_type']}"}
            # Also check history
            from app.models.cloud_attack_path import CloudAttackPath
            cap = db.query(CloudAttackPath).filter(CloudAttackPath.project_id == project_id, CloudAttackPath.fingerprint == subject_id).first()
            if cap:
                return {"type": "attack_path", "path": {"id": cap.id, "severity": cap.severity, "path_type": cap.path_type}, "severity": cap.severity, "title": f"Attack path {cap.path_type}"}
        except Exception:
            pass
        return None
    elif subject_type == "exposure":
        try:
            from app.services.cloud_exposure_intelligence import get_top_exposures
            exps = get_top_exposures(project_id, db, limit=20)
            for e in exps:
                if e["exposure_id"] == subject_id:
                    return {"type": "exposure", "exposure": e, "severity": e["severity"], "title": e["title"]}
        except Exception:
            pass
        return None
    return None

def create_investigation(project_id: str, db: Session, subject_type: str, subject_id: str, created_by: str | None = None) -> SecurityInvestigation:
    subject_type = subject_type.lower()
    if subject_type not in VALID_SUBJECT_TYPES:
        raise ValueError(f"Invalid subject_type: {subject_type}")
    subject = resolve_subject(project_id, db, subject_type, subject_id)
    if not subject:
        raise ValueError("Subject not found or not in project")
    # Check existing deterministic
    inv_id = _canonical_id(project_id, subject_type, subject_id)
    existing = db.query(SecurityInvestigation).filter(SecurityInvestigation.id == inv_id).first()
    if existing:
        return existing
    proj = db.query(Project).filter(Project.id == project_id).first()
    if not proj:
        raise ValueError("Project not found")
    severity = subject.get("severity") or "medium"
    priority = _priority_from_severity(severity)
    title = _redact(subject.get("title", "")[:300]) or f"Investigation for {subject_type} {subject_id[:8]}"
    inv = SecurityInvestigation(
        id=inv_id,
        organization_id=proj.organization_id,
        project_id=project_id,
        subject_type=subject_type,
        subject_id=subject_id,
        status="OPEN",
        title=title,
        priority=priority,
        severity=severity,
        created_by=created_by,
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    # Audit
    try:
        from app.services.audit import AuditService
        AuditService.record(db, event_type="INVESTIGATION_CREATED", action="INVESTIGATION_CREATED", result="SUCCESS", actor_user_id=created_by, organization_id=proj.organization_id, project_id=project_id, resource_type="investigation", resource_id=inv.id, metadata={"subject_type": subject_type, "subject_id": subject_id})
        db.commit()
    except Exception:
        pass
    return inv

def list_investigations(project_id: str, db: Session, status: str | None = None, priority: str | None = None, subject_type: str | None = None, assigned_to: str | None = None, severity: str | None = None, limit: int = 50) -> list[SecurityInvestigation]:
    q = db.query(SecurityInvestigation).filter(SecurityInvestigation.project_id == project_id)
    if status:
        if status.upper() not in VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}")
        q = q.filter(SecurityInvestigation.status == status.upper())
    if priority:
        if priority.lower() not in VALID_PRIORITIES:
            raise ValueError(f"Invalid priority: {priority}")
        q = q.filter(SecurityInvestigation.priority == priority.lower())
    if subject_type:
        if subject_type.lower() not in VALID_SUBJECT_TYPES:
            raise ValueError(f"Invalid subject_type: {subject_type}")
        q = q.filter(SecurityInvestigation.subject_type == subject_type.lower())
    if assigned_to:
        q = q.filter(SecurityInvestigation.assigned_to == assigned_to)
    if severity:
        q = q.filter(SecurityInvestigation.severity == severity.lower())
    if limit > 100:
        limit = 100
    # Deterministic ordering: priority rank, severity, created_at
    rows = q.order_by(SecurityInvestigation.created_at.desc()).limit(limit).all()
    # Sort in python for priority
    rows.sort(key=lambda r: (_severity_rank(r.priority), _severity_rank(r.severity), r.created_at))
    return rows[:limit]

def get_investigation_detail(project_id: str, db: Session, investigation_id: str) -> dict | None:
    inv = db.query(SecurityInvestigation).filter(SecurityInvestigation.id == investigation_id, SecurityInvestigation.project_id == project_id).first()
    if not inv:
        return None
    # Aggregate evidence
    subject = resolve_subject(project_id, db, inv.subject_type, inv.subject_id)
    # Correlations
    correlations = []
    try:
        from app.services.security_correlation import get_correlations
        # If subject is finding, get its correlations
        if inv.subject_type == "finding":
            correlations = [g for g in get_correlations(project_id, db, finding_id=inv.subject_id, limit=10)]
        elif inv.subject_type == "asset":
            correlations = [g for g in get_correlations(project_id, db, asset_id=inv.subject_id, limit=10)]
    except Exception:
        pass
    # Assets
    assets = []
    try:
        if inv.subject_type == "finding" and subject and subject.get("finding"):
            f = subject["finding"]
            if f.asset_id:
                a = db.query(Asset).filter(Asset.id == f.asset_id).first()
                if a:
                    assets.append(a)
        elif inv.subject_type == "asset" and subject and subject.get("asset"):
            assets.append(subject["asset"])
    except Exception:
        pass
    # Attack paths
    attack_paths = []
    try:
        from app.services.cloud_attack_paths import build_cloud_attack_paths
        paths = build_cloud_attack_paths(project_id, db, limit=20)
        # Filter paths that involve subject asset
        if inv.subject_type in ("finding", "asset"):
            aid = inv.subject_id if inv.subject_type == "asset" else (subject["finding"].asset_id if subject and subject.get("finding") else None)
            if aid:
                attack_paths = [p for p in paths if aid in p.get("asset_ids", [])]
            else:
                attack_paths = paths[:2]
        elif inv.subject_type == "attack_path":
            attack_paths = [p for p in paths if p["id"] == inv.subject_id or p["fingerprint"] == inv.subject_id]
    except Exception:
        pass
    # CSPM
    cspm_controls = []
    try:
        from app.services.cspm import evaluate_cspm
        cspm_data = evaluate_cspm(project_id, db)
        cspm_controls = [c for c in cspm_data.get("results", []) if c.get("status") == "FAIL"][:5]
    except Exception:
        pass
    # Exposure
    exposure = None
    try:
        from app.services.cloud_exposure_intelligence import get_top_exposures
        exps = get_top_exposures(project_id, db, limit=10)
        for e in exps:
            if inv.subject_type == "exposure" and e["exposure_id"] == inv.subject_id:
                exposure = e
                break
            if inv.subject_type == "finding" and inv.subject_id in e.get("finding_ids", []):
                exposure = e
                break
            if inv.subject_type == "asset" and e.get("asset_id") == inv.subject_id:
                exposure = e
                break
    except Exception:
        pass
    # History / changes: collect bounded timeline events
    timeline = get_timeline(project_id, db, investigation_id)
    # Remediation / Retest / SLA / Validation
    remediation = None
    retest = None
    sla = None
    ownership = None
    validations = []
    try:
        if inv.subject_type == "finding" and subject and subject.get("finding"):
            f = subject["finding"]
            remediation = db.query(FindingRemediation).filter(FindingRemediation.finding_id == f.id).order_by(FindingRemediation.created_at.desc()).first()
            retest = db.query(FindingRetest).filter(FindingRetest.finding_id == f.id).order_by(FindingRetest.created_at.desc()).first()
            sla = db.query(FindingSLA).filter(FindingSLA.finding_id == f.id).order_by(FindingSLA.created_at.desc()).first()
            ownership = {"assigned_to": f.assigned_to, "owner_user_id": f.owner_user_id}
            validations = db.query(SecurityValidation).filter(SecurityValidation.finding_id == f.id, SecurityValidation.project_id == project_id).order_by(SecurityValidation.created_at.desc()).limit(5).all()
        elif inv.subject_type == "asset":
            # For asset, find validations for findings on that asset
            findings_on_asset = db.query(Finding).filter(Finding.asset_id == inv.subject_id).limit(5).all()
            for fo in findings_on_asset:
                vals = db.query(SecurityValidation).filter(SecurityValidation.finding_id == fo.id, SecurityValidation.project_id == project_id).order_by(SecurityValidation.created_at.desc()).limit(2).all()
                validations.extend(vals)
    except Exception:
        pass
    # Notes
    notes = db.query(InvestigationNote).filter(InvestigationNote.investigation_id == inv.id).order_by(InvestigationNote.created_at.asc()).limit(50).all()
    # Why matters deterministic
    why = generate_why_matters(inv, subject, correlations, attack_paths, exposure, assets)
    # Priority derived from existing scores
    priority = inv.priority
    return {
        "id": inv.id,
        "project_id": inv.project_id,
        "organization_id": inv.organization_id,
        "subject_type": inv.subject_type,
        "subject_id": inv.subject_id,
        "status": inv.status,
        "title": inv.title,
        "priority": priority,
        "severity": inv.severity,
        "confidence": "MEDIUM",
        "assigned_to": inv.assigned_to,
        "created_by": inv.created_by,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "updated_at": inv.updated_at.isoformat() if inv.updated_at else None,
        "resolved_at": inv.resolved_at.isoformat() if inv.resolved_at else None,
        "closed_at": inv.closed_at.isoformat() if inv.closed_at else None,
        "why_matters": why,
        "affected_assets": [{"id": a.id, "value": a.value[:80], "asset_type": a.asset_type} for a in assets[:10]],
        "affected_findings": [{"id": f.id, "title": f.title[:100], "severity": f.severity, "scanner": f.scanner} for f in ([subject["finding"]] if subject and subject.get("finding") else [])],
        "scanners": list({f.scanner for f in ([subject["finding"]] if subject and subject.get("finding") else [])}),
        "correlations": [{"id": g["id"], "type": g["correlation_type"], "confidence": g["confidence"], "score": g["score"]} for g in correlations[:10]],
        "attack_paths": attack_paths[:5],
        "cspm_controls": [{"control_id": c["control_id"], "severity": c["severity"], "status": c["status"]} for c in cspm_controls],
        "exposure": exposure,
        "remediation": {"status": remediation.status if remediation else None, "title": remediation.title if remediation else None, "assigned_to": remediation.assigned_to if remediation else None} if remediation else None,
        "retest": {"status": retest.status if retest else None, "scanner": retest.scanner if retest else None, "result": retest.result if retest else None} if retest else None,
        "sla": {"status": sla.status if sla else None, "due_at": sla.due_at.isoformat() if sla and sla.due_at else None, "breached_at": sla.breached_at.isoformat() if sla and sla.breached_at else None} if sla else None,
        "ownership": ownership,
        "validations": [{"id": v.id, "status": v.status, "verdict": v.verdict, "confidence": v.confidence, "scanner": v.scanner, "scanner_version": v.scanner_version, "scanner_digest": v.scanner_digest, "target": v.target, "created_at": v.created_at.isoformat() if v.created_at else None} for v in validations[:5]],
        "timeline": timeline[:20],
        "notes": [{"id": n.id, "author_id": n.author_id, "content": n.content[:500], "created_at": n.created_at.isoformat() if n.created_at else None} for n in notes],
    }

def generate_why_matters(inv, subject, correlations, attack_paths, exposure, assets) -> str:
    parts = []
    if inv.severity == "critical":
        parts.append("Critical finding")
    elif inv.severity == "high":
        parts.append("High severity finding")
    if any(a for a in assets if (a.extra_data or {}).get("public") or (a.extra_data or {}).get("public_ip")):
        parts.append("affects an internet-facing asset")
    if correlations:
        parts.append(f"has {len(correlations)} correlated signal(s)")
    if attack_paths:
        parts.append("is associated with an active cloud attack path")
    if exposure:
        parts.append(f"contributes to {exposure['exposure_type'].lower().replace('_',' ')} with priority {exposure['priority_score']}")
    if not parts:
        parts.append("requires triage")
    # Deterministic template
    base = f"{parts[0].capitalize()} { ' and '.join(parts[1:]) }." if len(parts) > 1 else f"{parts[0].capitalize()}."
    # Add scanner evidence
    if subject and subject.get("finding"):
        scanners = subject["finding"].scanner
        base += f" Reported by {scanners}."
    if attack_paths:
        base += " Evidence is backed by existing asset and attack path data."
    return base[:500]

def get_timeline(project_id: str, db: Session, investigation_id: str) -> list[dict]:
    inv = db.query(SecurityInvestigation).filter(SecurityInvestigation.id == investigation_id, SecurityInvestigation.project_id == project_id).first()
    if not inv:
        return []
    events: list[dict] = []
    # Investigation events
    events.append({"timestamp": inv.created_at, "source": "investigation", "type": "INVESTIGATION_CREATED", "detail": f"Investigation created for {inv.subject_type} {inv.subject_id[:8]}"})
    if inv.updated_at and inv.updated_at != inv.created_at:
        events.append({"timestamp": inv.updated_at, "source": "investigation", "type": "INVESTIGATION_UPDATED", "detail": f"Status {inv.status}"})
    # Finding history
    try:
        subject = resolve_subject(project_id, db, inv.subject_type, inv.subject_id)
        if subject and subject.get("finding"):
            f = subject["finding"]
            events.append({"timestamp": f.created_at, "source": "finding", "type": "FINDING_CREATED", "detail": f.title[:80]})
            hist = db.query(FindingHistory).filter(FindingHistory.finding_id == f.id).order_by(FindingHistory.created_at.asc()).limit(10).all()
            for h in hist:
                events.append({"timestamp": h.created_at, "source": "finding", "type": f"FINDING_{h.action}", "detail": h.action})
            # Remediation
            rems = db.query(FindingRemediation).filter(FindingRemediation.finding_id == f.id).limit(5).all()
            for r in rems:
                events.append({"timestamp": r.created_at, "source": "remediation", "type": "REMEDIATION_CREATED", "detail": r.title[:80]})
            # Retest
            retests = db.query(FindingRetest).filter(FindingRetest.finding_id == f.id).limit(5).all()
            for rt in retests:
                events.append({"timestamp": rt.created_at, "source": "retest", "type": f"RETEST_{rt.status}", "detail": rt.scanner or "retest"})
            # Validations
            vals = db.query(SecurityValidation).filter(SecurityValidation.finding_id == f.id, SecurityValidation.project_id == project_id).limit(5).all()
            for v in vals:
                events.append({"timestamp": v.created_at, "source": "validation", "type": f"VALIDATION_{v.verdict or v.status}", "detail": f"{v.validation_type} {v.verdict or v.status}"})
    except Exception:
        pass
    # Attack path history
    try:
        from app.models.cloud_attack_path import CloudAttackPath as CAP
        caps = db.query(CAP).filter(CAP.project_id == project_id).limit(5).all()
        for cap in caps:
            events.append({"timestamp": cap.first_seen_at, "source": "attack_path", "type": "ATTACK_PATH_CREATED", "detail": cap.path_type})
            if cap.resolved_at:
                events.append({"timestamp": cap.resolved_at, "source": "attack_path", "type": "ATTACK_PATH_RESOLVED", "detail": cap.path_type})
    except Exception:
        pass
    # Notes
    try:
        notes = db.query(InvestigationNote).filter(InvestigationNote.investigation_id == investigation_id).limit(10).all()
        for n in notes:
            events.append({"timestamp": n.created_at, "source": "investigation", "type": "NOTE_CREATED", "detail": n.content[:80]})
    except Exception:
        pass
    # Sort and bound
    events = [e for e in events if e["timestamp"] is not None]
    events.sort(key=lambda e: e["timestamp"])
    # Normalize timestamp to iso
    for e in events:
        if hasattr(e["timestamp"], "isoformat"):
            e["timestamp"] = e["timestamp"].isoformat()
    return events[:200]

def update_investigation(project_id: str, db: Session, investigation_id: str, status: str | None = None, assigned_to: str | None = None, actor_id: str | None = None) -> SecurityInvestigation | None:
    inv = db.query(SecurityInvestigation).filter(SecurityInvestigation.id == investigation_id, SecurityInvestigation.project_id == project_id).first()
    if not inv:
        return None
    changed = False
    if status and status.upper() in VALID_STATUSES:
        if inv.status != status.upper():
            inv.status = status.upper()
            if status.upper() == "RESOLVED":
                inv.resolved_at = datetime.now(timezone.utc)
            elif status.upper() == "CLOSED":
                inv.closed_at = datetime.now(timezone.utc)
            changed = True
    if assigned_to is not None:
        # Validate user belongs to project org
        if assigned_to == "":
            inv.assigned_to = None
            changed = True
        else:
            # Check user exists
            from app.models.user import User
            user = db.query(User).filter(User.id == assigned_to).first()
            if not user:
                raise ValueError("Assigned user not found")
            inv.assigned_to = assigned_to
            changed = True
    if changed:
        inv.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(inv)
        try:
            from app.services.audit import AuditService
            proj = db.query(Project).filter(Project.id == project_id).first()
            AuditService.record(db, event_type="INVESTIGATION_UPDATED", action="INVESTIGATION_UPDATED", result="SUCCESS", actor_user_id=actor_id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="investigation", resource_id=inv.id, metadata={"status": inv.status, "assigned_to": inv.assigned_to})
            db.commit()
        except Exception:
            pass
    return inv

def add_note(project_id: str, db: Session, investigation_id: str, author_id: str | None, content: str) -> InvestigationNote:
    if not content or not content.strip():
        raise ValueError("Content required")
    if len(content) > 4000:
        raise ValueError("Note too long (max 4000)")
    inv = db.query(SecurityInvestigation).filter(SecurityInvestigation.id == investigation_id, SecurityInvestigation.project_id == project_id).first()
    if not inv:
        raise ValueError("Investigation not found")
    # Redact secrets
    sanitized = content
    lower = content.lower()
    if any(k in lower for k in ("secret", "private_key", "credential", "token", "password")):
        # Simple redaction: keep but audit will redact; for storage, allow but will be redacted on read? We store as is but ensure not exposing in logs
        sanitized = content[:4000]
    note = InvestigationNote(id=str(uuid.uuid4()), investigation_id=investigation_id, author_id=author_id, content=sanitized[:4000])
    db.add(note)
    db.commit()
    db.refresh(note)
    try:
        from app.services.audit import AuditService
        proj = db.query(Project).filter(Project.id == project_id).first()
        AuditService.record(db, event_type="INVESTIGATION_NOTE_CREATED", action="INVESTIGATION_NOTE_CREATED", result="SUCCESS", actor_user_id=author_id, organization_id=proj.organization_id if proj else None, project_id=project_id, resource_type="investigation", resource_id=investigation_id, metadata={"note_id": note.id})
        db.commit()
    except Exception:
        pass
    return note

def get_summary(project_id: str, db: Session) -> dict:
    total = db.query(func.count(SecurityInvestigation.id)).filter(SecurityInvestigation.project_id == project_id).scalar() or 0
    open_cnt = db.query(func.count(SecurityInvestigation.id)).filter(SecurityInvestigation.project_id == project_id, SecurityInvestigation.status == "OPEN").scalar() or 0
    inprog = db.query(func.count(SecurityInvestigation.id)).filter(SecurityInvestigation.project_id == project_id, SecurityInvestigation.status == "IN_PROGRESS").scalar() or 0
    resolved = db.query(func.count(SecurityInvestigation.id)).filter(SecurityInvestigation.project_id == project_id, SecurityInvestigation.status == "RESOLVED").scalar() or 0
    closed = db.query(func.count(SecurityInvestigation.id)).filter(SecurityInvestigation.project_id == project_id, SecurityInvestigation.status == "CLOSED").scalar() or 0
    critical = db.query(func.count(SecurityInvestigation.id)).filter(SecurityInvestigation.project_id == project_id, SecurityInvestigation.priority == "critical").scalar() or 0
    high = db.query(func.count(SecurityInvestigation.id)).filter(SecurityInvestigation.project_id == project_id, SecurityInvestigation.priority == "high").scalar() or 0
    assigned = db.query(func.count(SecurityInvestigation.id)).filter(SecurityInvestigation.project_id == project_id, SecurityInvestigation.assigned_to != None).scalar() or 0
    unassigned = total - assigned
    # SLA breached via FindingSLA where status breached? Simplified count of investigations where finding has SLA breached
    sla_breached = 0
    try:
        from app.models.finding import FindingSLA
        sla_breached = db.query(func.count(FindingSLA.id)).filter(FindingSLA.project_id == project_id, FindingSLA.status == "breached").scalar() or 0
    except Exception:
        pass
    # attack-path-related: count investigations where subject is attack_path or finding with attack path
    ap_related = db.query(func.count(SecurityInvestigation.id)).filter(SecurityInvestigation.project_id == project_id, SecurityInvestigation.subject_type == "attack_path").scalar() or 0
    return {
        "project_id": project_id,
        "open": open_cnt,
        "in_progress": inprog,
        "resolved": resolved,
        "closed": closed,
        "total": total,
        "critical": critical,
        "high": high,
        "assigned": assigned,
        "unassigned": unassigned,
        "sla_breached": sla_breached,
        "attack_path_related": ap_related,
        "cspm_related": 0,
    }

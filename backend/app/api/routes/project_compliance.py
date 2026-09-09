"""Project compliance evidence APIs (D5): summary, controls, evidence.

Read-only evaluation over existing VAPT evidence. All ownership is
derived server-side from the path project; control IDs are catalog-global
static knowledge, evidence rows are always project-filtered. No new
permission: any project member may read. Reads are not audited.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.user import User
from app.services.control_evaluation import coverage_summary, evaluate_project
from app.services.control_evidence_catalog import (
    CONTROLS,
    EVIDENCE_FRAMEWORK,
    get_control,
    seed_evidence_catalog,
)

router = APIRouter(prefix="/api/v1", tags=["Project Compliance"])


def _framework_or_400(framework: str | None) -> None:
    if framework is None:
        return
    if str(framework).strip().lower() not in (
        EVIDENCE_FRAMEWORK["framework"],
        EVIDENCE_FRAMEWORK["framework"].replace("_", "-"),
    ):
        raise HTTPException(
            status_code=400,
            detail="Evidence evaluation supports the vapt_control_readiness catalog only",
        )


def _control_payload(ev: dict, control: dict) -> dict:
    return {
        "framework": EVIDENCE_FRAMEWORK["framework"],
        "framework_version": EVIDENCE_FRAMEWORK["version"],
        "control_id": ev["control_id"],
        "title": control.get("title") if control else ev["control_id"],
        "description": control.get("description") if control else None,
        "category": control.get("category") if control else None,
        "importance": control.get("importance") if control else None,
        "status": ev["status"],
        "confidence": ev["confidence"],
        "freshness": ev["freshness"],
        "reasons": ev.get("reasons") or [],
        "supporting_count": len(ev.get("supporting") or []),
        "contradictory_count": len(ev.get("contradictory") or []),
        "evaluated_at": ev.get("evaluated_at"),
    }


@router.get("/projects/{project_id}/compliance/summary")
def compliance_summary(
    project_id: str,
    framework: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _framework_or_400(framework)
    seed_evidence_catalog(db)
    evaluations = evaluate_project(db, project_id)
    by_id = {c["control_id"]: c for c in CONTROLS}
    summary = coverage_summary(evaluations)
    return {
        "project_id": project_id,
        "framework": EVIDENCE_FRAMEWORK["framework"],
        "framework_version": EVIDENCE_FRAMEWORK["version"],
        "framework_display_name": EVIDENCE_FRAMEWORK["display_name"],
        "disclaimer": (
            "Evidence coverage / readiness only. Not certification, "
            "not an audit, not a compliance guarantee."
        ),
        **summary,
        "controls": [_control_payload(ev, by_id.get(ev["control_id"])) for ev in evaluations],
    }


@router.get("/projects/{project_id}/compliance/controls")
def compliance_controls(
    project_id: str,
    framework: str | None = Query(default=None),
    status: str | None = Query(default=None),
    category: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    _framework_or_400(framework)
    seed_evidence_catalog(db)
    evaluations = evaluate_project(db, project_id)
    by_id = {c["control_id"]: c for c in CONTROLS}
    items = [_control_payload(ev, by_id.get(ev["control_id"])) for ev in evaluations]
    if status:
        want = str(status).strip().upper()[:20]
        if want not in ("PASS", "PARTIAL", "FAIL", "NOT_ASSESSED", "NOT_APPLICABLE"):
            raise HTTPException(status_code=400, detail="Invalid status")
        items = [i for i in items if i["status"] == want]
    if category:
        want = str(category).strip().lower()[:100]
        items = [i for i in items if str(i.get("category") or "").lower() == want]
    total = len(items)
    total_pages = (total + page_size - 1) // page_size if total else 0
    rows = items[(page - 1) * page_size: page * page_size]
    return {"items": rows, "total": total, "page": page, "page_size": page_size, "total_pages": total_pages}


@router.get("/projects/{project_id}/compliance/controls/{control_id}")
def compliance_control_detail(
    project_id: str,
    control_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    control = get_control(control_id)
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")
    seed_evidence_catalog(db)
    evaluations = evaluate_project(db, project_id, [control])
    ev = evaluations[0]
    payload = _control_payload(ev, control)
    payload["supporting"] = ev.get("supporting") or []
    payload["contradictory"] = ev.get("contradictory") or []
    return payload


@router.get("/projects/{project_id}/compliance/controls/{control_id}/evidence")
def compliance_control_evidence(
    project_id: str,
    control_id: str,
    kind: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    control = get_control(control_id)
    if not control:
        raise HTTPException(status_code=404, detail="Control not found")
    if kind is not None and str(kind).strip().lower() not in ("supporting", "contradictory"):
        raise HTTPException(status_code=400, detail="Invalid kind")
    seed_evidence_catalog(db)
    evaluations = evaluate_project(db, project_id, [control])
    ev = evaluations[0]
    supporting = ev.get("supporting") or []
    contradictory = ev.get("contradictory") or []
    want = str(kind).strip().lower() if kind else None
    return {
        "project_id": project_id,
        "control_id": control_id,
        "status": ev["status"],
        "supporting": supporting if want in (None, "supporting") else [],
        "contradictory": contradictory if want in (None, "contradictory") else [],
        "total_supporting": len(supporting),
        "total_contradictory": len(contradictory),
    }

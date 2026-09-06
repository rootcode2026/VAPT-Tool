from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.database import get_db
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target
from app.models.finding import Finding
from app.models.user import User


router = APIRouter(
    prefix="/api/v1/dashboard",
    tags=["Dashboard"],
)


@router.get("/summary")
def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Backward compat for isolated test DBs without workflow columns
    try:
        from app.api.routes.findings import _ensure_finding_workflow_columns

        _ensure_finding_workflow_columns(db)
    except Exception:
        pass
    # ---------------------------------------------------------
    # Scan statistics — org-scoped via Scan -> Target -> Project
    # ---------------------------------------------------------

    def _scan_q():
        return (
            db.query(Scan)
            .join(Target, Target.id == Scan.target_id)
            .join(Project, Project.id == Target.project_id)
            .filter(Project.organization_id == current_user.organization_id)
        )

    def _finding_q():
        try:
            return (
                db.query(Finding)
                .join(Target, Target.id == Finding.target_id)
                .join(Project, Project.id == Target.project_id)
                .filter(Project.organization_id == current_user.organization_id)
            )
        except Exception as exc:
            # Backward compat: isolated test DBs without new finding columns
            if "no such column" in str(exc).lower():
                try:
                    db.rollback()
                except Exception:
                    pass
                try:
                    from app.api.routes.findings import _ensure_finding_workflow_columns

                    _ensure_finding_workflow_columns(db)
                except Exception:
                    pass
                return (
                    db.query(Finding)
                    .join(Target, Target.id == Finding.target_id)
                    .join(Project, Project.id == Target.project_id)
                    .filter(Project.organization_id == current_user.organization_id)
                )
            raise

    total_scans = _scan_q().count() or 0

    completed_scans = _scan_q().filter(Scan.status == "completed").count() or 0

    running_scans = (
        _scan_q().filter(Scan.status.in_(["queued", "running"])).count() or 0
    )

    failed_scans = _scan_q().filter(Scan.status == "failed").count() or 0

    # ---------------------------------------------------------
    # Finding statistics — org-scoped
    # ---------------------------------------------------------

    total_findings = _finding_q().count() or 0

    critical_findings = _finding_q().filter(Finding.severity == "critical").count() or 0

    high_findings = _finding_q().filter(Finding.severity == "high").count() or 0

    medium_findings = _finding_q().filter(Finding.severity == "medium").count() or 0

    low_findings = _finding_q().filter(Finding.severity == "low").count() or 0

    info_findings = _finding_q().filter(Finding.severity == "info").count() or 0

    # ---------------------------------------------------------
    # Risk score — org-scoped
    # ---------------------------------------------------------

    average_risk_score = (
        db.query(func.avg(Scan.risk_score))
        .join(Target, Target.id == Scan.target_id)
        .join(Project, Project.id == Target.project_id)
        .filter(
            Project.organization_id == current_user.organization_id,
            Scan.risk_score.is_not(None),
        )
        .scalar()
    )

    if average_risk_score is not None:
        average_risk_score = round(
            float(average_risk_score),
            2,
        )

    # ---------------------------------------------------------
    # Response
    # ---------------------------------------------------------

    return {
        "scans": {
            "total": total_scans,
            "completed": completed_scans,
            "running": running_scans,
            "failed": failed_scans,
        },
        "findings": {
            "total": total_findings,
            "critical": critical_findings,
            "high": high_findings,
            "medium": medium_findings,
            "low": low_findings,
            "info": info_findings,
        },
        "risk": {
            "average_score": average_risk_score,
        },
    }
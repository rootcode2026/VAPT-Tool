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
    # Code Security summary (org-scoped)
    # ---------------------------------------------------------
    try:
        from app.models.asset import Asset as _Asset

        code_scanners = ("sast", "sca", "secrets", "container", "iac", "api")
        code_findings = _finding_q().filter(Finding.scanner.in_(code_scanners)).count() or 0
        code_critical = _finding_q().filter(Finding.scanner.in_(code_scanners), Finding.severity == "critical").count() or 0
        code_high = _finding_q().filter(Finding.scanner.in_(code_scanners), Finding.severity == "high").count() or 0
        secrets_count = _finding_q().filter(Finding.scanner == "secrets").count() or 0
        cloud_findings = _finding_q().filter(Finding.scanner == "cloud").count() or 0
        cloud_critical = _finding_q().filter(Finding.scanner == "cloud", Finding.severity == "critical").count() or 0

        # assets - org via project join not available directly, use subquery via project
        from app.models.project import Project as _Project

        # count cloud resources/org via asset->project->org join
        cloud_accounts = (
            db.query(func.count(_Asset.id))
            .join(_Project, _Project.id == _Asset.project_id)
            .filter(_Project.organization_id == current_user.organization_id, _Asset.asset_type == "cloud_account")
            .scalar()
            or 0
        )
        cloud_resources = (
            db.query(func.count(_Asset.id))
            .join(_Project, _Project.id == _Asset.project_id)
            .filter(_Project.organization_id == current_user.organization_id, _Asset.asset_type == "cloud_resource")
            .scalar()
            or 0
        )
        repo_assets = (
            db.query(func.count(_Asset.id))
            .join(_Project, _Project.id == _Asset.project_id)
            .filter(_Project.organization_id == current_user.organization_id, _Asset.asset_type == "repository")
            .scalar()
            or 0
        )
        container_assets = (
            db.query(func.count(_Asset.id))
            .join(_Project, _Project.id == _Asset.project_id)
            .filter(_Project.organization_id == current_user.organization_id, _Asset.asset_type == "container_image")
            .scalar()
            or 0
        )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        code_findings = code_critical = code_high = secrets_count = cloud_findings = cloud_critical = cloud_accounts = cloud_resources = repo_assets = container_assets = 0

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
        "code_security": {
            "findings": code_findings,
            "critical": code_critical,
            "high": code_high,
            "secrets": secrets_count,
            "repositories": repo_assets,
            "container_images": container_assets,
        },
        "cloud_security": {
            "findings": cloud_findings,
            "critical": cloud_critical,
            "accounts": cloud_accounts,
            "resources": cloud_resources,
        },
        "network_security": {
            "findings": _finding_q().filter(Finding.scanner.in_(("nmap", "dns", "subdomain", "tls"))).count() or 0,
        },
        "web_security": {
            "findings": _finding_q().filter(Finding.scanner.in_(("nuclei", "zap", "nikto", "http_fingerprint"))).count() or 0,
        },
    }
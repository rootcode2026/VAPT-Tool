"""Project SOC dashboard summary (D4): one authoritative aggregated view.

The dashboard is an operational READ view over existing security data
(assets, findings, risk, runs, D2 change events, D3 alerts). It creates no
new data model and no new risk algorithm:

- risk: deterministic aggregation (AVG) of existing scan-level
  ``risk_score`` values produced by ``RiskAssessmentEngine``, graded with
  the same A/B/C/D thresholds used by reporting;
- open findings: status NOT IN the resolved set owned by finding
  lifecycle (mirrors ``worker/app/change_detection.py`` resolved set);
- alerts/changes/monitoring: direct aggregates over D3/D2/D1 tables.

All queries are project-scoped aggregates or small bounded lists (no N+1,
no full-history loads). Dashboard reads are not audited.
"""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, or_

from app.api.deps import get_current_user, require_project_access
from app.db.database import get_db
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.finding import Finding
from app.models.monitoring import MonitoringChangeEvent, MonitoringConfig, MonitoringRun
from app.models.scan import Scan
from app.models.target import Target
from app.models.user import User
from app.services.attack_surface import classify_exposure

from sqlalchemy.orm import Session

router = APIRouter(prefix="/api/v1", tags=["Project Dashboard"])

WINDOW_DAYS = {"24h": 1, "7d": 7, "30d": 30}

# Resolved finding statuses owned by finding lifecycle/routes (mirrors
# worker/app/change_detection.py RESOLVED_FINDING_STATUSES; duplicated
# here because the worker package is not importable backend-side).
RESOLVED_FINDING_STATUSES = frozenset(
    {"resolved", "closed", "remediated", "false_positive", "accepted_risk"}
)

# Risk grade thresholds identical to reporting (report_service parity).
_GRADE_CUTS = (("A", 90), ("B", 75), ("C", 50))

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_TOP_FINDINGS_LIMIT = 5
_TOP_ALERTS_LIMIT = 5
_RECENT_CHANGES_LIMIT = 10
_RECENT_RUNS_LIMIT = 5
_RISK_SCANS_LIMIT = 20
_EXPOSURE_CANDIDATE_LIMIT = 200


def _utcnow():
    return datetime.now(timezone.utc)


def _window_or_400(window: str) -> int:
    days = WINDOW_DAYS.get((window or "").strip().lower())
    if days is None:
        raise HTTPException(status_code=400, detail="Invalid window. Use 24h, 7d, or 30d.")
    return days


def _grade(score: float | None) -> str | None:
    if score is None:
        return None
    for grade, cutoff in _GRADE_CUTS:
        if score >= cutoff:
            return grade
    return "D"


def _sev_key(severity: str | None) -> str:
    s = str(severity or "info").strip().lower()
    if s == "informational":
        return "info"
    return s if s in _SEVERITY_ORDER else "info"


@router.get("/projects/{project_id}/dashboard/summary")
def project_dashboard_summary(
    project_id: str,
    window: str = Query(default="24h"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_project_access(project_id, db, current_user)
    days = _window_or_400(window)
    now = _utcnow().replace(tzinfo=None)
    cutoff = now - timedelta(days=days)

    # --- findings: one GROUP BY severity+status, open derived server-side ---
    sev_rows = (
        db.query(Finding.severity, Finding.status, func.count(Finding.id))
        .join(Target, Target.id == Finding.target_id)
        .filter(Target.project_id == project_id)
        .group_by(Finding.severity, Finding.status)
        .all()
    )
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    open_total = 0
    for raw_sev, status, count in sev_rows:
        sev = _sev_key(raw_sev)
        if status is None or str(status).lower() not in RESOLVED_FINDING_STATUSES:
            sev_counts[sev] = sev_counts.get(sev, 0) + int(count or 0)
            open_total += int(count or 0)

    # --- top findings: single ordered query with asset join (no N+1) ---
    sev_rank = case(
        (func.lower(Finding.severity) == "critical", 0),
        (func.lower(Finding.severity) == "high", 1),
        (func.lower(Finding.severity) == "medium", 2),
        (func.lower(Finding.severity) == "low", 3),
        (func.lower(Finding.severity) == "info", 4),
        else_=5,
    )
    top_finding_rows = (
        db.query(Finding, Asset.asset_type, Asset.value)
        .join(Target, Target.id == Finding.target_id)
        .outerjoin(Asset, Asset.id == Finding.asset_id)
        .filter(Target.project_id == project_id)
        .filter(or_(Finding.status.notin_(RESOLVED_FINDING_STATUSES), Finding.status.is_(None)))
        .order_by(sev_rank, Finding.score.desc(), Finding.created_at.desc())
        .limit(_TOP_FINDINGS_LIMIT)
        .all()
    )
    top_findings = []
    for finding, asset_type, asset_value in top_finding_rows:
        meta = finding.extra_data if isinstance(finding.extra_data, dict) else {}
        top_findings.append(
            {
                "id": finding.id,
                "title": finding.title,
                "severity": _sev_key(finding.severity),
                "status": finding.status,
                "score": finding.score,
                "scanner": finding.scanner,
                "asset_id": finding.asset_id,
                "asset_type": asset_type,
                "asset_value": asset_value,
                "confidence": meta.get("confidence_score", meta.get("confidence")),
                "created_at": finding.created_at.isoformat() if finding.created_at else None,
            }
        )

    # --- alerts: status/severity aggregates + top open/acknowledged ---
    alert_rows = (
        db.query(Alert.status, Alert.severity, func.count(Alert.id))
        .filter(Alert.project_id == project_id)
        .group_by(Alert.status, Alert.severity)
        .all()
    )
    active_alerts = 0
    open_alerts = 0
    ack_alerts = 0
    crit_alerts = 0
    high_alerts = 0
    for status, severity, count in alert_rows:
        n = int(count or 0)
        sev = _sev_key(severity)
        if str(status or "").lower() in ("open", "acknowledged"):
            active_alerts += n
            if sev == "critical":
                crit_alerts += n
            elif sev == "high":
                high_alerts += n
        if str(status or "").lower() == "open":
            open_alerts += n
        elif str(status or "").lower() == "acknowledged":
            ack_alerts += n
    alert_rank = case(
        (func.lower(Alert.severity) == "critical", 0),
        (func.lower(Alert.severity) == "high", 1),
        (func.lower(Alert.severity) == "medium", 2),
        (func.lower(Alert.severity) == "low", 3),
        (func.lower(Alert.severity) == "info", 4),
        else_=5,
    )
    top_alert_rows = (
        db.query(Alert)
        .filter(Alert.project_id == project_id, Alert.status.in_(["open", "acknowledged"]))
        .order_by(alert_rank, Alert.last_seen_at.desc())
        .limit(_TOP_ALERTS_LIMIT)
        .all()
    )
    top_alerts = [
        {
            "id": a.id,
            "title": a.title,
            "alert_type": a.alert_type,
            "severity": _sev_key(a.severity),
            "status": a.status,
            "event_count": a.event_count,
            "source_asset_id": a.source_asset_id,
            "source_finding_id": a.source_finding_id,
            "monitoring_run_id": a.monitoring_run_id,
            "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
        }
        for a in top_alert_rows
    ]

    # --- assets: total + by-type + exposure highlights (bounded) ---
    asset_total = (
        db.query(func.count(Asset.id)).filter(Asset.project_id == project_id).scalar() or 0
    )
    asset_type_rows = (
        db.query(Asset.asset_type, func.count(Asset.id))
        .filter(Asset.project_id == project_id)
        .group_by(Asset.asset_type)
        .all()
    )
    assets_by_type = {str(t or "unknown"): int(c or 0) for t, c in asset_type_rows}
    exposure_highlights: list = []
    if open_total:
        candidate_rows = (
            db.query(Finding, Asset.asset_type, Asset.value, Asset.extra_data, Asset.criticality)
            .join(Target, Target.id == Finding.target_id)
            .outerjoin(Asset, Asset.id == Finding.asset_id)
            .filter(Target.project_id == project_id)
            .filter(or_(Finding.status.notin_(RESOLVED_FINDING_STATUSES), Finding.status.is_(None)))
            .filter(func.lower(Finding.severity).in_(["critical", "high"]))
            .order_by(sev_rank, Finding.score.desc())
            .limit(_EXPOSURE_CANDIDATE_LIMIT)
            .all()
        )
        seen_assets: set = set()
        for finding, asset_type, asset_value, asset_meta, criticality in candidate_rows:
            if not finding.asset_id or finding.asset_id in seen_assets:
                continue
            seen_assets.add(finding.asset_id)
            try:
                exposure = classify_exposure(
                    asset_type, asset_value, asset_meta if isinstance(asset_meta, dict) else {}
                )
            except Exception:
                exposure = "UNKNOWN"
            if exposure in ("INTERNET_EXPOSED", "EXTERNALLY_REACHABLE"):
                exposure_highlights.append(
                    {
                        "asset_id": finding.asset_id,
                        "asset_type": asset_type,
                        "asset_value": asset_value,
                        "exposure": exposure,
                        "criticality": criticality or "unknown",
                        "finding_id": finding.id,
                        "finding_title": finding.title,
                        "severity": _sev_key(finding.severity),
                    }
                )
                if len(exposure_highlights) >= 5:
                    break

    # --- changes: windowed count + by-type + recent items (D2 events) ---
    change_count = (
        db.query(func.count(MonitoringChangeEvent.id))
        .filter(
            MonitoringChangeEvent.project_id == project_id,
            MonitoringChangeEvent.detected_at >= cutoff,
        )
        .scalar()
        or 0
    )
    change_type_rows = (
        db.query(MonitoringChangeEvent.change_type, func.count(MonitoringChangeEvent.id))
        .filter(
            MonitoringChangeEvent.project_id == project_id,
            MonitoringChangeEvent.detected_at >= cutoff,
        )
        .group_by(MonitoringChangeEvent.change_type)
        .all()
    )
    changes_by_type = {str(t or "unknown"): int(c or 0) for t, c in change_type_rows}
    recent_change_rows = (
        db.query(MonitoringChangeEvent)
        .filter(
            MonitoringChangeEvent.project_id == project_id,
            MonitoringChangeEvent.detected_at >= cutoff,
        )
        .order_by(MonitoringChangeEvent.detected_at.desc())
        .limit(_RECENT_CHANGES_LIMIT)
        .all()
    )
    new_assets_recent = (
        db.query(func.count(MonitoringChangeEvent.id))
        .filter(
            MonitoringChangeEvent.project_id == project_id,
            MonitoringChangeEvent.detected_at >= cutoff,
            MonitoringChangeEvent.change_type == "ASSET_CREATED",
        )
        .scalar()
        or 0
    )
    recent_changes = [
        {
            "id": e.id,
            "change_type": e.change_type,
            "asset_id": e.asset_id,
            "finding_id": e.finding_id,
            "curr_run_id": e.curr_run_id,
            "scanners": e.scanners or [],
            "completeness": e.completeness,
            "detected_at": e.detected_at.isoformat() if e.detected_at else None,
        }
        for e in recent_change_rows
    ]

    # --- monitoring health: latest + recent runs, next run, last good ---
    latest_run = (
        db.query(MonitoringRun)
        .filter(MonitoringRun.project_id == project_id)
        .order_by(MonitoringRun.created_at.desc())
        .first()
    )
    recent_run_rows = (
        db.query(MonitoringRun)
        .filter(MonitoringRun.project_id == project_id)
        .order_by(MonitoringRun.created_at.desc())
        .limit(_RECENT_RUNS_LIMIT)
        .all()
    )
    next_run_at = (
        db.query(func.min(MonitoringConfig.next_run_at))
        .filter(
            MonitoringConfig.project_id == project_id,
            MonitoringConfig.enabled.is_(True),
            MonitoringConfig.paused_at.is_(None),
            MonitoringConfig.next_run_at.isnot(None),
        )
        .scalar()
    )
    last_good = (
        db.query(MonitoringRun)
        .filter(MonitoringRun.project_id == project_id, MonitoringRun.status == "completed")
        .order_by(MonitoringRun.created_at.desc())
        .first()
    )

    def _run_brief(r):
        if r is None:
            return None
        return {
            "id": r.id,
            "monitoring_config_id": r.monitoring_config_id,
            "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "successful_scanners": r.successful_scanners,
            "failed_scanners": r.failed_scanners,
            "change_status": r.change_status,
            "alert_status": r.alert_status,
        }

    # --- risk: AVG over recent completed scans with scores (existing engine output) ---
    risk_rows = (
        db.query(Scan.risk_score)
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.project_id == project_id, Scan.status == "completed", Scan.risk_score.isnot(None))
        .order_by(Scan.created_at.desc())
        .limit(_RISK_SCANS_LIMIT)
        .all()
    )
    scores = [int(r[0]) for r in risk_rows if r and r[0] is not None]
    risk_score = round(sum(scores) / len(scores), 1) if scores else None

    return {
        "project_id": project_id,
        "window": window.strip().lower() if isinstance(window, str) else "24h",
        "generated_at": _utcnow().isoformat(),
        "risk": {"score": risk_score, "grade": _grade(risk_score), "scans_counted": len(scores)},
        "findings": {
            "open": open_total,
            "critical": sev_counts.get("critical", 0),
            "high": sev_counts.get("high", 0),
            "medium": sev_counts.get("medium", 0),
            "low": sev_counts.get("low", 0),
            "info": sev_counts.get("info", 0),
        },
        "alerts": {
            "active": active_alerts,
            "open": open_alerts,
            "acknowledged": ack_alerts,
            "critical": crit_alerts,
            "high": high_alerts,
        },
        "assets": {
            "total": int(asset_total or 0),
            "by_type": assets_by_type,
            "exposure_highlights": exposure_highlights,
        },
        "changes": {
            "recent": int(change_count or 0),
            "new_assets": int(new_assets_recent or 0),
            "by_type": changes_by_type,
            "items": recent_changes,
        },
        "monitoring": {
            "last_run": _run_brief(latest_run),
            "recent_runs": [_run_brief(r) for r in recent_run_rows],
            "next_run_at": next_run_at.isoformat() if next_run_at else None,
            "last_good_observation": (
                {"run_id": last_good.id, "completed_at": last_good.completed_at.isoformat() if last_good.completed_at else None}
                if last_good
                else None
            ),
        },
        "top_findings": top_findings,
        "active_alerts": top_alerts,
    }

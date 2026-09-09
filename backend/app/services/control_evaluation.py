"""D5 deterministic control evaluation over existing VAPT evidence.

Evaluates the versioned ``vapt_control_readiness`` catalog against one
project's findings, scans, assets and monitoring runs. No new tables, no
snapshots, no LLM: every conclusion derives from indexed project-scoped
queries plus the explicit rules in ``control_evidence_catalog``.

Status semantics:
- PASS: fresh-enough positive evidence (a completed scan by a mapped
  scanner) and no open critical/high matches. Absence of findings alone
  is never a PASS without positive coverage.
- PARTIAL: only medium/low/info matches, accepted-risk-only matches,
  stale positive evidence, or exposure present without proven issues.
- FAIL: an open critical/high match (or accepted-risk-excluded
  equivalent) directly contradicting the control.
- NOT_ASSESSED: insufficient evidence (no coverage, no matches).
- NOT_APPLICABLE: project has neither the required asset types nor any
  scan or finding by the required scanners (data-derived scope; no scope UI).

Confidence HIGH/MEDIUM/LOW and freshness FRESH/STALE/UNKNOWN follow the
documented deterministic rules. Coverage = (PASS+PARTIAL) /
(PASS+PARTIAL+FAIL+NOT_ASSESSED), null when nothing is assessable.
"Evidence coverage" — never "compliant" or "certified".
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.monitoring import MonitoringRun
from app.models.scan import Scan
from app.models.scan_result import ScanResult
from app.models.target import Target
from app.services.attack_surface import classify_exposure
from app.services.control_evidence_catalog import (
    ACCEPTED_RISK_STATUSES,
    ACTIONABLE_SEVERITIES,
    CONTROLS,
    EVIDENCE_FRAMEWORK,
    FRESH_DAYS,
    OPEN_STATUSES,
    finding_matches,
    get_control,
)

DETAIL_LIMIT = 25
CANDIDATE_SCAN_LIMIT = 200
EXPOSURE_ASSET_LIMIT = 200

_OPEN_OR_NULL = "open_null_placeholder"


def _count_open_matches(db: Session, project_id: str, control: dict) -> dict:
    """Exact open/accepted-risk match counts per control (cheap COUNT; detail
    lists stay capped separately so reasons text is truthful at any scale)."""
    scanners: set = set()
    keywords: set = set()
    for matcher in control.get("matchers") or []:
        scanners.update(str(s).lower() for s in (matcher.get("scanners") or []))
        for kw in matcher.get("keywords") or []:
            keywords.add(str(kw).lower())
    if not scanners:
        return {"actionable": 0, "lower": 0, "accepted": 0}
    q = (
        db.query(func.count(Finding.id))
        .join(Target, Target.id == Finding.target_id)
        .filter(Target.project_id == project_id, func.lower(Finding.scanner).in_(sorted(scanners)))
    )
    if keywords:
        ors = [func.lower(Finding.title).like(f"%{kw}%") for kw in sorted(keywords)]
        q = q.filter(or_(*ors))
    eff_sev = func.coalesce(
        func.lower(func.coalesce(Finding.severity_override, Finding.severity)), "info"
    )
    open_status = or_(Finding.status.in_(list(OPEN_STATUSES)), Finding.status.is_(None))
    actionable = q.filter(open_status, eff_sev.in_(["critical", "high"])).scalar() or 0
    lower = q.filter(open_status, eff_sev.notin_(["critical", "high"])).scalar() or 0
    accepted = q.filter(Finding.status.in_(list(ACCEPTED_RISK_STATUSES))).scalar() or 0
    return {"actionable": int(actionable), "lower": int(lower), "accepted": int(accepted)}


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _effective_severity(row_severity, row_override) -> str:
    raw = row_override or row_severity or "info"
    s = str(raw).strip().lower()
    if s == "informational":
        return "info"
    return s if s in ("critical", "high", "medium", "low", "info") else "info"


def _freshness(latest) -> str:
    if latest is None:
        return "UNKNOWN"
    try:
        ts = latest.replace(tzinfo=None) if getattr(latest, "tzinfo", None) else latest
    except Exception:
        return "UNKNOWN"
    age_days = (_utcnow_naive() - ts).total_seconds() / 86400.0
    if age_days <= FRESH_DAYS:
        return "FRESH"
    # Anything older is STALE (evidence exists but aged); UNKNOWN is
    # reserved for no evidence at all (handled by the None check above).
    return "STALE"


def _project_scanners(db: Session, project_id: str) -> dict:
    """Completed scan executions per scanner: {scanner: {count, latest}}."""
    rows = (
        db.query(
            ScanResult.scanner,
            func.count(ScanResult.id),
            func.max(ScanResult.completed_at),
        )
        .join(Scan, Scan.id == ScanResult.scan_id)
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.project_id == project_id, ScanResult.status == "completed")
        .group_by(ScanResult.scanner)
        .all()
    )
    return {str(s or "").lower(): {"count": int(c or 0), "latest": latest} for s, c, latest in rows}


def _project_asset_types(db: Session, project_id: str) -> set:
    rows = (
        db.query(Asset.asset_type, func.count(Asset.id))
        .filter(Asset.project_id == project_id)
        .group_by(Asset.asset_type)
        .all()
    )
    return {str(t or "").lower() for t, _ in rows}


def _control_applicable(control: dict, scanners: dict, asset_types: set, finding_scanners: set) -> tuple[bool, str]:
    need_scanners = [str(s).lower() for s in (control.get("requires_any_scanners") or [])]
    need_assets = [str(t).lower() for t in (control.get("requires_any_assets") or [])]
    if not need_scanners and not need_assets:
        return True, "always applicable (operations control)"
    if any(s in scanners for s in need_scanners):
        return True, "required scanner coverage present"
    if any(s in finding_scanners for s in need_scanners):
        return True, "required scanner findings present"
    if any(t in asset_types for t in need_assets):
        return True, "required asset types present"
    return False, "no required scanners, findings, or asset types in this project"


def _matched_findings(db: Session, project_id: str, control: dict, limit: int = DETAIL_LIMIT):
    """Candidate open findings for a control (bounded). Returns row dicts."""
    scanners: set = set()
    for matcher in control.get("matchers") or []:
        scanners.update(str(s).lower() for s in (matcher.get("scanners") or []))
    if not scanners:
        return []
    rows = (
        db.query(Finding, Scan.scanner_version, Scan.created_at)
        .join(Target, Target.id == Finding.target_id)
        .outerjoin(Scan, Scan.id == Finding.scan_id)
        .filter(Target.project_id == project_id, func.lower(Finding.scanner).in_(sorted(scanners)))
        .order_by(Finding.created_at.desc())
        .limit(CANDIDATE_SCAN_LIMIT)
        .all()
    )
    matched = []
    for finding, scanner_version, scan_created in rows:
        status = str(finding.status or "open").lower()
        if status not in OPEN_STATUSES and status not in ACCEPTED_RISK_STATUSES:
            continue
        probe = {"scanner": finding.scanner, "title": finding.title}
        if not finding_matches(probe, control.get("matchers") or []):
            continue
        matched.append(
            {
                "finding": finding,
                "scanner_version": scanner_version,
                "scan_created_at": scan_created,
            }
        )
        if len(matched) >= limit:
            break
    return matched


def _finding_evidence(item: dict) -> dict:
    finding = item["finding"]
    return {
        "kind": "finding",
        "id": finding.id,
        "title": finding.title,
        "severity": _effective_severity(finding.severity, finding.severity_override),
        "status": finding.status,
        "scanner": finding.scanner,
        "scan_id": finding.scan_id,
        "scanner_version": item.get("scanner_version"),
        "observed_at": finding.created_at.isoformat() if finding.created_at else None,
    }


def _exposed_assets(db: Session, project_id: str) -> list:
    """Internet-exposed assets (bounded), classified with existing logic."""
    rows = (
        db.query(Asset)
        .filter(Asset.project_id == project_id)
        .limit(EXPOSURE_ASSET_LIMIT)
        .all()
    )
    exposed = []
    for asset in rows:
        try:
            meta = asset.extra_data if isinstance(asset.extra_data, dict) else {}
            level = classify_exposure(asset.asset_type, asset.value, meta)
        except Exception:
            level = "UNKNOWN"
        if level == "INTERNET_EXPOSED":
            exposed.append({"asset": asset, "exposure": level})
    return exposed


def _latest(*times):
    valid = [t for t in times if t is not None]
    if not valid:
        return None
    try:
        return max(valid)
    except Exception:
        return None


def evaluate_control(db: Session, project_id: str, control: dict, ctx: dict) -> dict:
    """Evaluate one control using preloaded project context.

    ``ctx`` carries scanners map, asset types, and monitoring facts so the
    hot path issues no extra queries beyond capped evidence detail.
    """
    control_id = control["control_id"]
    applicable, scope_reason = _control_applicable(
        control, ctx["scanners"], ctx["asset_types"], ctx.get("finding_scanners") or set()
    )
    if not applicable:
        return {
            "control_id": control_id,
            "status": "NOT_APPLICABLE",
            "confidence": "LOW",
            "freshness": "UNKNOWN",
            "reasons": [scope_reason],
            "supporting": [],
            "contradictory": [],
            "evaluated_at": _utcnow_naive().isoformat(),
        }

    if control.get("monitoring_review"):
        return _evaluate_monitoring_control(control, ctx)
    if control.get("change_review"):
        return _evaluate_change_control(control, ctx)
    if control.get("exposure_review"):
        return _evaluate_exposure_control(db, project_id, control, ctx)
    if control.get("coverage_only"):
        return _evaluate_coverage_control(control, ctx)
    return _evaluate_finding_control(db, project_id, control, ctx)


def _evaluate_finding_control(db: Session, project_id: str, control: dict, ctx: dict) -> dict:
    matched = _matched_findings(db, project_id, control)
    counts = _count_open_matches(db, project_id, control)
    actionable = [
        m for m in matched
        if _effective_severity(m["finding"].severity, m["finding"].severity_override)
        in ACTIONABLE_SEVERITIES
        and str(m["finding"].status or "").lower() in OPEN_STATUSES
    ]
    accepted_only = [
        m for m in matched
        if str(m["finding"].status or "").lower() in ACCEPTED_RISK_STATUSES
    ]
    lower = [
        m for m in matched
        if _effective_severity(m["finding"].severity, m["finding"].severity_override)
        not in ACTIONABLE_SEVERITIES
        and str(m["finding"].status or "").lower() in OPEN_STATUSES
    ]
    mapped_scanners = {
        str(s).lower()
        for matcher in (control.get("matchers") or [])
        for s in (matcher.get("scanners") or [])
    }
    coverage = [
        (s, info) for s, info in ctx["scanners"].items() if s in mapped_scanners
    ]
    latest_evidence = _latest(
        *([m["finding"].created_at for m in matched] + [info["latest"] for _, info in coverage])
    )
    freshness = _freshness(latest_evidence)

    contradictory = [_finding_evidence(m) for m in actionable[:DETAIL_LIMIT]]
    control_id = control["control_id"]
    if counts["actionable"]:
        return _result(control_id, "FAIL", "HIGH" if freshness == "FRESH" else "MEDIUM",
                       freshness, [f"{counts['actionable']} unresolved critical/high finding(s) contradict this control"],
                       [], contradictory)
    if counts["accepted"] and not counts["lower"]:
        return _result(control_id, "PARTIAL", "MEDIUM", freshness,
                       [f"{counts['accepted']} accepted-risk finding(s) only; risk acceptance is authoritative, not a pass"],
                       [], [_finding_evidence(m) for m in accepted_only[:DETAIL_LIMIT]])
    if counts["lower"]:
        return _result(control_id, "PARTIAL", "MEDIUM", freshness,
                       [f"{counts['lower']} lower-severity finding(s) merit review"],
                       [], [_finding_evidence(m) for m in lower[:DETAIL_LIMIT]])
    if coverage:
        if freshness == "STALE":
            return _result(control_id, "PARTIAL", "LOW", freshness,
                           ["coverage is older than 7 days; re-assessment due"],
                           _coverage_evidence(coverage), [])
        if freshness == "UNKNOWN" and not any(info["latest"] for _, info in coverage):
            return _result(control_id, "PARTIAL", "LOW", freshness,
                           ["coverage lacks usable timestamps"],
                           _coverage_evidence(coverage), [])
        return _result(control_id, "PASS", "HIGH" if freshness == "FRESH" else "MEDIUM",
                       freshness, ["completed assessment coverage with no unresolved critical/high findings"],
                       _coverage_evidence(coverage), [])
    return _result(control_id, "NOT_ASSESSED", "LOW", "UNKNOWN",
                   ["no mapped scanner coverage and no matching findings in this project"], [], [])


def _coverage_evidence(coverage: list) -> list:
    return [
        {"kind": "scan", "scanner": scanner, "completed_count": info["count"],
         "observed_at": info["latest"].isoformat() if info["latest"] else None}
        for scanner, info in sorted(coverage)[:DETAIL_LIMIT]
    ]


def _evaluate_exposure_control(db: Session, project_id: str, control: dict, ctx: dict) -> dict:
    control_id = control["control_id"]
    exposed = _exposed_assets(db, project_id)
    if not exposed:
        cov = [(s, i) for s, i in ctx["scanners"].items()
               if s in ("nmap", "dns", "subdomain")]
        if cov:
            latest = _latest(*[i["latest"] for _, i in cov])
            freshness = _freshness(latest)
            if freshness == "STALE":
                return _result(control_id, "PARTIAL", "LOW", freshness,
                               ["network coverage is stale"], _coverage_evidence(cov), [])
            return _result(control_id, "PASS", "HIGH" if freshness == "FRESH" else "MEDIUM",
                           freshness, ["no internet-exposed assets observed with network coverage"],
                           _coverage_evidence(cov), [])
        return _result(control_id, "NOT_ASSESSED", "LOW", "UNKNOWN",
                       ["no network coverage and no exposed assets observed"], [], [])
    exposed_ids = {e["asset"].id for e in exposed}
    rows = (
        db.query(Finding)
        .join(Target, Target.id == Finding.target_id)
        .filter(Target.project_id == project_id, Finding.asset_id.in_(sorted(exposed_ids)))
        .limit(CANDIDATE_SCAN_LIMIT)
        .all()
    ) if exposed_ids else []
    bad = [
        {"kind": "finding", "id": f.id, "title": f.title,
         "severity": _effective_severity(f.severity, f.severity_override),
         "status": f.status, "scanner": f.scanner, "scan_id": f.scan_id,
         "observed_at": f.created_at.isoformat() if f.created_at else None}
        for f in rows
        if _effective_severity(f.severity, f.severity_override) in ACTIONABLE_SEVERITIES
        and str(f.status or "").lower() in OPEN_STATUSES
    ]
    latest = _latest(*([f.created_at for f in rows] + [ctx.get("now")]))
    freshness = _freshness(latest)
    supporting = [
        {"kind": "asset", "id": e["asset"].id, "asset_type": e["asset"].asset_type,
         "value": e["asset"].value, "exposure": e["exposure"],
         "observed_at": e["asset"].last_seen_at.isoformat() if e["asset"].last_seen_at else None}
        for e in exposed[:DETAIL_LIMIT]
    ]
    if bad:
        return _result(control_id, "FAIL", "HIGH" if freshness == "FRESH" else "MEDIUM",
                       freshness, [f"{len(bad)} unresolved critical/high finding(s) on internet-exposed assets"],
                       supporting, bad[:DETAIL_LIMIT])
    return _result(control_id, "PARTIAL", "MEDIUM", freshness,
                   [f"{len(exposed)} internet-exposed asset(s) with no proven critical/high issues; exposure present is not a pass"],
                   supporting, [])


def _evaluate_coverage_control(control: dict, ctx: dict) -> dict:
    control_id = control["control_id"]
    latest_scan = ctx.get("latest_scan_at")
    if latest_scan is None:
        return _result(control_id, "NOT_ASSESSED", "LOW", "UNKNOWN",
                       ["no completed scans in this project"], [], [])
    freshness = _freshness(latest_scan)
    if freshness == "FRESH":
        return _result(control_id, "PASS", "HIGH", freshness,
                       ["completed vulnerability scans within 7 days"],
                       [{"kind": "scan", "observed_at": latest_scan.isoformat() if hasattr(latest_scan, "isoformat") else str(latest_scan)}], [])
    return _result(control_id, "PARTIAL", "LOW", freshness,
                   ["most recent completed scan is older than 7 days"],
                   [{"kind": "scan", "observed_at": latest_scan.isoformat() if hasattr(latest_scan, "isoformat") else str(latest_scan)}], [])


def _evaluate_monitoring_control(control: dict, ctx: dict) -> dict:
    control_id = control["control_id"]
    last_good = ctx.get("last_good_run_at")
    last_any = ctx.get("last_run_at")
    if last_good is not None:
        freshness = _freshness(last_good)
        if freshness == "FRESH":
            return _result(control_id, "PASS", "HIGH", freshness,
                           ["a monitoring run completed within 7 days"], [], [])
        return _result(control_id, "PARTIAL", "LOW", freshness,
                       ["no monitoring run completed within 7 days"], [], [])
    if last_any is not None:
        return _result(control_id, "PARTIAL", "LOW", _freshness(last_any),
                       ["monitoring runs exist but none completed recently"], [], [])
    return _result(control_id, "NOT_ASSESSED", "LOW", "UNKNOWN",
                   ["no monitoring runs in this project"], [], [])


def _evaluate_change_control(control: dict, ctx: dict) -> dict:
    control_id = control["control_id"]
    evaluated = ctx.get("last_evaluated_change_at")
    if evaluated is not None:
        freshness = _freshness(evaluated)
        if freshness == "STALE":
            return _result(control_id, "PARTIAL", "LOW", freshness,
                           ["no evaluated change records within 7 days"], [], [])
        return _result(control_id, "PASS", "HIGH" if freshness == "FRESH" else "MEDIUM",
                       freshness, ["recent monitoring observations produced evaluated change records"], [], [])
    if ctx.get("has_runs"):
        return _result(control_id, "PARTIAL", "LOW", _freshness(ctx.get("last_run_at")),
                       ["monitoring runs exist but produced no evaluated change records"], [], [])
    return _result(control_id, "NOT_ASSESSED", "LOW", "UNKNOWN",
                   ["no monitoring observations in this project"], [], [])


def _result(control_id, status, confidence, freshness, reasons, supporting, contradictory):
    return {
        "control_id": control_id,
        "status": status,
        "confidence": confidence,
        "freshness": freshness,
        "reasons": list(reasons),
        "supporting": supporting,
        "contradictory": contradictory,
        "evaluated_at": _utcnow_naive().isoformat(),
    }


def build_project_context(db: Session, project_id: str) -> dict:
    """Preload bounded project aggregates once (no per-control fan-out)."""
    scanners = _project_scanners(db, project_id)
    asset_rows = (
        db.query(Asset.asset_type, func.count(Asset.id))
        .filter(Asset.project_id == project_id)
        .group_by(Asset.asset_type)
        .all()
    )
    asset_types = {str(t or "").lower() for t, _ in asset_rows}
    finding_scanners = {
        str(s or "").lower()
        for s, in db.query(Finding.scanner)
        .join(Target, Target.id == Finding.target_id)
        .filter(Target.project_id == project_id)
        .distinct()
        .all()
    }
    latest_scan = (
        db.query(func.max(Scan.created_at))
        .join(Target, Target.id == Scan.target_id)
        .filter(Target.project_id == project_id, Scan.status == "completed")
        .scalar()
    )
    last_good = (
        db.query(func.max(MonitoringRun.completed_at))
        .filter(MonitoringRun.project_id == project_id, MonitoringRun.status == "completed")
        .scalar()
    )
    last_any = (
        db.query(func.max(MonitoringRun.created_at))
        .filter(MonitoringRun.project_id == project_id)
        .scalar()
    )
    last_change = (
        db.query(func.max(MonitoringRun.completed_at))
        .filter(MonitoringRun.project_id == project_id, MonitoringRun.change_status == "completed")
        .scalar()
    )
    has_runs = (
        db.query(func.count(MonitoringRun.id))
        .filter(MonitoringRun.project_id == project_id)
        .scalar()
        or 0
    ) > 0
    return {
        "scanners": scanners,
        "asset_types": asset_types,
        "finding_scanners": finding_scanners,
        "latest_scan_at": latest_scan,
        "last_good_run_at": last_good,
        "last_run_at": last_any,
        "last_evaluated_change_at": last_change,
        "has_runs": has_runs,
        "now": _utcnow_naive(),
    }


def evaluate_project(db: Session, project_id: str, controls: list | None = None) -> list[dict]:
    """Evaluate controls for one project. Returns evaluations in catalog order."""
    ctx = build_project_context(db, project_id)
    return [evaluate_control(db, project_id, c, ctx) for c in (controls if controls is not None else CONTROLS)]


def coverage_summary(evaluations: list[dict]) -> dict:
    counts = {"PASS": 0, "PARTIAL": 0, "FAIL": 0, "NOT_ASSESSED": 0, "NOT_APPLICABLE": 0}
    for ev in evaluations:
        status = str(ev.get("status") or "NOT_ASSESSED")
        counts[status] = counts.get(status, 0) + 1
    denom = counts["PASS"] + counts["PARTIAL"] + counts["FAIL"] + counts["NOT_ASSESSED"]
    coverage = round((counts["PASS"] + counts["PARTIAL"]) / denom * 100, 1) if denom else None
    return {
        "total_controls": len(evaluations),
        "pass": counts["PASS"],
        "partial": counts["PARTIAL"],
        "fail": counts["FAIL"],
        "not_assessed": counts["NOT_ASSESSED"],
        "not_applicable": counts["NOT_APPLICABLE"],
        "evidence_coverage": coverage,
    }

"""F3 Risk Evolution & Security Exposure Trends — deterministic, bounded, evidence-first."""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from typing import Any
from sqlalchemy.orm import Session
from sqlalchemy import func, text

from app.models.asset import Asset
from app.models.application import Application
from app.models.finding import Finding

WINDOW_DAYS = {"7d":7, "30d":30, "90d":90}
MAX_FINDINGS = 500
MAX_ASSETS = 500
MAX_APPLICATIONS = 100
MAX_ATTACK_PATHS = 100
MAX_RESULTS = 20

def _validate_window(window:str) -> int:
    if window not in WINDOW_DAYS:
        raise ValueError(f"Invalid window: {window}. Use 7d|30d|90d")
    return WINDOW_DAYS[window]

def _periods(window:str, now:datetime|None=None):
    days = _validate_window(window)
    now = now or datetime.now(timezone.utc)
    current_start = now - timedelta(days=days)
    previous_start = current_start - timedelta(days=days)
    previous_end = current_start
    return (current_start, now, previous_start, previous_end)

def _direction(metric:str, current:float, previous:float) -> str:
    if current == previous:
        return "STABLE"
    # metrics where higher is worse
    worse = {"critical_findings","high_findings","total_findings","attack_paths","critical_attack_paths","externally_reachable","cloud_exposed","sla_breached","priority_score","avg_priority","max_priority","worsening_apps"}
    better = {"remediation_completed","validation_valid","retest_pass","resolved_findings"}
    if metric in worse:
        return "WORSENING" if current > previous else "IMPROVING"
    if metric in better:
        return "IMPROVING" if current > previous else "WORSENING"
    # default: higher is worse for counts, but for scores higher is worse
    return "WORSENING" if current > previous else "IMPROVING"

def _pct_change(current:float, previous:float):
    if previous == 0:
        return None
    return round((current - previous)/ previous * 100, 1)

def _sanitize(val: str|None):
    if not val: return val
    if any(k in val.lower() for k in ("secret","password","token","private_key","credential")):
        return "[REDACTED]"
    return val[:500]

def _compute_period_metrics(project_id:str, db:Session, start:datetime, end:datetime) -> dict:
    # Findings
    findings = db.query(Finding).join(Asset, Finding.asset_id==Asset.id, isouter=True).filter(
        ((Asset.project_id==project_id) | (Finding.asset_id.is_(None)))
    ).filter(Finding.created_at >= start, Finding.created_at < end).limit(MAX_FINDINGS).all()
    # fallback via asset ids if join missed
    if not findings:
        asset_ids = [r[0] for r in db.query(Asset.id).filter(Asset.project_id==project_id).limit(MAX_ASSETS).all()]
        if asset_ids:
            findings = db.query(Finding).filter(Finding.asset_id.in_(asset_ids), Finding.created_at >= start, Finding.created_at < end).limit(MAX_FINDINGS).all()
    counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        counts[(f.severity or "info").lower()] = counts.get((f.severity or "info").lower(),0)+1
    # attack paths in period
    attack_total = 0
    attack_crit = 0
    try:
        from app.models.cloud_attack_path import CloudAttackPath
        attack_total = db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id==project_id, CloudAttackPath.first_seen_at >= start, CloudAttackPath.first_seen_at < end).scalar() or 0
        attack_crit = db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id==project_id, CloudAttackPath.severity=="high", CloudAttackPath.first_seen_at >= start, CloudAttackPath.first_seen_at < end).scalar() or 0
    except: pass
    # externally reachable
    external = 0
    try:
        # count assets with externally_reachable true created in period
        assets_in_period = db.query(Asset).filter(Asset.project_id==project_id, Asset.created_at >= start, Asset.created_at < end).limit(MAX_ASSETS).all()
        external = sum(1 for a in assets_in_period if (a.extra_data or {}).get("externally_reachable"))
    except: pass
    # cloud exposed
    cloud_exposed = 0
    try:
        cloud_exposed = db.query(func.count(Asset.id)).filter(Asset.project_id==project_id, Asset.asset_type.in_(["cloud_resource","cloud_account"]), Asset.created_at >= start, Asset.created_at < end).scalar() or 0
    except: pass
    # remediation
    remediation_opened = 0
    remediation_completed = 0
    try:
        from app.models.finding import FindingRemediation
        remediation_opened = db.query(func.count(FindingRemediation.id)).filter(FindingRemediation.project_id==project_id, FindingRemediation.created_at >= start, FindingRemediation.created_at < end).scalar() or 0
        remediation_completed = db.query(func.count(FindingRemediation.id)).filter(FindingRemediation.project_id==project_id, FindingRemediation.status=="completed", FindingRemediation.updated_at >= start, FindingRemediation.updated_at < end).scalar() or 0
    except: pass
    # SLA breached
    sla_breached = 0
    try:
        from app.models.finding import FindingSLA
        sla_breached = db.query(func.count(FindingSLA.id)).filter(FindingSLA.project_id==project_id, FindingSLA.status=="breached", FindingSLA.created_at >= start, FindingSLA.created_at < end).scalar() or 0
    except: pass
    # validations
    val_total = 0
    val_valid = 0
    try:
        from app.models.security_validation import SecurityValidation
        val_total = db.query(func.count(SecurityValidation.id)).filter(SecurityValidation.project_id==project_id, SecurityValidation.created_at >= start, SecurityValidation.created_at < end).scalar() or 0
        val_valid = db.query(func.count(SecurityValidation.id)).filter(SecurityValidation.project_id==project_id, SecurityValidation.verdict=="VALID", SecurityValidation.created_at >= start, SecurityValidation.created_at < end).scalar() or 0
    except: pass
    # retests
    retest_pass = 0
    retest_fail = 0
    try:
        from app.models.finding import FindingRetest
        retest_pass = db.query(func.count(FindingRetest.id)).filter(FindingRetest.project_id==project_id, FindingRetest.result=="fixed", FindingRetest.created_at >= start, FindingRetest.created_at < end).scalar() or 0
        retest_fail = db.query(func.count(FindingRetest.id)).filter(FindingRetest.project_id==project_id, FindingRetest.result=="not_fixed", FindingRetest.created_at >= start, FindingRetest.created_at < end).scalar() or 0
    except: pass
    # priority scores for posture (average of F2)
    total_score = 0
    max_score = 0
    avg = 0
    try:
        from app.services.security_prioritization import calculate_finding_priority
        scores = []
        for f in findings:
            p = calculate_finding_priority(f, db, project_id)
            scores.append(p["score"])
        if scores:
            total_score = sum(scores)
            max_score = max(scores)
            avg = round(sum(scores)/len(scores),1)
    except: pass
    return {
        "findings_total": len(findings),
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "info": counts.get("info",0),
        "attack_paths": attack_total,
        "critical_attack_paths": attack_crit,
        "externally_reachable": external,
        "cloud_exposed": cloud_exposed,
        "remediation_opened": remediation_opened,
        "remediation_completed": remediation_completed,
        "sla_breached": sla_breached,
        "validations": val_total,
        "valid_validations": val_valid,
        "retest_pass": retest_pass,
        "retest_fail": retest_fail,
        "total_priority_score": total_score,
        "avg_priority": avg,
        "max_priority": max_score,
    }

def _build_trends(current:dict, previous:dict) -> dict:
    trends = {}
    for k in current.keys():
        cur = float(current.get(k,0) or 0)
        prev = float(previous.get(k,0) or 0)
        delta = cur - prev
        pct = _pct_change(cur, prev)
        direction = _direction(k, cur, prev)
        trends[k] = {"current": cur, "previous": prev, "delta": delta, "pct": pct, "direction": direction}
    return trends

def get_trends(project_id:str, db:Session, window:str="7d") -> dict:
    days = _validate_window(window)
    now = datetime.now(timezone.utc)
    cur_start, cur_end, prev_start, prev_end = _periods(window, now)
    cur = _compute_period_metrics(project_id, db, cur_start, cur_end)
    prev = _compute_period_metrics(project_id, db, prev_start, prev_end)
    trends = _build_trends(cur, prev)
    # posture: average priority
    post_score = cur.get("avg_priority",0)
    prev_score = prev.get("avg_priority",0)
    # if insufficient data (no findings in both periods)
    if cur.get("findings_total",0)==0 and prev.get("findings_total",0)==0:
        posture = {"score": post_score, "previous_score": prev_score, "delta": 0, "direction": "INSUFFICIENT_DATA", "tier": "INFO", "confidence": "LOW", "reasons": ["Insufficient historical data"]}
    else:
        delta = post_score - prev_score
        direction = _direction("priority_score", post_score, prev_score) if delta !=0 else "STABLE"
        tier = "CRITICAL" if post_score >=80 else "HIGH" if post_score>=60 else "MEDIUM" if post_score>=40 else "LOW" if post_score>=20 else "INFO"
        reasons = []
        if trends["critical"]["delta"] >0:
            reasons.append(f"{int(trends['critical']['delta'])} new critical findings appeared")
        if trends["critical"]["delta"] <0:
            reasons.append(f"{int(abs(trends['critical']['delta']))} critical findings resolved")
        if trends["externally_reachable"]["delta"] >0:
            reasons.append(f"{int(trends['externally_reachable']['delta'])} new internet-facing assets discovered")
        if trends["attack_paths"]["delta"] >0:
            reasons.append("1 critical attack path became active" if trends["attack_paths"]["delta"]==1 else f"{int(trends['attack_paths']['delta'])} attack paths became active")
        if trends["sla_breached"]["delta"] >0:
            reasons.append(f"{int(trends['sla_breached']['delta'])} SLA breaches increased")
        if trends["remediation_completed"]["delta"] >0:
            reasons.append(f"{int(trends['remediation_completed']['delta'])} remediations completed")
        if not reasons:
            reasons.append("No significant change in key risk indicators")
        posture = {"score": round(post_score,1), "previous_score": round(prev_score,1), "delta": round(delta,1), "direction": direction, "tier": tier, "confidence": "HIGH" if cur["findings_total"]>5 else "MEDIUM", "reasons": reasons}
    # top worsening/improving
    top_worsening = _top_worsening(project_id, db, cur_start, cur_end, prev_start, prev_end)
    top_improving = _top_improving(project_id, db, cur_start, cur_end, prev_start, prev_end)
    # data quality
    data_quality = "GOOD" if cur["findings_total"] + prev["findings_total"] > 10 else "LIMITED" if cur["findings_total"] + prev["findings_total"] > 0 else "INSUFFICIENT_DATA"
    return {
        "window": window,
        "current_period": {"start": cur_start.isoformat(), "end": cur_end.isoformat()},
        "previous_period": {"start": prev_start.isoformat(), "end": prev_end.isoformat()},
        "posture": posture,
        "metrics": {"current": cur, "previous": prev},
        "trends": trends,
        "top_worsening": top_worsening,
        "top_improving": top_improving,
        "reasons": posture["reasons"],
        "data_quality": data_quality,
    }

def _top_worsening(project_id:str, db:Session, cur_start, cur_end, prev_start, prev_end):
    results = []
    # findings worsening: compare priority scores?
    try:
        findings_cur = db.query(Finding).join(Asset, Finding.asset_id==Asset.id, isouter=True).filter((Asset.project_id==project_id) | (Finding.asset_id.is_(None))).filter(Finding.created_at >= cur_start, Finding.created_at < cur_end).limit(100).all()
        for f in findings_cur[:20]:
            # check if new and critical/high
            if (f.severity or "").lower() in ("critical","high"):
                results.append({"type":"finding","id": f.id, "severity": f.severity, "title": _sanitize(f.title)[:80], "delta": 1, "reason": "New critical/high finding"})
        # attack paths
        from app.models.cloud_attack_path import CloudAttackPath
        caps = db.query(CloudAttackPath).filter(CloudAttackPath.project_id==project_id, CloudAttackPath.first_seen_at >= cur_start, CloudAttackPath.first_seen_at < cur_end).limit(5).all()
        for cap in caps:
            results.append({"type":"attack_path","id": cap.id, "severity": cap.severity, "delta": 1, "reason": "New attack path"})
        # assets externally reachable new
        assets = db.query(Asset).filter(Asset.project_id==project_id, Asset.created_at >= cur_start, Asset.created_at < cur_end).limit(20).all()
        for a in assets:
            if (a.extra_data or {}).get("externally_reachable"):
                results.append({"type":"asset","id": a.id, "value": a.value[:40], "delta": 1, "reason": "New internet-facing asset"})
    except: pass
    # deterministic sort
    results.sort(key=lambda x: (x.get("severity","medium"), x["id"]))
    return results[:MAX_RESULTS]

def _top_improving(project_id:str, db:Session, cur_start, cur_end, prev_start, prev_end):
    results = []
    try:
        # resolved findings = findings with status closed in current period but created before
        # use FindingRemediation completed as proxy
        from app.models.finding import FindingRemediation
        rems = db.query(FindingRemediation).filter(FindingRemediation.project_id==project_id, FindingRemediation.status=="completed", FindingRemediation.updated_at >= cur_start, FindingRemediation.updated_at < cur_end).limit(10).all()
        for r in rems:
            results.append({"type":"finding","id": r.finding_id, "delta": -1, "reason": "Remediation completed"})
        # resolved attack paths
        from app.models.cloud_attack_path import CloudAttackPath
        caps = db.query(CloudAttackPath).filter(CloudAttackPath.project_id==project_id, CloudAttackPath.resolved_at != None, CloudAttackPath.resolved_at >= cur_start, CloudAttackPath.resolved_at < cur_end).limit(5).all()
        for cap in caps:
            results.append({"type":"attack_path","id": cap.id, "delta": -1, "reason": "Attack path resolved"})
    except: pass
    results.sort(key=lambda x: x["id"])
    return results[:MAX_RESULTS]

def get_trends_summary(project_id:str, db:Session, window:str="7d") -> dict:
    full = get_trends(project_id, db, window)
    return {
        "window": window,
        "posture": full["posture"],
        "critical_trend": full["trends"].get("critical"),
        "high_trend": full["trends"].get("high"),
        "attack_path_trend": full["trends"].get("attack_paths"),
        "external_trend": full["trends"].get("externally_reachable"),
        "reasons": full["reasons"][:3],
        "data_quality": full["data_quality"],
    }

def get_subject_trends(project_id:str, db:Session, subject_type:str, subject_id:str, window:str="7d") -> dict|None:
    # Validate subject exists
    from app.services.security_intelligence import _resolve_subject
    subj = _resolve_subject(project_id, db, subject_type, subject_id)
    if not subj:
        return None
    # For subject, compare priority scores over periods
    now = datetime.now(timezone.utc)
    cur_start, cur_end, prev_start, prev_end = _periods(window, now)
    # For finding: check if finding created in current vs previous
    # simplified: if subject is finding, check its created_at
    cur = _compute_subject_period(project_id, db, subject_type, subject_id, cur_start, cur_end)
    prev = _compute_subject_period(project_id, db, subject_type, subject_id, prev_start, prev_end)
    delta = cur.get("score",0) - prev.get("score",0)
    direction = "WORSENING" if delta>0 else "IMPROVING" if delta<0 else "STABLE"
    if cur.get("count",0)==0 and prev.get("count",0)==0:
        direction = "INSUFFICIENT_DATA"
    return {
        "window": window,
        "subject_type": subject_type.lower(),
        "subject_id": subject_id,
        "current": cur,
        "previous": prev,
        "delta": delta,
        "direction": direction,
    }

def _compute_subject_period(project_id:str, db:Session, subject_type:str, subject_id:str, start, end):
    # For asset: check asset and its findings in period
    # Simplified: return score based on findings for that subject in period
    try:
        if subject_type.lower() == "finding":
            f = db.query(Finding).filter(Finding.id==subject_id).first()
            if not f or (f.created_at and not (start <= f.created_at < end)):
                return {"score":0,"count":0}
            from app.services.security_prioritization import calculate_finding_priority
            p = calculate_finding_priority(f, db, project_id)
            return {"score": p["score"], "count":1, "severity": f.severity}
        elif subject_type.lower() in ("asset","external_asset","cloud_resource"):
            a = db.query(Asset).filter(Asset.id==subject_id).first()
            if not a or not (a.created_at and start <= a.created_at < end):
                # still check findings for asset in period
                findings = db.query(Finding).filter(Finding.asset_id==subject_id, Finding.created_at >= start, Finding.created_at < end).limit(10).all()
                if findings:
                    from app.services.security_prioritization import calculate_finding_priority
                    scores = [calculate_finding_priority(f, db, project_id)["score"] for f in findings]
                    return {"score": max(scores) if scores else 0, "count": len(findings)}
                return {"score":0,"count":0}
            return {"score":10,"count":1}
        elif subject_type.lower() == "application":
            from app.services.application_intelligence import calculate_application_risk
            r = calculate_application_risk(subject_id, db, project_id)
            # check if app findings in period
            findings = db.query(Finding).join(ApplicationAsset, Finding.asset_id==ApplicationAsset.asset_id).filter(ApplicationAsset.application_id==subject_id, Finding.created_at >= start, Finding.created_at < end).limit(10).all()
            return {"score": r.get("score",0), "count": len(findings)}
        elif subject_type.lower() == "attack_path":
            from app.models.cloud_attack_path import CloudAttackPath
            cap = db.query(CloudAttackPath).filter(CloudAttackPath.id==subject_id).first()
            if cap and cap.first_seen_at and start <= cap.first_seen_at < end:
                return {"score": cap.priority_score or 0, "count":1}
            return {"score":0,"count":0}
    except: pass
    return {"score":0,"count":0}

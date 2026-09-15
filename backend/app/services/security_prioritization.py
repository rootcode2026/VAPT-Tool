"""F2 Security Exposure Prioritization — deterministic, explainable, bounded.
Reuses FindingEngine severity, RiskAssessmentEngine not duplicated, F1 intelligence, E11/E9/E10/E12/E16/D2/D7/D8/E14.
Score 0-100, tier CRITICAL/HIGH/MEDIUM/LOW/INFO, deterministic per evidence.
"""
from __future__ import annotations
import hashlib
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from app.models.asset import Asset
from app.models.application import Application, ApplicationAsset
from app.models.finding import Finding
from app.models.project import Project

MAX_FINDINGS = 500
MAX_ASSETS = 500
MAX_APPLICATIONS = 100
MAX_ATTACK_PATHS = 100
MAX_CORRELATIONS = 200
MAX_DEPTH = 6

SEV_BASE = {"critical":35,"high":20,"medium":10,"low":3,"info":0}
TIER_THRESH = [("CRITICAL",80),("HIGH",60),("MEDIUM",40),("LOW",20),("INFO",0)]

def _tier(score:int)->str:
    for t,thr in TIER_THRESH:
        if score >= thr:
            return t
    return "INFO"

def _sanitize(s:str|None)->str|None:
    if not s: return s
    if any(k in s.lower() for k in ("secret","password","token","private_key","credential")):
        return "[REDACTED]"
    return s[:500]

def _fingerprint(project_id:str, subject_type:str, subject_id:str)->str:
    return hashlib.sha256(f"{project_id}|{subject_type.lower()}|{subject_id}".encode()).hexdigest()[:32]

def _is_internet_facing(asset: Asset) -> bool:
    ed = asset.extra_data or {}
    return bool(ed.get("externally_reachable")) or asset.asset_type in ("url","domain","subdomain") and ed.get("ownership_confidence") in ("CONFIRMED","HIGH_CONFIDENCE")

def _app_for_asset(asset_id:str, db:Session, project_id:str):
    rows = db.query(Application).join(ApplicationAsset, ApplicationAsset.application_id==Application.id).filter(ApplicationAsset.asset_id==asset_id, Application.project_id==project_id).limit(1).all()
    return rows[0] if rows else None

def calculate_finding_priority(finding: Finding, db:Session, project_id:str) -> dict:
    """Deterministic priority for a single finding, reusing existing evidence."""
    score = 0
    reasons = []
    sev = (finding.severity or "info").lower()
    base = SEV_BASE.get(sev,0)
    if base:
        score += base
        reasons.append(f"+{base} Severity {sev.upper()} (FindingEngine)")
    # asset context
    asset = None
    if finding.asset_id:
        asset = db.query(Asset).filter(Asset.id==finding.asset_id).first()
    # internet exposure
    internet = False
    if asset and _is_internet_facing(asset):
        internet = True
        score += 15
        reasons.append("+15 Internet-facing asset (E15/E11)")
    else:
        # check via application linked external
        if asset:
            app = _app_for_asset(asset.id, db, project_id)
            if app:
                # check app exposure
                try:
                    from app.services.application_intelligence import get_application_exposure
                    exp = get_application_exposure(app.id, db, project_id)
                    if exp.get("internet_facing"):
                        internet = True
                        score += 15
                        reasons.append("+15 Internet-facing via application exposure")
                except: pass
    # application criticality
    app_crit = None
    lifecycle = None
    if asset:
        app = _app_for_asset(asset.id, db, project_id)
        if app:
            app_crit = (app.criticality or "unknown").lower()
            lifecycle = (app.lifecycle or "UNKNOWN").upper()
            if app_crit == "critical":
                score += 15
                reasons.append("+15 Application criticality CRITICAL (E16)")
            elif app_crit == "high":
                score += 10
                reasons.append("+10 Application criticality HIGH")
            elif app_crit == "medium":
                score += 5
                reasons.append("+5 Application criticality MEDIUM")
            if lifecycle == "PRODUCTION":
                score += 5
                reasons.append("+5 Lifecycle PRODUCTION")
    # attack-path
    attack = False
    try:
        from app.services.cloud_attack_paths import build_cloud_attack_paths
        paths = build_cloud_attack_paths(project_id, db, limit=50)
        for p in paths:
            aids = p.get("asset_ids") or []
            if asset and asset.id in aids:
                attack = True
                prio = p.get("priority_score",0)
                add = 10 if prio >= 70 else 5
                score += add
                reasons.append(f"+{add} Connected to active attack path (E9/E10, priority {prio})")
                break
        if not attack and asset:
            # fallback DB check for manually created paths (tests)
            from app.models.cloud_attack_path import CloudAttackPath
            caps = db.query(CloudAttackPath).filter(CloudAttackPath.project_id==project_id).limit(20).all()
            for cap in caps:
                aids = cap.asset_ids or []
                if asset.id in aids:
                    attack = True
                    prio = cap.priority_score or 0
                    add = 10 if prio >= 70 else 5
                    score += add
                    reasons.append(f"+{add} Connected to active attack path (E9/E10, priority {prio})")
                    break
    except: pass
    # cloud exposure
    if asset and asset.asset_type in ("cloud_resource","cloud_account"):
        score += 5
        reasons.append("+5 Cloud resource asset (E11)")
    # exploit evidence: cve present
    if finding.cve:
        score += 5
        reasons.append(f"+5 CVE present {finding.cve[:20]}")
    # sensitive asset context: api_endpoint, container
    if asset and asset.asset_type in ("api_endpoint","container_image"):
        score += 3
        reasons.append(f"+3 Sensitive asset type {asset.asset_type}")
    # related assets/applications via correlations
    try:
        from app.services.security_correlation import get_correlations
        groups = get_correlations(project_id, db)
        # count groups containing finding
        cnt = sum(1 for g in groups if any(m.get("finding_id")==finding.id for m in g.get("members",[])))
        if cnt >= 1:
            score += 5
            reasons.append(f"+5 Correlated with {cnt} related findings (E12)")
        # also count related assets via AssetRelationship
        rel_cnt = db.query(func.count(text("id"))).select_from(text("asset_relationships")).where(text("project_id=:pid")).params(pid=project_id).scalar() or 0
    except: pass
    # SLA breach
    try:
        from app.models.finding import FindingSLA
        sla = db.query(FindingSLA).filter(FindingSLA.finding_id==finding.id, FindingSLA.status=="breached").first()
        if sla:
            score += 10
            reasons.append("+10 SLA breached (D7)")
    except: pass
    # remediation state
    try:
        from app.models.finding import FindingRemediation
        rem = db.query(FindingRemediation).filter(FindingRemediation.finding_id==finding.id).order_by(FindingRemediation.created_at.desc()).first()
        if rem and rem.status in ("open","blocked"):
            add = 5 if rem.status=="open" else 3
            score += add
            reasons.append(f"+{add} Remediation {rem.status} (D7)")
    except: pass
    # retest/validation
    try:
        from app.models.security_validation import SecurityValidation
        from app.models.finding import FindingRetest
        val = db.query(SecurityValidation).filter(SecurityValidation.finding_id==finding.id).order_by(SecurityValidation.created_at.desc()).first()
        if val and val.verdict in ("INVALID","INCONCLUSIVE"):
            score += 5
            reasons.append(f"+5 Validation {val.verdict} (E14)")
        retest = db.query(FindingRetest).filter(FindingRetest.finding_id==finding.id).order_by(FindingRetest.created_at.desc()).first()
        if retest and retest.result == "not_fixed":
            score += 5
            reasons.append("+5 Retest not_fixed (D8)")
    except: pass
    # change/recurrence
    try:
        from app.models.asset_change_event import AssetChangeEvent
        from app.models.finding import FindingHistory
        recent = db.query(AssetChangeEvent).filter(AssetChangeEvent.asset_id==finding.asset_id, AssetChangeEvent.detected_at >= datetime.now(timezone.utc)-timedelta(days=7)).first() if finding.asset_id else None
        if recent:
            score += 5
            reasons.append("+5 Recent asset change (D2)")
        # recurrence via reopened
        hist = db.query(FindingHistory).filter(FindingHistory.finding_id==finding.id, FindingHistory.action=="reopened").first()
        if hist:
            score += 5
            reasons.append("+5 Recurrence/reopened")
    except: pass
    score = max(0, min(100, score))
    tier = _tier(score)
    # preserve original severity tier not replaced but prioritization is separate
    return {
        "finding_id": finding.id,
        "fingerprint": _fingerprint(project_id, "finding", finding.id),
        "score": score,
        "tier": tier,
        "severity": sev,
        "reasons": reasons,
        "internet_exposure": internet,
        "application_criticality": app_crit,
        "attack_path": attack,
        "evidence": {"finding_id": finding.id, "asset_id": finding.asset_id, "scanner": finding.scanner},
    }

def get_prioritized_findings(project_id:str, db:Session, limit:int=50) -> list[dict]:
    limit = max(1, min(limit, MAX_FINDINGS))
    findings = db.query(Finding).join(Asset, Finding.asset_id==Asset.id, isouter=True).filter((Asset.project_id==project_id) | (Finding.asset_id.is_(None))).limit(MAX_FINDINGS).all()
    # fallback if join fails: just filter via asset project or any finding with asset in project
    if not findings:
        # try direct via asset ids in project
        asset_ids = [r[0] for r in db.query(Asset.id).filter(Asset.project_id==project_id).limit(MAX_ASSETS).all()]
        if asset_ids:
            findings = db.query(Finding).filter(Finding.asset_id.in_(asset_ids)).limit(MAX_FINDINGS).all()
        else:
            findings = db.query(Finding).filter(Finding.asset_id.is_(None)).limit(MAX_FINDINGS).all()
    # calculate priority
    scored = []
    for f in findings:
        # ensure project isolation: if asset, check asset project
        if f.asset_id:
            a = db.query(Asset).filter(Asset.id==f.asset_id).first()
            if a and a.project_id != project_id:
                continue
        pri = calculate_finding_priority(f, db, project_id)
        scored.append({**pri, "finding": f})
    scored.sort(key=lambda x: (-x["score"], -SEV_BASE.get(x["severity"],0), x["finding_id"]))
    # sanitize
    for s in scored:
        s["finding_obj"] = s.pop("finding")
        # redact evidence
        if s["finding_obj"].evidence:
            s["evidence_redacted"] = _sanitize(s["finding_obj"].evidence)
        else:
            s["evidence_redacted"] = None
    return scored[:limit]

def get_top_risks(project_id:str, db:Session) -> dict:
    # top findings, top apps, top attack paths
    prioritized = get_prioritized_findings(project_id, db, limit=10)
    # top apps via application risk
    try:
        from app.services.application_intelligence import calculate_application_risk, list_applications
        apps = list_applications(project_id, db, limit=MAX_APPLICATIONS)
        app_risks = []
        for a in apps:
            r = calculate_application_risk(a.id, db, project_id)
            app_risks.append({"application_id": a.id, "name": a.name, "score": r["score"], "tier": r["tier"], "factors": r["factors"]})
        app_risks.sort(key=lambda x: -x["score"])
        top_apps = app_risks[:5]
    except:
        top_apps = []
    # top attack paths
    try:
        from app.services.cloud_attack_paths import build_cloud_attack_paths
        paths = build_cloud_attack_paths(project_id, db, limit=20)
        # prioritize by priority_score
        paths.sort(key=lambda p: -p.get("priority_score",0))
        top_paths = paths[:5]
    except:
        top_paths = []
    # recently worsened exposure: assets with recent change + internet
    worsened = []
    try:
        from app.models.asset_change_event import AssetChangeEvent
        recent = db.query(AssetChangeEvent).filter(AssetChangeEvent.project_id==project_id, AssetChangeEvent.detected_at >= datetime.now(timezone.utc)-timedelta(days=7)).limit(10).all()
        for ch in recent:
            a = db.query(Asset).filter(Asset.id==ch.asset_id).first()
            if a and (a.extra_data or {}).get("externally_reachable"):
                worsened.append({"asset_id": a.id, "value": a.value[:60], "change_type": ch.change_type})
    except: pass
    return {
        "project_id": project_id,
        "top_findings": [{"finding_id": p["finding_id"], "score": p["score"], "tier": p["tier"], "severity": p["severity"], "reasons": p["reasons"][:3]} for p in prioritized[:5]],
        "top_applications": top_apps,
        "top_attack_paths": top_paths,
        "recently_worsened_exposure": worsened[:5],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

def get_priority_summary(project_id:str, db:Session) -> dict:
    prioritized = get_prioritized_findings(project_id, db, limit=MAX_FINDINGS)
    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0,"INFO":0}
    for p in prioritized:
        counts[p["tier"]] += 1
    # SLA breached count
    sla_breached = 0
    try:
        from app.models.finding import FindingSLA
        sla_breached = db.query(func.count(FindingSLA.id)).filter(FindingSLA.project_id==project_id, FindingSLA.status=="breached").scalar() or 0
    except: pass
    # remediation open
    open_rem = 0
    try:
        from app.models.finding import FindingRemediation
        open_rem = db.query(func.count(FindingRemediation.id)).join(Finding, FindingRemediation.finding_id==Finding.id).join(Asset, Finding.asset_id==Asset.id).filter(Asset.project_id==project_id, FindingRemediation.status=="open").scalar() or 0
    except: pass
    # validation pending
    pending_val = 0
    try:
        from app.models.security_validation import SecurityValidation
        pending_val = db.query(func.count(SecurityValidation.id)).filter(SecurityValidation.project_id==project_id, SecurityValidation.status.in_(["QUEUED","RUNNING"])).scalar() or 0
    except: pass
    return {
        "project_id": project_id,
        "total_findings": len(prioritized),
        "by_tier": counts,
        "by_severity": {k: sum(1 for p in prioritized if p["severity"]==k) for k in ["critical","high","medium","low","info"]},
        "top_priority": prioritized[0] if prioritized else None,
        "sla_breached": sla_breached,
        "open_remediation": open_rem,
        "pending_validation": pending_val,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

def get_finding_priority_detail(project_id:str, db:Session, finding_id:str) -> dict | None:
    f = db.query(Finding).filter(Finding.id==finding_id).first()
    if not f:
        return None
    # project isolation check
    if f.asset_id:
        a = db.query(Asset).filter(Asset.id==f.asset_id).first()
        if not a or a.project_id != project_id:
            return None
    return calculate_finding_priority(f, db, project_id)

def get_application_priority_detail(project_id:str, db:Session, app_id:str) -> dict | None:
    app = db.query(Application).filter(Application.id==app_id, Application.project_id==project_id).first()
    if not app:
        return None
    try:
        from app.services.application_intelligence import calculate_application_risk, get_application_findings
        risk = calculate_application_risk(app_id, db, project_id)
        findings = get_application_findings(app_id, db, project_id, limit=10)
        # prioritize findings within app
        prioritized = []
        for f in findings:
            p = calculate_finding_priority(f, db, project_id)
            prioritized.append(p)
        prioritized.sort(key=lambda x: -x["score"])
        return {"application_id": app_id, "application risk": risk, "prioritized_findings": prioritized[:5]}
    except Exception as e:
        return {"application_id": app_id, "error": str(e)[:200]}

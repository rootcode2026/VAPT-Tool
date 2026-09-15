"""F7 Security Operations Decision Center — deterministic operational layer over F1-F6.
Reuses existing intelligence, no new risk engine, bounded on-read.
"""
from __future__ import annotations
import hashlib
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.asset import Asset
from app.models.application import Application
from app.models.finding import Finding

MAX_DECISIONS = 20
MAX_RESULTS = 20
MAX_ASSETS = 500
MAX_FINDINGS = 500
MAX_ATTACK_PATHS = 100
SEV_RANK = {"critical":0,"high":1,"medium":2,"low":3,"info":4}

DECISION_CATEGORIES = {"CRITICAL_EXPOSURE","WORSENING_EXPOSURE","RECURRING_EXPOSURE","FAILED_REMEDIATION","OVERDUE_SECURITY_WORK","AGING_RISK_ACCEPTANCE","DANGEROUS_ATTACK_PATH","MAJOR_COVERAGE_GAP","IMPORTANT_RECENT_CHANGE","IMPROVEMENT","VALIDATION_FAILURE"}

def _sanitize(v: str | None) -> str | None:
    if not v: return v
    low=v.lower()
    if any(k in low for k in ("secret","password","token","private_key","credential","api_key","access_key")):
        return "[REDACTED]"
    return v[:500]

def _sev(s): return (s or "info").lower()

def _dq(a,f):
    if a==0 and f==0: return {"status":"INSUFFICIENT_DATA","limitations":["No data"]}
    if a<5 and f<5: return {"status":"PARTIAL","limitations":["Limited"]}
    return {"status":"SUFFICIENT","limitations":[]}

def _priority(f: Finding, db: Session, pid: str) -> dict:
    try:
        from app.services.security_prioritization import calculate_finding_priority
        return calculate_finding_priority(f, db, pid)
    except Exception:
        sev=_sev(f.severity)
        return {"score":{"critical":35,"high":20,"medium":10,"low":3}.get(sev,0),"tier":"HIGH" if sev=="critical" else "MEDIUM","severity":sev,"reasons":[f"Severity {sev}"]}

def _is_external(a: Asset) -> bool:
    ed=a.extra_data or {}
    if isinstance(ed, dict):
        if ed.get("externally_reachable") is True: return True
        if ed.get("public") is True: return True
        if str(ed.get("exposure") or "").upper()=="INTERNET_EXPOSED": return True
    return False

def _build_decisions(project_id: str, db: Session) -> list[dict]:
    decisions: list[dict]=[]
    assets = db.query(Asset).filter(Asset.project_id==project_id).limit(MAX_ASSETS).all()
    findings = []
    asset_ids=[r[0] for r in db.query(Asset.id).filter(Asset.project_id==project_id).limit(MAX_ASSETS).all()]
    if asset_ids:
        findings=db.query(Finding).filter(Finding.asset_id.in_(asset_ids)).limit(MAX_FINDINGS).all()
    asset_map={a.id:a for a in assets}
    # F2 priorities
    scored=[]
    for f in findings:
        pri=_priority(f, db, project_id)
        scored.append((pri["score"], f, pri))
    scored.sort(key=lambda x: (-x[0], SEV_RANK.get(_sev(x[1].severity),99), x[1].id))
    # CRITICAL_EXPOSURE: critical + internet
    for score,f,pri in scored[:20]:
        if _sev(f.severity)=="critical" and f.asset_id and asset_map.get(f.asset_id) and _is_external(asset_map[f.asset_id]):
            # check investigation existing
            inv_id=None
            try:
                from app.models.security_investigation import SecurityInvestigation
                inv=db.query(SecurityInvestigation).filter(SecurityInvestigation.project_id==project_id, SecurityInvestigation.subject_id==f.id).first()
                if inv: inv_id=inv.id
            except: pass
            decisions.append(_mk_decision(project_id, f.id, "finding", f.id, "Critical exposure — internet-facing", pri["score"], _sev(f.severity), "CRITICAL_EXPOSURE","WORSENING" if score>=80 else "ACTIVE","Critical finding on internet-facing asset"+(" with attack path" if f.asset_id in _attack_assets(project_id,db) else ""), [f.id], "Investigate immediately", f, asset_map.get(f.asset_id), inv_id, db, project_id))
            if len(decisions)>=MAX_DECISIONS: break
    # WORSENING_EXPOSURE via F3
    try:
        from app.services.security_trends import get_trends
        tr=get_trends(project_id, db, window="7d")
        for w in tr.get("top_worsening",[])[:5]:
            if len(decisions)>=MAX_DECISIONS: break
            fid=w.get("id")
            f=next((x[1] for x in scored if x[1].id==fid), None)
            pri_val=50
            sev="high"
            if f:
                pri=_priority(f,db,project_id)
                pri_val=pri["score"]; sev=_sev(f.severity)
            decisions.append(_mk_decision(project_id, fid or w.get("id"), w.get("type","finding"), fid or w.get("id"), f"Worsening exposure — {w.get('reason','')[:40]}", pri_val, sev, "WORSENING_EXPOSURE","WORSENING","Trend worsening in 7d window", [fid], "Validate exposure", f, None, None, db, project_id))
    except: pass
    # RECURRING_EXPOSURE
    try:
        from app.services.security_decision_history import get_recurring_exposure
        rec=get_recurring_exposure(project_id, db, limit=5)
        for r in rec.get("recurring",[])[:3]:
            if len(decisions)>=MAX_DECISIONS: break
            sid=r.get("subject_id")
            # find finding
            f=next((x[1] for x in scored if x[1].id==sid), None)
            pri_val=40
            sev="medium"
            if f:
                pri=_priority(f,db,project_id)
                pri_val=pri["score"]; sev=_sev(f.severity)
            decisions.append(_mk_decision(project_id, sid, "finding" if r.get("type")=="finding_reopened" else "asset", sid, f"Recurring exposure — {r.get('recurrence_type')}", pri_val, sev, "RECURRING_EXPOSURE","RECURRING",f"Recurrence ×{r.get('recurrence_count')}", [sid], "Review root cause", f, None, None, db, project_id))
    except: pass
    # FAILED_REMEDIATION
    try:
        from app.services.security_decision_history import get_remediation_effectiveness
        rem=get_remediation_effectiveness(project_id, db)
        if rem.get("failed",0)>0 or rem.get("reopened",0)>0:
            # pick one failed finding
            from app.models.finding import FindingRemediation, FindingHistory
            rows=db.query(FindingRemediation.finding_id).filter(FindingRemediation.project_id==project_id, FindingRemediation.status!="completed").limit(3).all()
            for (fid,) in rows:
                if len(decisions)>=MAX_DECISIONS: break
                f=next((x[1] for x in scored if x[1].id==fid), None)
                pri_val=30
                sev="medium"
                if f:
                    pri=_priority(f,db,project_id)
                    pri_val=pri["score"]; sev=_sev(f.severity)
                decisions.append(_mk_decision(project_id, fid, "finding", fid, "Failed remediation", pri_val, sev, "FAILED_REMEDIATION","FAILED","Remediation without successful retest/validation", [fid], "Review remediation", f, None, None, db, project_id))
    except: pass
    # OVERDUE_SECURITY_WORK via SLA
    try:
        from app.models.finding import FindingSLA
        rows=db.query(FindingSLA.finding_id).filter(FindingSLA.project_id==project_id, FindingSLA.status=="breached").limit(3).all()
        for (fid,) in rows:
            if len(decisions)>=MAX_DECISIONS: break
            f=next((x[1] for x in scored if x[1].id==fid), None)
            pri_val=50
            sev="high"
            if f:
                pri=_priority(f,db,project_id)
                pri_val=pri["score"]; sev=_sev(f.severity)
            decisions.append(_mk_decision(project_id, fid, "finding", fid, "Overdue security work — SLA breached", pri_val, sev, "OVERDUE_SECURITY_WORK","OVERDUE","SLA breached, immediate action required", [fid], "Assign owner", f, None, None, db, project_id))
    except: pass
    # AGING_RISK_ACCEPTANCE
    try:
        from app.services.security_decision_history import get_risk_acceptance_aging
        aging=get_risk_acceptance_aging(project_id, db)
        for det in aging.get("details",[])[:2]:
            if len(decisions)>=MAX_DECISIONS: break
            fid=det.get("finding_id")
            f=next((x[1] for x in scored if x[1].id==fid), None)
            decisions.append(_mk_decision(project_id, det.get("id"), "finding", fid, "Aging risk acceptance", 30, "medium", "AGING_RISK_ACCEPTANCE","AGING",f"Aging accepted risk since {det.get('created_at','')[:10]}", [fid], "Review risk acceptance", f, None, None, db, project_id))
    except: pass
    # DANGEROUS_ATTACK_PATH
    try:
        from app.services.cloud_attack_paths import build_cloud_attack_paths
        paths=build_cloud_attack_paths(project_id, db, limit=5)
        if not paths:
            from app.models.cloud_attack_path import CloudAttackPath
            rows=db.query(CloudAttackPath).filter(CloudAttackPath.project_id==project_id).limit(5).all()
            paths=[{"id":r.id,"path_type":r.path_type,"severity":r.severity,"priority_score":r.priority_score,"provider":r.provider} for r in rows]
        for p in paths[:2]:
            if len(decisions)>=MAX_DECISIONS: break
            sev=_sev(p.get("severity"))
            pri_val=p.get("priority_score",70)
            decisions.append(_mk_decision(project_id, p.get("id"), "attack_path", p.get("id"), f"Dangerous attack path — {p.get('path_type')}", pri_val, sev, "DANGEROUS_ATTACK_PATH","ACTIVE",f"Provider {p.get('provider')} critical path", [p.get("id")], "Validate exposure", None, None, None, db, project_id))
    except: pass
    # MAJOR_COVERAGE_GAP
    try:
        from app.services.attack_surface_analytics import get_coverage_gaps
        cov=get_coverage_gaps(project_id, db)
        for g in cov.get("coverage_gaps",[])[:2]:
            if len(decisions)>=MAX_DECISIONS: break
            decisions.append(_mk_decision(project_id, g.get("subject_id"), g.get("subject_type","application"), g.get("subject_id"), f"Major coverage gap — {g.get('gap_type')}", 20, "low", "MAJOR_COVERAGE_GAP","GAP",g.get("evidence","")[:80], [g.get("subject_id")], g.get("recommendation","Assign owner")[:60], None, None, None, db, project_id))
    except: pass
    # IMPORTANT_RECENT_CHANGE
    try:
        from app.models.asset_change_event import AssetChangeEvent
        rows=db.query(AssetChangeEvent).filter(AssetChangeEvent.project_id==project_id).order_by(AssetChangeEvent.detected_at.desc()).limit(2).all()
        for ch in rows:
            if len(decisions)>=MAX_DECISIONS: break
            decisions.append(_mk_decision(project_id, ch.asset_id, "asset", ch.asset_id, f"Important recent change — {ch.change_type}", 25, "low", "IMPORTANT_RECENT_CHANGE","NEW",f"Change {ch.change_type} detected {ch.detected_at.isoformat()[:10] if ch.detected_at else ''}", [ch.asset_id], "Validate exposure", None, asset_map.get(ch.asset_id), None, db, project_id))
    except: pass
    # VALIDATION_FAILURE
    try:
        from app.models.security_validation import SecurityValidation
        rows=db.query(SecurityValidation).filter(SecurityValidation.project_id==project_id, SecurityValidation.verdict.in_(["INVALID","INCONCLUSIVE"])).limit(2).all()
        for v in rows:
            if len(decisions)>=MAX_DECISIONS: break
            f=next((x[1] for x in scored if x[1].id==v.finding_id), None)
            pri_val=40
            sev="medium"
            if f:
                pri=_priority(f,db,project_id)
                pri_val=pri["score"]; sev=_sev(f.severity)
            decisions.append(_mk_decision(project_id, v.finding_id, "finding", v.finding_id, f"Validation failure — {v.verdict}", pri_val, sev, "VALIDATION_FAILURE","FAILED",f"Validation {v.verdict} confidence {v.confidence}", [v.finding_id], "Review remediation", f, None, None, db, project_id))
    except: pass
    # IMPROVEMENT (if any remediated)
    try:
        from app.services.security_decision_history import get_remediation_effectiveness
        rem=get_remediation_effectiveness(project_id, db)
        if rem.get("successful",0)>0:
            decisions.append(_mk_decision(project_id, "improvement-1", "project", project_id, "Improvement — remediation success", 10, "low", "IMPROVEMENT","IMPROVED",f"{rem.get('successful')} successful remediations", [], "Continue improvement", None, None, None, db, project_id))
    except: pass
    # deterministic sort
    decisions.sort(key=lambda d: (-d["priority"], SEV_RANK.get(_sev(d["severity"]),99), d["decision_id"]))
    return decisions[:MAX_DECISIONS]

def _attack_assets(pid: str, db: Session) -> set[str]:
    s=set()
    try:
        from app.services.cloud_attack_paths import build_cloud_attack_paths
        paths=build_cloud_attack_paths(pid, db, limit=MAX_ATTACK_PATHS)
        for p in paths:
            for aid in p.get("asset_ids") or []:
                s.add(aid)
    except: pass
    if not s:
        try:
            from app.models.cloud_attack_path import CloudAttackPath
            rows=db.query(CloudAttackPath).filter(CloudAttackPath.project_id==pid).limit(MAX_ATTACK_PATHS).all()
            for r in rows:
                for aid in r.asset_ids or []:
                    s.add(aid)
        except: pass
    return s

def _mk_decision(pid, decision_id, subject_type, subject_id, title, priority, severity, status, direction, why, evidence_refs, action, finding: Finding | None, asset: Asset | None, inv_id, db: Session, project_id: str):
    # fingerprint
    raw=f"{pid}|{status}|{subject_id}|{title}"
    fid=hashlib.sha256(raw.encode()).hexdigest()[:32]
    # owner if known via asset
    owner=None
    if asset and getattr(asset, "owner_user_id", None):
        owner=asset.owner_user_id
    # SLA state
    sla_state=None
    if finding:
        try:
            from app.models.finding import FindingSLA
            sla=db.query(FindingSLA).filter(FindingSLA.finding_id==finding.id, FindingSLA.status=="breached").first()
            if sla: sla_state="BREACHED"
        except: pass
    # remediation state
    rem_state=None
    if finding:
        try:
            from app.models.finding import FindingRemediation
            rem=db.query(FindingRemediation).filter(FindingRemediation.finding_id==finding.id).order_by(FindingRemediation.created_at.desc()).first()
            if rem: rem_state=rem.status
        except: pass
    # validation state
    val_state=None
    if finding:
        try:
            from app.models.security_validation import SecurityValidation
            v=db.query(SecurityValidation).filter(SecurityValidation.finding_id==finding.id).order_by(SecurityValidation.created_at.desc()).first()
            if v: val_state=v.verdict
        except: pass
    # recurrence
    rec_state=None
    if finding:
        try:
            from app.models.finding import FindingHistory
            cnt=db.query(func.count(FindingHistory.id)).filter(FindingHistory.finding_id==finding.id, FindingHistory.action=="reopened").scalar() or 0
            if cnt>0: rec_state=f"REOPENED ×{cnt}"
        except: pass
    confidence="HIGH" if priority>=60 else "MEDIUM" if priority>=30 else "LOW"
    return {
        "decision_id": fid,
        "project_id": pid,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "title": _sanitize(title)[:120],
        "priority": int(priority),
        "severity": _sev(severity),
        "status": status,
        "direction": direction,
        "why_it_matters": _sanitize(why)[:500],
        "evidence_refs": [x for x in evidence_refs if x][:5],
        "recommended_action": _sanitize(action)[:120],
        "owner": owner,
        "sla_state": sla_state,
        "remediation_state": rem_state,
        "validation_state": val_state,
        "recurrence_state": rec_state,
        "confidence": confidence,
        "related_finding": finding.id if finding else None,
        "related_asset": asset.id if asset else None,
        "investigation_id": inv_id,
    }

def get_decision_center(project_id: str, db: Session) -> dict:
    decisions=_build_decisions(project_id, db)
    # snapshot counts
    assets_cnt=db.query(func.count(Asset.id)).filter(Asset.project_id==project_id).scalar() or 0
    findings_cnt=0
    asset_ids=[r[0] for r in db.query(Asset.id).filter(Asset.project_id==project_id).limit(MAX_ASSETS).all()]
    if asset_ids:
        findings_cnt=db.query(func.count(Finding.id)).filter(Finding.asset_id.in_(asset_ids)).scalar() or 0
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"data_quality":_dq(assets_cnt, findings_cnt),"decisions":decisions,"total":len(decisions)}

def get_decisions(project_id: str, db: Session, limit: int = 20, category: str | None = None) -> dict:
    limit=max(1,min(limit, MAX_DECISIONS))
    decs=_build_decisions(project_id, db)
    if category and category.upper() in DECISION_CATEGORIES:
        decs=[d for d in decs if d["status"]==category.upper()]
    decs=decs[:limit]
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"decisions":decs,"total":len(decs),"category":category}

def get_attention_queue(project_id: str, db: Session, limit: int = 20) -> dict:
    limit=max(1,min(limit, MAX_RESULTS))
    decs=_build_decisions(project_id, db)
    # classify
    queue=[]
    for d in decs[:limit]:
        pri=d["priority"]
        if pri>=80: q="IMMEDIATE"
        elif pri>=60: q="HIGH"
        elif pri>=30: q="NORMAL"
        else: q="WATCH"
        queue.append({"subject_type":d["subject_type"],"subject_id":d["subject_id"],"title":d["title"],"priority":pri,"severity":d["severity"],"queue":q,"reason":d["why_it_matters"],"evidence_refs":d["evidence_refs"],"suggested_next_step":d["recommended_action"],"decision_id":d["decision_id"]})
    queue.sort(key=lambda x: (-x["priority"], SEV_RANK.get(_sev(x["severity"]),99), x["decision_id"]))
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"queue":queue[:limit],"total":len(queue)}

def get_executive_summary(project_id: str, db: Session) -> dict:
    # reuse F6 scorecard + F3 trends
    try:
        from app.services.security_decision_history import get_scorecard
        sc=get_scorecard(project_id, db, window="7d")
        overall=sc.get("overall_direction","UNCHANGED")
    except:
        overall="UNKNOWN"
        sc={}
    decisions=_build_decisions(project_id, db)
    crit=len([d for d in decisions if _sev(d["severity"])=="critical"])
    high=len([d for d in decisions if _sev(d["severity"])=="high"])
    worsening=len([d for d in decisions if d["direction"]=="WORSENING"])
    recurring=len([d for d in decisions if d["status"]=="RECURRING_EXPOSURE"])
    # unresolved remediation
    unresolved=0
    try:
        from app.models.finding import FindingRemediation
        unresolved=db.query(func.count(FindingRemediation.id)).filter(FindingRemediation.project_id==project_id, FindingRemediation.status.in_(["open","blocked"])).scalar() or 0
    except: pass
    failed=0
    try:
        from app.models.security_validation import SecurityValidation
        failed=db.query(func.count(SecurityValidation.id)).filter(SecurityValidation.project_id==project_id, SecurityValidation.verdict.in_(["INVALID","INCONCLUSIVE"])).scalar() or 0
    except: pass
    # attack paths
    attack_cnt=0
    try:
        from app.models.cloud_attack_path import CloudAttackPath
        attack_cnt=db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id==project_id, CloudAttackPath.status=="ACTIVE").scalar() or 0
    except: pass
    # aging risk
    aging=0
    try:
        from app.services.security_decision_history import get_risk_acceptance_aging
        aging=get_risk_acceptance_aging(project_id, db).get("aging",0)
    except: pass
    # coverage gaps
    gaps=0
    try:
        from app.services.attack_surface_analytics import get_coverage_gaps
        gaps=get_coverage_gaps(project_id, db).get("total_gaps",0)
    except: pass
    # recent changes
    recent=0
    try:
        from app.models.asset_change_event import AssetChangeEvent
        cutoff=datetime.now(timezone.utc)-timedelta(days=7)
        recent=db.query(func.count(AssetChangeEvent.id)).filter(AssetChangeEvent.project_id==project_id, AssetChangeEvent.detected_at>=cutoff).scalar() or 0
    except: pass
    # strongest improvement
    strongest=sc.get("strongest_improvement","No improvement") if isinstance(sc, dict) else "—"
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"overall_direction":overall,"critical_active":crit,"high_active":high,"worsening_count":worsening,"recurring_count":recurring,"unresolved_remediation":unresolved,"failed_validation":failed,"active_attack_paths":attack_cnt,"aging_risk_acceptances":aging,"major_coverage_gaps":gaps,"recent_changes":recent,"strongest_improvement":strongest,"data_quality":_dq(gaps, crit+high)}

def get_security_snapshot(project_id: str, db: Session) -> dict:
    assets_cnt=db.query(func.count(Asset.id)).filter(Asset.project_id==project_id).scalar() or 0
    apps_cnt=db.query(func.count(Application.id)).filter(Application.project_id==project_id).scalar() or 0
    asset_ids=[r[0] for r in db.query(Asset.id).filter(Asset.project_id==project_id).limit(MAX_ASSETS).all()]
    findings_cnt=0; crit=high=0
    if asset_ids:
        findings_cnt=db.query(func.count(Finding.id)).filter(Finding.asset_id.in_(asset_ids)).scalar() or 0
        crit=db.query(func.count(Finding.id)).filter(Finding.asset_id.in_(asset_ids), Finding.severity=="critical").scalar() or 0
        high=db.query(func.count(Finding.id)).filter(Finding.asset_id.in_(asset_ids), Finding.severity=="high").scalar() or 0
    internet=0
    if asset_ids:
        assets=db.query(Asset).filter(Asset.id.in_(asset_ids)).limit(MAX_ASSETS).all()
        internet=sum(1 for a in assets if _is_external(a))
    cloud_exp=0
    if asset_ids:
        cloud_exp=db.query(func.count(Asset.id)).filter(Asset.project_id==project_id, Asset.asset_type.in_(["cloud_resource","cloud_account"])).scalar() or 0
    active_paths=0
    try:
        from app.models.cloud_attack_path import CloudAttackPath
        active_paths=db.query(func.count(CloudAttackPath.id)).filter(CloudAttackPath.project_id==project_id, CloudAttackPath.status=="ACTIVE").scalar() or 0
    except: pass
    open_inv=0
    try:
        from app.models.security_investigation import SecurityInvestigation
        open_inv=db.query(func.count(SecurityInvestigation.id)).filter(SecurityInvestigation.project_id==project_id, SecurityInvestigation.status.in_(["open","OPEN","investigating"])).scalar() or 0
    except: pass
    open_rem=0
    try:
        from app.models.finding import FindingRemediation
        open_rem=db.query(func.count(FindingRemediation.id)).filter(FindingRemediation.project_id==project_id, FindingRemediation.status.in_(["open","blocked"])).scalar() or 0
    except: pass
    failed_retest=0
    try:
        from app.models.finding import FindingRetest
        failed_retest=db.query(func.count(FindingRetest.id)).filter(FindingRetest.project_id==project_id, FindingRetest.result=="failed").scalar() or 0
    except: pass
    val_fail=0
    try:
        from app.models.security_validation import SecurityValidation
        val_fail=db.query(func.count(SecurityValidation.id)).filter(SecurityValidation.project_id==project_id, SecurityValidation.verdict.in_(["INVALID","INCONCLUSIVE"])).scalar() or 0
    except: pass
    cov_gaps=0
    try:
        from app.services.attack_surface_analytics import get_coverage_gaps
        cov_gaps=get_coverage_gaps(project_id, db).get("total_gaps",0)
    except: pass
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"assets":assets_cnt,"applications":apps_cnt,"findings":findings_cnt,"critical_findings":crit,"high_findings":high,"internet_facing_assets":internet,"cloud_exposures":cloud_exp,"active_attack_paths":active_paths,"open_investigations":open_inv,"open_remediation":open_rem,"failed_retests":failed_retest,"validation_failures":val_fail,"coverage_gaps":cov_gaps}

def get_recent_changes(project_id: str, db: Session, limit: int = 20) -> dict:
    limit=max(1,min(limit, MAX_RESULTS))
    try:
        from app.models.asset_change_event import AssetChangeEvent
        rows=db.query(AssetChangeEvent).filter(AssetChangeEvent.project_id==project_id).order_by(AssetChangeEvent.detected_at.desc()).limit(limit).all()
        items=[{"id":r.id,"asset_id":r.asset_id,"change_type":r.change_type,"detected_at":r.detected_at.isoformat() if r.detected_at else None, "temporal":"TEMPORALLY_ASSOCIATED"} for r in rows]
    except:
        items=[]
    # also findings recent
    try:
        asset_ids=[r[0] for r in db.query(Asset.id).filter(Asset.project_id==project_id).limit(MAX_ASSETS).all()]
        if asset_ids:
            findings=db.query(Finding).filter(Finding.asset_id.in_(asset_ids)).order_by(Finding.created_at.desc()).limit(limit).all()
            for f in findings:
                items.append({"id":f.id,"type":"new_finding","severity":_sev(f.severity),"created_at":f.created_at.isoformat() if f.created_at else None, "title":_sanitize(f.title)})
    except: pass
    items.sort(key=lambda x: x.get("detected_at") or x.get("created_at") or "", reverse=True)
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"changes":items[:limit],"total":len(items)}

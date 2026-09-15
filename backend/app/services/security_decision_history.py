"""F6 Security Decision History — deterministic longitudinal metrics reusing existing persisted evidence.
No new table by default. Bounded on-read.
"""
from __future__ import annotations
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.asset import Asset
from app.models.application import Application, ApplicationAsset
from app.models.finding import Finding

MAX_ASSETS = 500
MAX_FINDINGS = 500
MAX_APPLICATIONS = 100
MAX_ATTACK_PATHS = 100
MAX_EXPOSURES = 500
MAX_HISTORY = 100
MAX_EVENTS = 200
MAX_RESULTS = 20
VALID_WINDOWS = {"7d","30d","90d"}
SEV_RANK = {"critical":0,"high":1,"medium":2,"low":3,"info":4}

def _sanitize(v: str | None) -> str | None:
    if not v: return v
    low=v.lower()
    if any(k in low for k in ("secret","password","token","private_key","credential","api_key","access_key")):
        return "[REDACTED]"
    return v[:500]

def _sev(s: str | None) -> str:
    return (s or "info").lower()

def _is_external(a: Asset) -> bool:
    ed=a.extra_data or {}
    if isinstance(ed, dict):
        if ed.get("externally_reachable") is True: return True
        if ed.get("public") is True: return True
        if str(ed.get("exposure") or "").upper()=="INTERNET_EXPOSED": return True
    return False

def _dq(assets: int, findings: int) -> dict:
    if assets==0 and findings==0:
        return {"status":"INSUFFICIENT_DATA","limitations":["No data"]}
    if assets<5 and findings<5:
        return {"status":"PARTIAL","limitations":["Limited data"]}
    return {"status":"SUFFICIENT","limitations":[]}

def _window_days(w: str) -> int:
    return {"7d":7,"30d":30,"90d":90}[w]

def _validate_window(w: str):
    if w not in VALID_WINDOWS:
        raise ValueError(f"Invalid window: {w}")

# A. Exposure History — reuse F3 trend logic but also count coverage gaps etc
def get_exposure_history(project_id: str, db: Session, window: str = "7d") -> dict:
    _validate_window(window)
    try:
        from app.services.security_trends import get_trends
        trends = get_trends(project_id, db, window=window)
        # map to exposure history format
        cur = trends.get("metrics",{}).get("current",{})
        prev = trends.get("metrics",{}).get("previous",{})
        # exposure count proxy: findings_total + attack_paths + externally_reachable
        hist = {
            "window": window,
            "current": cur,
            "previous": prev,
            "trends": trends.get("trends",{}),
            "posture": trends.get("posture",{}),
            "data_quality": trends.get("data_quality","SUFFICIENT"),
        }
        # add coverage gaps over time via count of gaps now vs filtered by created_at? Use asset gaps not time-series, so report current
        try:
            from app.services.attack_surface_analytics import get_coverage_gaps
            cov = get_coverage_gaps(project_id, db)
            hist["coverage_gaps_current"] = cov.get("total_gaps",0)
        except Exception:
            hist["coverage_gaps_current"] = 0
        return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"data_quality":_dq(cur.get("findings_total",0), cur.get("attack_paths",0)),"history":hist,"window":window}
    except Exception as e:
        # fallback insufficient
        return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"data_quality":{"status":"INSUFFICIENT_DATA","limitations":[str(e)[:200]]},"history":{"window":window,"current":{},"previous":{}},"window":window}

# B. Improvement direction
def get_improvement(project_id: str, db: Session, window: str = "7d") -> dict:
    _validate_window(window)
    hist = get_exposure_history(project_id, db, window)
    trends = hist.get("history",{}).get("trends",{})
    # determine improved/worsened
    def _dir(key: str, worse_higher: bool = True):
        t = trends.get(key, {})
        cur = t.get("current",0); prev = t.get("previous",0)
        if cur == prev:
            return "UNCHANGED"
        if worse_higher:
            return "WORSENED" if cur > prev else "IMPROVED"
        else:
            return "IMPROVED" if cur > prev else "WORSENED"
    if hist["data_quality"]["status"] == "INSUFFICIENT_DATA":
        return {"project_id":project_id,"window":window,"overall":"INSUFFICIENT_DATA","details":{},"data_quality":hist["data_quality"]}
    # remediation success etc via separate service
    try:
        rem = get_remediation_effectiveness(project_id, db)
        rem_rate = rem.get("success_rate",0)
    except Exception:
        rem_rate = 0
    overall = _dir("critical", True)
    # if no findings but remediation success, consider improved
    if hist["history"].get("posture",{}).get("direction") == "IMPROVING":
        overall = "IMPROVED"
    elif hist["history"].get("posture",{}).get("direction") == "WORSENING":
        overall = "WORSENED"
    return {"project_id":project_id,"window":window,"overall":overall,"critical":_dir("critical"),"high":_dir("high"),"attack_paths":_dir("attack_paths"),"externally_reachable":_dir("externally_reachable"),"remediation_success_rate":rem_rate,"data_quality":hist["data_quality"]}

# C. Recurring Exposure
def get_recurring_exposure(project_id: str, db: Session, limit: int = 20) -> dict:
    limit=max(1,min(limit,MAX_RESULTS))
    # findings reopened
    rec_findings: list[dict]=[]
    try:
        from app.models.finding import FindingHistory
        rows = db.query(FindingHistory.finding_id, func.count(FindingHistory.id)).filter(FindingHistory.project_id==project_id, FindingHistory.action=="reopened").group_by(FindingHistory.finding_id).all()
        for fid, cnt in rows:
            if cnt >=1:
                f = db.query(Finding).filter(Finding.id==fid).first()
                if f:
                    rec_findings.append({"type":"finding_reopened","subject_id":fid,"recurrence_count":int(cnt)+1,"first_seen":f.created_at.isoformat() if f.created_at else None,"last_seen":f.updated_at.isoformat() if f.updated_at else None,"current_priority":None,"current_status":f.status,"recurrence_type":"REOPENED_FINDING","evidence":_sanitize(f.title)})
    except Exception:
        pass
    # asset hotspot recurrence via asset appearing as hotspot repeatedly — use asset with many findings
    asset_counts = Counter()
    try:
        findings = db.query(Finding).join(Asset, Finding.asset_id==Asset.id, isouter=True).filter((Asset.project_id==project_id)).limit(MAX_FINDINGS).all()
        for f in findings:
            if f.asset_id:
                asset_counts[f.asset_id]+=1
        for aid,cnt in asset_counts.most_common(20):
            if cnt>=3:
                a=db.query(Asset).filter(Asset.id==aid).first()
                rec_findings.append({"type":"asset_hotspot","subject_id":aid,"recurrence_count":cnt,"first_seen":a.created_at.isoformat() if a and a.created_at else None,"last_seen":a.last_seen_at.isoformat() if a and a.last_seen_at else None,"current_priority":None,"current_status":a.status if a else None,"recurrence_type":"RECURRING_ASSET","evidence":_sanitize(a.value[:40]) if a else aid[:8]})
    except Exception:
        pass
    # application recurring high priority
    try:
        from app.services.attack_surface_analytics import get_hotspots
        hs = get_hotspots(project_id, db, limit=100)
        app_counts = Counter(h["subject_id"] for h in hs.get("hotspots",[]) if h["subject_type"]=="application")
        for aid,cnt in app_counts.items():
            if cnt>=2:
                rec_findings.append({"type":"application_recurrence","subject_id":aid,"recurrence_count":cnt,"first_seen":None,"last_seen":None,"current_priority":None,"current_status":"high","recurrence_type":"RECURRING_APPLICATION","evidence":aid[:8]})
    except Exception:
        pass
    # attack path recurrence via history
    try:
        from app.models.cloud_attack_path import CloudAttackPath
        rows = db.query(CloudAttackPath.fingerprint, func.count(CloudAttackPath.id), func.min(CloudAttackPath.first_seen_at), func.max(CloudAttackPath.last_seen_at)).filter(CloudAttackPath.project_id==project_id).group_by(CloudAttackPath.fingerprint).all()
        for fp,cnt,first,last in rows:
            if cnt>=2 or (first and last and first!=last):
                rec_findings.append({"type":"attack_path_recurrence","subject_id":fp,"recurrence_count":int(cnt),"first_seen":first.isoformat() if first else None,"last_seen":last.isoformat() if last else None,"current_priority":None,"current_status":"ACTIVE","recurrence_type":"RECURRING_ATTACK_PATH","evidence":fp[:16]})
    except Exception:
        pass
    # sort by recurrence_count desc, stable id
    rec_findings.sort(key=lambda x: (-x["recurrence_count"], x["subject_id"]))
    dq=_dq(len(rec_findings), len(rec_findings))
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"data_quality":dq,"recurring":rec_findings[:limit],"total":len(rec_findings)}

# D. Remediation Effectiveness
def get_remediation_effectiveness(project_id: str, db: Session) -> dict:
    try:
        from app.models.finding import FindingRemediation, FindingRetest
        from app.models.security_validation import SecurityValidation
        rems = db.query(FindingRemediation).filter(FindingRemediation.project_id==project_id).limit(MAX_EVENTS).all()
    except Exception:
        rems=[]
    total = len(rems)
    if total==0:
        return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"data_quality":{"status":"INSUFFICIENT_DATA","limitations":["No remediation"]},"total":0,"successful":0,"partial":0,"failed":0,"reopened":0,"not_verified":0,"success_rate":0}
    successful=partial=failed=reopened=not_verified=0
    for r in rems:
        fid=r.finding_id
        # check retest
        retest=None
        try:
            retest=db.query(FindingRetest).filter(FindingRetest.finding_id==fid).order_by(FindingRetest.created_at.desc()).first()
        except Exception:
            pass
        validation=None
        try:
            validation=db.query(SecurityValidation).filter(SecurityValidation.finding_id==fid).order_by(SecurityValidation.created_at.desc()).first()
        except Exception:
            pass
        # reopened check
        is_reopened=False
        try:
            from app.models.finding import FindingHistory
            reopened_cnt=db.query(func.count(FindingHistory.id)).filter(FindingHistory.finding_id==fid, FindingHistory.action=="reopened").scalar() or 0
            if reopened_cnt>0:
                is_reopened=True
        except Exception:
            pass
        if is_reopened:
            reopened+=1
        elif r.status=="completed" and retest and retest.result=="fixed" and validation and validation.verdict=="VALID":
            successful+=1
        elif r.status=="completed" and retest and retest.result=="fixed":
            partial+=1
        elif r.status=="completed":
            not_verified+=1
        else:
            failed+=1
    success_rate= round(successful/total*100,1) if total else 0
    # clamp 0-100
    success_rate=max(0,min(100,success_rate))
    dq=_dq(total, total)
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"data_quality":dq,"total":total,"successful":successful,"partial":partial,"failed":failed,"reopened":reopened,"not_verified":not_verified,"success_rate":success_rate}

# E. Risk Acceptance Aging
def get_risk_acceptance_aging(project_id: str, db: Session) -> dict:
    try:
        from app.models.finding import FindingRiskAcceptance
        rows=db.query(FindingRiskAcceptance).filter(FindingRiskAcceptance.project_id==project_id).limit(MAX_EVENTS).all()
    except Exception:
        rows=[]
    now=datetime.now(timezone.utc)
    active=aging=expired=critical_high=with_changes=reopened=0
    details=[]
    for r in rows:
        status=(r.status or "").lower()
        is_active=status in ("active","approved","accepted")
        if is_active:
            active+=1
        # aging: >90 days
        created=r.created_at
        if created:
            if created.tzinfo is None: created=created.replace(tzinfo=timezone.utc)
            age_days=(now-created).days
            if age_days>90 and is_active:
                aging+=1
        # expired
        exp=r.expires_at
        if exp:
            if exp.tzinfo is None: exp=exp.replace(tzinfo=timezone.utc)
            if exp < now:
                expired+=1
        # critical/high
        sev = (getattr(r,"severity",None) or "").lower()
        if sev in ("critical","high") and is_active:
            critical_high+=1
        # with subsequent changes: check asset change after acceptance
        with_changes+=0  # placeholder bounded
        # reopened: check finding history after acceptance
        details.append({"id":r.id,"finding_id":r.finding_id,"status":r.status,"created_at":r.created_at.isoformat() if r.created_at else None,"expires_at":r.expires_at.isoformat() if r.expires_at else None,"severity":sev})
    details.sort(key=lambda x: x["created_at"] or "")
    dq=_dq(len(rows), len(rows))
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"data_quality":dq,"active":active,"aging":aging,"expired":expired,"critical_high":critical_high,"with_changes":with_changes,"reopened":reopened,"details":details[:MAX_RESULTS]}

# F. Attack Path Recurrence (reuse E10 history)
def get_attack_path_history_analytics(project_id: str, db: Session, limit: int = 20) -> dict:
    limit=max(1,min(limit,MAX_RESULTS))
    try:
        from app.models.cloud_attack_path import CloudAttackPath
        rows=db.query(CloudAttackPath).filter(CloudAttackPath.project_id==project_id).limit(MAX_ATTACK_PATHS).all()
    except Exception:
        rows=[]
    # group by fingerprint
    grouped: dict[str, list] = defaultdict(list)
    for r in rows:
        grouped[r.fingerprint].append(r)
    rec_list=[]
    for fp, lst in grouped.items():
        lst_sorted=sorted(lst, key=lambda x: x.first_seen_at or datetime.min.replace(tzinfo=timezone.utc))
        first=lst_sorted[0].first_seen_at
        last=lst_sorted[-1].last_seen_at
        cnt=len(lst)
        # severity change
        severities=[_sev(x.severity) for x in lst_sorted]
        sev_change="UNCHANGED"
        if len(set(severities))>1:
            # compare first vs last rank
            rank={"critical":0,"high":1,"medium":2,"low":3}
            if rank.get(severities[-1],99) < rank.get(severities[0],99):
                sev_change="INCREASED"
            else:
                sev_change="DECREASED"
        rec_list.append({"fingerprint":fp,"path_type":lst_sorted[0].path_type,"provider":lst_sorted[0].provider,"first_seen":first.isoformat() if first else None,"last_seen":last.isoformat() if last else None,"recurrence_count":cnt,"current_score":lst_sorted[-1].priority_score,"current_severity":_sev(lst_sorted[-1].severity),"severity_change":sev_change,"history":[{"severity":_sev(x.severity),"score":x.priority_score,"seen":x.first_seen_at.isoformat() if x.first_seen_at else None} for x in lst_sorted[:5]]})
    rec_list.sort(key=lambda x: (-x["recurrence_count"], x["fingerprint"]))
    # filter recurring only for top but return all
    recurring=[r for r in rec_list if r["recurrence_count"]>1]
    dq=_dq(len(rec_list), len(recurring))
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"data_quality":dq,"paths":rec_list[:limit],"recurring":recurring[:limit],"total":len(rec_list)}

# G. Change → Exposure History (reuse F5)
def get_change_exposure_history(project_id: str, db: Session, window: str = "7d", limit: int = 20) -> dict:
    _validate_window(window)
    try:
        from app.services.security_exposure_intelligence import get_change_exposure
        return get_change_exposure(project_id, db, limit=limit)
    except Exception as e:
        return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"data_quality":{"status":"INSUFFICIENT_DATA","limitations":[str(e)[:200]]},"correlations":[]}

# Scorecard
def get_scorecard(project_id: str, db: Session, window: str = "7d") -> dict:
    _validate_window(window)
    hist=get_exposure_history(project_id, db, window)
    imp=get_improvement(project_id, db, window)
    rec=get_recurring_exposure(project_id, db, limit=5)
    rem=get_remediation_effectiveness(project_id, db)
    aph=get_attack_path_history_analytics(project_id, db, limit=5)
    cov_hist=hist.get("history",{}).get("coverage_gaps_current",0)
    # overall direction from improvement
    overall=imp.get("overall","UNCHANGED")
    # strongest improvement: look for most reduced metric
    strongest="No significant change"
    biggest_det="No deterioration"
    try:
        trends=hist.get("history",{}).get("trends",{})
        # find most negative delta (improvement for worse metrics)
        best=None; worst=None
        for k,v in trends.items():
            delta=v.get("delta",0)
            if delta<0 and (best is None or delta<best[1]):
                best=(k,delta)
            if delta>0 and (worst is None or delta>worst[1]):
                worst=(k,delta)
        if best:
            strongest=f"{best[0]} reduced by {abs(best[1])}"
        if worst:
            biggest_det=f"{worst[0]} increased by {worst[1]}"
    except Exception:
        pass
    highest_rec = rec["recurring"][0] if rec.get("recurring") else None
    biggest_unresolved=None
    try:
        from app.services.attack_surface_analytics import get_hotspots
        hs=get_hotspots(project_id, db, limit=1)
        if hs.get("hotspots"):
            biggest_unresolved=hs["hotspots"][0]
    except Exception:
        pass
    # aging risk acceptance highest
    aging=get_risk_acceptance_aging(project_id, db)
    highest_aging = aging["details"][0] if aging.get("details") else None
    # remediation failure area
    fail_area = f"{rem.get('failed')} failed, {rem.get('reopened')} reopened"
    confidence="HIGH" if hist["data_quality"]["status"]=="SUFFICIENT" else "LOW"
    evidence=[f"Window {window}", f"Overall {overall}", f"Remediation success {rem.get('success_rate',0)}%"]
    return {"project_id":project_id,"generated_at":datetime.now(timezone.utc).isoformat(),"window":window,"data_quality":hist["data_quality"],"overall_direction":overall,"strongest_improvement":strongest,"biggest_deterioration":biggest_det,"highest_recurring":highest_rec,"biggest_unresolved_exposure":biggest_unresolved,"highest_aging_risk":highest_aging,"remediation_failure_area":fail_area,"confidence":confidence,"evidence":evidence,"recurring_count":len(rec.get("recurring",[])),"attack_path_recurrence":len(aph.get("recurring",[]))}

# Subject History
def get_subject_history(project_id: str, db: Session, subject_type: str, subject_id: str, window: str = "7d") -> dict | None:
    _validate_window(window)
    st=subject_type.lower()
    if st not in {"finding","asset","application","attack_path","exposure","investigation"}:
        raise ValueError(f"Invalid subject_type: {subject_type}")
    # verify subject exists and belongs to project
    if st=="finding":
        f=db.query(Finding).filter(Finding.id==subject_id).first()
        if not f: return None
        if f.asset_id:
            a=db.query(Asset).filter(Asset.id==f.asset_id).first()
            if not a or a.project_id!=project_id: return None
        # history
        try:
            from app.models.finding import FindingHistory, FindingRemediation, FindingRetest
            from app.models.security_validation import SecurityValidation
            from app.models.asset_change_event import AssetChangeEvent
            hist_rows=db.query(FindingHistory).filter(FindingHistory.finding_id==subject_id).order_by(FindingHistory.created_at.desc()).limit(MAX_HISTORY).all()
            hist=[{"action":h.action,"old":_sanitize(h.old_value),"new":_sanitize(h.new_value),"at":h.created_at.isoformat() if h.created_at else None} for h in hist_rows]
            rems=db.query(FindingRemediation).filter(FindingRemediation.finding_id==subject_id).order_by(FindingRemediation.created_at.desc()).limit(20).all()
            rems_d=[{"status":r.status,"created_at":r.created_at.isoformat() if r.created_at else None} for r in rems]
            retests=db.query(FindingRetest).filter(FindingRetest.finding_id==subject_id).order_by(FindingRetest.created_at.desc()).limit(20).all()
            retests_d=[{"result":r.result,"created_at":r.created_at.isoformat() if r.created_at else None} for r in retests]
            vals=db.query(SecurityValidation).filter(SecurityValidation.finding_id==subject_id).order_by(SecurityValidation.created_at.desc()).limit(20).all()
            vals_d=[{"verdict":v.verdict,"created_at":v.created_at.isoformat() if v.created_at else None} for v in vals]
            # priority history not persisted, use current
            try:
                from app.services.security_prioritization import calculate_finding_priority
                pri=calculate_finding_priority(f, db, project_id)
            except Exception:
                pri={"score":0,"tier":"INFO"}
            # related changes
            changes=[]
            if f.asset_id:
                changes=db.query(AssetChangeEvent).filter(AssetChangeEvent.asset_id==f.asset_id).order_by(AssetChangeEvent.detected_at.desc()).limit(20).all()
                changes=[{"change_type":c.change_type,"detected_at":c.detected_at.isoformat() if c.detected_at else None} for c in changes]
            # recurrence
            reopened = sum(1 for h in hist_rows if h.action=="reopened")
            return {"project_id":project_id,"subject_type":st,"subject_id":subject_id,"first_seen":f.created_at.isoformat() if f.created_at else None,"latest_seen":f.updated_at.isoformat() if f.updated_at else None,"current_state":f.status,"priority_history":[{"score":pri["score"],"tier":pri["tier"]}],"status_changes":hist[:20],"remediation_history":rems_d,"retest_history":retests_d,"validation_history":vals_d,"related_changes":changes,"recurrence":reopened,"evidence":[_sanitize(f.title)]}
        except Exception as e:
            return {"project_id":project_id,"subject_type":st,"subject_id":subject_id,"error":str(e)[:200]}
    elif st=="asset":
        a=db.query(Asset).filter(Asset.id==subject_id, Asset.project_id==project_id).first()
        if not a: return None
        try:
            from app.models.asset_change_event import AssetChangeEvent
            changes=db.query(AssetChangeEvent).filter(AssetChangeEvent.asset_id==subject_id).order_by(AssetChangeEvent.detected_at.desc()).limit(MAX_HISTORY).all()
            changes_d=[{"change_type":c.change_type,"detected_at":c.detected_at.isoformat() if c.detected_at else None} for c in changes]
            findings=db.query(Finding).filter(Finding.asset_id==subject_id).limit(20).all()
            findings_d=[{"id":f.id,"severity":_sev(f.severity),"status":f.status} for f in findings]
            return {"project_id":project_id,"subject_type":st,"subject_id":subject_id,"first_seen":a.first_seen_at.isoformat() if a.first_seen_at else (a.created_at.isoformat() if a.created_at else None),"latest_seen":a.last_seen_at.isoformat() if a.last_seen_at else None,"current_state":a.status,"priority_history":[],"status_changes":changes_d[:20],"related_findings":findings_d,"recurrence":len(changes_d)}
        except Exception as e:
            return {"project_id":project_id,"subject_type":st,"subject_id":subject_id,"error":str(e)[:200]}
    elif st=="application":
        app_obj=db.query(Application).filter(Application.id==subject_id, Application.project_id==project_id).first()
        if not app_obj: return None
        try:
            aids=[r[0] for r in db.query(ApplicationAsset.asset_id).filter(ApplicationAsset.application_id==subject_id).limit(MAX_ASSETS).all()]
            findings=db.query(Finding).filter(Finding.asset_id.in_(aids)).limit(20).all() if aids else []
            findings_d=[{"id":f.id,"severity":_sev(f.severity)} for f in findings]
            return {"project_id":project_id,"subject_type":st,"subject_id":subject_id,"first_seen":app_obj.created_at.isoformat() if app_obj.created_at else None,"latest_seen":app_obj.updated_at.isoformat() if app_obj.updated_at else None,"current_state":app_obj.status,"related_findings":findings_d,"recurrence":len(findings_d)}
        except Exception as e:
            return {"project_id":project_id,"subject_type":st,"subject_id":subject_id,"error":str(e)[:200]}
    elif st=="attack_path":
        # lookup by fingerprint or id
        try:
            from app.models.cloud_attack_path import CloudAttackPath
            cap=db.query(CloudAttackPath).filter(CloudAttackPath.project_id==project_id, (CloudAttackPath.fingerprint==subject_id) | (CloudAttackPath.id==subject_id)).first()
            if not cap: return None
            # history: all with same fingerprint
            rows=db.query(CloudAttackPath).filter(CloudAttackPath.project_id==project_id, CloudAttackPath.fingerprint==cap.fingerprint).order_by(CloudAttackPath.first_seen_at.desc()).limit(MAX_HISTORY).all()
            hist=[{"severity":_sev(r.severity),"score":r.priority_score,"first_seen":r.first_seen_at.isoformat() if r.first_seen_at else None,"last_seen":r.last_seen_at.isoformat() if r.last_seen_at else None} for r in rows]
            return {"project_id":project_id,"subject_type":st,"subject_id":subject_id,"first_seen":cap.first_seen_at.isoformat() if cap.first_seen_at else None,"latest_seen":cap.last_seen_at.isoformat() if cap.last_seen_at else None,"current_state":cap.status,"history":hist,"recurrence":len(rows)}
        except Exception:
            return None
    elif st=="exposure":
        # generic exposure via asset
        a=db.query(Asset).filter(Asset.id==subject_id, Asset.project_id==project_id).first()
        if not a: return None
        return {"project_id":project_id,"subject_type":st,"subject_id":subject_id,"first_seen":a.first_seen_at.isoformat() if a.first_seen_at else None,"latest_seen":a.last_seen_at.isoformat() if a.last_seen_at else None,"current_state":a.status}
    elif st=="investigation":
        try:
            from app.models.security_investigation import SecurityInvestigation
            inv=db.query(SecurityInvestigation).filter(SecurityInvestigation.id==subject_id, SecurityInvestigation.project_id==project_id).first()
            if not inv: return None
            return {"project_id":project_id,"subject_type":st,"subject_id":subject_id,"first_seen":inv.created_at.isoformat() if inv.created_at else None,"latest_seen":inv.updated_at.isoformat() if inv.updated_at else None,"current_state":inv.status}
        except Exception:
            return None
    return None

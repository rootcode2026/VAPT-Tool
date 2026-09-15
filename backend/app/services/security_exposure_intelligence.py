"""F5 Security Exposure Intelligence — deterministic exposure chains, decision support, blast radius, concentration, change correlation, coverage.
Reuses F1/F2/F3/F4, E9-E16, D1/D2, FindingEngine. No new tables, bounded on-read.
"""
from __future__ import annotations
import hashlib
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.application import Application, ApplicationAsset
from app.models.finding import Finding

MAX_ASSETS = 500
MAX_APPLICATIONS = 100
MAX_FINDINGS = 500
MAX_RELATIONSHIPS = 1000
MAX_ATTACK_PATHS = 100
MAX_CHAINS = 100
MAX_DEPTH = 6
MAX_EXPOSURES = 500
MAX_RESULTS = 20
SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _sanitize(val: str | None) -> str | None:
    if not val:
        return val
    low = val.lower()
    if any(k in low for k in ("secret","password","token","private_key","credential","api_key","access_key")):
        return "[REDACTED]"
    return val[:500]

def _sev(s: str | None) -> str:
    return (s or "info").lower()

def _is_external(asset: Asset) -> bool:
    ed = asset.extra_data or {}
    if isinstance(ed, dict):
        if ed.get("externally_reachable") is True:
            return True
        if ed.get("public") is True:
            return True
        if str(ed.get("exposure") or "").upper() == "INTERNET_EXPOSED":
            return True
    return False

def _provider(asset: Asset | None) -> str:
    if not asset:
        return "unknown"
    val = str(asset.value or "").lower()
    for p in ("aws","gcp","azure"):
        if f":{p}:" in val or p in val:
            return p
    ed = asset.extra_data or {}
    if isinstance(ed, dict):
        for k in ("provider","resource_type","service"):
            v = str(ed.get(k) or "").lower()
            for p in ("aws","gcp","azure"):
                if p in v:
                    return p
    return "unknown"

def _bounded_assets(pid: str, db: Session) -> list[Asset]:
    return db.query(Asset).filter(Asset.project_id == pid).limit(MAX_ASSETS).all()

def _bounded_findings(pid: str, db: Session) -> list[Finding]:
    asset_ids = [r[0] for r in db.query(Asset.id).filter(Asset.project_id == pid).limit(MAX_ASSETS).all()]
    if not asset_ids:
        return []
    return db.query(Finding).filter(Finding.asset_id.in_(asset_ids)).limit(MAX_FINDINGS).all()

def _bounded_apps(pid: str, db: Session) -> list[Application]:
    return db.query(Application).filter(Application.project_id == pid).limit(MAX_APPLICATIONS).all()

def _dq(total_assets: int, total_findings: int) -> dict:
    if total_assets == 0 and total_findings == 0:
        return {"status": "INSUFFICIENT_DATA", "limitations": ["No assets or findings"]}
    if total_assets < 5 and total_findings < 5:
        return {"status": "PARTIAL", "limitations": ["Limited data"]}
    return {"status": "SUFFICIENT", "limitations": []}

def _priority_for_finding(f: Finding, db: Session, pid: str) -> dict:
    try:
        from app.services.security_prioritization import calculate_finding_priority
        return calculate_finding_priority(f, db, pid)
    except Exception:
        sev = _sev(f.severity)
        base = {"critical": 35, "high": 20, "medium": 10, "low": 3}.get(sev, 0)
        return {"score": base, "tier": "HIGH" if sev == "critical" else "MEDIUM", "severity": sev, "reasons": [f"Severity {sev.upper()}"]}

# A. Exposure Chains
def get_exposure_chains(project_id: str, db: Session, limit: int = 20) -> dict:
    limit = max(1, min(limit, MAX_RESULTS))
    assets = _bounded_assets(project_id, db)
    findings = _bounded_findings(project_id, db)
    apps = _bounded_apps(project_id, db)
    asset_map = {a.id: a for a in assets}
    # app by asset
    app_by_asset: dict[str, list[Application]] = defaultdict(list)
    try:
        rows = db.query(ApplicationAsset, Application).join(Application, ApplicationAsset.application_id == Application.id).filter(Application.project_id == project_id).limit(MAX_RELATIONSHIPS).all()
        for link, app_obj in rows:
            app_by_asset[link.asset_id].append(app_obj)
    except Exception:
        pass
    # attack paths asset set
    attack_asset_ids: set[str] = set()
    path_by_asset: dict[str, list] = defaultdict(list)
    try:
        from app.services.cloud_attack_paths import build_cloud_attack_paths
        built = build_cloud_attack_paths(project_id, db, limit=MAX_ATTACK_PATHS)
        # fallback to DB if empty
        if not built:
            raise ValueError("empty")
        for p in built:
            for aid in p.get("asset_ids") or []:
                attack_asset_ids.add(aid)
                path_by_asset[aid].append(p)
    except Exception:
        try:
            from app.models.cloud_attack_path import CloudAttackPath
            rows = db.query(CloudAttackPath).filter(CloudAttackPath.project_id == project_id).limit(MAX_ATTACK_PATHS).all()
            for r in rows:
                for aid in r.asset_ids or []:
                    attack_asset_ids.add(aid)
                    path_by_asset[aid].append({"id": r.id, "path_type": r.path_type, "severity": r.severity, "provider": r.provider, "priority_score": r.priority_score})
        except Exception:
            pass

    chains: list[dict] = []
    # Sort findings by F2 priority descending to get strongest chains first
    scored_findings: list[tuple[int, Finding]] = []
    for f in findings:
        pri = _priority_for_finding(f, db, project_id)
        scored_findings.append((pri["score"], f))
    scored_findings.sort(key=lambda x: (-x[0], SEV_RANK.get(_sev(x[1].severity), 99), x[1].id))
    for score, f in scored_findings[:MAX_CHAINS]:
        if len(chains) >= limit:
            break
        asset = asset_map.get(f.asset_id) if f.asset_id else None
        # entry asset: external reachable asset linked to same app if possible
        entry_asset = None
        # find apps for this finding's asset
        linked_apps = app_by_asset.get(f.asset_id, []) if f.asset_id else []
        # try to find external asset in same app
        if linked_apps:
            for app_obj in linked_apps:
                # assets of this app
                aids = [r[0] for r in db.query(ApplicationAsset.asset_id).filter(ApplicationAsset.application_id == app_obj.id).limit(MAX_ASSETS).all()]
                for aid in aids:
                    cand = asset_map.get(aid)
                    if cand and _is_external(cand):
                        entry_asset = cand
                        break
                if entry_asset:
                    break
        if not entry_asset and asset and _is_external(asset):
            entry_asset = asset
        # cloud resource: try to find cloud asset in same app or via relationship
        cloud_res = None
        if linked_apps:
            for app_obj in linked_apps:
                aids = [r[0] for r in db.query(ApplicationAsset.asset_id).filter(ApplicationAsset.application_id == app_obj.id).limit(MAX_ASSETS).all()]
                for aid in aids:
                    cand = asset_map.get(aid)
                    if cand and cand.asset_type in ("cloud_resource","cloud_account"):
                        cloud_res = cand
                        break
                if cloud_res:
                    break
        # attack path for this asset
        attack_path = None
        if f.asset_id and f.asset_id in path_by_asset:
            # pick highest priority path
            cands = sorted(path_by_asset[f.asset_id], key=lambda p: (-p.get("priority_score", 0), p.get("id","")))
            attack_path = cands[0] if cands else None
        # application
        application = linked_apps[0] if linked_apps else None
        # confidence: HIGH if entry+finding+app all present, MEDIUM if 2, LOW if 1
        present = sum(1 for x in [entry_asset, asset, application, f, cloud_res, attack_path] if x)
        if present >= 4:
            confidence = "HIGH"
        elif present >= 2:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        # chain id deterministic
        raw = f"{project_id}|{f.id}|{asset.id if asset else ''}|{application.id if application else ''}"
        chain_id = hashlib.sha256(raw.encode()).hexdigest()[:32]
        pri = _priority_for_finding(f, db, project_id)
        explanation = []
        if entry_asset:
            explanation.append("Internet → external asset")
        if asset:
            explanation.append(f"Affected asset {asset.asset_type}")
        if application:
            explanation.append(f"Application {application.name}")
        if f:
            explanation.append(f"Finding {pri['severity']} {pri['tier']}")
        if cloud_res:
            explanation.append(f"Cloud {_provider(cloud_res)} resource")
        if attack_path:
            explanation.append(f"Attack path {attack_path.get('path_type','')}")
        if not explanation:
            explanation.append("Isolated finding with limited exposure evidence")
        chains.append({
            "chain_id": chain_id,
            "project_id": project_id,
            "entry_asset": {"id": entry_asset.id, "value": _sanitize(entry_asset.value[:60]), "asset_type": entry_asset.asset_type} if entry_asset else None,
            "affected_asset": {"id": asset.id, "value": _sanitize(asset.value[:60]), "asset_type": asset.asset_type} if asset else None,
            "application": {"id": application.id, "name": _sanitize(application.name), "criticality": application.criticality} if application else None,
            "finding": {"id": f.id, "title": _sanitize(f.title), "severity": _sev(f.severity), "scanner": f.scanner, "evidence": _sanitize(f.evidence) if f.evidence and "secret" not in f.evidence.lower() else "[REDACTED]"},
            "cloud_resource": {"id": cloud_res.id, "value": _sanitize(cloud_res.value[:60]), "asset_type": cloud_res.asset_type, "provider": _provider(cloud_res)} if cloud_res else None,
            "attack_path": {"id": attack_path.get("id"), "path_type": attack_path.get("path_type"), "severity": attack_path.get("severity"), "provider": attack_path.get("provider")} if attack_path else None,
            "priority": pri["score"],
            "severity": _sev(f.severity),
            "confidence": confidence,
            "evidence_refs": [f.id, asset.id if asset else None, application.id if application else None, cloud_res.id if cloud_res else None, attack_path.get("id") if attack_path else None],
            "explanation": " → ".join(explanation),
        })
    # deterministic sort already by priority, then severity, confidence, chain_id
    chains.sort(key=lambda c: (-c["priority"], SEV_RANK.get(c["severity"], 99), {"HIGH":0,"MEDIUM":1,"LOW":2}.get(c["confidence"], 99), c["chain_id"]))
    dq = _dq(len(assets), len(findings))
    return {"project_id": project_id, "generated_at": datetime.now(timezone.utc).isoformat(), "data_quality": dq, "chains": chains[:limit], "total_chains": len(chains)}

# B. Hotspot context — enhance F4 hotspots with contextual evidence (reuse F4)
def get_hotspot_context(project_id: str, db: Session, limit: int = 20) -> dict:
    try:
        from app.services.attack_surface_analytics import get_hotspots
        base = get_hotspots(project_id, db, limit=limit)
    except Exception as e:
        return {"project_id": project_id, "generated_at": datetime.now(timezone.utc).isoformat(), "data_quality": {"status": "INSUFFICIENT_DATA", "limitations": [str(e)[:200]]}, "hotspots": []}
    # Enrich each hotspot with related findings count, recent changes, SLA, remediation, validation
    assets = _bounded_assets(project_id, db)
    findings = _bounded_findings(project_id, db)
    findings_by_asset = defaultdict(list)
    for f in findings:
        if f.asset_id:
            findings_by_asset[f.asset_id].append(f)
    # add why matters already in F4; here add extra evidence counts
    for hs in base.get("hotspots", []):
        sid = hs["subject_id"]
        if hs["subject_type"] == "asset":
            flist = findings_by_asset.get(sid, [])
            hs["related_findings"] = len(flist)
            hs["critical_findings"] = sum(1 for f in flist if _sev(f.severity) == "critical")
        elif hs["subject_type"] == "application":
            # find app assets
            try:
                aids = [r[0] for r in db.query(ApplicationAsset.asset_id).filter(ApplicationAsset.application_id == sid).limit(MAX_ASSETS).all()]
                flist = [f for f in findings if f.asset_id in aids]
                hs["related_findings"] = len(flist)
                hs["critical_findings"] = sum(1 for f in flist if _sev(f.severity) == "critical")
            except Exception:
                hs["related_findings"] = 0
        # ensure evidence_refs sanitized
        hs["evidence_refs"] = [_sanitize(str(x)) if x else x for x in hs.get("evidence_refs", [])[:5]]
    return base

# C. Blast Radius — reuse F1
def get_blast_radius_enhanced(project_id: str, db: Session, subject_type: str, subject_id: str) -> dict | None:
    try:
        from app.services.security_intelligence import get_blast_radius
        br = get_blast_radius(project_id, db, subject_type, subject_id)
        if not br:
            return None
        # enrich with counts
        affected_assets = br.get("affected_assets", [])
        related_findings = br.get("related_findings", [])
        # fetch severities for related findings
        crit = high = 0
        if related_findings:
            rows = db.query(Finding.severity).filter(Finding.id.in_(related_findings[:MAX_FINDINGS])).all()
            for (sev,) in rows:
                if _sev(sev) == "critical":
                    crit += 1
                elif _sev(sev) == "high":
                    high += 1
        br["exposure_count"] = len(affected_assets)
        br["critical_count"] = crit
        br["high_count"] = high
        # sanitize
        return br
    except Exception:
        return None

# D. Exposure Concentration — reuse F4
def get_exposure_concentration_f5(project_id: str, db: Session) -> dict:
    try:
        from app.services.attack_surface_analytics import get_exposure_concentration, get_risk_concentration
        conc = get_exposure_concentration(project_id, db)
        risk = get_risk_concentration(project_id, db)
        # add tier
        total = conc.get("details", {}).get("total_critical_high", 0)
        top = conc.get("details", {}).get("top_critical_high", 0)
        pct = conc.get("concentration", {}).get("top_assets_critical_high_pct", 0)
        if pct >= 80:
            tier = "CRITICAL_CONCENTRATION"
        elif pct >= 50:
            tier = "HIGH_CONCENTRATION"
        elif pct >= 20:
            tier = "MEDIUM_CONCENTRATION"
        else:
            tier = "LOW_CONCENTRATION"
        conc["concentration_tier"] = tier
        conc["risk_concentration"] = risk
        return conc
    except Exception as e:
        return {"project_id": project_id, "generated_at": datetime.now(timezone.utc).isoformat(), "data_quality": {"status": "INSUFFICIENT_DATA", "limitations": [str(e)[:200]]}, "concentration": {}, "concentration_tier": "UNKNOWN"}

# E. Root-cause context via E12
def get_root_cause_context(project_id: str, db: Session, limit: int = 20) -> dict:
    limit = max(1, min(limit, MAX_RESULTS))
    try:
        from app.services.security_correlation import get_correlations
        groups = get_correlations(project_id, db, limit=100)
    except Exception:
        groups = []
    candidates: list[dict] = []
    for g in groups:
        # only groups with >=2 members are candidates
        if g.get("finding_count", 0) < 2:
            continue
        ctype = g.get("correlation_type", "RELATED")
        confidence = g.get("confidence", "MEDIUM")
        # map to root_cause_candidate phrasing
        candidates.append({
            "root_cause_candidate": f"{ctype} — {g.get('canonical_key','')[:40]}",
            "correlation_type": ctype,
            "canonical_key": g.get("canonical_key"),
            "related_findings": g.get("finding_ids", [])[:10],
            "asset_ids": g.get("asset_ids", [])[:5],
            "confidence": confidence,
            "evidence_refs": g.get("finding_ids", [])[:5],
            "explanation": g.get("explanation", "")[:200],
            "finding_count": g.get("finding_count", 0),
        })
    candidates.sort(key=lambda x: (-x["finding_count"], {"HIGH":0,"MEDIUM":1,"LOW":2}.get(x["confidence"], 99), x["canonical_key"] or ""))
    dq = _dq(len(candidates), sum(c["finding_count"] for c in candidates))
    return {"project_id": project_id, "generated_at": datetime.now(timezone.utc).isoformat(), "data_quality": dq, "candidates": candidates[:limit], "total_candidates": len(candidates)}

# F. Change-to-Exposure correlation
def get_change_exposure(project_id: str, db: Session, limit: int = 20) -> dict:
    limit = max(1, min(limit, MAX_RESULTS))
    try:
        from app.models.asset_change_event import AssetChangeEvent
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        changes = db.query(AssetChangeEvent).filter(AssetChangeEvent.project_id == project_id, AssetChangeEvent.detected_at >= cutoff).order_by(AssetChangeEvent.detected_at.desc()).limit(MAX_RESULTS).all()
    except Exception:
        changes = []
    assets = {a.id: a for a in _bounded_assets(project_id, db)}
    findings = _bounded_findings(project_id, db)
    # map asset -> findings created after change
    correlations: list[dict] = []
    for ch in changes:
        asset = assets.get(ch.asset_id)
        if not asset:
            continue
        # findings on same asset created within 3 days after change
        related = []
        for f in findings:
            if f.asset_id == ch.asset_id and f.created_at:
                fa = f.created_at
                if fa.tzinfo is None:
                    fa = fa.replace(tzinfo=timezone.utc)
                ca = ch.detected_at
                if ca.tzinfo is None:
                    ca = ca.replace(tzinfo=timezone.utc)
                delta = (fa - ca).total_seconds()
                if 0 <= delta <= 3*24*3600:
                    related.append(f)
        # check if priority increased via F3 trends? For now use TEMPORALLY_ASSOCIATED
        for f in related[:3]:
            pri = _priority_for_finding(f, db, project_id)
            correlations.append({
                "change_event": {"id": ch.id, "asset_id": ch.asset_id, "change_type": ch.change_type, "detected_at": ch.detected_at.isoformat() if ch.detected_at else None, "value": _sanitize(asset.value[:60])},
                "affected_asset": {"id": asset.id, "value": _sanitize(asset.value[:60]), "asset_type": asset.asset_type},
                "finding": {"id": f.id, "title": _sanitize(f.title), "severity": _sev(f.severity), "priority": pri["score"]},
                "change_type": ch.change_type,
                "time_relationship": "TEMPORALLY_ASSOCIATED",
                "confidence": "MEDIUM" if len(related) >= 2 else "LOW",
                "explanation": f"Change {ch.change_type} on {asset.asset_type} temporally associated with new {pri['severity']} finding within 3d; causality not proven.",
            })
        if not related and len(correlations) < limit:
            # still report change without finding as potential new exposure
            correlations.append({
                "change_event": {"id": ch.id, "asset_id": ch.asset_id, "change_type": ch.change_type, "detected_at": ch.detected_at.isoformat() if ch.detected_at else None, "value": _sanitize(asset.value[:60])},
                "affected_asset": {"id": asset.id, "value": _sanitize(asset.value[:60]), "asset_type": asset.asset_type},
                "finding": None,
                "change_type": ch.change_type,
                "time_relationship": "TEMPORALLY_ASSOCIATED",
                "confidence": "LOW",
                "explanation": "Recent change with no directly associated finding yet; monitor for emerging exposure.",
            })
        if len(correlations) >= limit:
            break
    correlations = correlations[:limit]
    dq = _dq(len(changes), len(findings))
    return {"project_id": project_id, "generated_at": datetime.now(timezone.utc).isoformat(), "data_quality": dq, "correlations": correlations, "total_changes": len(changes)}

# G. Security Coverage — combine F4 + monitoring etc
def get_security_coverage(project_id: str, db: Session) -> dict:
    try:
        from app.services.attack_surface_analytics import get_coverage_gaps
        f4cov = get_coverage_gaps(project_id, db)
    except Exception as e:
        f4cov = {"coverage_gaps": [], "total_gaps": 0, "data_quality": {"status": "INSUFFICIENT_DATA", "limitations": [str(e)[:200]]}}
    # Enrich with monitoring coverage if available
    monitoring_gaps: list[dict] = []
    try:
        from app.models.monitoring import MonitoringConfig
        configs = db.query(MonitoringConfig).filter(MonitoringConfig.project_id == project_id).limit(10).all()
        if not configs:
            monitoring_gaps.append({"gap_type": "NO_MONITORING_CONFIG", "subject_type": "project", "subject_id": project_id, "status": "COVERAGE_GAP", "evidence": "No monitoring configs for project", "recommendation": "Configure continuous monitoring for coverage (COVERAGE_GAP)"})
    except Exception:
        pass
    # Merge
    gaps = f4cov.get("coverage_gaps", []) + monitoring_gaps
    gaps.sort(key=lambda x: (x["gap_type"], x["subject_id"]))
    # Classify overall coverage
    total_gaps = len(gaps)
    if total_gaps == 0:
        overall = "ASSESSED"
    elif total_gaps <= 3:
        overall = "PARTIAL_COVERAGE"
    else:
        overall = "COVERAGE_GAP"
    return {"project_id": project_id, "generated_at": datetime.now(timezone.utc).isoformat(), "data_quality": f4cov.get("data_quality", {"status": "SUFFICIENT", "limitations": []}), "overall_coverage": overall, "coverage_gaps": gaps[:MAX_RESULTS], "total_gaps": total_gaps, "not_assessed": sum(1 for g in gaps if g.get("status") == "NOT_ASSESSED")}

# Exposure Decision Summary
def get_exposure_decision(project_id: str, db: Session) -> dict:
    # Reuse F2, F4, F3
    try:
        from app.services.attack_surface_analytics import get_hotspots, get_top_risk_hotspots, get_exposure_concentration
        hotspots = get_hotspots(project_id, db, limit=5)
        top = get_top_risk_hotspots(project_id, db)
        conc = get_exposure_concentration(project_id, db)
    except Exception:
        hotspots = {"hotspots": []}
        top = {"top_assets": [], "top_applications": [], "top_attack_paths": []}
        conc = {"concentration": {}}
    try:
        from app.services.security_trends import get_trends
        trends = get_trends(project_id, db, window="7d")
        worsening = trends.get("top_worsening", [])[:5]
    except Exception:
        worsening = []
        trends = {"data_quality": "INSUFFICIENT_DATA"}
    # coverage
    cov = get_security_coverage(project_id, db)
    # validation failures, overdue remediation, reopened
    overdue = 0
    reopened = 0
    validation_failures = 0
    try:
        from app.models.finding import FindingRemediation, FindingSLA
        from app.models.security_validation import SecurityValidation
        from app.models.finding import FindingHistory
        overdue = db.query(func.count(FindingSLA.id)).filter(FindingSLA.project_id == project_id, FindingSLA.status == "breached").scalar() or 0
        # reopened via history action reopened
        reopened = db.query(func.count(FindingHistory.id)).filter(FindingHistory.project_id == project_id, FindingHistory.action == "reopened").scalar() or 0
        validation_failures = db.query(func.count(SecurityValidation.id)).filter(SecurityValidation.project_id == project_id, SecurityValidation.verdict.in_(["INVALID","INCONCLUSIVE"])).scalar() or 0
    except Exception:
        pass
    # Build why matters per top hotspot
    why = []
    for hs in hotspots.get("hotspots", [])[:3]:
        why.append(f"{hs['subject_type']} {hs['name'][:30]} — priority {hs['priority']} — {', '.join(hs.get('reasons', [])[:2])}")
    return {
        "project_id": project_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "data_quality": _dq(len(hotspots.get("hotspots", [])), len(top.get("top_assets", []))),
        "top_exposures": hotspots.get("hotspots", [])[:5],
        "top_applications": top.get("top_applications", [])[:5],
        "top_external_assets": top.get("top_external_assets", [])[:5],
        "top_cloud_resources": top.get("top_cloud_resources", [])[:5],
        "top_attack_paths": top.get("top_attack_paths", [])[:5],
        "concentration": conc.get("concentration", {}),
        "recent_worsening": worsening,
        "major_coverage_gaps": cov.get("coverage_gaps", [])[:5],
        "validation_failures": validation_failures,
        "overdue_remediation": overdue,
        "reopened_issues": reopened,
        "why_it_matters": why,
        "trend_quality": trends.get("data_quality") if isinstance(trends, dict) else "INSUFFICIENT_DATA",
    }

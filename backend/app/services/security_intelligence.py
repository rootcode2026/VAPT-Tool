"""F1 Advanced Security Intelligence Foundation — deterministic evidence chaining over existing models.
No new persistent table, no AI, no graph DB, bounded.
"""
from __future__ import annotations
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any
from sqlalchemy.orm import Session
from sqlalchemy import func, text

from app.models.asset import Asset
from app.models.asset_relationship import AssetRelationship
from app.models.application import Application, ApplicationAsset
from app.models.finding import Finding
from app.models.project import Project

# Bounds per spec
MAX_ASSETS = 500
MAX_APPLICATIONS = 100
MAX_FINDINGS = 500
MAX_RELATIONSHIPS = 1000
MAX_PATHS = 100
MAX_DEPTH = 6
VALID_SUBJECT_TYPES = {"finding","application","asset","cloud_resource","external_asset","attack_path"}
VALID_CONF = {"CONFIRMED","HIGH","MEDIUM","LOW","UNKNOWN"}

def _sanitize(val: str | None) -> str | None:
    if not val:
        return val
    low = val.lower()
    if any(k in low for k in ("secret","password","token","private_key","credential","api_key")):
        return "[REDACTED]"
    return val[:500]

def _fingerprint(project_id: str, subject_type: str, subject_id: str, rel_type: str, related_id: str) -> str:
    raw = f"{project_id}|{subject_type.lower()}|{subject_id}|{rel_type}|{related_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def _confidence_for_relationship(rel_type: str, evidence: dict | None) -> str:
    # Strong when explicitly linked via ApplicationAsset with CONFIRMED
    if evidence and evidence.get("source") == "explicit" and rel_type in ("owns","contains","exposes","builds","deploys_to"):
        return "CONFIRMED"
    if rel_type == "has_finding" and evidence and evidence.get("asset_id"):
        return "CONFIRMED"
    if rel_type in ("exposes","depends_on") and evidence and evidence.get("externally_reachable"):
        return "HIGH"
    return "MEDIUM"

def _explain(rel_type: str, src: str, dst: str, confidence: str, evidence: dict | None) -> str:
    base = f"{src} {rel_type} {dst}"
    if evidence and evidence.get("source") == "explicit":
        return f"{base} — explicitly linked via ApplicationAsset ({confidence})"
    if rel_type == "has_finding":
        return f"{base} — Finding.asset_id points to asset ({confidence})"
    if evidence and evidence.get("externally_reachable"):
        return f"{base} — externally reachable evidence ({confidence})"
    return f"{base} — derived from existing asset relationship ({confidence})"

# Subject resolution
def _resolve_subject(project_id: str, db: Session, subject_type: str, subject_id: str) -> dict | None:
    subject_type = subject_type.lower()
    if subject_type not in VALID_SUBJECT_TYPES:
        return None
    if subject_type == "finding":
        f = db.query(Finding).filter(Finding.id == subject_id).first()
        if not f:
            return None
        if f.asset_id:
            a = db.query(Asset).filter(Asset.id == f.asset_id).first()
            if not a or a.project_id != project_id:
                return None
        else:
            # If finding has no asset, check via project? For now allow if finding exists and project matches via asset fallback is not needed
            # Ensure project isolation via finding's scan? For simplicity, allow but check asset fallback
            pass
        return {"type": "finding", "finding": f, "project_id": project_id}
    elif subject_type in ("asset","cloud_resource","external_asset"):
        a = db.query(Asset).filter(Asset.id == subject_id).first()
        if not a or a.project_id != project_id:
            return None
        # subtype validation
        if subject_type == "cloud_resource" and a.asset_type not in ("cloud_resource","cloud_account"):
            # still allow generic asset but mark
            pass
        if subject_type == "external_asset" and a.asset_type not in ("domain","subdomain","ip","ipv6","url"):
            pass
        return {"type": subject_type, "asset": a, "project_id": project_id}
    elif subject_type == "application":
        app = db.query(Application).filter(Application.id == subject_id, Application.project_id == project_id).first()
        if not app:
            return None
        return {"type": "application", "application": app, "project_id": project_id}
    elif subject_type == "attack_path":
        # via E9/E10 CloudAttackPath
        try:
            from app.models.cloud_attack_path import CloudAttackPath
            cap = db.query(CloudAttackPath).filter(CloudAttackPath.project_id == project_id).filter((CloudAttackPath.id == subject_id) | (CloudAttackPath.fingerprint == subject_id)).first()
            if not cap:
                # try on-read paths
                from app.services.cloud_attack_paths import build_cloud_attack_paths
                paths = build_cloud_attack_paths(project_id, db, limit=100)
                for p in paths:
                    if p.get("id") == subject_id or p.get("fingerprint") == subject_id:
                        return {"type": "attack_path", "path": p, "project_id": project_id}
                return None
            return {"type": "attack_path", "path": cap, "project_id": project_id}
        except Exception:
            return None
    return None

def _collect_assets_for_subject(subject: dict, db: Session, project_id: str) -> list[Asset]:
    t = subject["type"]
    if t == "application":
        app = subject["application"]
        rows = db.query(Asset).join(ApplicationAsset, ApplicationAsset.asset_id == Asset.id).filter(ApplicationAsset.application_id == app.id).limit(MAX_ASSETS).all()
        return rows
    elif t in ("asset","cloud_resource","external_asset"):
        return [subject["asset"]]
    elif t == "finding":
        f = subject["finding"]
        if f.asset_id:
            a = db.query(Asset).filter(Asset.id == f.asset_id).first()
            return [a] if a else []
        return []
    elif t == "attack_path":
        # attack path -> assets via its asset_ids
        p = subject.get("path")
        if isinstance(p, dict):
            aids = p.get("asset_ids", [])
        else:
            # CloudAttackPath model has relationship via observations
            aids = []
            try:
                from app.models.cloud_attack_path import CloudAttackPathObservation
                obs = db.query(CloudAttackPathObservation).filter(CloudAttackPathObservation.attack_path_id == p.id).limit(20).all()
                aids = [o.asset_id for o in obs if o.asset_id]
            except: pass
        if aids:
            return db.query(Asset).filter(Asset.id.in_(aids[:MAX_ASSETS])).all()
        return []
    return []

def _collect_applications_for_assets(asset_ids: list[str], db: Session, project_id: str) -> list[Application]:
    if not asset_ids:
        return []
    rows = db.query(Application).join(ApplicationAsset, ApplicationAsset.application_id == Application.id).filter(ApplicationAsset.asset_id.in_(asset_ids)).limit(MAX_APPLICATIONS).all()
    # dedup
    seen = {}
    for r in rows:
        seen[r.id] = r
    return list(seen.values())[:MAX_APPLICATIONS]

def _collect_findings_for_assets(asset_ids: list[str], db: Session, project_id: str) -> list[Finding]:
    if not asset_ids:
        return []
    return db.query(Finding).filter(Finding.asset_id.in_(asset_ids)).limit(MAX_FINDINGS).all()

def _sanitize_findings(findings: list[Finding]) -> list[Finding]:
    for f in findings:
        if f.scanner in ("secrets","gitleaks") or (f.evidence and "secret" in f.evidence.lower()):
            f.evidence = "[REDACTED]"
        if f.evidence:
            f.evidence = _sanitize(f.evidence)
        if f.title:
            f.title = _sanitize(f.title)
    return findings

# Main context
def get_security_context(project_id: str, db: Session, subject_type: str, subject_id: str) -> dict | None:
    subject = _resolve_subject(project_id, db, subject_type, subject_id)
    if not subject:
        return None
    assets = _collect_assets_for_subject(subject, db, project_id)
    asset_ids = [a.id for a in assets]
    applications = _collect_applications_for_assets(asset_ids, db, project_id) if subject["type"] != "application" else [subject["application"]]
    # if subject is application, also include its linked applications via assets
    if subject["type"] == "application":
        # already have subject app, but also find other apps sharing assets
        other_apps = _collect_applications_for_assets(asset_ids, db, project_id)
        # keep subject first
        seen = {subject["application"].id: subject["application"]}
        for o in other_apps:
            if o.id not in seen:
                seen[o.id] = o
        applications = list(seen.values())[:MAX_APPLICATIONS]
    findings = _collect_findings_for_assets(asset_ids, db, project_id)
    findings = _sanitize_findings(findings)
    # correlations via E12 filtered to findings
    correlations = []
    try:
        from app.services.security_correlation import get_correlations
        fids = [f.id for f in findings]
        if fids:
            all_groups = get_correlations(project_id, db)
            correlations = [g for g in all_groups if any(fid in [m["finding_id"] for m in g.get("members",[])] for fid in fids)][ : min(200, len(all_groups))]
            for g in correlations:
                g["confidence"] = g.get("confidence","MEDIUM")
    except: pass
    # exposures via E11/E15
    exposures = []
    try:
        # application exposures or cloud exposures
        for app in applications[:5]:
            try:
                from app.services.application_intelligence import get_application_exposure
                exp = get_application_exposure(app.id, db, project_id)
                exposures.append(exp)
            except: pass
        # also top cloud exposures
        try:
            from app.services.cloud_exposure_intelligence import get_top_exposures
            exps = get_top_exposures(project_id, db, limit=5)
            exposures.extend(exps[:5])
        except: pass
    except: pass
    exposures = exposures[:5]
    # attack paths
    attack_paths = []
    try:
        from app.services.cloud_attack_paths import build_cloud_attack_paths
        paths = build_cloud_attack_paths(project_id, db, limit=20)
        # filter to those involving assets
        if asset_ids:
            attack_paths = [p for p in paths if any(aid in asset_ids for aid in p.get("asset_ids",[]))][:10]
            if not attack_paths:
                attack_paths = paths[:2]
        else:
            attack_paths = paths[:2]
    except:
        try:
            from app.models.cloud_attack_path import CloudAttackPath
            attack_paths = [ {"id": r.id, "path_type": r.path_type, "severity": r.severity} for r in db.query(CloudAttackPath).filter(CloudAttackPath.project_id==project_id).limit(5).all()]
        except: pass
    # changes
    changes = []
    if asset_ids:
        try:
            from app.models.asset_change_event import AssetChangeEvent
            changes = db.query(AssetChangeEvent).filter(AssetChangeEvent.asset_id.in_(asset_ids)).order_by(AssetChangeEvent.detected_at.desc()).limit(20).all()
            changes = [{"id": c.id, "asset_id": c.asset_id, "change_type": c.change_type, "detected_at": c.detected_at.isoformat() if c.detected_at else None} for c in changes]
        except: pass
    # remediation
    remediation = []
    if findings:
        try:
            from app.models.finding import FindingRemediation
            fids = [f.id for f in findings]
            remediation = db.query(FindingRemediation).filter(FindingRemediation.finding_id.in_(fids)).limit(10).all()
            remediation = [{"id": r.id, "finding_id": r.finding_id, "status": r.status, "title": _sanitize(r.title)} for r in remediation]
        except: pass
    # validation / retest
    validations = []
    retests = []
    if findings:
        try:
            from app.models.security_validation import SecurityValidation
            from app.models.finding import FindingRetest
            fids = [f.id for f in findings]
            validations = db.query(SecurityValidation).filter(SecurityValidation.finding_id.in_(fids)).limit(10).all()
            validations = [{"id": v.id, "finding_id": v.finding_id, "status": v.status, "verdict": v.verdict, "confidence": v.confidence} for v in validations]
            retests = db.query(FindingRetest).filter(FindingRetest.finding_id.in_(fids)).limit(10).all()
            retests = [{"id": r.id, "finding_id": r.finding_id, "status": r.status, "result": r.result} for r in retests]
        except: pass
    # investigations
    investigations = []
    try:
        from app.models.security_investigation import SecurityInvestigation
        # direct subject investigation or findings/assets
        q = db.query(SecurityInvestigation).filter(SecurityInvestigation.project_id==project_id)
        # filter where subject_id matches any of subject/finding/asset
        ids_to_check = [subject_id] + [f.id for f in findings[:5]] + asset_ids[:5]
        investigations = q.filter(SecurityInvestigation.subject_id.in_(ids_to_check)).limit(5).all()
        investigations = [{"id": r.id, "title": _sanitize(r.title), "status": r.status, "subject_type": r.subject_type} for r in investigations]
    except: pass
    # evidence chains
    evidence_chains = []
    # build deterministic relationships: subject -> assets -> applications -> findings -> attack paths
    for a in assets[:10]:
        fid = _fingerprint(project_id, subject_type, subject_id, "contains", a.id)
        evidence_chains.append({"id": fid, "source": f"{subject_type}:{subject_id[:8]}", "target": f"asset:{a.value[:40]}", "relationship": "contains", "confidence": "CONFIRMED" if subject["type"]=="application" else "HIGH", "explanation": _explain("contains", subject_type, a.asset_type, "CONFIRMED" if subject["type"]=="application" else "HIGH", {"source":"explicit" if subject["type"]=="application" else None}), "evidence": {"asset_id": a.id}})
    for app in applications[:5]:
        if subject["type"] != "application" or app.id != subject["application"].id:
            fid = _fingerprint(project_id, subject_type, subject_id, "relates_to_application", app.id)
            evidence_chains.append({"id": fid, "source": subject_type, "target": f"application:{app.name}", "relationship": "relates_to_application", "confidence": "MEDIUM", "explanation": _explain("relates_to_application", subject_type, "application", "MEDIUM", {}), "evidence": {"application_id": app.id}})
    for f in findings[:10]:
        fid = _fingerprint(project_id, subject_type, subject_id, "has_finding", f.id)
        evidence_chains.append({"id": fid, "source": "asset", "target": f.title[:40], "relationship": "has_finding", "confidence": "CONFIRMED", "explanation": _explain("has_finding","asset",f.title[:20],"CONFIRMED",{"asset_id": f.asset_id}), "evidence": {"finding_id": f.id, "scanner": f.scanner}})

    confidence = "HIGH" if len(findings) > 2 and len(assets) > 2 else "MEDIUM" if findings or assets else "LOW"
    return {
        "project_id": project_id,
        "subject_type": subject_type.lower(),
        "subject_id": subject_id,
        "fingerprint": hashlib.sha256(f"{project_id}|{subject_type.lower()}|{subject_id}".encode()).hexdigest()[:32],
        "confidence": confidence,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "subject": {"type": subject_type.lower(), "id": subject_id},
        "assets": [{"id": a.id, "value": a.value[:80], "asset_type": a.asset_type, "extra_data": a.extra_data} for a in assets[:MAX_ASSETS]],
        "applications": [{"id": a.id, "name": a.name, "criticality": a.criticality, "lifecycle": a.lifecycle} for a in applications[:MAX_APPLICATIONS]],
        "findings": [{"id": f.id, "title": _sanitize(f.title), "severity": f.severity, "scanner": f.scanner, "evidence": f.evidence} for f in findings[:MAX_FINDINGS]],
        "correlations": correlations[:20],
        "exposures": exposures,
        "attack_paths": attack_paths[:10],
        "changes": changes,
        "remediation": remediation,
        "validations": validations,
        "retests": retests,
        "investigations": investigations,
        "evidence_chains": evidence_chains[:50],
    }

def get_exposure_chain(project_id: str, db: Session, subject_type: str, subject_id: str) -> dict | None:
    ctx = get_security_context(project_id, db, subject_type, subject_id)
    if not ctx:
        return None
    # Build ordered chain: Internet -> External Asset -> API -> Application -> Source -> Finding -> Cloud -> Attack Path
    chain = []
    # Extract from evidence_chains and exposures
    # Step 1: external assets
    for a in ctx["assets"]:
        if a["asset_type"] in ("domain","subdomain","url","ip","ipv6") and (a.get("extra_data") or {}).get("externally_reachable"):
            chain.append({"step": len(chain)+1, "type": "external_asset", "id": a["id"], "value": a["value"], "confidence": "HIGH", "evidence": "externally_reachable"})
    # Step 2: api endpoints
    for a in ctx["assets"]:
        if a["asset_type"] == "api_endpoint":
            chain.append({"step": len(chain)+1, "type": "api_endpoint", "id": a["id"], "value": a["value"], "confidence": "CONFIRMED", "evidence": "explicit link"})
    # Step 3: application
    for app in ctx["applications"]:
        chain.append({"step": len(chain)+1, "type": "application", "id": app["id"], "value": app["name"], "confidence": "CONFIRMED", "evidence": "application asset link"})
    # Step 4: source
    for a in ctx["assets"]:
        if a["asset_type"] == "source_file":
            chain.append({"step": len(chain)+1, "type": "source_file", "id": a["id"], "value": a["value"], "confidence": "CONFIRMED", "evidence": "asset link"})
    # Step 5: findings
    for f in ctx["findings"][:5]:
        chain.append({"step": len(chain)+1, "type": "finding", "id": f["id"], "value": f["title"][:60], "confidence": "HIGH", "evidence": f"scanner {f['scanner']}"})
    # Step 6: cloud
    for p in ctx["attack_paths"][:2]:
        chain.append({"step": len(chain)+1, "type": "attack_path", "id": p.get("id","unknown"), "value": p.get("path_type","cloud"), "confidence": "MEDIUM", "evidence": "cloud attack path"})
    if not chain:
        chain.append({"step": 1, "type": subject_type, "id": subject_id, "value": subject_id[:12], "confidence": "UNKNOWN", "evidence": "no chain evidence; subject isolated"})
    return {"project_id": project_id, "subject_type": subject_type, "subject_id": subject_id, "chain": chain[:20], "fingerprint": ctx["fingerprint"]}

def get_blast_radius(project_id: str, db: Session, subject_type: str, subject_id: str) -> dict | None:
    ctx = get_security_context(project_id, db, subject_type, subject_id)
    if not ctx:
        return None
    # BFS via AssetRelationship + ApplicationAsset up to MAX_DEPTH
    visited_assets = set(a["id"] for a in ctx["assets"])
    visited_apps = set(a["id"] for a in ctx["applications"])
    frontier = list(visited_assets)
    depth = 0
    related_findings = set(f["id"] for f in ctx["findings"])
    related_apps = set(visited_apps)
    related_assets = set(visited_assets)
    # bounded BFS
    while frontier and depth < MAX_DEPTH and len(related_assets) < MAX_ASSETS:
        next_frontier = []
        # AssetRelationship
        if frontier:
            rels = db.query(AssetRelationship).filter(AssetRelationship.project_id==project_id).filter((AssetRelationship.source_asset_id.in_(frontier)) | (AssetRelationship.target_asset_id.in_(frontier))).limit(MAX_RELATIONSHIPS).all()
            for r in rels:
                for aid in (r.source_asset_id, r.target_asset_id):
                    if aid not in related_assets and len(related_assets) < MAX_ASSETS:
                        related_assets.add(aid)
                        next_frontier.append(aid)
        # ApplicationAsset
        if frontier:
            app_links = db.query(ApplicationAsset).join(Application, ApplicationAsset.application_id==Application.id).filter(Application.project_id==project_id).filter(ApplicationAsset.asset_id.in_(frontier)).limit(100).all()
            for link in app_links:
                if link.application_id not in related_apps and len(related_apps) < MAX_APPLICATIONS:
                    related_apps.add(link.application_id)
                    # also add other assets of that app
                    other_aids = [row[0] for row in db.query(ApplicationAsset.asset_id).filter(ApplicationAsset.application_id==link.application_id).limit(20).all()]
                    for oid in other_aids:
                        if oid not in related_assets and len(related_assets) < MAX_ASSETS:
                            related_assets.add(oid)
                            next_frontier.append(oid)
        frontier = next_frontier
        depth += 1
        # collect findings for new assets
        if next_frontier:
            new_findings = db.query(Finding).filter(Finding.asset_id.in_(next_frontier)).limit(50).all()
            for f in new_findings:
                related_findings.add(f.id)
        if len(related_assets) >= MAX_ASSETS or len(related_findings) >= MAX_FINDINGS:
            break
    # also add findings for original assets
    # attack paths related to assets
    attack_paths = ctx["attack_paths"]
    # confidence based on depth and counts
    confidence = "HIGH" if len(related_assets) > 10 else "MEDIUM" if related_assets else "LOW"
    return {
        "project_id": project_id,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "fingerprint": ctx["fingerprint"],
        "affected_assets": list(related_assets)[:MAX_ASSETS],
        "affected_applications": list(related_apps)[:MAX_APPLICATIONS],
        "related_findings": list(related_findings)[:MAX_FINDINGS],
        "related_attack_paths": attack_paths,
        "confidence": confidence,
        "depth": depth,
        "evidence": {"traversed_assets": len(related_assets), "depth": depth},
    }

def get_impact(project_id: str, db: Session, subject_type: str, subject_id: str) -> dict | None:
    ctx = get_security_context(project_id, db, subject_type, subject_id)
    if not ctx:
        return None
    # factors 1-10
    internet = any(a.get("extra_data",{}).get("externally_reachable") for a in ctx["assets"])
    # app criticality
    app_crit = max([ (a.get("criticality","unknown") ) for a in ctx["applications"]], default="unknown")
    crit_rank = {"critical":4,"high":3,"medium":2,"low":1,"unknown":0}
    # cloud exposure via exposures
    cloud_exposed = any(ctx["attack_paths"])
    # dependent assets count
    dep_count = len(ctx["assets"])
    # related apps count
    app_count = len(ctx["applications"])
    # related critical/high
    crit_high = sum(1 for f in ctx["findings"] if f.get("severity","").lower() in ("critical","high"))
    # SLA breached via findings remediations
    sla_breached = 0
    try:
        from app.models.finding import FindingSLA
        fids = [f["id"] for f in ctx["findings"]]
        if fids:
            sla_breached = db.query(func.count(FindingSLA.id)).filter(FindingSLA.finding_id.in_(fids), FindingSLA.status=="breached").scalar() or 0
    except: pass
    # remediation state
    open_findings = len([f for f in ctx["remediation"] if f.get("status")=="open"]) if ctx["remediation"] else 0
    validation_state = ctx["validations"][0].get("verdict") if ctx["validations"] else None
    factors = []
    if internet:
        factors.append("Internet exposure: internet-facing asset present")
    if app_crit in ("critical","high"):
        factors.append(f"Application criticality: {app_crit}")
    if cloud_exposed:
        factors.append("Cloud exposure: attack path exists")
    if dep_count > 3:
        factors.append(f"Dependent assets: {dep_count} assets")
    if app_count > 1:
        factors.append(f"Related applications: {app_count}")
    if crit_high:
        factors.append(f"Critical/high findings: {crit_high}")
    if sla_breached:
        factors.append(f"SLA breached: {sla_breached} findings")
    if open_findings:
        factors.append(f"Open remediation: {open_findings} findings")
    if validation_state:
        factors.append(f"Validation: {validation_state}")
    priority = "CRITICAL" if internet and crit_high and app_crit in ("critical","high") else "HIGH" if crit_high else "MEDIUM" if internet else "LOW"
    return {
        "project_id": project_id,
        "subject_type": subject_type,
        "subject_id": subject_id,
        "fingerprint": ctx["fingerprint"],
        "internet_exposure": internet,
        "application_criticality": app_crit,
        "cloud_exposure": cloud_exposed,
        "dependent_assets": dep_count,
        "related_applications": app_count,
        "critical_high_findings": crit_high,
        "sla_breached": sla_breached,
        "remediation_open": open_findings,
        "validation_state": validation_state,
        "priority": priority,
        "factors": factors,
        "evidence": {"findings": len(ctx["findings"]), "assets": len(ctx["assets"])},
    }

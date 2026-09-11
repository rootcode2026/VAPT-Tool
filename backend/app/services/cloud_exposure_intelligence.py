"""E11 Cloud Exposure Intelligence — deterministic, bounded, correlates findings + CSPM + paths + history."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding

# Reuse E9/E10
from app.services.cloud_attack_paths import (
    build_cloud_attack_paths,
    MAX_PATHS as ATTACK_MAX,
    VALID_PROVIDERS,
)
from app.services.cspm import evaluate_cspm

# Limits
MAX_FINDINGS = 500
MAX_ASSETS = 500
MAX_TOP = 20
MAX_EVIDENCE = 20

VALID_EXPOSURE_TYPES = {"ATTACK_PATH_EXPOSURE", "FINDING_EXPOSURE", "CSPM_EXPOSURE", "ASSET_EXPOSURE"}
VALID_SEVERITIES = {"critical", "high", "medium", "low"}
RISK_TIERS = {"critical": 85, "high": 70, "medium": 40, "low": 0}

# Risk factors taxonomy
FACTORS = {
    "EXTERNAL_EXPOSURE",
    "CRITICAL_FINDING",
    "HIGH_FINDING",
    "PRIVILEGED_IDENTITY",
    "SENSITIVE_TARGET",
    "ACTIVE_ATTACK_PATH",
    "PERSISTENT_ATTACK_PATH",
    "REOPENED_ATTACK_PATH",
    "UNREMEDIATED",
    "SLA_BREACH",
    "RECENTLY_CREATED",
    "RECURRING_EXPOSURE",
}

SEVERITY_SCORE = {"critical": 20, "high": 15, "medium": 10, "low": 5, "info": 0, "unknown": 0}

def _provider_from_asset(asset: Asset) -> str:
    try:
        val = str(asset.value or "").lower()
        for p in ("aws", "gcp", "azure"):
            if f":{p}:" in val:
                return p
    except Exception:
        pass
    return "unknown"

def _is_exposed(asset: Asset) -> bool:
    meta = asset.extra_data if isinstance(asset.extra_data, dict) else {}
    if meta.get("public") is True or str(meta.get("public_ip") or "").strip():
        return True
    if str(meta.get("exposure") or "").upper() == "INTERNET_EXPOSED":
        return True
    if str(meta.get("scheme") or "").lower() == "internet-facing":
        return True
    if meta.get("allow_blob_public_access") is True or meta.get("is_public") is True:
        return True
    return False

def _is_sensitive(asset: Asset) -> bool:
    meta = asset.extra_data if isinstance(asset.extra_data, dict) else {}
    rtype = str(meta.get("resource_type") or "").lower()
    sensitive = {"aws_rds_instance", "aws_s3_bucket", "aws_ebs_volume", "gcp_storage_bucket", "azure_storage_account", "azure_vm", "gcp_compute_instance"}
    return rtype in sensitive

def _has_privilege(findings: list) -> bool:
    for f in findings:
        rid = str((f.extra_data or {}).get("rule_id") or "").upper()
        if rid.startswith("AWS-IAM-") or rid.startswith("GCP-IAM-") or rid.startswith("AZURE-IAM-"):
            return True
    return False

def _max_severity(findings: list) -> str:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    best = "low"
    best_rank = -1
    for f in findings:
        sev = str(f.severity or "low").lower()
        r = rank.get(sev, 0)
        if r > best_rank:
            best_rank = r
            best = sev
    return best

def _exposure_score(
    max_sev: str,
    path_priority: int | None,
    exposed: bool,
    privileged: bool,
    sensitive: bool,
    persistence_days: int | None,
    reopened: bool,
    unremediated: bool,
) -> tuple[int, list[str]]:
    """Deterministic 0-100, documented."""
    factors: list[str] = []
    score = 0
    # A Finding severity 0-20
    sev_score = SEVERITY_SCORE.get(max_sev.lower(), 0)
    score += sev_score
    if sev_score >= 20:
        factors.append("CRITICAL_FINDING")
    elif sev_score >= 15:
        factors.append("HIGH_FINDING")
    # B Attack path priority 0-30
    if path_priority is not None:
        path_contrib = int(path_priority * 0.3)  # 0-30
        score += path_contrib
        if path_priority >= 40:
            factors.append("ACTIVE_ATTACK_PATH")
    else:
        path_contrib = 0
    # C External exposure 0/15
    if exposed:
        score += 15
        factors.append("EXTERNAL_EXPOSURE")
    # D Privilege 0/10
    if privileged:
        score += 10
        factors.append("PRIVILEGED_IDENTITY")
    # E Sensitive 0/10
    if sensitive:
        score += 10
        factors.append("SENSITIVE_TARGET")
    # F Persistence 0-5
    if persistence_days is not None and persistence_days > 7:
        score += 5
        factors.append("PERSISTENT_ATTACK_PATH")
    elif persistence_days is not None and persistence_days > 0:
        # proportional
        add = int(persistence_days / 7 * 5)
        score += add
        if add > 0:
            factors.append("PERSISTENT_ATTACK_PATH")
    # G Recurrence 0/5
    if reopened:
        score += 5
        factors.append("REOPENED_ATTACK_PATH")
        factors.append("RECURRING_EXPOSURE")
    # H Remediation 0/5
    if unremediated:
        score += 5
        factors.append("UNREMEDIATED")
    # clamp
    score = max(0, min(100, score))
    # ensure at least one factor if score >0
    if score > 0 and not factors:
        factors.append("HIGH_FINDING" if max_sev in ("high", "critical") else "EXTERNAL_EXPOSURE")
    return score, sorted(set(factors))

def _severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"

def _confidence_for_exposure(path_confidence: str | None, finding_count: int) -> str:
    if path_confidence == "HIGH":
        return "HIGH"
    if path_confidence == "MEDIUM" or finding_count > 0:
        return "MEDIUM"
    return "LOW"

def _canonical_id(project_id: str, exp_type: str, primary_asset_id: str, fingerprint: str) -> str:
    raw = f"{project_id}|{exp_type}|{primary_asset_id}|{fingerprint}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def _bounded_evidence(findings: list, paths: list, controls: list) -> list[dict]:
    out = []
    for f in findings[:10]:
        title = _redact(str(f.title or "")[:200])
        out.append({"type": "finding", "rule_id": str((f.extra_data or {}).get("rule_id") or "")[:64], "finding_id": f.id, "severity": str(f.severity).lower()[:20], "title": title})
    for p in paths[:5]:
        out.append({"type": "attack_path", "path_id": p.get("id") or p.get("fingerprint"), "severity": str(p.get("severity") or "")[:20], "priority_score": p.get("priority_score")})
    for c in controls[:5]:
        out.append({"type": "cspm", "control_id": c.get("control_id"), "severity": str(c.get("severity") or "")[:20]})
    return out[:MAX_EVIDENCE]

def _redact(text: str) -> str:
    lower = text.lower()
    if any(k in lower for k in ("secret", "private_key", "credential", "token", "password")):
        return "[REDACTED]"
    return text[:500]

def get_top_exposures(
    project_id: str,
    db: Session,
    provider: str | None = None,
    severity: str | None = None,
    exposure_type: str | None = None,
    limit: int = 20,
) -> list[dict]:
    if provider and provider.lower() not in VALID_PROVIDERS and provider.lower() != "multi":
        raise ValueError(f"Invalid provider: {provider}")
    if severity and severity.lower() not in VALID_SEVERITIES:
        raise ValueError(f"Invalid severity: {severity}")
    if exposure_type and exposure_type.upper() not in VALID_EXPOSURE_TYPES:
        raise ValueError(f"Invalid exposure_type: {exposure_type}")
    if limit < 1:
        limit = 1
    if limit > MAX_TOP:
        limit = MAX_TOP

    # Bounded batch retrieval
    assets = db.query(Asset).filter(Asset.project_id == project_id).limit(MAX_ASSETS).all()
    assets_by_id = {a.id: a for a in assets}
    cloud_assets = [a for a in assets if a.asset_type in ("cloud_account", "cloud_resource")]
    findings = db.query(Finding).join(Asset, Asset.id == Finding.asset_id).filter(Asset.project_id == project_id, Finding.scanner == "cloud").limit(MAX_FINDINGS).all()
    findings_by_asset: dict[str, list] = {}
    for f in findings:
        if f.asset_id:
            findings_by_asset.setdefault(f.asset_id, []).append(f)

    # CSPM
    try:
        cspm_data = evaluate_cspm(project_id, db)
        failed_controls = [r for r in cspm_data.get("results", []) if r.get("status") == "FAIL"]
    except Exception:
        failed_controls = []

    # Attack paths (E9)
    try:
        paths = build_cloud_attack_paths(project_id, db, limit=ATTACK_MAX)
    except Exception:
        paths = []

    # History for persistence/recurrence
    from app.models.cloud_attack_path import CloudAttackPath as CAP
    history_by_fp: dict[str, Any] = {}
    try:
        history_rows = db.query(CAP).filter(CAP.project_id == project_id).limit(100).all()
        for h in history_rows:
            history_by_fp[h.fingerprint] = h
    except Exception:
        history_rows = []

    exposures: dict[str, dict] = {}

    # 1. ATTACK_PATH_EXPOSURE — each path is an exposure (prefer)
    for p in paths:
        primary_asset_id = p.get("target_asset_id") or p.get("entry_asset_id")
        asset = assets_by_id.get(primary_asset_id)
        prov = p.get("provider") or (_provider_from_asset(asset) if asset else "unknown")
        if provider and prov != provider.lower() and prov != "multi":
            continue
        findings_on_path = []
        for aid in p.get("asset_ids", []):
            findings_on_path.extend(findings_by_asset.get(aid, []))
        max_sev = _max_severity(findings_on_path) if findings_on_path else str(p.get("severity") or "medium").lower()
        exposed = asset and _is_exposed(asset) if asset else True
        privileged = _has_privilege(findings_on_path)
        sensitive = asset and _is_sensitive(asset) if asset else False
        # history
        fp = p.get("fingerprint") or p.get("id")
        h = history_by_fp.get(fp)
        persistence_days = None
        reopened = False
        if h:
            try:
                first = h.first_seen_at
                last = h.last_seen_at
                if first and last:
                    # handle naive vs aware
                    if first.tzinfo is None:
                        first = first.replace(tzinfo=timezone.utc)
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    persistence_days = (last - first).days
                    # reopened if first_seen < last_seen and resolved_at was once set
                    if h.first_seen_at != h.last_seen_at and h.resolved_at is None and h.status == "ACTIVE":
                        # heuristic: if path has been resolved before, it would have been reopened
                        # For now, consider reopened if count of observations >1 and status ACTIVE and first != last
                        reopened = persistence_days > 1  # bounded
                    if h.status == "ACTIVE" and persistence_days and persistence_days > 0:
                        pass
            except Exception:
                pass
        # remediation: if any finding open and critical
        unremediated = any(str(f.status).lower() == "open" and str(f.severity).lower() in ("critical", "high") for f in findings_on_path)
        score, factors = _exposure_score(max_sev, p.get("priority_score"), exposed, privileged, sensitive, persistence_days, reopened, unremediated)
        sev = _severity_from_score(score)
        if severity and sev != severity.lower():
            continue
        if exposure_type and exposure_type.upper() != "ATTACK_PATH_EXPOSURE":
            continue
        exp_id = _canonical_id(project_id, "ATTACK_PATH_EXPOSURE", primary_asset_id or fp, fp)
        if exp_id in exposures:
            continue
        exp = {
            "exposure_id": exp_id,
            "project_id": project_id,
            "provider": prov,
            "exposure_type": "ATTACK_PATH_EXPOSURE",
            "asset_id": primary_asset_id,
            "asset_type": asset.asset_type if asset else "unknown",
            "title": f"Attack path to {asset.value[:80] if asset else 'resource'}",
            "priority_score": score,
            "severity": sev,
            "confidence": _confidence_for_exposure(p.get("confidence"), len(findings_on_path)),
            "risk_factors": factors,
            "finding_ids": [f.id for f in findings_on_path[:10]],
            "attack_path_ids": [p.get("id")],
            "cspm_control_ids": [],
            "first_seen": h.first_seen_at.isoformat() if h and h.first_seen_at else None,
            "last_seen": h.last_seen_at.isoformat() if h and h.last_seen_at else None,
            "remediation_state": "OPEN" if unremediated else "UNKNOWN",
            "owner": None,
            "sla_state": None,
            "explanation": f"Priority {score} because {', '.join(factors).lower().replace('_',' ')}; path priority {p.get('priority_score')} with {len(findings_on_path)} finding(s).",
            "evidence": _bounded_evidence(findings_on_path, [p], []),
            "attack_path": p,
        }
        # sanitize
        exp["title"] = _redact(exp["title"])
        exposures[exp_id] = exp

    # 2. FINDING_EXPOSURE — one per asset (deduplicate multiple findings on same asset)
    covered_finding_ids = set()
    for e in exposures.values():
        covered_finding_ids.update(e.get("finding_ids", []))
    for asset_id, flist in findings_by_asset.items():
        uncovered = [f for f in flist if f.id not in covered_finding_ids]
        if not uncovered:
            continue
        if not any(str(f.severity).lower() in ("critical", "high") for f in uncovered):
            continue
        # use max severity
        max_sev = _max_severity(uncovered)
        # use first finding's asset for metadata
        rep = uncovered[0]
        asset = assets_by_id.get(asset_id)
        prov = _provider_from_asset(asset) if asset else "unknown"
        if provider and prov != provider.lower() and prov != "multi":
            continue
        exposed = asset and _is_exposed(asset) if asset else False
        sensitive = asset and _is_sensitive(asset) if asset else False
        score, factors = _exposure_score(max_sev, None, exposed, _has_privilege(uncovered), sensitive, None, False, any(str(f.status).lower() == "open" for f in uncovered))
        sev = _severity_from_score(score)
        if severity and sev != severity.lower():
            continue
        if exposure_type and exposure_type.upper() != "FINDING_EXPOSURE":
            continue
        exp_id = _canonical_id(project_id, "FINDING_EXPOSURE", asset_id, asset_id)
        if exp_id in exposures:
            continue
        if len(exposures) >= MAX_TOP:
            break
        exp = {
            "exposure_id": exp_id,
            "project_id": project_id,
            "provider": prov,
            "exposure_type": "FINDING_EXPOSURE",
            "asset_id": asset_id,
            "asset_type": asset.asset_type if asset else "unknown",
            "title": rep.title[:200],
            "priority_score": score,
            "severity": sev,
            "confidence": "MEDIUM",
            "risk_factors": factors,
            "finding_ids": [f.id for f in uncovered[:10]],
            "attack_path_ids": [],
            "cspm_control_ids": [],
            "first_seen": rep.created_at.isoformat() if hasattr(rep, "created_at") and rep.created_at else None,
            "last_seen": rep.created_at.isoformat() if hasattr(rep, "created_at") and rep.created_at else None,
            "remediation_state": str(rep.status).upper() if hasattr(rep, "status") else "UNKNOWN",
            "owner": None,
            "sla_state": None,
            "explanation": f"Priority {score} because {', '.join(factors).lower().replace('_',' ')}; isolated {max_sev} finding.",
            "evidence": _bounded_evidence(uncovered, [], []),
        }
        exp["title"] = _redact(exp["title"])
        exposures[exp_id] = exp

    # 3. CSPM_EXPOSURE for failed controls not already covered (limit)
    if len(exposures) < MAX_TOP and not exposure_type:
        for c in failed_controls[:5]:
            if len(exposures) >= MAX_TOP:
                break
            provs = list(c.get("mappings", {}).keys())
            prov = provs[0] if provs else "unknown"
            if provider and prov != provider.lower():
                continue
            max_sev = str(c.get("severity") or "medium").lower()
            sev_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}
            max_sev = sev_map.get(max_sev, "medium")
            score, factors = _exposure_score(max_sev, None, True, False, True, None, False, True)
            sev = _severity_from_score(score)
            if severity and sev != severity.lower():
                continue
            exp_id = _canonical_id(project_id, "CSPM_EXPOSURE", c.get("control_id"), c.get("control_id"))
            if exp_id in exposures:
                continue
            exp = {
                "exposure_id": exp_id,
                "project_id": project_id,
                "provider": prov,
                "exposure_type": "CSPM_EXPOSURE",
                "asset_id": None,
                "asset_type": "control",
                "title": c.get("title", "")[:200],
                "priority_score": score,
                "severity": sev,
                "confidence": "MEDIUM",
                "risk_factors": factors,
                "finding_ids": [],
                "attack_path_ids": [],
                "cspm_control_ids": [c.get("control_id")],
                "first_seen": None,
                "last_seen": None,
                "remediation_state": "OPEN",
                "owner": None,
                "sla_state": None,
                "explanation": f"Priority {score} because {', '.join(factors).lower().replace('_',' ')}; CSPM control failing.",
                "evidence": _bounded_evidence([], [], [c]),
            }
            exposures[exp_id] = exp

    # Sort deterministic: priority desc, severity rank, exposure_id
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    sorted_exps = sorted(exposures.values(), key=lambda e: (-e["priority_score"], rank.get(e["severity"], 99), e["exposure_id"]))
    return sorted_exps[:limit]

def get_exposure_intelligence(project_id: str, db: Session) -> dict:
    top = get_top_exposures(project_id, db, limit=MAX_TOP)
    # Project risk score: top exposure + concentration
    if not top:
        score = 0
        grade = "A"
    else:
        top_score = top[0]["priority_score"]
        critical = sum(1 for e in top if e["severity"] == "critical")
        high = sum(1 for e in top if e["severity"] == "high")
        # bounded concentration
        conc = min(critical * 4 + high * 2, 15)
        active_paths = len([e for e in top if e["exposure_type"] == "ATTACK_PATH_EXPOSURE"])
        conc2 = min(active_paths, 5)
        score = min(top_score + conc + conc2, 100)
        if score >= 85:
            grade = "D"  # inverse? Actually risk grade: high risk = low grade? Use same as CSPM: A 90-100 good, but exposure risk high is bad. Use risk grade mapping: 0-20 A, 21-40 B, 41-70 C, 71-100 D? But spec says reuse E9: CRITICAL >=85 etc. For project score, map to same.
            # For project, reuse severity mapping
            pass
        # Map project score to grade via same severity tiers
    # Map to grade via severity tiers
    if score >= 85:
        grade = "D" if score >= 85 else "C"  # Actually risk high = D, but keep consistent with E9: critical >=85
        # Use E9 severity mapping for project risk: critical high risk
        grade = "D"
    elif score >= 70:
        grade = "C"
    elif score >= 40:
        grade = "B"
    else:
        grade = "A"
    # But for exposure intelligence, grade should reflect risk: A low risk, D high risk. Keep as above.
    # More simply: reuse E9 grade logic
    if score >= 85:
        grade = "D"
    elif score >= 70:
        grade = "C"
    elif score >= 40:
        grade = "B"
    else:
        grade = "A"

    critical = sum(1 for e in top if e["severity"] == "critical")
    high = sum(1 for e in top if e["severity"] == "high")
    medium = sum(1 for e in top if e["severity"] == "medium")
    low = sum(1 for e in top if e["severity"] == "low")
    # providers
    providers: dict[str, int] = {}
    for e in top:
        providers[e["provider"]] = providers.get(e["provider"], 0) + 1
    # exposure types
    exp_types: dict[str, int] = {}
    for e in top:
        exp_types[e["exposure_type"]] = exp_types.get(e["exposure_type"], 0) + 1
    # trends via history
    trends = {"7d": {}, "30d": {}, "90d": {}}
    try:
        from app.models.cloud_attack_path import CloudAttackPath as CAP
        now = datetime.now(timezone.utc)
        for days, key in [(7, "7d"), (30, "30d"), (90, "90d")]:
            since = now - timedelta(days=days)
            active = db.query(func.count(CAP.id)).filter(CAP.project_id == project_id, CAP.status == "ACTIVE", CAP.first_seen_at >= since).scalar() or 0
            resolved = db.query(func.count(CAP.id)).filter(CAP.project_id == project_id, CAP.status == "RESOLVED", CAP.resolved_at != None, CAP.resolved_at >= since).scalar() or 0
            trends[key] = {"new": active, "resolved": resolved}
    except Exception:
        pass

    return {
        "project_id": project_id,
        "score": score,
        "grade": grade,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "total": len(top),
        "top_exposures": top,
        "providers": providers,
        "exposure_types": exp_types,
        "trends": trends,
    }

def get_exposure_detail(project_id: str, db: Session, exposure_id: str) -> dict | None:
    top = get_top_exposures(project_id, db, limit=MAX_TOP)
    for e in top:
        if e["exposure_id"] == exposure_id:
            # Enrich with history, remediation, SLA
            # History: fetch from CloudAttackPath if attack path exposure
            history = None
            if e["exposure_type"] == "ATTACK_PATH_EXPOSURE":
                try:
                    from app.models.cloud_attack_path import CloudAttackPath as CAP
                    # Find by fingerprint derived from attack_path_id
                    # exposure_id is hash of project|type|asset|fp, not directly fp, but we can get via attack_path_ids
                    ap_id = e["attack_path_ids"][0] if e["attack_path_ids"] else None
                    if ap_id:
                        # Need to find path via E9 on-read to get fp? Use ap_id as fingerprint lookup
                        # Try lookup via fingerprint
                        cap = db.query(CAP).filter(CAP.project_id == project_id, CAP.fingerprint == ap_id).first()
                        if not cap:
                            cap = db.query(CAP).filter(CAP.id == ap_id).first()
                        if cap:
                            history = {
                                "first_seen_at": cap.first_seen_at.isoformat() if cap.first_seen_at else None,
                                "last_seen_at": cap.last_seen_at.isoformat() if cap.last_seen_at else None,
                                "resolved_at": cap.resolved_at.isoformat() if cap.resolved_at else None,
                                "status": cap.status,
                                "persistence_days": (cap.last_seen_at - cap.first_seen_at).days if cap.first_seen_at and cap.last_seen_at else 0,
                            }
                except Exception:
                    history = None
            return {**e, "history": history}
    return None

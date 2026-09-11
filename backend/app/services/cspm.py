"""E8 CSPM Control Engine — provider-neutral, deterministic, on-read.

Consumes normalized evidence from E1-E7 (assets, findings, check runs) and produces
unified CSPM posture: PASS/FAIL/NOT_ASSESSED per control, posture score, compliance.

No new discovery, no new scanner, no AI, no remediation.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding

# Control catalog — 21 high-value provider-neutral controls (within 20-40), runtime-verified
# Each control maps to provider-specific rule IDs from E1-E7 (AWS_CHECKS)
# Category totals: IDENTITY 3, NETWORK 7, STORAGE 3, ENCRYPTION 3, COMPUTE 2, EXPOSURE 2, LOGGING 1 = 21
# All mapped rule IDs verified against AWS_CHECKS (no orphan mappings)

CSPM_CONTROLS: list[dict[str, Any]] = [
    # IDENTITY (3)
    {"control_id": "CSPM-IAM-001", "title": "Privileged subscription/account access must be restricted", "description": "Owner/Admin at subscription/account scope should be least-privilege.", "category": "IDENTITY", "severity": "high", "provider": "multi", "mappings": {"aws": ["AWS-IAM-001", "AWS-IAM-003"], "gcp": ["GCP-IAM-002", "GCP-IAM-003"], "azure": ["AZURE-IAM-001", "AZURE-IAM-002"]}},
    {"control_id": "CSPM-IAM-002", "title": "Wildcard administrative access must be avoided", "description": "Wildcard Action * or excessive admin permissions.", "category": "IDENTITY", "severity": "critical", "provider": "multi", "mappings": {"aws": ["AWS-IAM-001", "AWS-IAM-002", "AWS-IAM-003"], "gcp": ["GCP-IAM-001"], "azure": ["AZURE-IAM-001"]}},
    {"control_id": "CSPM-IAM-003", "title": "User access administration must be restricted", "description": "User Access Administrator at subscription scope.", "category": "IDENTITY", "severity": "high", "provider": "multi", "mappings": {"azure": ["AZURE-IAM-003"], "aws": ["AWS-IAM-003"], "gcp": ["GCP-IAM-002"]}},
    # NETWORK (7)
    {"control_id": "CSPM-NET-001", "title": "SSH must not be exposed to the Internet", "description": "TCP 22 from 0.0.0.0/0", "category": "NETWORK", "severity": "high", "provider": "multi", "mappings": {"aws": ["AWS-EC2-002", "AWS-NET-002"], "gcp": ["GCP-NET-001"], "azure": ["AZURE-NET-001"]}},
    {"control_id": "CSPM-NET-002", "title": "RDP must not be exposed to the Internet", "description": "TCP 3389 from Internet", "category": "NETWORK", "severity": "high", "provider": "multi", "mappings": {"aws": ["AWS-NET-003"], "gcp": ["GCP-NET-002"], "azure": ["AZURE-NET-002"]}},
    {"control_id": "CSPM-NET-003", "title": "Database ports must not be exposed to the Internet", "description": "3306/5432/1433/1521/27017/6379/9200", "category": "NETWORK", "severity": "high", "provider": "multi", "mappings": {"aws": ["AWS-NET-004"], "gcp": ["GCP-NET-003"], "azure": ["AZURE-NET-003"]}},
    {"control_id": "CSPM-NET-004", "title": "All ports must not be exposed to the Internet", "description": "All ports/protocols from Internet", "category": "NETWORK", "severity": "critical", "provider": "multi", "mappings": {"aws": ["AWS-NET-005"], "gcp": ["GCP-NET-004"], "azure": ["AZURE-NET-004"]}},
    {"control_id": "CSPM-NET-005", "title": "Broad Internet ingress should be restricted", "description": "0.0.0.0/0 broad ingress", "category": "NETWORK", "severity": "high", "provider": "multi", "mappings": {"aws": ["AWS-EC2-002", "AWS-NET-001"], "gcp": ["GCP-NET-005"], "azure": ["AZURE-NET-005"]}},
    {"control_id": "CSPM-NET-006", "title": "Public compute resources must not have permissive Internet ingress", "description": "VM with public IP + NSG/firewall Internet ingress", "category": "NETWORK", "severity": "high", "provider": "multi", "mappings": {"aws": ["AWS-NET-007"], "gcp": ["GCP-COMPUTE-002"], "azure": ["AZURE-NET-006"]}},
    {"control_id": "CSPM-NET-007", "title": "Unrestricted outbound access should be reviewed", "description": "0.0.0.0/0 all ports egress (AWS-only: no GCP/Azure egress check exists)", "category": "NETWORK", "severity": "low", "provider": "multi", "mappings": {"aws": ["AWS-NET-010"]}},
    # STORAGE (3)
    {"control_id": "CSPM-STORAGE-001", "title": "Public storage access must be disabled unless justified", "description": "S3/GCS/storage public", "category": "STORAGE", "severity": "high", "provider": "multi", "mappings": {"aws": ["AWS-S3-003", "AWS-S3-005"], "gcp": ["GCP-GCS-001"], "azure": ["AZURE-STORAGE-001"]}},
    {"control_id": "CSPM-STORAGE-002", "title": "Secure transport must be enforced for storage", "description": "HTTPS-only", "category": "STORAGE", "severity": "medium", "provider": "multi", "mappings": {"aws": ["AWS-S3-001"], "azure": ["AZURE-STORAGE-003"]}},
    {"control_id": "CSPM-STORAGE-003", "title": "Weak TLS configuration must not be used", "description": "TLS <1.2", "category": "STORAGE", "severity": "medium", "provider": "multi", "mappings": {"azure": ["AZURE-STORAGE-004"], "aws": ["AWS-S3-001"]}},
    {"control_id": "CSPM-STORAGE-004", "title": "Storage encryption must be enabled", "description": "Unencrypted storage", "category": "ENCRYPTION", "severity": "medium", "provider": "multi", "mappings": {"aws": ["AWS-S3-002", "AWS-EBS-001", "AWS-EFS-001", "AWS-RDS-002"], "gcp": ["GCP-GCS-004"], "azure": ["AZURE-STORAGE-005"]}},
    # COMPUTE (2)
    {"control_id": "CSPM-COMPUTE-001", "title": "Public compute exposure must be minimized", "description": "Public IP + permissive (compute perspective of NET-006)", "category": "COMPUTE", "severity": "high", "provider": "multi", "mappings": {"aws": ["AWS-NET-007"], "gcp": ["GCP-COMPUTE-002"], "azure": ["AZURE-NET-006"]}},
    {"control_id": "CSPM-COMPUTE-002", "title": "Secure compute security features should be enabled", "description": "Secure boot, vTPM, shielded VM", "category": "COMPUTE", "severity": "info", "provider": "multi", "mappings": {"azure": ["AZURE-COMPUTE-001", "AZURE-COMPUTE-002"], "gcp": ["GCP-COMPUTE-001"]}},
    # ENCRYPTION (3 — includes STORAGE-004)
    {"control_id": "CSPM-ENC-001", "title": "Sensitive cloud storage should use encryption", "description": "Default encryption", "category": "ENCRYPTION", "severity": "medium", "provider": "multi", "mappings": {"aws": ["AWS-S3-002"], "gcp": ["GCP-GCS-004"], "azure": ["AZURE-STORAGE-005"]}},
    {"control_id": "CSPM-ENC-002", "title": "Unencrypted persistent storage must be avoided", "description": "EBS/RDS/EFS/GCP disk", "category": "ENCRYPTION", "severity": "high", "provider": "multi", "mappings": {"aws": ["AWS-EBS-001", "AWS-RDS-002", "AWS-EFS-001"], "gcp": ["GCP-GCS-004"], "azure": ["AZURE-STORAGE-005"]}},
    # EXPOSURE (2)
    {"control_id": "CSPM-EXP-001", "title": "Internet-facing resources should have controlled exposure", "description": "Public IP + network policy", "category": "EXPOSURE", "severity": "high", "provider": "multi", "mappings": {"aws": ["AWS-EC2-002"], "gcp": ["GCP-NET-005"], "azure": ["AZURE-NET-005"]}},
    {"control_id": "CSPM-EXP-002", "title": "Critical administrative services must not be Internet exposed", "description": "SSH/RDP", "category": "EXPOSURE", "severity": "critical", "provider": "multi", "mappings": {"aws": ["AWS-NET-002", "AWS-NET-003"], "gcp": ["GCP-NET-001", "GCP-NET-002"], "azure": ["AZURE-NET-001", "AZURE-NET-002"]}},
    # LOGGING (1)
    {"control_id": "CSPM-LOG-001", "title": "Cloud storage access logging should be enabled", "description": "S3/GCS logging", "category": "LOGGING", "severity": "info", "provider": "multi", "mappings": {"aws": ["AWS-S3-007"], "gcp": ["GCP-GCS-003"]}},
]

# Ensure stable IDs and no duplicates
assert len({c["control_id"] for c in CSPM_CONTROLS}) == len(CSPM_CONTROLS), "duplicate control_id"

VALID_PROVIDERS = {"aws", "gcp", "azure"}
VALID_CATEGORIES = {"IDENTITY", "NETWORK", "STORAGE", "COMPUTE", "ENCRYPTION", "EXPOSURE", "LOGGING", "CONFIGURATION"}
VALID_STATUSES = {"PASS", "FAIL", "NOT_ASSESSED"}
SEVERITY_WEIGHTS = {"critical": 25, "high": 15, "medium": 7, "low": 2, "info": 1}

MAX_EVIDENCE = 10
MAX_AFFECTED_RESOURCES = 20
MAX_TOP_FAILURES = 20
MAX_CSPM_FINDINGS = 500

def _get_findings_by_rule(project_id: str, db: Session) -> dict[str, list]:
    """Map rule_id -> findings (bounded)."""
    findings = db.query(Finding).join(Asset, Asset.id == Finding.asset_id).filter(Asset.project_id == project_id, Finding.scanner == "cloud").limit(MAX_CSPM_FINDINGS).all()
    by_rule: dict[str, list] = {}
    for f in findings:
        rule = str((f.extra_data or {}).get("rule_id") or "").upper()
        if rule:
            by_rule.setdefault(rule, []).append(f)
    return by_rule

def _get_check_runs_breakdown(project_id: str, db: Session) -> dict[str, dict]:
    try:
        from app.models.cloud_check import CloudCheckRun
        last = db.query(CloudCheckRun).filter(CloudCheckRun.project_id == project_id).order_by(CloudCheckRun.created_at.desc()).first()
        if last and isinstance(last.breakdown, dict):
            return last.breakdown
    except Exception:
        pass
    return {}

def _sanitize_evidence(evidence: list[dict]) -> list[dict]:
    """Ensure evidence never leaks secrets; bound and sanitized."""
    out = []
    for e in evidence[:MAX_EVIDENCE]:
        # Only retain safe fields; strip any secret-like keys
        safe = {
            "rule_id": str(e.get("rule_id") or "")[:64],
            "finding_id": str(e.get("finding_id") or "")[:64],
            "title": str(e.get("title") or "")[:500],
            "severity": str(e.get("severity") or "").lower()[:20],
        }
        # Block secrets in title
        lower_title = safe["title"].lower()
        if any(k in lower_title for k in ("secret", "credential", "private_key", "token", "password")):
            safe["title"] = "[REDACTED]"
        out.append(safe)
    return out

def validate_provider_filter(provider: str | None) -> str | None:
    if provider is None:
        return None
    p = provider.strip().lower()
    if p not in VALID_PROVIDERS:
        raise ValueError(f"Invalid provider: {provider}")
    return p

def validate_category_filter(category: str | None) -> str | None:
    if category is None:
        return None
    c = category.strip().upper()
    if c not in VALID_CATEGORIES:
        raise ValueError(f"Invalid category: {category}")
    return c

def validate_status_filter(status: str | None) -> str | None:
    if status is None:
        return None
    s = status.strip().upper()
    if s not in VALID_STATUSES:
        raise ValueError(f"Invalid status: {status}")
    return s

def evaluate_cspm(project_id: str, db: Session, provider_filter: str | None = None, category_filter: str | None = None) -> dict:
    # Validate filters (fail-fast for API validation)
    if provider_filter is not None:
        validate_provider_filter(provider_filter)
    if category_filter is not None:
        validate_category_filter(category_filter)
    findings_by_rule = _get_findings_by_rule(project_id, db)
    breakdown = _get_check_runs_breakdown(project_id, db)
    results = []
    prov_filter_norm = provider_filter.strip().lower() if provider_filter else None
    cat_filter_norm = category_filter.strip().upper() if category_filter else None
    for ctrl in CSPM_CONTROLS:
        # Provider filter: include only controls that support that provider
        if prov_filter_norm:
            mappings = ctrl.get("mappings") or {}
            if prov_filter_norm not in [k.lower() for k in mappings.keys()]:
                continue
        if cat_filter_norm and str(ctrl.get("category") or "").upper() != cat_filter_norm:
            continue
        # Determine status per control aggregated across providers
        # Semantics: FAIL if any mapped rule has finding(s); else PASS if breakdown has passed; else NOT_ASSESSED
        # Never convert missing evidence into PASS
        statuses: list[str] = []
        evidence: list[dict] = []
        affected: list[str] = []
        for prov, rule_ids in (ctrl.get("mappings") or {}).items():
            if prov_filter_norm and prov.lower() != prov_filter_norm:
                continue
            prov_has_fail = False
            prov_has_pass = False
            prov_has_not_assessed = False
            for rid in rule_ids:
                rid_up = str(rid).upper()
                # Check findings — FAIL evidence takes precedence
                if rid_up in findings_by_rule and findings_by_rule[rid_up]:
                    prov_has_fail = True
                    for f in findings_by_rule[rid_up][:2]:
                        evidence.append({"rule_id": rid_up, "finding_id": f.id, "title": f.title, "severity": f.severity})
                        if f.asset_id:
                            affected.append(str(f.asset_id))
                else:
                    bd = breakdown.get(rid_up) or breakdown.get(rid) or {}
                    if bd.get("failed", 0) > 0:
                        prov_has_fail = True
                    elif bd.get("not_assessed", 0) > 0:
                        prov_has_not_assessed = True
                    elif bd.get("passed", 0) > 0:
                        prov_has_pass = True
                    else:
                        # No findings, no positive evidence -> NOT_ASSESSED (never auto PASS)
                        prov_has_not_assessed = True
            if prov_has_fail:
                statuses.append("FAIL")
            elif prov_has_not_assessed:
                statuses.append("NOT_ASSESSED")
            elif prov_has_pass:
                statuses.append("PASS")
            else:
                statuses.append("NOT_ASSESSED")
        if not statuses:
            status = "NOT_ASSESSED"
            not_assessed_reason = "Control has no evaluated provider mappings for selected filter."
        elif "FAIL" in statuses:
            status = "FAIL"
            not_assessed_reason = ""
        elif "NOT_ASSESSED" in statuses:
            status = "NOT_ASSESSED"
            not_assessed_reason = "Evidence insufficient to determine control state (missing or unsupported provider data)."
        else:
            status = "PASS"
            not_assessed_reason = ""
        # Priority: FAIL > NOT_ASSESSED > PASS ; both positive and negative -> FAIL (fail already prioritized)
        evidence = _sanitize_evidence(evidence)
        affected_dedup = list(dict.fromkeys(affected))[:MAX_AFFECTED_RESOURCES]
        results.append({
            "control_id": ctrl["control_id"],
            "title": ctrl["title"],
            "description": ctrl["description"],
            "category": ctrl["category"],
            "severity": ctrl["severity"],
            "provider": ctrl["provider"],
            "mappings": ctrl["mappings"],
            "status": status,
            "not_assessed_reason": not_assessed_reason if status == "NOT_ASSESSED" else "",
            "evidence": evidence,
            "affected_resources": affected_dedup,
        })
    # Posture score — per FAILED CSPM CONTROL, not per finding (no double-counting within a control)
    failed = [r for r in results if r["status"] == "FAIL"]
    score = 100
    for r in failed:
        score -= SEVERITY_WEIGHTS.get(str(r["severity"]).lower(), 5)
    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 50:
        grade = "C"
    else:
        grade = "D"
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed_cnt = len(failed)
    not_assessed = sum(1 for r in results if r["status"] == "NOT_ASSESSED")
    total = len(results)
    evaluated = passed + failed_cnt
    compliance = (passed / evaluated * 100) if evaluated else 0
    coverage = (evaluated / total * 100) if total else 0
    # Provider breakdown
    providers: dict[str, dict] = {}
    for prov in ("aws", "gcp", "azure"):
        prov_results = [r for r in results if prov in (r.get("mappings") or {})]
        providers[prov] = {
            "total": len(prov_results),
            "passed": sum(1 for r in prov_results if r["status"] == "PASS"),
            "failed": sum(1 for r in prov_results if r["status"] == "FAIL"),
            "not_assessed": sum(1 for r in prov_results if r["status"] == "NOT_ASSESSED"),
        }
    # Category breakdown
    categories: dict[str, dict] = {}
    for cat in set(r["category"] for r in results):
        cat_results = [r for r in results if r["category"] == cat]
        categories[cat] = {
            "total": len(cat_results),
            "passed": sum(1 for r in cat_results if r["status"] == "PASS"),
            "failed": sum(1 for r in cat_results if r["status"] == "FAIL"),
            "not_assessed": sum(1 for r in cat_results if r["status"] == "NOT_ASSESSED"),
        }
    top_failures = sorted(failed, key=lambda x: SEVERITY_WEIGHTS.get(str(x["severity"]).lower(), 5), reverse=True)[:MAX_TOP_FAILURES]
    return {
        "project_id": project_id,
        "score": score,
        "grade": grade,
        "compliance_percent": round(compliance, 1),
        "coverage_percent": round(coverage, 1),
        "controls": {"total": total, "passed": passed, "failed": failed_cnt, "not_assessed": not_assessed},
        "providers": providers,
        "categories": categories,
        "results": results,
        "top_failures": top_failures,
        "evaluated": evaluated,
    }

def list_controls(project_id: str, db: Session, provider: str | None = None, category: str | None = None, status: str | None = None) -> list[dict]:
    if provider is not None:
        validate_provider_filter(provider)
    if category is not None:
        validate_category_filter(category)
    if status is not None:
        validate_status_filter(status)
    eval_data = evaluate_cspm(project_id, db, provider_filter=provider, category_filter=category)
    results = eval_data["results"]
    if status:
        results = [r for r in results if r["status"].upper() == status.strip().upper()]
    return results

def get_control_detail(project_id: str, db: Session, control_id: str) -> dict | None:
    # Validate control_id format (CSPM- prefix)
    if not control_id or not str(control_id).strip():
        return None
    eval_data = evaluate_cspm(project_id, db)
    for r in eval_data["results"]:
        if r["control_id"].upper() == str(control_id).strip().upper():
            return r
    return None

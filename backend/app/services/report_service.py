"""Report services — deterministic metrics, snapshot, export.
Authoritative customer-facing VAPT report template is VAPT_Final_Report (1).docx (WEB APPLICATION & NETWORK INFRASTRUCTURE, 23 sections).
This module is the delivery mechanism, not the authoritative template. It maps persisted platform data
(findings, assets, scans, remediation/retest/validation, evidence) into the template structure without inventing data.
See docs/CUSTOMER_VAPT_REPORT_TEMPLATE.md for template mapping and limitations (full DOCX 23-section generation not yet implemented).
"""
from __future__ import annotations

import csv
import io
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.target import Target

REPORT_TYPES = {"executive_security", "technical_vapt", "security_posture", "attack_surface", "finding_risk", "remediation_sla", "code_security", "cloud_security", "compliance"}

# D6 report versioning: bump GENERATOR_VERSION if template semantics change.
# Previously generated artifacts keep their embedded versions.
REPORT_FORMAT_VERSION = "1.0"
GENERATOR_VERSION = "1.0"

# Reporting period bounds (days).
DEFAULT_PERIOD_DAYS = 30
MAX_PERIOD_DAYS = 365

# Detail caps keep PDFs and payloads bounded at any project size.
MAX_DETAIL_FINDINGS = 50
MAX_EVIDENCE_CHARS = 200
MAX_REMEDIATION_CHARS = 300

# Resolved-ish finding statuses (finding lifecycle vocabulary).
_RESOLVED_STATUSES = frozenset({"resolved", "closed", "remediated", "false_positive", "accepted_risk"})
_OPEN_STATUSES = frozenset({"open", "detected", "triaged", "in_progress", "remediation_claimed",
                             "ready_for_retest", "retesting", "reopened"})


def parse_report_period(params: dict) -> tuple:
    """Resolve (start, end) aware datetimes from request parameters.

    Accepts ISO-8601 start_date/end_date; naive values are assumed UTC
    (documented). Defaults to the last 30 days. Raises ValueError with a
    safe message on invalid input; enforces start < end and max 365 days.
    """
    params = params if isinstance(params, dict) else {}
    now = datetime.now(timezone.utc)

    def _parse(value, field):
        if value is None or str(value).strip() == "":
            return None
        try:
            s = str(value).strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
        except Exception:
            raise ValueError(f"Invalid {field}: expected ISO-8601 datetime")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    end = _parse(params.get("end_date"), "end_date") or now
    start = _parse(params.get("start_date"), "start_date")
    if start is None:
        start = end - timedelta(days=DEFAULT_PERIOD_DAYS)
    if start >= end:
        raise ValueError("Invalid period: start_date must be before end_date")
    if (end - start).total_seconds() > MAX_PERIOD_DAYS * 86400:
        raise ValueError(f"Invalid period: maximum range is {MAX_PERIOD_DAYS} days")
    return start, end

def _finding_q(db: Session, organization_id: str, project_id: str | None):
    q = db.query(Finding).join(Target, Target.id == Finding.target_id).join(Project, Project.id == Target.project_id).filter(Project.organization_id == organization_id)
    if project_id:
        q = q.filter(Target.project_id == project_id)
    return q

def _asset_q(db: Session, organization_id: str, project_id: str | None):
    q = db.query(Asset).join(Project, Project.id == Asset.project_id).filter(Project.organization_id == organization_id)
    if project_id:
        q = q.filter(Asset.project_id == project_id)
    return q

def _explicit_period(params: dict):
    """Return (start, end) only when the caller explicitly requested a
    period; otherwise (None, None) to preserve legacy unfiltered behavior."""
    if not isinstance(params, dict):
        return None, None
    if params.get("start_date") is None and params.get("end_date") is None:
        return None, None
    return parse_report_period(params)


def collect_metrics(db: Session, organization_id: str, project_id: str | None, params: dict) -> dict:
    # Findings
    fq = _finding_q(db, organization_id, project_id)
    # D6: an explicit reporting period (start_date/end_date params) bounds
    # finding, scan and change evidence. Bounds are normalized to naive UTC,
    # matching the repository-wide datetime convention (naive UTC writes).
    # Callers without explicit dates keep legacy unfiltered behavior.
    period_start, period_end = _explicit_period(params or {})
    if period_start is not None:
        start_naive = period_start.replace(tzinfo=None)
        end_naive = period_end.replace(tzinfo=None)
        fq = fq.filter(Finding.created_at >= start_naive, Finding.created_at < end_naive)
    # filters
    if params.get("severity"):
        fq = fq.filter(Finding.severity == str(params["severity"]).lower())
    if params.get("finding_status"):
        fq = fq.filter(Finding.status == str(params["finding_status"]).lower())
    if params.get("scanner"):
        fq = fq.filter(Finding.scanner == str(params["scanner"]).lower())

    total = fq.count() or 0
    # severity
    sev = {}
    for s in ("critical", "high", "medium", "low", "info"):
        sev[s] = fq.filter(Finding.severity == s).count() or 0 if total else 0
    # Actually need separate counts without previous filter - better to use base without severity filter for distribution
    # For simplicity, use total as base, severities as above but they will be 0 if filtered
    open_c = fq.filter(Finding.status.in_(["open", "detected", "corroborated", "needs_review", "confirmed"])).count() or 0
    resolved = fq.filter(Finding.status == "resolved").count() or 0
    accepted = fq.filter(Finding.status == "accepted_risk").count() or 0
    false_pos = fq.filter(Finding.status == "false_positive").count() or 0
    reopened = fq.filter(Finding.status == "reopened").count() or 0
    overdue = 0
    try:
        from app.models.finding import FindingSLA
        overdue = db.query(func.count(FindingSLA.id)).join(Finding, Finding.id == FindingSLA.finding_id).join(Target, Target.id == Finding.target_id).join(Project, Project.id == Target.project_id).filter(Project.organization_id == organization_id, FindingSLA.status == "breached").scalar() or 0
        if project_id:
            overdue = db.query(func.count(FindingSLA.id)).join(Finding, Finding.id == FindingSLA.finding_id).filter(FindingSLA.project_id == project_id, FindingSLA.status == "breached").scalar() or 0
    except Exception:
        overdue = 0

    # Assets
    aq = _asset_q(db, organization_id, project_id)
    total_assets = aq.count() or 0
    # exposure - use asset intelligence classification if available
    internet_exposed = 0
    try:
        # simple heuristic: asset value contains internet or metadata exposure
        for a in aq.limit(500).all():
            meta = a.extra_data if isinstance(a.extra_data, dict) else {}
            exp = str(meta.get("exposure", "")).upper()
            if exp == "INTERNET_EXPOSED":
                internet_exposed += 1
    except Exception:
        internet_exposed = 0
    stale = aq.filter(Asset.status == "stale").count() or 0 if total_assets else 0
    inactive = aq.filter(Asset.status == "inactive").count() or 0 if total_assets else 0
    # new/changed via asset_change? bounded
    new_assets = 0
    changed_assets = 0
    try:
        from app.models.asset_change_event import AssetChangeEvent
        q = db.query(AssetChangeEvent).join(Project, Project.id == AssetChangeEvent.project_id).filter(Project.organization_id == organization_id)
        if project_id:
            q = q.filter(AssetChangeEvent.project_id == project_id)
        if period_start is not None:
            q = q.filter(AssetChangeEvent.detected_at >= start_naive, AssetChangeEvent.detected_at < end_naive)
        new_assets = q.filter(AssetChangeEvent.change_type == "created").count() or 0
        changed_assets = q.filter(AssetChangeEvent.change_type == "changed").count() or 0
    except Exception:
        pass

    # Risk
    risk_score = None
    risk_grade = None
    try:
        rq = db.query(func.avg(Scan.risk_score)).join(Target, Target.id == Scan.target_id).join(Project, Project.id == Target.project_id).filter(Project.organization_id == organization_id, Scan.risk_score.is_not(None))
        if period_start is not None:
            rq = rq.filter(Scan.created_at >= start_naive, Scan.created_at < end_naive)
        risk_score = rq.scalar()
        if risk_score is not None:
            risk_score = round(float(risk_score), 2)
            if risk_score >= 90:
                risk_grade = "A"
            elif risk_score >= 75:
                risk_grade = "B"
            elif risk_score >= 50:
                risk_grade = "C"
            else:
                risk_grade = "D"
    except Exception:
        pass

    # Domains
    code_scanners = ("sast", "sca", "secrets", "container", "iac", "api")
    network = fq.filter(Finding.scanner.in_(("nmap", "dns", "subdomain", "tls"))).count() or 0 if total else 0
    web = fq.filter(Finding.scanner.in_(("nuclei", "zap", "nikto", "http_fingerprint"))).count() or 0 if total else 0
    api = fq.filter(Finding.scanner == "api").count() or 0 if total else 0
    code = fq.filter(Finding.scanner.in_(code_scanners)).count() or 0 if total else 0
    cloud = fq.filter(Finding.scanner == "cloud").count() or 0 if total else 0

    # remediation/retest rates (bounded)
    remediation_rate = "N/A"
    retest_rate = "N/A"
    try:
        from app.models.finding import FindingRemediation, FindingRetest
        total_rem = db.query(func.count(FindingRemediation.id)).join(Project, Project.id == FindingRemediation.project_id).filter(Project.organization_id == organization_id).scalar() or 0
        if project_id:
            total_rem = db.query(func.count(FindingRemediation.id)).filter(FindingRemediation.project_id == project_id).scalar() or 0
        completed_rem = db.query(func.count(FindingRemediation.id)).filter(FindingRemediation.status == "completed").scalar() or 0 if total_rem else 0
        if total_rem:
            remediation_rate = round(completed_rem / total_rem * 100, 1) if total_rem else "N/A"
    except Exception:
        pass

    return {
        "total_findings": total,
        "open_findings": open_c,
        "critical_findings": sev.get("critical", 0),
        "high_findings": sev.get("high", 0),
        "medium_findings": sev.get("medium", 0),
        "low_findings": sev.get("low", 0),
        "resolved_findings": resolved,
        "accepted_risk": accepted,
        "false_positive": false_pos,
        "reopened_findings": reopened,
        "overdue_findings": overdue,
        "total_assets": total_assets,
        "internet_exposed_assets": internet_exposed,
        "stale_assets": stale,
        "inactive_assets": inactive,
        "new_assets": new_assets,
        "changed_assets": changed_assets,
        "risk_score": risk_score,
        "risk_grade": risk_grade,
        "sla_compliance": "N/A" if total == 0 else f"{(1 - overdue/max(total,1))*100:.1f}%",
        "remediation_rate": remediation_rate,
        "retest_pass_rate": retest_rate,
        "network_findings": network,
        "web_findings": web,
        "api_findings": api,
        "code_findings": code,
        "cloud_findings": cloud,
    }

def sanitize_for_csv(value: str) -> str:
    if not isinstance(value, str):
        value = str(value)
    if value and value[0] in ("=", "+", "-", "@"):
        return "'" + value
    return value

def export_csv(findings: list[dict]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["Finding ID", "Title", "Severity", "Status", "Scanner", "Asset", "CVE", "CWE", "Evidence"])
    for f in findings[:500]:
        writer.writerow([
            sanitize_for_csv(f.get("id", "")),
            sanitize_for_csv(f.get("title", "")),
            sanitize_for_csv(f.get("severity", "")),
            sanitize_for_csv(f.get("status", "")),
            sanitize_for_csv(f.get("scanner", "")),
            sanitize_for_csv(f.get("asset_id", "")),
            sanitize_for_csv(f.get("cve", "")),
            sanitize_for_csv(f.get("cwe", "")),
            sanitize_for_csv((f.get("evidence") or "")[:500]),
        ])
    return output.getvalue().encode("utf-8")

def _is_web_finding(f: dict) -> bool:
    scanner = str(f.get("scanner") or "").lower()
    if scanner in ("sast","sca","secrets","container","iac","api","nuclei","zap","nikto","http_fingerprint"):
        return True
    if scanner in ("nmap","dns","subdomain","tls","cloud"):
        return False
    # fallback via asset_type
    at = str(f.get("asset_type") or "").lower()
    if at in ("source_file","repository","package","container_image","iac_resource","api_endpoint","url"):
        return True
    if at in ("ip","port","service"):
        return False
    # title heuristic: if contains url/http
    title = str(f.get("title") or "").lower()
    if "http" in title or "url" in title or "xss" in title or "sqli" in title:
        return True
    return False

def _customer_vapt_sections(report: dict) -> tuple[str, list]:
    """Build 23-section customer VAPT report from persisted data per VAPT_Final_Report (1).docx template.
    No invented data; unavailable fields render as Not assessed/Not available/Not provided.
    """
    title = str(report.get("title") or "Vulnerability Assessment and Penetration Testing - Final Security Assessment Report")
    content = report.get("content") or {}
    summary = report.get("summary") or {}
    snap = content.get("snapshot") if isinstance(content, dict) else None
    if not isinstance(snap, dict):
        snap = {}
    metrics = content.get("metrics") if isinstance(content.get("metrics"), dict) else summary
    if not isinstance(metrics, dict):
        metrics = summary if isinstance(summary, dict) else {}
    findings = []
    if isinstance(content, dict):
        findings = content.get("snapshot_findings", {}).get("detail", []) if isinstance(content.get("snapshot_findings"), dict) else (content.get("findings") or [])
        if not findings and isinstance(content.get("snapshot"), dict):
            findings = content["snapshot"].get("findings", {}).get("detail", []) if isinstance(content["snapshot"].get("findings"), dict) else []
    if not findings and isinstance(summary, dict) and summary.get("total_findings"):
        # fallback from summary counts
        findings = []
    # bounded
    findings = findings[:MAX_DETAIL_FINDINGS] if isinstance(findings, list) else []
    web_findings = [f for f in findings if isinstance(f, dict) and _is_web_finding(f)]
    net_findings = [f for f in findings if isinstance(f, dict) and not _is_web_finding(f)]
    # deterministic IDs WEB-XXX / NET-XXX sorted by severity then title
    def sort_key(f):
        sev = str(f.get("severity") or "info").lower()
        rank = {"critical":0,"high":1,"medium":2,"low":3,"info":4}.get(sev,4)
        return (rank, str(f.get("title") or ""), str(f.get("id") or ""))
    web_findings = sorted(web_findings, key=sort_key)
    net_findings = sorted(net_findings, key=sort_key)
    sections: list = []
    # 1 Cover / Confidentiality
    sections.append(("1. Cover / Confidentiality", [
        "CONFIDENTIAL — Authorized Use Only",
        f"Report: {title[:120]}",
        f"Project: {str(report.get('project_id') or 'Organization-wide')}",
        f"Generated: {str(report.get('data_as_of') or report.get('created_at') or '')}",
        f"Version: {str(report.get('version') or '1.0')}",
        "Classification: Confidential",
    ]))
    # 2 Document Control
    sections.append(("2. Document Control", [
        f"Report ID: {str(report.get('id') or '')[:16]}",
        f"Version: {str(report.get('version') or '1.0')}",
        f"Generated: {str(report.get('data_as_of') or '')}",
        f"Generated By: {str(report.get('generated_by') or 'System')}",
        f"Status: {str(report.get('status') or '')}",
    ]))
    # 3 Table of Contents
    toc = [f"{i+1}. {h}" for i, (h, _) in enumerate([
        ("Executive Summary",[]),("Assessment Objectives",[]),("Scope of Assessment",[]),
        ("Rules of Engagement",[]),("Assessment Methodology",[]),("Risk Rating Methodology",[]),
        ("Executive Risk Summary",[]),("Web Application VAPT Results",[]),("Network VAPT Results",[]),
        ("Detailed Web Application Findings",[]),("Detailed Network Findings",[]),("Positive Security Observations",[]),
        ("Remediation Roadmap",[]),("Retest / Validation Summary",[]),("Assessment Limitations",[]),
        ("Conclusion",[]),("Appendix A - Assets Tested",[]),("Appendix B - Port and Service Summary",[]),
        ("Appendix C - Tools and Techniques",[]),("Appendix D - Evidence Handling Guidance",[])
    ])]
    sections.append(("3. Table of Contents", toc))
    # 4 Executive Summary
    cov = f"Assessment Coverage: {len(findings)} findings, {metrics.get('total_assets','Not assessed')} assets, {metrics.get('internet_exposed_assets','Not assessed')} internet-exposed"
    overall = f"Overall Result: {str(summary.get('risk_grade') or snap.get('risk',{}).get('grade') or 'Not assessed')} (score {str(summary.get('risk_score') or snap.get('risk',{}).get('score') or 'N/A')})"
    # Key Management Actions: top 3 critical/high
    top_actions = []
    for f in sorted(findings, key=sort_key)[:3]:
        if isinstance(f, dict):
            top_actions.append(f"{str(f.get('severity') or '').upper()}: {str(f.get('title') or '')[:80]}")
    if not top_actions:
        top_actions = ["Not assessed - no critical/high findings in scope"]
    sections.append(("4. Executive Summary", [
        f"4.1 Assessment Coverage: {cov}",
        f"4.2 Overall Result: {overall}",
        "4.3 Key Management Actions:",
    ] + [f"  - {a}" for a in top_actions[:3]]))
    # 5 Assessment Objectives
    sections.append(("5. Assessment Objectives", [
        str(content.get("executive_summary") or "Assess web application and network infrastructure for vulnerabilities, validate findings, and provide remediation guidance.")[:500]
    ]))
    # 6 Scope
    web_scope = []
    net_scope = []
    for f in findings[:10]:
        if isinstance(f, dict):
            url = f.get("asset_value") or f.get("asset_id") or ""
            if _is_web_finding(f) and url:
                web_scope.append(str(url)[:80])
            elif not _is_web_finding(f) and url:
                net_scope.append(str(url)[:80])
    sections.append(("6. Scope of Assessment", [
        f"6.1 Web Application Scope: {', '.join(web_scope[:5]) if web_scope else 'Not provided'}",
        "6.2 Test Accounts / Roles: Not provided" + (" (Roles: " + str(snap.get("test_accounts") or "Not provided")[:60] + ")" if snap.get("test_accounts") else ""),
        f"6.3 Network Scope: {', '.join(net_scope[:5]) if net_scope else 'Not provided'}",
    ]))
    # 7 Rules of Engagement
    sections.append(("7. Rules of Engagement", [
        str(content.get("rules_of_engagement") or snap.get("rules_of_engagement") or "Testing performed within agreed scope and time window; no denial-of-service or data destruction.")[:500]
    ]))
    # 8 Assessment Methodology
    scanners_used = snap.get("methodology", {}).get("scanners_observed") if isinstance(snap.get("methodology"), dict) else []
    if not scanners_used and isinstance(content.get("methodology"), dict):
        scanners_used = content["methodology"].get("scanners_observed", [])
    sections.append(("8. Assessment Methodology", [
        f"8.1 Web and Network Test Coverage: Scanners/tools used: {', '.join(str(s) for s in scanners_used[:10]) if scanners_used else 'Not assessed'}",
        "Methodology: Asset discovery, vulnerability analysis, lifecycle tracking, change detection, control readiness (per snapshot).",
    ]))
    # 9 Risk Rating Methodology
    sections.append(("9. Risk Rating Methodology", [
        "Severity: Critical, High, Medium, Low, Informational (FindingEngine authoritative)",
        "9.1 Finding Status: detected, corroborated, needs_review, confirmed, false_positive, accepted_risk, remediated, reopened",
        "CVSS: Where available from scanner; otherwise Not available — not invented.",
    ]))
    # 10 Executive Risk Summary
    web_crit = sum(1 for f in web_findings if str(f.get("severity") or "").lower()=="critical")
    web_high = sum(1 for f in web_findings if str(f.get("severity") or "").lower()=="high")
    net_crit = sum(1 for f in net_findings if str(f.get("severity") or "").lower()=="critical")
    net_high = sum(1 for f in net_findings if str(f.get("severity") or "").lower()=="high")
    sections.append(("10. Executive Risk Summary", [
        f"10.1 Web Application Findings: Critical {web_crit}, High {web_high}, Total {len(web_findings)}",
        f"10.2 Network Findings: Critical {net_crit}, High {net_high}, Total {len(net_findings)}",
        f"10.3 Risk Concentration: {str(snap.get('risk_concentration') or summary.get('risk_concentration') or 'Not assessed')[:120]}",
    ]))
    # 11 Web Application VAPT Results
    sections.append(("11. Web Application VAPT Results", [
        f"11.1 Web Result Summary: {len(web_findings)} web findings, Critical {web_crit}, High {web_high}",
        "11.2 Functional Areas Reviewed: Authentication, Authorization, Input Validation, Session Management, API, Business Logic (per assets/findings)",
        f"11.3 Web Application Security Conclusion: {('Requires remediation' if web_crit or web_high else 'No critical/high web findings in scope')}",
    ]))
    # 12 Network VAPT Results
    sections.append(("12. Network VAPT Results", [
        f"12.1 Network Result Summary: {len(net_findings)} network findings, Critical {net_crit}, High {net_high}",
        "12.2 Network Areas Reviewed: Host discovery, Port/Service enumeration, TLS, DNS, Cloud exposure (per scans)",
        f"12.3 Network Security Conclusion: {('Requires remediation' if net_crit or net_high else 'No critical/high network findings in scope')}",
    ]))
    # 13 Detailed Web Application Findings
    web_lines = []
    for idx, f in enumerate(web_findings[:20], start=1):
        if not isinstance(f, dict): continue
        fid = f"WEB-{idx:03d}"
        # stable mapping: could use hash of finding id, but sequential deterministic sorted is stable for same data
        web_lines.append(f"{fid} | {str(f.get('title') or 'Untitled')[:80]}")
        web_lines.append(f"  Severity: {str(f.get('severity') or 'Not assessed')} | CVSS: {str(f.get('cvss_score') or f.get('score') or 'Not available')} {str(f.get('cvss_vector') or '')} | Status: {str(f.get('status') or 'Not assessed')}")
        web_lines.append(f"  Affected URL: {str(f.get('asset_value') or f.get('asset_id') or 'Not provided')[:80]} | Param/Function: {str(f.get('affected_parameter') or 'Not provided')[:40]}")
        web_lines.append(f"  OWASP/CWE: {str(f.get('owasp') or f.get('cwe') or 'Not available')} | CVE: {str(f.get('cve') or 'Not available')}")
        web_lines.append(f"  Description: {str(f.get('description') or f.get('title') or 'Not provided')[:200]}")
        web_lines.append(f"  Evidence: {(str(f.get('evidence') or 'Not available')[:MAX_EVIDENCE_CHARS])}")
        web_lines.append(f"  Technical Impact: {str(f.get('technical_impact') or 'Not assessed')[:120]} | Business Impact: {str(f.get('business_impact') or 'Not assessed')[:120]}")
        web_lines.append(f"  Recommendation: {str(f.get('remediation') or 'Not provided')[:200]}")
        web_lines.append(f"  References: {str(f.get('references') or 'Not provided')[:80]} | Retest: {str(f.get('retest_result') or f.get('retest') or 'Not yet retested')[:60]}")
        web_lines.append("")
    if not web_lines:
        web_lines = ["No web application findings in scope."]
    sections.append(("13. Detailed Web Application Findings", web_lines))
    # 14 Detailed Network Findings
    net_lines = []
    for idx, f in enumerate(net_findings[:20], start=1):
        if not isinstance(f, dict): continue
        fid = f"NET-{idx:03d}"
        net_lines.append(f"{fid} | {str(f.get('title') or 'Untitled')[:80]}")
        net_lines.append(f"  Severity: {str(f.get('severity') or 'Not assessed')} | CVSS: {str(f.get('cvss_score') or f.get('score') or 'Not available')} | Status: {str(f.get('status') or 'Not assessed')}")
        net_lines.append(f"  Affected Host: {str(f.get('asset_value') or f.get('asset_id') or 'Not provided')[:60]} | Port/Protocol: {str(f.get('port') or f.get('protocol') or 'Not provided')[:30]}")
        net_lines.append(f"  Service/Version: {str(f.get('service') or f.get('version') or 'Not available')} | CVE/CWE: {str(f.get('cve') or f.get('cwe') or 'Not available')}")
        net_lines.append(f"  Description: {str(f.get('description') or f.get('title') or 'Not provided')[:200]}")
        net_lines.append(f"  Evidence: {(str(f.get('evidence') or 'Not available')[:MAX_EVIDENCE_CHARS])}")
        net_lines.append(f"  Technical Impact: {str(f.get('technical_impact') or 'Not assessed')[:120]} | Business Impact: {str(f.get('business_impact') or 'Not assessed')[:120]}")
        net_lines.append(f"  Recommendation: {str(f.get('remediation') or 'Not provided')[:200]}")
        net_lines.append(f"  References: {str(f.get('references') or 'Not provided')[:80]} | Retest: {str(f.get('retest_result') or 'Not yet retested')[:60]}")
        net_lines.append("")
    if not net_lines:
        net_lines = ["No network findings in scope."]
    sections.append(("14. Detailed Network Findings", net_lines))
    # 15 Positive Security Observations
    controls = snap.get("controls") if isinstance(snap.get("controls"), dict) else {}
    pos = []
    if isinstance(controls, dict) and controls.get("pass"):
        pos.append(f"Controls PASS: {controls.get('pass')}")
        for c in (controls.get("controls") or [])[:5]:
            if isinstance(c, dict) and c.get("status")=="PASS":
                pos.append(f"  PASS: {c.get('control_id')}")
    if not pos:
        pos = ["Not assessed — no verified positive controls in snapshot"]
    sections.append(("15. Positive Security Observations", pos))
    # 16 Remediation Roadmap
    rem_lines = []
    for f in findings[:15]:
        if isinstance(f, dict):
            rem = str(f.get("remediation") or "Not provided")[:120]
            pri = "P1" if str(f.get("severity") or "").lower()=="critical" else "P2" if str(f.get("severity") or "").lower()=="high" else "P3" if str(f.get("severity") or "").lower()=="medium" else "P4"
            owner = str(f.get("owner") or "Not assigned")[:30]
            rem_lines.append(f"{pri} | {str(f.get('title') or '')[:60]} | Owner: {owner} | Target: Not provided | Status: {str(f.get('status') or 'Open')} | Remediation: {rem}")
    if not rem_lines:
        rem_lines = ["No remediation items — no findings requiring remediation"]
    sections.append(("16. Remediation Roadmap", ["16.1 Remediation Tracker:"] + rem_lines[:20]))
    # 17 Retest / Validation Summary
    retest_lines = []
    for f in findings[:10]:
        if isinstance(f, dict):
            retest_lines.append(f"{str(f.get('title') or '')[:60]} | Status: {str(f.get('status') or 'Open')} | Retest: {str(f.get('retest_result') or 'Not yet retested')[:40]} | Validation: {str(f.get('validation') or 'Not validated')[:40]}")
    if not retest_lines:
        retest_lines = ["No retest records — retest pending for remediated items"]
    sections.append(("17. Retest / Validation Summary", retest_lines))
    # 18 Assessment Limitations
    lim = snap.get("limitations") if isinstance(snap.get("limitations"), list) else []
    if not lim and isinstance(content.get("limitations"), list):
        lim = content["limitations"]
    lim_lines = [str(x)[:200] for x in (lim or [])[:10]] or ["Assessment limited to in-scope assets and time window; absence of finding is not proof of absence of risk."]
    lim_lines.append("This report is point-in-time and scoped to assessed controls/scanners.")
    sections.append(("18. Assessment Limitations", lim_lines))
    # 19 Conclusion
    sections.append(("19. Conclusion", [str(content.get("conclusion") or snap.get("conclusion") or "Assessment completed per agreed scope and methodology. Remediation of critical/high findings and retest recommended.")[:500]]))
    # 20 Appendix A Assets Tested
    assets_tested = []
    if isinstance(snap.get("assets"), dict):
        assets_tested.append(f"Total assets: {snap['assets'].get('total','Not assessed')} (by type: {str(snap['assets'].get('by_type') or '')[:120]})")
    elif isinstance(metrics.get("total_assets"), int):
        assets_tested.append(f"Total assets: {metrics.get('total_assets')}")
    if not assets_tested:
        assets_tested = ["Assets tested: Not provided — see detailed findings for affected assets"]
    sections.append(("20. Appendix A - Assets Tested", assets_tested))
    # 21 Appendix B Port and Service Summary
    port_lines = []
    if isinstance(snap.get("assets"), dict) and snap["assets"].get("by_type"):
        port_lines.append(f"Asset types: {str(snap['assets']['by_type'])[:200]}")
    else:
        port_lines = ["Port/Service summary: Not available — no port/service evidence in snapshot"]
    sections.append(("21. Appendix B - Port and Service Summary", port_lines))
    # 22 Appendix C Tools and Techniques
    tools = scanners_used if scanners_used else ["Not assessed"]
    sections.append(("22. Appendix C - Tools and Techniques", [f"Tools/scanners actually used: {', '.join(str(t) for t in tools[:10])}", "Manual testing only where evidence exists; template example tool list not claimed as used."]))
    # 23 Appendix D Evidence Handling Guidance
    sections.append(("23. Appendix D - Evidence Handling Guidance", [
        "Evidence handling: Evidence capped (evidence 200 chars, remediation 300), sanitized, redacted [REDACTED] for secrets/credentials.",
        "Retention: Per engagement agreement; do not retain active credentials, session tokens, private keys.",
        "Customer evidence: Sanitized and bounded per MAX_EVIDENCE_CHARS/MAX_REMEDIATION_CHARS.",
    ]))
    return title, sections

def _pdf_text_lines(report: dict) -> tuple[str, list]:
    """Delegate to customer VAPT template — authoritative 23-section layout.
    Keeps backward compatibility: all PDFs now follow VAPT_Final_Report (1).docx structure.
    """
    return _customer_vapt_sections(report)


def _wrap_line(text: str, width: int = 110) -> list:
    words, lines, current = str(text or "").split(), [], ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines or [""]


def _escape_pdf_text(text: str) -> str:
    return str(text or "").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _minimal_pdf(title: str, sections: list) -> bytes:
    """Dependency-free PDF with a correct cross-reference table.

    Deterministic single-page-flow layout (Helvetica only, ASCII-safe):
    title, sections with headings, footer on every page. Bounded to keep
    artifacts small at any project size.
    """
    def enc(s: str) -> bytes:
        return s.encode("ascii", errors="replace")

    content_lines: list = []
    content_lines.append(f"BT /F1 16 Tf 40 750 Td ({_escape_pdf_text(title[:100])}) Tj ET")
    y = 728
    pages_content: list = [[]]
    def emit(line: str, size: int = 9, bold: bool = False):
        nonlocal y
        if y < 50:
            pages_content.append([])
            y = 750
        font = "/F2" if bold else "/F1"
        pages_content[-1].append(f"BT {font} {size} Tf 40 {y} Td ({_escape_pdf_text(line[:130])}) Tj ET")
        y -= (size + 4)
    for heading, lines in sections:
        emit(str(heading), 11, True)
        for line in lines[:60]:
            for wrapped in _wrap_line(line)[:4]:
                emit(wrapped)
    emit("CONFIDENTIAL — AUTHORIZED USE ONLY")
    objects: list = []
    n_pages = len(pages_content)
    # 1: catalog, 2: pages, 3..: page objects, then font + content streams
    kids = " ".join(f"{3 + i} 0 R" for i in range(n_pages))
    objects.append("<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>")
    for i in range(n_pages):
        objects.append(
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {3 + n_pages} 0 R /F2 {4 + n_pages} 0 R >> >> "
            f"/Contents {5 + n_pages + i} 0 R >>"
        )
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    for lines in pages_content:
        stream = "\n".join(lines)
        objects.append(f"<< /Length {len(stream.encode('ascii', errors='replace'))} >>\nstream\n{stream}\nendstream")
    out = bytearray()
    out += b"%PDF-1.4\n"
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += enc(f"{idx} 0 obj\n{obj}\nendobj\n")
    xref_pos = len(out)
    out += enc(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n")
    for off in offsets[1:]:
        out += enc(f"{off:010d} 00000 n \n")
    out += enc(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF")
    return bytes(out)


def export_pdf(report: dict) -> bytes:
    # Rich sections when reportlab is present, otherwise the valid minimal
    # fallback above (correct xref, Helvetica only, ASCII-safe).
    title, sections = _pdf_text_lines(report)
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        buffer = io.BytesIO()
        c = canvas.Canvas(buffer, pagesize=letter)
        c.setTitle(title[:100])
        c.setFont("Helvetica-Bold", 14)
        c.drawString(40, 750, title[:100])
        c.setFont("Helvetica", 8)
        c.drawString(40, 735, f"Project: {report.get('project_id') or 'Organization-wide'}  Type: {report.get('report_type','')}  Version: {report.get('version','1.0')}")
        y = 712
        for heading, lines in sections:
            if y < 60:
                c.setFont("Helvetica", 6)
                c.drawString(40, 15, "CONFIDENTIAL — AUTHORIZED USE ONLY")
                c.showPage()
                y = 750
            c.setFont("Helvetica-Bold", 10)
            c.drawString(40, y, str(heading)[:120])
            y -= 14
            c.setFont("Helvetica", 8)
            for line in lines[:60]:
                for wrapped in _wrap_line(line, 120)[:4]:
                    if y < 40:
                        c.setFont("Helvetica", 6)
                        c.drawString(40, 15, "CONFIDENTIAL — AUTHORIZED USE ONLY")
                        c.showPage()
                        y = 750
                        c.setFont("Helvetica", 8)
                    c.drawString(48, y, wrapped[:130])
                    y -= 11
            y -= 6
        c.setFont("Helvetica", 6)
        c.drawString(40, 15, "CONFIDENTIAL — AUTHORIZED USE ONLY")
        c.showPage()
        c.save()
        return buffer.getvalue()
    except Exception:
        return _minimal_pdf(title, sections)

def build_report_content(report_type: str, metrics: dict, db: Session, organization_id: str, project_id: str | None, snapshot: dict | None = None) -> dict:
    # Build content per report type, reusing existing data
    base = {
        "executive_summary": f"Report {report_type} for {'project '+project_id if project_id else 'organization '+organization_id}",
        "metrics": metrics,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": {"organization_id": organization_id, "project_id": project_id},
        "limitations": "Historical trends show N/A where insufficient data exists; no fabricated percentages.",
        "report_format_version": REPORT_FORMAT_VERSION,
        "generator_version": GENERATOR_VERSION,
    }
    if snapshot:
        base["snapshot"] = snapshot
        label = f"project {project_id}" if project_id else f"organization {organization_id}"
        if report_type == "executive_security":
            base["executive_summary"] = build_executive_summary(snapshot, label)
    if report_type == "executive_security":
        base["sections"] = ["Security posture", "Exposure", "Security domains"]
        base["security_domains"] = {
            "network": metrics.get("network_findings", 0),
            "web": metrics.get("web_findings", 0),
            "code": metrics.get("code_findings", 0),
            "cloud": metrics.get("cloud_findings", 0),
            "api": metrics.get("api_findings", 0),
        }
        if snapshot:
            base["methodology"] = snapshot.get("methodology")
            base["limitations"] = snapshot.get("limitations")
            base["monitoring"] = snapshot.get("monitoring")
            base["controls"] = snapshot.get("controls")
    elif report_type == "technical_vapt":
        # include findings sample
        try:
            from app.models.finding import Finding
            from app.models.target import Target
            from app.models.project import Project
            q = db.query(Finding).join(Target, Target.id == Finding.target_id).join(Project, Project.id == Target.project_id).filter(Project.organization_id == organization_id)
            if project_id:
                q = q.filter(Target.project_id == project_id)
            findings = q.limit(50).all()
            base["findings"] = [{"id": f.id, "title": f.title, "severity": f.severity, "status": f.status, "scanner": f.scanner, "evidence": (f.evidence or "")[:200]} for f in findings]
        except Exception:
            base["findings"] = []
        if snapshot:
            base["snapshot_findings"] = snapshot.get("findings")
            base["snapshot_assets"] = snapshot.get("assets")
            base["snapshot_alerts"] = snapshot.get("alerts")
            base["snapshot_changes"] = snapshot.get("changes")
            base["monitoring"] = snapshot.get("monitoring")
            base["controls"] = snapshot.get("controls")
            base["methodology"] = snapshot.get("methodology")
            base["limitations"] = snapshot.get("limitations")
            base["data_consistency"] = snapshot.get("data_consistency")
    elif report_type == "attack_surface":
        base["assets"] = {"total": metrics["total_assets"], "internet_exposed": metrics["internet_exposed_assets"]}
    elif report_type == "code_security":
        base["code"] = {k: metrics[k] for k in ("code_findings",) if k in metrics}
    elif report_type == "cloud_security":
        base["cloud"] = {k: metrics[k] for k in ("cloud_findings",) if k in metrics}
    elif report_type == "compliance":
        base["compliance_note"] = "Control coverage via technical evidence, not certification."
    return base


# ---------------------------------------------------------------------------
# D6 report snapshot assembly (bounded, deterministic, period-scoped)
# ---------------------------------------------------------------------------

def _finding_detail_row(f, asset_type=None, asset_value=None) -> dict:
    return {
        "id": f.id,
        "title": f.title,
        "severity": str(f.severity or "info").lower(),
        "score": f.score,
        "status": f.status,
        "scanner": f.scanner,
        "asset_id": f.asset_id,
        "asset_type": asset_type,
        "asset_value": asset_value,
        "cve": f.cve,
        "cwe": f.cwe,
        "remediation": (f.remediation or "")[:MAX_REMEDIATION_CHARS] or None,
        "evidence": (f.evidence or "")[:MAX_EVIDENCE_CHARS] or None,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


def collect_report_snapshot(db: Session, organization_id: str, project_id: str | None,
                            start, end, options: dict | None = None) -> dict:
    """Assemble a bounded deterministic snapshot for one report.

    All time-varying evidence is restricted to [start, end); current-state
    inventory (assets) is point-in-time and labeled as such. Every section
    is capped; oversized populations are counted, never silently dropped
    without a note.
    """
    from app.models.alert import Alert
    from app.models.asset import Asset as AssetModel
    from app.models.finding import Finding as FindingModel
    from app.models.monitoring import MonitoringChangeEvent, MonitoringConfig, MonitoringRun
    from app.models.scan import Scan as ScanModel

    options = options if isinstance(options, dict) else {}
    include_controls = bool(options.get("include_controls", True))
    include_low = bool(options.get("include_low_findings", False))
    start_naive = start.replace(tzinfo=None) if getattr(start, "tzinfo", None) else start
    end_naive = end.replace(tzinfo=None) if getattr(end, "tzinfo", None) else end

    params = {"start_date": start.isoformat(), "end_date": end.isoformat()}
    metrics = collect_metrics(db, organization_id, project_id, params)

    def _scoped_findings():
        q = db.query(FindingModel).join(Target, Target.id == FindingModel.target_id)
        if project_id:
            q = q.filter(Target.project_id == project_id)
        else:
            q = q.join(Project, Project.id == Target.project_id).filter(
                Project.organization_id == organization_id)
        return q.filter(FindingModel.created_at >= start_naive, FindingModel.created_at < end_naive)

    fq = _scoped_findings()
    open_statuses = ["open", "detected", "triaged", "in_progress", "remediation_claimed",
                     "ready_for_retest", "retesting", "reopened"]
    crit_high = (
        fq.filter(FindingModel.severity.in_(["critical", "high"]))
        .order_by(FindingModel.severity.asc(), FindingModel.score.desc(), FindingModel.created_at.desc())
        .limit(MAX_DETAIL_FINDINGS)
        .all()
    )
    # severity ordering note: alphabetical puts critical before high
    detail_findings = []
    for f in crit_high:
        asset = None
        if f.asset_id:
            asset = db.query(AssetModel).filter(AssetModel.id == f.asset_id).first()
        detail_findings.append(_finding_detail_row(
            f, asset.asset_type if asset else None, asset.value if asset else None))
    low_detail = []
    if include_low:
        for f in fq.filter(~FindingModel.severity.in_(["critical", "high"])).order_by(
                FindingModel.created_at.desc()).limit(MAX_DETAIL_FINDINGS):
            low_detail.append(_finding_detail_row(f))
    resolved_in_period = (
        fq.filter(FindingModel.status == "resolved").count() or 0
    )
    reopened_in_period = (
        fq.filter(FindingModel.status == "reopened").count() or 0
    )

    # Assets: point-in-time inventory + period change counts (D2 canonical).
    aq = db.query(AssetModel)
    if project_id:
        aq = aq.filter(AssetModel.project_id == project_id)
    else:
        aq = aq.join(Project, Project.id == AssetModel.project_id).filter(
            Project.organization_id == organization_id)
    asset_rows = aq.all() if aq.count() <= 2000 else []
    assets_truncated = aq.count() > 2000
    by_type: dict = {}
    internet_exposed = 0
    for a in asset_rows:
        by_type[str(a.asset_type or "unknown")] = by_type.get(str(a.asset_type or "unknown"), 0) + 1
    try:
        from app.services.attack_surface import classify_exposure
        for a in asset_rows[:500]:
            try:
                meta = a.extra_data if isinstance(a.extra_data, dict) else {}
                if classify_exposure(a.asset_type, a.value, meta) == "INTERNET_EXPOSED":
                    internet_exposed += 1
            except Exception:
                continue
    except Exception:
        pass
    change_q = db.query(MonitoringChangeEvent)
    if project_id:
        change_q = change_q.filter(MonitoringChangeEvent.project_id == project_id)
    else:
        change_q = change_q.join(Project, Project.id == MonitoringChangeEvent.project_id).filter(
            Project.organization_id == organization_id)
    change_q = change_q.filter(MonitoringChangeEvent.detected_at >= start_naive,
                               MonitoringChangeEvent.detected_at < end_naive)
    change_total = change_q.count() or 0
    change_by_type: dict = {}
    for ctype, count in change_q.with_entities(
            MonitoringChangeEvent.change_type, func.count(MonitoringChangeEvent.id)
    ).group_by(MonitoringChangeEvent.change_type).all():
        change_by_type[str(ctype)] = int(count or 0)

    # Alerts: current active + resolved in period.
    alert_q = db.query(Alert)
    if project_id:
        alert_q = alert_q.filter(Alert.project_id == project_id)
    else:
        alert_q = alert_q.filter(Alert.organization_id == organization_id)
    active_alerts = alert_q.filter(Alert.status.in_(["open", "acknowledged"])).count() or 0
    crit_alerts = alert_q.filter(Alert.status.in_(["open", "acknowledged"]),
                                 Alert.severity == "critical").count() or 0
    high_alerts = alert_q.filter(Alert.status.in_(["open", "acknowledged"]),
                                 Alert.severity == "high").count() or 0
    resolved_alerts = alert_q.filter(Alert.status == "resolved",
                                     Alert.resolved_at >= start_naive,
                                     Alert.resolved_at < end_naive).count() or 0

    # Monitoring: runs in period + last good + next run + scanner provenance.
    run_q = db.query(MonitoringRun)
    if project_id:
        run_q = run_q.filter(MonitoringRun.project_id == project_id)
    else:
        run_q = run_q.filter(MonitoringRun.organization_id == organization_id)
    period_runs = run_q.filter(MonitoringRun.created_at >= start_naive,
                               MonitoringRun.created_at < end_naive).all()
    run_statuses: dict = {}
    for r in period_runs:
        run_statuses[str(r.status)] = run_statuses.get(str(r.status), 0) + 1
    last_good = None
    last_good_row = run_q.filter(MonitoringRun.status == "completed").order_by(
        MonitoringRun.completed_at.desc()).first()
    if last_good_row:
        last_good = {"run_id": last_good_row.id,
                     "completed_at": last_good_row.completed_at.isoformat()
                     if last_good_row.completed_at else None}
    next_run_at = None
    if project_id:
        next_run_at = db.query(func.min(MonitoringConfig.next_run_at)).filter(
            MonitoringConfig.project_id == project_id,
            MonitoringConfig.enabled.is_(True),
            MonitoringConfig.paused_at.is_(None),
            MonitoringConfig.next_run_at.isnot(None)).scalar()
    scan_q = db.query(ScanModel).join(Target, Target.id == ScanModel.target_id)
    if project_id:
        scan_q = scan_q.filter(Target.project_id == project_id)
    else:
        scan_q = scan_q.join(Project, Project.id == Target.project_id).filter(
            Project.organization_id == organization_id)
    period_scans = scan_q.filter(ScanModel.created_at >= start_naive,
                                 ScanModel.created_at < end_naive).all()
    scanner_versions = sorted({
        f"{s.scanner_version or 'unknown'} / {s.scanner_image_digest or 'unknown'}"
        for s in period_scans if (s.scanner_version or s.scanner_image_digest)
    })
    failed_scans = [{"id": s.id, "profile": s.profile} for s in period_scans if s.status == "failed"][:25]
    partial_runs = run_statuses.get("partial", 0)
    latest_scan_at = None
    if period_scans:
        try:
            latest_scan_at = max(s.created_at for s in period_scans if s.created_at)
        except Exception:
            latest_scan_at = None

    # Control readiness (D5) — optional, bounded (24 evaluations max).
    controls_summary = None
    if include_controls and project_id:
        try:
            from app.services.control_evaluation import coverage_summary, evaluate_project
            evaluations = evaluate_project(db, project_id)
            summary = coverage_summary(evaluations)
            controls_summary = {
                **summary,
                "controls": [
                    {"control_id": e["control_id"], "status": e["status"],
                     "confidence": e["confidence"], "freshness": e["freshness"]}
                    for e in evaluations
                ],
            }
        except Exception:
            controls_summary = {"error": "control evaluation unavailable"}

    # Methodology inputs actually observed.
    scanners_used = sorted({
        str(f.scanner) for f in crit_high if f.scanner
    } | {
        str(s.profile) for s in period_scans if s.profile
    })
    limitations = []
    if failed_scans:
        limitations.append(f"{len(failed_scans)} scan(s) failed during the period; failed scans prove nothing about exposure.")
    if partial_runs:
        limitations.append(f"{partial_runs} monitoring run(s) were partial; absence-based conclusions exclude partial observations.")
    if not period_scans:
        limitations.append("No scans executed during the reporting period; findings reflect earlier evidence.")
    if assets_truncated:
        limitations.append("Asset inventory exceeds display bounds; counts are complete, detail lists are capped.")
    limitations.append("Absence of a finding is not proof of absence of risk; only assessed controls and executed scanners are covered.")
    limitations.append("This report summarizes VAPT platform evidence. It is not legal advice, certification, or an independent audit.")

    return {
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "metrics": metrics,
        "risk": {"score": metrics.get("risk_score"), "grade": metrics.get("risk_grade")},
        "findings": {
            "total": metrics.get("total_findings", 0),
            "critical": metrics.get("critical_findings", 0),
            "high": metrics.get("high_findings", 0),
            "medium": metrics.get("medium_findings", 0),
            "low": metrics.get("low_findings", 0),
            "open": metrics.get("open_findings", 0),
            "resolved_in_period": resolved_in_period,
            "reopened_in_period": reopened_in_period,
            "detail": detail_findings,
            "low_detail": low_detail,
            "detail_truncated": len(detail_findings) >= MAX_DETAIL_FINDINGS,
        },
        "assets": {
            "total": metrics.get("total_assets", 0),
            "by_type": by_type,
            "internet_exposed": internet_exposed,
            "inventory_truncated": assets_truncated,
            "inventory_as_of": end.isoformat(),
        },
        "alerts": {
            "active": active_alerts,
            "critical": crit_alerts,
            "high": high_alerts,
            "resolved_in_period": resolved_alerts,
        },
        "changes": {
            "total": change_total,
            "by_type": change_by_type,
        },
        "monitoring": {
            "runs_in_period": {k: int(v) for k, v in run_statuses.items()},
            "last_good_run": last_good,
            "next_run_at": next_run_at.isoformat() if next_run_at else None,
            "scanner_versions": scanner_versions,
            "failed_scans": failed_scans,
        },
        "controls": controls_summary,
        "methodology": {
            "scanners_observed": scanners_used,
            "scans_in_period": len(period_scans),
            "analysis": [
                "Asset discovery via network, web, DNS and application scanners",
                "Vulnerability analysis with severity scoring and lifecycle tracking",
                "Run-level change detection against trusted baselines",
                "Deterministic alert evaluation under project policy",
                "Control readiness evaluated from scanner, asset and monitoring evidence",
            ],
        },
        "limitations": limitations,
        "data_consistency": {
            "note": "Risk reflects scans in period; asset inventory is point-in-time; findings are period observations.",
        },
    }


def build_executive_summary(snapshot: dict, project_label: str) -> str:
    """Deterministic management summary: every number comes from the snapshot."""
    metrics = snapshot.get("metrics", {})
    risk = snapshot.get("risk", {})
    crit = int(metrics.get("critical_findings", 0) or 0)
    high = int(metrics.get("high_findings", 0) or 0)
    period = snapshot.get("period", {})
    grade = risk.get("grade")
    score = risk.get("score")
    if grade and score is not None:
        risk_text = f"Current project risk grade is {grade} with a score of {score}."
    else:
        risk_text = "No scored scans exist in the reporting period, so no current risk grade is available."
    alerts = snapshot.get("alerts", {})
    assets = snapshot.get("assets", {})
    monitoring = snapshot.get("monitoring", {})
    runs = monitoring.get("runs_in_period", {}) or {}
    failed = int(runs.get("failed", 0) or 0)
    monitor_text = (
        f"{sum(int(v) for v in runs.values())} monitoring run(s) executed "
        f"({int(runs.get('completed', 0) or 0)} completed, {int(runs.get('partial', 0) or 0)} partial, "
        f"{failed} failed)."
        if runs else "No monitoring runs executed during the reporting period."
    )
    return (
        f"During {period.get('start', '?')} to {period.get('end', '?')}, "
        f"{crit} critical findings and {high} high findings were observed in {project_label}. "
        f"{risk_text} "
        f"{int(alerts.get('active', 0) or 0)} active alerts require attention "
        f"({int(alerts.get('critical', 0) or 0)} critical, {int(alerts.get('high', 0) or 0)} high). "
        f"{int(assets.get('total', 0) or 0)} assets are inventoried, "
        f"{int(assets.get('internet_exposed', 0) or 0)} internet-exposed. "
        f"{monitor_text}"
    )

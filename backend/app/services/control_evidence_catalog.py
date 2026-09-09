"""D5 evidence-backed control catalog + deterministic evaluation.

This extends (never replaces) the demo catalog in ``compliance_service``:
a versioned ``vapt_control_readiness`` framework whose controls carry
machine-readable evidence rules. Rules live in code (immutable per
version); the database holds only display rows seeded idempotently.

Design rules (documented, deterministic, no LLM):
- Identity: findings by scanner (+ narrow title keywords where a scanner
  family spans categories); assets by canonical type; scans by scanner.
- Negative evidence (open critical/high matches) -> FAIL; open
  medium/low/info only -> PARTIAL; accepted-risk-only matches -> PARTIAL
  (existing risk acceptance stays authoritative, never auto-PASS).
- Positive evidence (a completed scan by a mapped scanner, no open
  critical/high matches) -> PASS. Absence of findings alone is never a
  PASS without positive coverage.
- Freshness from latest relevant evidence time: FRESH (<=7d), STALE
  (older), UNKNOWN (none). Stale positive -> PARTIAL, LOW confidence.
- Confidence: HIGH (fresh positive, no contradiction), MEDIUM (stale
  positive or partial/indirect), LOW (insufficient or old evidence).
- Applicability: data-derived scope (required asset types or scanners);
  otherwise NOT_APPLICABLE. No scope-configuration UI in MMP-1.
- Statuses: PASS / PARTIAL / FAIL / NOT_ASSESSED / NOT_APPLICABLE.
  Never "compliant", "certified", or "audit passed".
"""

from __future__ import annotations

EVIDENCE_FRAMEWORK = {
    "framework": "vapt_control_readiness",
    "version": "1.0",
    "display_name": "VAPT Control Readiness 1.0",
    "description": (
        "Evidence coverage of security controls from VAPT scanner, asset, "
        "and monitoring data. Readiness only — not certification, not an audit."
    ),
}

# Severity sets driving deterministic outcomes.
ACTIONABLE_SEVERITIES = frozenset({"critical", "high"})
LOWER_SEVERITIES = frozenset({"medium", "low", "info"})

# Accepted-risk findings are addressed, not clean (existing lifecycle stays
# authoritative): they can only ever yield PARTIAL, never PASS or FAIL.
ACCEPTED_RISK_STATUSES = frozenset({"accepted_risk"})

# Open (unresolved) finding statuses for evaluation. Mirrors the D2 open
# set; anything resolved-ish is excluded from negative evidence.
OPEN_STATUSES = frozenset(
    {
        "open",
        "detected",
        "triaged",
        "in_progress",
        "remediation_claimed",
        "ready_for_retest",
        "retesting",
        "reopened",
    }
)

FRESH_DAYS = 7

# Control catalog: 24 controls, each justified by concrete VAPT evidence.
# matchers: [{scanners: [...], keywords: [...]|None}] — a finding matches
# when its scanner is listed and (no keywords or any keyword appears in
# the lowercased title). Keywords stay narrow to avoid mapping every
# finding to every control.
CONTROLS = [
    {
        "control_id": "VAPT-APP-AUTH-01",
        "title": "Authentication verification",
        "description": "Login, credential, session-creation and MFA/brute-force surfaces show no unresolved critical or high findings.",
        "category": "Application Security",
        "importance": "high",
        "matchers": [
            {"scanners": ["zap", "nuclei"], "keywords": ["auth", "login", "password", "credential", "session", "mfa", "brute", "otp"]},
        ],
        "positive_scanners": ["zap", "nuclei"],
        "requires_any_scanners": ["zap", "nuclei"],
        "requires_any_assets": ["url", "web_host", "web_site", "domain"],
    },
    {
        "control_id": "VAPT-APP-AUTHZ-01",
        "title": "Access control enforcement",
        "description": "No unresolved critical or high findings indicating broken access control, IDOR, traversal or privilege issues.",
        "category": "Application Security",
        "importance": "high",
        "matchers": [
            {"scanners": ["zap", "nuclei"], "keywords": ["access", "authori", "privilege", "idor", "travers", "forced brows"]},
        ],
        "positive_scanners": ["zap", "nuclei"],
        "requires_any_scanners": ["zap", "nuclei"],
        "requires_any_assets": ["url", "web_host", "web_site", "domain"],
    },
    {
        "control_id": "VAPT-APP-INJ-01",
        "title": "Injection resistance",
        "description": "No unresolved critical or high SQLi/XSS/command/LDAP/SSTI findings.",
        "category": "Application Security",
        "importance": "high",
        "matchers": [
            {"scanners": ["nuclei", "zap", "nikto", "sqlmap"], "keywords": ["sql", "inject", "xss", "cross-site", "command", "ldap", "xxe", "ssti", "template"]},
        ],
        "positive_scanners": ["nuclei", "zap", "nikto", "sqlmap"],
        "requires_any_scanners": ["nuclei", "zap", "nikto", "sqlmap"],
        "requires_any_assets": ["url", "web_host", "web_site", "domain"],
    },
    {
        "control_id": "VAPT-APP-HEADERS-01",
        "title": "HTTP security headers",
        "description": "Security-header findings (CSP, HSTS, framing, sniffing) are resolved or absent with header-capable coverage.",
        "category": "Application Security",
        "importance": "medium",
        "matchers": [
            {"scanners": ["nuclei", "zap", "nikto", "http_fingerprint"], "keywords": ["header", "csp", "hsts", "frame", "nosniff", "clickjack", "policy"]},
        ],
        "positive_scanners": ["nuclei", "zap", "nikto", "http_fingerprint"],
        "requires_any_scanners": ["nuclei", "zap", "nikto", "http_fingerprint"],
        "requires_any_assets": ["url", "web_host", "web_site", "domain"],
    },
    {
        "control_id": "VAPT-APP-SESS-01",
        "title": "Session management",
        "description": "No unresolved critical or high session, cookie or CSRF findings.",
        "category": "Application Security",
        "importance": "medium",
        "matchers": [
            {"scanners": ["zap", "nuclei"], "keywords": ["session", "cookie", "samesite", "csrf", "xsrf", "token fixation"]},
        ],
        "positive_scanners": ["zap", "nuclei"],
        "requires_any_scanners": ["zap", "nuclei"],
        "requires_any_assets": ["url", "web_host", "web_site", "domain"],
    },
    {
        "control_id": "VAPT-APP-DATA-01",
        "title": "Sensitive data exposure review",
        "description": "No unresolved critical or high findings indicating sensitive-data disclosure, debug output or directory listing.",
        "category": "Application Security",
        "importance": "high",
        "matchers": [
            {"scanners": ["nuclei", "zap"], "keywords": ["sensitive", "disclosure", "leak", "exposure", "pii", "debug", "stack trace", "directory listing", "backup"]},
        ],
        "positive_scanners": ["nuclei", "zap"],
        "requires_any_scanners": ["nuclei", "zap"],
        "requires_any_assets": ["url", "web_host", "web_site", "domain"],
    },
    {
        "control_id": "VAPT-APP-TECH-01",
        "title": "Web technology hygiene",
        "description": "No unresolved findings about outdated, end-of-life or default web technologies with known risk.",
        "category": "Application Security",
        "importance": "medium",
        "matchers": [
            {"scanners": ["http_fingerprint", "nikto", "nuclei"], "keywords": ["outdated", "out-of-date", "eol", "end-of-life", "deprecated", "default", "version disclosure"]},
        ],
        "positive_scanners": ["http_fingerprint", "nikto", "nuclei"],
        "requires_any_scanners": ["http_fingerprint", "nikto", "nuclei"],
        "requires_any_assets": ["url", "web_host", "web_site", "domain", "technology"],
    },
    {
        "control_id": "VAPT-CRYPTO-TLS-01",
        "title": "TLS configuration",
        "description": "TLS endpoints show no unresolved critical or high findings with recent TLS assessment coverage.",
        "category": "Cryptography",
        "importance": "high",
        "matchers": [{"scanners": ["tls"], "keywords": None}],
        "positive_scanners": ["tls"],
        "requires_any_scanners": ["tls"],
        "requires_any_assets": ["tls_endpoint", "url", "domain"],
    },
    {
        "control_id": "VAPT-NET-EXP-01",
        "title": "Network exposure review",
        "description": "Internet-exposed assets carry no unresolved critical or high findings; exposure without proven issues is partial, not passing.",
        "category": "Network",
        "importance": "high",
        "matchers": [],
        "exposure_review": True,
        "positive_scanners": ["nmap", "dns", "subdomain"],
        "requires_any_scanners": ["nmap", "dns", "subdomain"],
        "requires_any_assets": ["ip", "ipv6", "domain", "host"],
    },
    {
        "control_id": "VAPT-NET-PORT-01",
        "title": "Exposed services review",
        "description": "Port/service findings show no unresolved critical or high issues with recent network coverage.",
        "category": "Network",
        "importance": "high",
        "matchers": [{"scanners": ["nmap"], "keywords": None}],
        "positive_scanners": ["nmap"],
        "requires_any_scanners": ["nmap"],
        "requires_any_assets": ["ip", "ipv6", "port", "service", "host"],
    },
    {
        "control_id": "VAPT-NET-DNS-01",
        "title": "DNS configuration review",
        "description": "DNS findings show no unresolved critical or high issues with recent DNS coverage.",
        "category": "Network",
        "importance": "medium",
        "matchers": [{"scanners": ["dns", "subdomain"], "keywords": None}],
        "positive_scanners": ["dns", "subdomain"],
        "requires_any_scanners": ["dns", "subdomain"],
        "requires_any_assets": ["domain", "subdomain", "dns_cname", "dns_mx", "dns_ns", "dns_txt", "dns_soa"],
    },
    {
        "control_id": "VAPT-NET-PROTO-01",
        "title": "Insecure protocol review",
        "description": "No unresolved findings evidencing cleartext or deprecated protocols/services.",
        "category": "Network",
        "importance": "medium",
        "matchers": [
            {"scanners": ["nmap", "tls"], "keywords": ["telnet", "ftp", "smtp", "snmp", "rdp", "vnc", "cleartext", "plain text", "weak", "deprecated", "sslv", "tls 1.0", "tls1.0"]},
        ],
        "positive_scanners": ["nmap", "tls"],
        "requires_any_scanners": ["nmap", "tls"],
        "requires_any_assets": ["ip", "ipv6", "port", "service", "tls_endpoint"],
    },
    {
        "control_id": "VAPT-API-AUTH-01",
        "title": "API authentication",
        "description": "API authentication surfaces show no unresolved critical or high findings.",
        "category": "API Security",
        "importance": "high",
        "matchers": [
            {"scanners": ["api", "zap"], "keywords": ["api", "auth", "jwt", "oauth", "token", "key"]},
        ],
        "positive_scanners": ["api", "zap"],
        "requires_any_scanners": ["api", "zap"],
        "requires_any_assets": ["api_spec", "api_endpoint", "url"],
    },
    {
        "control_id": "VAPT-API-AUTHZ-01",
        "title": "API authorization",
        "description": "No unresolved findings indicating broken object/function-level authorization or mass assignment.",
        "category": "API Security",
        "importance": "high",
        "matchers": [
            {"scanners": ["api"], "keywords": ["bola", "bfla", "authori", "object", "function", "mass assignment", "excessive"]},
        ],
        "positive_scanners": ["api"],
        "requires_any_scanners": ["api"],
        "requires_any_assets": ["api_spec", "api_endpoint", "url"],
    },
    {
        "control_id": "VAPT-API-INP-01",
        "title": "API input validation",
        "description": "No unresolved API injection, fuzzing, method or schema findings at critical or high severity.",
        "category": "API Security",
        "importance": "medium",
        "matchers": [
            {"scanners": ["api", "zap"], "keywords": ["inject", "valid", "fuzz", "schema", "method", "verb", "mass"]},
        ],
        "positive_scanners": ["api", "zap"],
        "requires_any_scanners": ["api", "zap"],
        "requires_any_assets": ["api_spec", "api_endpoint", "url"],
    },
    {
        "control_id": "VAPT-API-TLS-01",
        "title": "API transport security",
        "description": "API transport shows no unresolved TLS/HTTPS findings with API or TLS coverage.",
        "category": "API Security",
        "importance": "medium",
        "matchers": [
            {"scanners": ["api"], "keywords": ["tls", "ssl", "https", "hsts", "certificate"]},
        ],
        "positive_scanners": ["api", "tls"],
        "requires_any_scanners": ["api"],
        "requires_any_assets": ["api_spec", "api_endpoint", "url"],
    },
    {
        "control_id": "VAPT-CODE-SAST-01",
        "title": "Secure coding (SAST)",
        "description": "SAST findings show no unresolved critical or high issues with recent static-analysis coverage.",
        "category": "Code Security",
        "importance": "high",
        "matchers": [{"scanners": ["sast"], "keywords": None}],
        "positive_scanners": ["sast"],
        "requires_any_scanners": ["sast"],
        "requires_any_assets": ["repository", "project", "directory", "path"],
    },
    {
        "control_id": "VAPT-CODE-SCA-01",
        "title": "Dependency management (SCA)",
        "description": "Software-composition findings show no unresolved critical or high vulnerable dependencies.",
        "category": "Code Security",
        "importance": "high",
        "matchers": [{"scanners": ["sca"], "keywords": None}],
        "positive_scanners": ["sca"],
        "requires_any_scanners": ["sca"],
        "requires_any_assets": ["repository", "project", "directory", "path"],
    },
    {
        "control_id": "VAPT-CODE-SEC-01",
        "title": "Secret management",
        "description": "No unresolved secrets detected in code with recent secrets-scanning coverage.",
        "category": "Code Security",
        "importance": "critical",
        "matchers": [{"scanners": ["secrets"], "keywords": None}],
        "positive_scanners": ["secrets"],
        "requires_any_scanners": ["secrets"],
        "requires_any_assets": ["repository", "project", "directory", "path"],
    },
    {
        "control_id": "VAPT-CODE-CONT-01",
        "title": "Container image security",
        "description": "Container image findings show no unresolved critical or high vulnerabilities.",
        "category": "Code Security",
        "importance": "high",
        "matchers": [{"scanners": ["container"], "keywords": None}],
        "positive_scanners": ["container"],
        "requires_any_scanners": ["container"],
        "requires_any_assets": ["container_image", "image", "docker_image"],
    },
    {
        "control_id": "VAPT-CODE-IAC-01",
        "title": "Infrastructure-as-code review",
        "description": "IaC findings show no unresolved critical or high misconfigurations.",
        "category": "Code Security",
        "importance": "medium",
        "matchers": [{"scanners": ["iac"], "keywords": None}],
        "positive_scanners": ["iac"],
        "requires_any_scanners": ["iac"],
        "requires_any_assets": ["repository", "project", "directory"],
    },
    {
        "control_id": "VAPT-OPS-SCAN-01",
        "title": "Vulnerability scanning coverage",
        "description": "At least one completed scan exists recently; older coverage is partial, not passing.",
        "category": "Operations",
        "importance": "medium",
        "matchers": [],
        "coverage_only": True,
        "positive_scanners": [],
        "requires_any_scanners": [],
        "requires_any_assets": [],
    },
    {
        "control_id": "VAPT-OPS-MON-01",
        "title": "Continuous monitoring active",
        "description": "A monitoring run completed recently; stale or failed monitoring is partial, never passing.",
        "category": "Operations",
        "importance": "medium",
        "matchers": [],
        "monitoring_review": True,
        "positive_scanners": [],
        "requires_any_scanners": [],
        "requires_any_assets": [],
    },
    {
        "control_id": "VAPT-OPS-CHANGE-01",
        "title": "Security change review",
        "description": "Recent monitoring observations produced evaluated change records; absence of change data is not assessed.",
        "category": "Operations",
        "importance": "medium",
        "matchers": [],
        "change_review": True,
        "positive_scanners": [],
        "requires_any_scanners": [],
        "requires_any_assets": [],
    },
]

CONTROL_IDS = [c["control_id"] for c in CONTROLS]

assert len(CONTROLS) == len(set(CONTROL_IDS)), "duplicate control IDs in D5 catalog"


def get_control(control_id: str) -> dict | None:
    for control in CONTROLS:
        if control["control_id"] == control_id:
            return control
    return None


def finding_matches(finding: dict, matchers: list) -> bool:
    """A finding matches when its scanner is listed and (no keywords or any
    keyword appears in the lowercased title). Scanner-exact, keyword-narrow
    by design so one finding never maps to every control."""
    scanner = str(finding.get("scanner") or "").strip().lower()
    title = str(finding.get("title") or "").lower()
    for matcher in matchers or []:
        scanners = {str(s).lower() for s in (matcher.get("scanners") or [])}
        if scanner not in scanners:
            continue
        keywords = matcher.get("keywords")
        if not keywords:
            return True
        if any(str(k).lower() in title for k in keywords):
            return True
    return False


def seed_evidence_catalog(db) -> int:
    """Idempotently seed the D5 framework + controls. Returns rows created.
    Existing demo frameworks/controls are never modified."""
    from app.models.compliance import ComplianceControl, ComplianceFramework

    created = 0
    fw = (
        db.query(ComplianceFramework)
        .filter(
            ComplianceFramework.framework == EVIDENCE_FRAMEWORK["framework"],
            ComplianceFramework.version == EVIDENCE_FRAMEWORK["version"],
        )
        .first()
    )
    if fw is None:
        fw = ComplianceFramework(
            framework=EVIDENCE_FRAMEWORK["framework"],
            version=EVIDENCE_FRAMEWORK["version"],
            display_name=EVIDENCE_FRAMEWORK["display_name"],
            description=EVIDENCE_FRAMEWORK["description"],
        )
        db.add(fw)
        db.flush()
        created += 1
    existing = {
        c.control_id
        for c in db.query(ComplianceControl).filter(ComplianceControl.framework_id == fw.id).all()
    }
    for ctrl in CONTROLS:
        if ctrl["control_id"] in existing:
            continue
        db.add(
            ComplianceControl(
                framework_id=fw.id,
                control_id=ctrl["control_id"],
                title=ctrl["title"],
                description=ctrl["description"],
                category=ctrl["category"],
                status="not_assessed",
            )
        )
        created += 1
    if created:
        db.commit()
    return created

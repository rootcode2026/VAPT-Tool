"""Canonical scanner catalog — declarative, mirrors the worker ScannerRegistry.

The worker registry remains the source of truth for *executable* scanners.
This catalog decorates it with control-plane metadata (versions, health,
capacity). It never imports worker code (which requires Docker at import).
"""

from __future__ import annotations

# Canonical 15-scanner fleet (14 + SQLmap advanced). Capabilities/profiles mirror
# worker/app/scanner/scanners/*.py and worker/app/scanner/profiles.py.
SCANNER_CATALOG: list[dict] = [
    {
        "key": "nmap",
        "name": "Nmap",
        "category": "recon",
        "family": "network",
        "description": "Network and service discovery",
        "capabilities": ["host_discovery", "port_scanning", "service_detection", "version_detection"],
        "profiles": ["quick", "web", "full"],
        "requires_workspace": False,
        "execution_type": "docker",
        "timeout_seconds": 300,
        "default_image": "vapt-tool-nmap",
    },
    {
        "key": "nuclei",
        "name": "Nuclei",
        "category": "vulnerability",
        "family": "web",
        "description": "Template-based vulnerability and security misconfiguration detection",
        "capabilities": ["vulnerability_detection", "misconfiguration_detection", "exposure_detection", "technology_detection"],
        "profiles": ["web", "full"],
        "requires_workspace": False,
        "execution_type": "docker",
        "timeout_seconds": 600,
        "default_image": "vapt-tool-nuclei",
    },
    {
        "key": "http_fingerprint",
        "name": "HTTP Fingerprint",
        "category": "web_recon",
        "family": "web",
        "description": "HTTP and HTTPS web service fingerprinting and security header analysis",
        "capabilities": ["http_fingerprinting", "https_detection", "header_analysis", "redirect_detection", "technology_detection"],
        "profiles": ["web", "full"],
        "requires_workspace": False,
        "execution_type": "docker",
        "timeout_seconds": 30,
        "default_image": None,
    },
    {
        "key": "zap",
        "name": "OWASP ZAP",
        "category": "web_vulnerability",
        "family": "dast",
        "description": "OWASP ZAP web application vulnerability scanning",
        "capabilities": ["web_vulnerability_scanning", "active_scanning", "spidering", "security_header_analysis", "misconfiguration_detection"],
        "profiles": ["web", "full"],
        "requires_workspace": False,
        "execution_type": "docker",
        "timeout_seconds": 900,
        "default_image": "zaproxy",
    },
    {
        "key": "nikto",
        "name": "Nikto",
        "category": "web_vulnerability",
        "family": "web",
        "description": "Web server misconfiguration and known-vulnerability scanning",
        "capabilities": ["web_vulnerability_scanning", "misconfiguration_detection", "known_vulnerability_detection", "security_header_analysis"],
        "profiles": ["web", "full"],
        "requires_workspace": False,
        "execution_type": "docker",
        "timeout_seconds": 600,
        "default_image": "nikto",
    },
    {
        "key": "tls",
        "name": "TLS Analyzer",
        "category": "tls",
        "family": "network",
        "description": "TLS/SSL protocol, cipher, and certificate security analysis",
        "capabilities": ["tls_protocol_analysis", "cipher_suite_analysis", "certificate_analysis", "tls_vulnerability_detection"],
        "profiles": ["web", "full"],
        "requires_workspace": False,
        "execution_type": "docker",
        "timeout_seconds": 900,
        "default_image": "tls",
    },
    {
        "key": "dns",
        "name": "DNS Discovery",
        "category": "asset_discovery",
        "family": "network",
        "description": "DNS record discovery for authorized domains",
        "capabilities": ["dns_record_discovery", "a_record_lookup", "aaaa_record_lookup", "cname_lookup", "mx_lookup", "ns_lookup", "txt_lookup", "soa_lookup"],
        "profiles": ["web", "full"],
        "requires_workspace": False,
        "execution_type": "docker",
        "timeout_seconds": 120,
        "default_image": "dns",
    },
    {
        "key": "subdomain",
        "name": "Subdomain Discovery",
        "category": "asset_discovery",
        "family": "network",
        "description": "Passive subdomain discovery for authorized domains",
        "capabilities": ["subdomain_discovery", "passive_reconnaissance"],
        "profiles": ["web", "full"],
        "requires_workspace": False,
        "execution_type": "docker",
        "timeout_seconds": 180,
        "default_image": "subdomain",
    },
    {
        "key": "sast",
        "name": "SAST (Semgrep)",
        "category": "application_security",
        "family": "sast",
        "description": "Static Application Security Testing for source code",
        "capabilities": ["sast", "static_analysis", "python", "javascript", "typescript", "java", "go", "sarif"],
        "profiles": ["sast", "full", "code", "code_full"],
        "requires_workspace": True,
        "execution_type": "docker",
        "timeout_seconds": 120,
        "default_image": "vapt-sast:latest",
    },
    {
        "key": "sca",
        "name": "SCA (OSV-Scanner)",
        "category": "application_security",
        "family": "sca",
        "description": "Software Composition Analysis — dependency vulnerability detection",
        "capabilities": ["sca", "dependency", "vulnerability", "sarif", "osv"],
        "profiles": ["sca", "full", "code", "code_full"],
        "requires_workspace": True,
        "execution_type": "docker",
        "timeout_seconds": 120,
        "default_image": None,
    },
    {
        "key": "secrets",
        "name": "Secrets (Gitleaks)",
        "category": "application_security",
        "family": "secrets",
        "description": "Secret and credential leak detection in source",
        "capabilities": ["secrets", "secret_detection", "sarif", "gitleaks", "credential_scan"],
        "profiles": ["secrets", "secrets_full", "full_secrets", "code", "code_full"],
        "requires_workspace": True,
        "execution_type": "docker",
        "timeout_seconds": 120,
        "default_image": "vapt-secrets:latest",
    },
    {
        "key": "container",
        "name": "Container (Trivy)",
        "category": "container_security",
        "family": "container",
        "description": "Container image vulnerability scanning",
        "capabilities": ["container", "image_scan", "vulnerability", "misconfiguration", "sarif", "trivy", "cve"],
        "profiles": ["container", "container_full", "code", "code_full"],
        "requires_workspace": False,
        "execution_type": "docker",
        "timeout_seconds": 300,
        "default_image": "vapt-container:latest",
    },
    {
        "key": "iac",
        "name": "IaC (Checkov)",
        "category": "application_security",
        "family": "iac",
        "description": "Infrastructure-as-code misconfiguration scanning",
        "capabilities": ["iac", "misconfiguration", "policy", "terraform", "kubernetes", "cloudformation", "dockerfile", "sarif", "checkov"],
        "profiles": ["iac", "iac_full", "code", "code_full"],
        "requires_workspace": True,
        "execution_type": "docker",
        "timeout_seconds": 180,
        "default_image": "vapt-iac:latest",
    },
    {
        "key": "api",
        "name": "API Validator",
        "category": "application_security",
        "family": "api",
        "description": "OpenAPI specification security validation",
        "capabilities": ["api", "openapi", "swagger", "endpoint_discovery", "security_config", "sarif", "vapt-api"],
        "profiles": ["api", "api_full", "code", "code_full", "advanced_dast", "api_authenticated"],
        "requires_workspace": True,
        "execution_type": "docker",
        "timeout_seconds": 120,
        "default_image": "vapt-api:latest",
    },
    {
        "key": "sqlmap",
        "name": "SQLMap",
        "category": "database_security",
        "family": "dast",
        "description": "SQL injection detection — controlled database security testing",
        "capabilities": ["sqli_detection", "database_fingerprint", "injection_testing", "dast"],
        "profiles": ["database_security", "advanced_dast"],
        "requires_workspace": False,
        "execution_type": "docker",
        "timeout_seconds": 300,
        "default_image": "vapt-sqlmap:latest",
    },
]

# Documented stable versions (from project verification evidence).
# Scanners without a documented version ship as "unknown" — never fabricated.
DOCUMENTED_STABLE_VERSIONS: dict[str, str] = {
    "sast": "1.75.0",
    "sca": "1.9.2",
    "secrets": "8.30.1",
    "container": "0.66.0",
    "iac": "3.3.16",
    "api": "1.0.0",
    "sqlmap": "1.8.5",
}

PROFILE_SCANNERS: dict[str, list[str]] = {
    "quick": ["nmap"],
    "web": ["nmap", "http_fingerprint", "nuclei", "zap", "nikto", "tls", "dns", "subdomain"],
    "full": ["nmap", "http_fingerprint", "nuclei", "zap", "nikto", "tls", "dns", "subdomain"],
    "sca": ["sca"],
    "sast": ["sast"],
    "secrets": ["secrets"],
    "container": ["container"],
    "iac": ["iac"],
    "api": ["api"],
    "code": ["sast", "sca", "secrets", "container", "iac", "api"],
    "code_full": ["sast", "sca", "secrets", "container", "iac", "api"],
    "api_authenticated": ["api", "zap"],
    "advanced_dast": ["zap", "nuclei", "nikto", "http_fingerprint", "api"],
    "database_security": ["sqlmap"],
}


def get_catalog() -> list[dict]:
    return [dict(s) for s in SCANNER_CATALOG]


def get_scanner_entry(key: str) -> dict | None:
    for s in SCANNER_CATALOG:
        if s["key"] == key:
            return dict(s)
    return None


def scanners_for_profile(profile: str) -> list[str]:
    return list(PROFILE_SCANNERS.get(profile, []))


def seed_definitions(db) -> int:
    """Idempotently seed ScannerDefinition rows. Returns number created."""
    from app.models.scanner_fleet import ScannerDefinition

    created = 0
    for entry in SCANNER_CATALOG:
        existing = db.query(ScannerDefinition).filter(ScannerDefinition.scanner_key == entry["key"]).first()
        if existing:
            continue
        db.add(
            ScannerDefinition(
                scanner_key=entry["key"],
                display_name=entry["name"],
                description=entry["description"],
                category=entry["category"],
                family=entry["family"],
                enabled=True,
                current_version=DOCUMENTED_STABLE_VERSIONS.get(entry["key"]),
                capabilities=list(entry["capabilities"]),
                requirements=[],
                supported_profiles=list(entry["profiles"]),
                requires_workspace=bool(entry["requires_workspace"]),
                execution_type=entry["execution_type"],
                timeout_seconds=int(entry["timeout_seconds"]),
                default_image=entry["default_image"],
            )
        )
        created += 1
    if created:
        db.commit()
    return created


def get_eligible_scanners(profile: str, db) -> list[str] | None:
    """Availability-aware profile selection.

    Returns None when the control plane has no opinions (no definition rows
    or tables missing) so callers fall back to existing profile behavior.
    Otherwise returns profile scanners minus disabled/unhealthy/no-active-version.
    """
    try:
        from app.models.scanner_fleet import ScannerDefinition, ScannerHealth, ScannerVersion

        defs = {d.scanner_key: d for d in db.query(ScannerDefinition).all()}
    except Exception:
        return None
    if not defs:
        return None
    base = scanners_for_profile(profile)
    if not base:
        return None
    eligible: list[str] = []
    for key in base:
        d = defs.get(key)
        if d is None:
            eligible.append(key)  # no opinion → keep existing behavior
            continue
        if not d.enabled:
            continue
        if d.current_version:
            try:
                v = (
                    db.query(ScannerVersion)
                    .filter(ScannerVersion.definition_id == d.id, ScannerVersion.version == d.current_version)
                    .first()
                )
                if v is not None and v.channel == "failed":
                    continue
            except Exception:
                pass
        try:
            h = (
                db.query(ScannerHealth)
                .filter(ScannerHealth.definition_id == d.id)
                .order_by(ScannerHealth.checked_at.desc())
                .first()
            )
            if h is not None and h.status == "unhealthy":
                continue
        except Exception:
            pass
        eligible.append(key)
    return eligible

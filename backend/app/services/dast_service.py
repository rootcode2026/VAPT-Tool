"""DAST service — profile policy, target validation, SSRF, endpoint/parameter discovery."""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlparse

# Execution policy per profile
DAST_PROFILES = {
    "quick": {"passive": True, "max_requests": 100, "max_duration": 60, "max_endpoints": 10, "max_parameters": 20, "rate_limit": 2, "allowed_scanners": ["nmap", "http_fingerprint"], "destructive": False, "active_allowed": False, "db_allowed": False},
    "web": {"passive": True, "max_requests": 500, "max_duration": 300, "max_endpoints": 50, "max_parameters": 50, "rate_limit": 5, "allowed_scanners": ["nmap", "http_fingerprint", "nuclei", "zap", "nikto", "tls", "dns", "subdomain"], "destructive": False, "active_allowed": False, "db_allowed": False},
    "full": {"passive": False, "max_requests": 1000, "max_duration": 600, "max_endpoints": 100, "max_parameters": 100, "rate_limit": 5, "allowed_scanners": ["nmap", "http_fingerprint", "nuclei", "zap", "nikto", "tls", "dns", "subdomain"], "destructive": False, "active_allowed": False, "db_allowed": False},
    "api": {"passive": True, "max_requests": 300, "max_duration": 300, "max_endpoints": 50, "max_parameters": 50, "rate_limit": 5, "allowed_scanners": ["api"], "destructive": False, "active_allowed": False, "db_allowed": False},
    "api_authenticated": {"passive": False, "max_requests": 500, "max_duration": 600, "max_endpoints": 50, "max_parameters": 50, "rate_limit": 5, "allowed_scanners": ["api", "zap"], "destructive": False, "active_allowed": True, "db_allowed": False},
    "advanced_dast": {"passive": False, "max_requests": 1000, "max_duration": 900, "max_endpoints": 100, "max_parameters": 100, "rate_limit": 3, "allowed_scanners": ["zap", "nuclei", "nikto", "http_fingerprint", "api"], "destructive": False, "active_allowed": True, "db_allowed": False},
    "database_security": {"passive": False, "max_requests": 200, "max_duration": 300, "max_endpoints": 10, "max_parameters": 10, "rate_limit": 2, "allowed_scanners": ["sqlmap"], "destructive": False, "active_allowed": True, "db_allowed": True},
}

MAX_DAST_DURATION = 900
MAX_REQUESTS = 1000
MAX_ENDPOINTS = 100
MAX_PARAMETERS = 100
MAX_RESPONSE_SIZE = 500 * 1024
MAX_CONCURRENCY = 3

_PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token"}

def get_policy(profile: str) -> dict:
    return DAST_PROFILES.get(profile, DAST_PROFILES["web"])

def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in _PRIVATE_RANGES:
            if ip in net:
                return True
        return False
    except Exception:
        return False

def validate_target_url(url: str, allowed_domains: list[str] | None = None) -> str:
    if not url or not isinstance(url, str):
        raise ValueError("Invalid target URL")
    url = url.strip()
    if len(url) > 2048:
        raise ValueError("URL too long")
    if any(c in url for c in ";\n\r"):
        raise ValueError("Invalid URL characters")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must be http/https")
    host = parsed.hostname or ""
    if not host:
        raise ValueError("Missing hostname")
    # Block metadata endpoints
    if host.lower() in ("169.254.169.254", "metadata.google.internal", "metadata.google", "metadata.azure.internal"):
        raise ValueError("Metadata endpoint not allowed")
    # Check private IP literal
    try:
        ip = ipaddress.ip_address(host)
        if _is_private_ip(str(ip)):
            raise ValueError("Private IP not allowed")
    except ValueError as e:
        if "Private IP" in str(e):
            raise
        # not an IP literal -> domain, allow (DNS resolution omitted for bounded check)
        pass
    # Allowed domains check
    if allowed_domains:
        allowed = [d.strip().lower() for d in allowed_domains if d.strip()]
        if allowed:
            host_lower = host.lower()
            if not any(host_lower == dom or host_lower.endswith("." + dom) for dom in allowed):
                raise ValueError("Host not in allowed domains")
    return url

def validate_target_authorization(target_id: str, db, user, project_id: str):
    from app.models.target import Target
    from app.api.deps import require_project_access
    require_project_access(project_id, db, user)
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise ValueError("Target not found")
    if target.project_id != project_id:
        raise ValueError("Target not in project")
    return target

def sanitize_headers(headers: dict) -> dict:
    sanitized = {}
    for k, v in (headers or {}).items():
        lk = k.lower()
        if lk in _SENSITIVE_HEADERS:
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = str(v)[:500]
    return sanitized

def detect_endpoints_from_target(target_value: str) -> list[dict]:
    # Simple endpoint discovery: from target URL, create base endpoint
    endpoints = []
    try:
        parsed = urlparse(target_value if target_value.startswith("http") else f"https://{target_value}")
        host = parsed.hostname or target_value
        base = f"{parsed.scheme or 'https'}://{host}"
        endpoints.append({"url": f"{base}/", "method": "GET", "host": host, "path": "/", "discovered_via": "target"})
        endpoints.append({"url": f"{base}/api", "method": "GET", "host": host, "path": "/api", "discovered_via": "heuristic"})
    except Exception:
        pass
    return endpoints[:10]

def detect_parameters(endpoint_url: str, method: str = "GET") -> list[dict]:
    # Bounded parameter discovery
    params = []
    parsed = urlparse(endpoint_url)
    # query params
    if parsed.query:
        for pair in parsed.query.split("&")[:5]:
            if "=" in pair:
                name = pair.split("=")[0][:100]
                if name and name not in ("password", "token", "secret"):
                    params.append({"name": name, "location": "query", "http_method": method})
    # heuristic: common params
    for name in ["id", "user", "page"][:3]:
        params.append({"name": name, "location": "query", "http_method": method})
    return params[:10]

def sanitize_evidence(evidence: str) -> str:
    if not evidence:
        return ""
    # Redact sensitive
    for tok in ("Authorization:", "Cookie:", "X-API-Key"):
        if tok.lower() in evidence.lower():
            evidence = re.sub(r"(?i)(authorization|cookie|x-api-key)\s*:\s*[^\n]+", r"\1: [REDACTED]", evidence)
    return evidence[:2000]

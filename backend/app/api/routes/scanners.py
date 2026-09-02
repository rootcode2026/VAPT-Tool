from fastapi import APIRouter

from app.schemas.scanner import ScannerResponse


router = APIRouter(
    prefix="/api/v1/scanners",
    tags=["Scanners"],
)


SCANNERS = [
    {
        "name": "nmap",
        "category": "recon",
        "description": "Network and service discovery",
        "target_types": ["domain", "ip"],
    },
    {
        "name": "nuclei",
        "category": "vulnerability",
        "description": (
            "Template-based vulnerability and "
            "security misconfiguration detection"
        ),
        "target_types": ["domain", "ip", "url"],
    },
    {
        "name": "http_fingerprint",
        "category": "web_recon",
        "description": (
            "HTTP and HTTPS web service fingerprinting "
            "and security header analysis"
        ),
        "target_types": ["domain", "url"],
    },
    {
        "name": "zap",
        "category": "web_vulnerability",
        "description": "OWASP ZAP web application vulnerability scanning",
        "target_types": ["domain", "url"],
    },
    {
        "name": "nikto",
        "category": "web_vulnerability",
        "description": (
            "Web server misconfiguration and known-vulnerability scanning"
        ),
        "target_types": ["domain", "url"],
    },
    {
        "name": "tls",
        "category": "tls",
        "description": (
            "TLS/SSL protocol, cipher, and certificate security analysis"
        ),
        "target_types": ["domain", "ip", "url"],
    },
    {
        "name": "dns",
        "category": "asset_discovery",
        "description": "DNS record discovery for authorized domains",
        "target_types": ["domain"],
    },
    {
        "name": "subdomain",
        "category": "asset_discovery",
        "description": (
            "Passive subdomain discovery for authorized domains"
        ),
        "target_types": ["domain"],
    },
]


@router.get(
    "",
    response_model=list[ScannerResponse],
)
def get_scanners():
    return SCANNERS

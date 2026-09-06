SCAN_PROFILES = {
    "quick": [
        "nmap",
    ],
    "web": [
        "nmap",
        "http_fingerprint",
        "nuclei",
        "zap",
        "nikto",
        "tls",
        "dns",
        "subdomain",
    ],
    "full": [
        "nmap",
        "http_fingerprint",
        "nuclei",
        "zap",
        "nikto",
        "tls",
        "dns",
        "subdomain",
    ],
    "sca": [
        "sca",
    ],
    "sast": [
        "sast",
    ],
    # AppSec families — declarative, registry-driven
    "secrets": ["secrets"],
    "container": ["container"],
    "iac": ["iac"],
    "api": ["api"],
    "secrets_full": ["secrets"],
    "container_full": ["container"],
    "iac_full": ["iac"],
    "api_full": ["api"],
    "code": ["sast", "sca", "secrets", "container", "iac", "api"],
    "code_full": ["sast", "sca", "secrets", "container", "iac", "api"],
}


def get_scanners_for_profile(profile: str) -> list[str]:

    scanners = SCAN_PROFILES.get(profile)

    if scanners is None:
        raise ValueError(
            f"Unknown scan profile: {profile}"
        )

    return scanners
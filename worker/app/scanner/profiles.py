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
}


def get_scanners_for_profile(profile: str) -> list[str]:

    scanners = SCAN_PROFILES.get(profile)

    if scanners is None:
        raise ValueError(
            f"Unknown scan profile: {profile}"
        )

    return scanners
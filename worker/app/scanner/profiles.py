SCAN_PROFILES = {
    "quick": [
        "nmap",
    ],
    "web": [
        "nmap",
        "nuclei",
    ],
    "full": [
        "nmap",
        "nuclei",
    ],
}


def get_scanners_for_profile(profile: str) -> list[str]:
    scanners = SCAN_PROFILES.get(profile)

    if scanners is None:
        raise ValueError(
            f"Unsupported scan profile: {profile}"
        )

    return scanners
import pytest

from app.scanner.profiles import get_scanners_for_profile


def test_quick_profile_is_nmap_only():
    assert get_scanners_for_profile("quick") == ["nmap"]


def test_web_profile_includes_new_scanners_after_existing_order():
    assert get_scanners_for_profile("web") == [
        "nmap",
        "http_fingerprint",
        "nuclei",
        "zap",
        "nikto",
        "tls",
        "dns",
        "subdomain",
    ]


def test_full_profile_matches_web_coverage():
    assert get_scanners_for_profile("full") == [
        "nmap",
        "http_fingerprint",
        "nuclei",
        "zap",
        "nikto",
        "tls",
        "dns",
        "subdomain",
    ]


def test_unknown_profile_raises_value_error():
    with pytest.raises(ValueError, match="Unknown scan profile"):
        get_scanners_for_profile("invalid")

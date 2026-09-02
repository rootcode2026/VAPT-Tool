from app.scanner.parsers.registry import ParserRegistry
from app.scanner.registry import ScannerRegistry


EXPECTED_SCANNERS = [
    "nmap",
    "nuclei",
    "http_fingerprint",
    "zap",
    "nikto",
    "tls",
    "dns",
    "subdomain",
]


def test_all_scanners_are_registered():
    names = [item["name"] for item in ScannerRegistry().list()]

    for name in EXPECTED_SCANNERS:
        assert name in names


def test_scanner_registry_rejects_unknown_scanner():
    registry = ScannerRegistry()

    try:
        registry.get("does-not-exist")
    except ValueError as exc:
        assert "does-not-exist" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unknown scanner")


def test_all_parsers_are_registered():
    names = ParserRegistry().list()

    for name in EXPECTED_SCANNERS:
        assert name in names


def test_parser_registry_rejects_unknown_parser():
    registry = ParserRegistry()

    try:
        registry.get("does-not-exist")
    except ValueError as exc:
        assert "does-not-exist" in str(exc)
    else:
        raise AssertionError("Expected ValueError for unknown parser")

from unittest.mock import MagicMock

from app.scanner.pipeline import ScannerPipeline
from app.scanner.scanners.dns import DNSScanner
from app.scanner.scanners.http_fingerprint import HTTPFingerprintScanner
from app.scanner.scanners.nikto import NiktoScanner
from app.scanner.scanners.subdomain import SubdomainScanner
from app.scanner.scanners.tls import TLSScanner

from tests.helpers import load_fixture


def test_pipeline_nikto_fixture_round_trip(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(
        pipeline.manager,
        "run",
        lambda scanner, target: load_fixture("nikto.json"),
    )

    result = pipeline.run("nikto", "https://internal.test")

    assert result["scanner"] == "nikto"
    assert len(result["parsed_result"]["assets"]) == 1
    assert len(result["findings"]) == 3
    assert result["findings"][2]["cve"] == "CVE-2021-41773"
    assert result["findings"][2]["metadata"]["url"] == "/cgi-bin/test.cgi"


def test_pipeline_tls_fixture_round_trip(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(
        pipeline.manager,
        "run",
        lambda scanner, target: load_fixture("tls.json"),
    )

    result = pipeline.run("tls", "internal.test")

    assert result["scanner"] == "tls"
    assert len(result["findings"]) == 3
    assert result["findings"][0]["metadata"]["id"] == "SSLv3"


def test_pipeline_zap_fixture_round_trip(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(
        pipeline.manager,
        "run",
        lambda scanner, target: load_fixture("zap.xml"),
    )

    result = pipeline.run("zap", "https://internal.test")

    assert result["scanner"] == "zap"
    assert len(result["findings"]) == 2
    assert result["findings"][0]["metadata"]["uri"] == "https://internal.test/"


def test_pipeline_nmap_fixture_round_trip(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(
        pipeline.manager,
        "run",
        lambda scanner, target: load_fixture("nmap.xml"),
    )

    result = pipeline.run("nmap", "10.0.0.8")

    assert result["scanner"] == "nmap"
    assert result["findings"][0]["title"] == "HTTP service exposed"


def test_pipeline_nuclei_fixture_round_trip(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(
        pipeline.manager,
        "run",
        lambda scanner, target: load_fixture("nuclei.jsonl"),
    )

    result = pipeline.run("nuclei", "https://internal.test")

    assert result["scanner"] == "nuclei"
    assert len(result["findings"]) == 2
    assert result["findings"][1]["cve"] == "CVE-2021-44228"


def test_pipeline_http_fingerprint_fixture_round_trip(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(
        pipeline.manager,
        "run",
        lambda scanner, target: load_fixture("http_fingerprint.json"),
    )

    result = pipeline.run("http_fingerprint", "https://internal.test")

    assert result["scanner"] == "http_fingerprint"
    assert result["parsed_result"]["assets"]
    assert result["findings"]


def test_nikto_scanner_uses_json_output_and_normalizes_domain():
    scanner = NiktoScanner()
    scanner.runner = MagicMock()
    scanner.runner.run.return_value = "{}"

    scanner.scan("internal.test")

    kwargs = scanner.runner.run.call_args.kwargs
    assert kwargs["image"] == "vapt-nikto:latest"
    assert kwargs["command"][1] == "https://internal.test"
    assert "-Format" in kwargs["command"]
    assert "json" in kwargs["command"]


def test_tls_scanner_strips_url_to_host():
    scanner = TLSScanner()
    scanner.runner = MagicMock()
    scanner.runner.run.return_value = "[]"

    scanner.scan("https://internal.test/path")

    kwargs = scanner.runner.run.call_args.kwargs
    assert kwargs["image"] == "vapt-tls:latest"
    assert kwargs["command"] == ["internal.test"]


def test_nikto_scanner_rejects_empty_target():
    scanner = NiktoScanner()
    scanner.runner = MagicMock()

    try:
        scanner.scan("  ")
    except ValueError as exc:
        assert "empty" in str(exc).lower()
    else:
        raise AssertionError("Expected ValueError")

    scanner.runner.run.assert_not_called()


def test_tls_scanner_rejects_empty_target():
    scanner = TLSScanner()
    scanner.runner = MagicMock()

    try:
        scanner.scan("")
    except ValueError as exc:
        assert "empty" in str(exc).lower()
    else:
        raise AssertionError("Expected ValueError")

    scanner.runner.run.assert_not_called()


def test_http_fingerprint_scanner_mocked_request(monkeypatch):
    class FakeResponse:
        url = "https://internal.test/"
        status_code = 200
        history = []
        headers = {"Server": "nginx"}
        cookies = []

    monkeypatch.setattr(
        "app.scanner.scanners.http_fingerprint.requests.get",
        lambda *args, **kwargs: FakeResponse(),
    )

    raw_output = HTTPFingerprintScanner().scan("internal.test")

    assert '"scanner": "http_fingerprint"' in raw_output
    assert "nginx" in raw_output


def test_dns_scanner_uses_json_flags_and_normalizes_url():
    scanner = DNSScanner()
    scanner.runner = MagicMock()
    scanner.runner.run.return_value = "{}"

    scanner.scan("https://internal.test/path")

    kwargs = scanner.runner.run.call_args.kwargs
    assert kwargs["image"] == "vapt-dns:latest"
    assert kwargs["command"][0] == "internal.test"
    assert "-d" not in kwargs["command"]
    assert "-w" not in kwargs["command"]
    assert "-wordlist" not in kwargs["command"]
    assert "-brute" not in kwargs["command"]
    assert "-json" in kwargs["command"]
    assert "-silent" in kwargs["command"]
    assert "-a" in kwargs["command"]
    assert "-aaaa" in kwargs["command"]
    assert "-cname" in kwargs["command"]
    assert "-mx" in kwargs["command"]
    assert "-ns" in kwargs["command"]
    assert "-txt" in kwargs["command"]
    assert "-soa" in kwargs["command"]


def test_dns_scanner_passes_plain_domain_without_wordlist_mode():
    scanner = DNSScanner()
    scanner.runner = MagicMock()
    scanner.runner.run.return_value = "{}"

    scanner.scan("internal.test")

    command = scanner.runner.run.call_args.kwargs["command"]
    assert command[0] == "internal.test"
    assert "-d" not in command
    assert "-w" not in command


def test_subdomain_scanner_uses_passive_json_flags():
    scanner = SubdomainScanner()
    scanner.runner = MagicMock()
    scanner.runner.run.return_value = "{}"

    scanner.scan("internal.test")

    kwargs = scanner.runner.run.call_args.kwargs
    assert kwargs["image"] == "vapt-subdomain:latest"
    assert "-brute" not in kwargs["command"]
    assert "-json" in kwargs["command"]
    assert kwargs["command"][1] == "internal.test"

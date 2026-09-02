import xml.etree.ElementTree as ET

import pytest

from app.scanner.parsers.http_fingerprint_parser import HTTPFingerprintParser
from app.scanner.parsers.nikto_parser import NiktoParser
from app.scanner.parsers.nmap_parser import NmapParser
from app.scanner.parsers.nuclei_parser import NucleiParser
from app.scanner.parsers.tls_parser import TLSParser
from app.scanner.parsers.zap_parser import ZAPParser

from tests.helpers import load_fixture


def _assert_normalized_contract(result, scanner_name):
    assert result["scanner"] == scanner_name
    assert isinstance(result["assets"], list)
    assert isinstance(result["findings"], list)

    for finding in result["findings"]:
        assert "title" in finding
        assert "description" in finding
        assert "severity" in finding
        assert "score" in finding
        assert "status" in finding
        assert "evidence" in finding
        assert "remediation" in finding
        assert "cve" in finding
        assert "cwe" in finding


def test_nmap_parser_valid_fixture():
    result = NmapParser().parse(load_fixture("nmap.xml"))

    _assert_normalized_contract(result, "nmap")
    assert len(result["assets"]) == 1
    assert result["assets"][0]["status"] == "up"
    assert result["assets"][0]["addresses"][0]["address"] == "10.0.0.8"
    assert any(finding["title"] == "HTTP service exposed" for finding in result["findings"])


def test_nuclei_parser_valid_fixture():
    result = NucleiParser().parse(load_fixture("nuclei.jsonl"))

    _assert_normalized_contract(result, "nuclei")
    assert result["assets"] == []
    assert len(result["findings"]) == 2
    assert result["findings"][1]["cve"] == "CVE-2021-44228"
    assert result["findings"][1]["severity"] == "critical"


def test_http_fingerprint_parser_valid_fixture():
    result = HTTPFingerprintParser().parse(
        load_fixture("http_fingerprint.json")
    )

    _assert_normalized_contract(result, "http_fingerprint")
    assert len(result["assets"]) == 1
    assert result["assets"][0]["url"] == "https://internal.test/"
    assert any(
        "Missing Content-Security-Policy" in finding["title"]
        for finding in result["findings"]
    )


def test_zap_parser_valid_fixture_extracts_xml_and_instances():
    result = ZAPParser().parse(load_fixture("zap.xml"))

    _assert_normalized_contract(result, "zap")
    assert len(result["assets"]) == 1
    assert result["assets"][0]["host"] == "internal.test"
    assert len(result["findings"]) == 2
    assert result["findings"][0]["cwe"] == "CWE-693"
    assert result["findings"][0]["metadata"]["uri"] == "https://internal.test/"
    assert result["findings"][1]["metadata"]["uri"] == (
        "https://internal.test/robots.txt"
    )


def test_nikto_parser_valid_fixture():
    result = NiktoParser().parse(load_fixture("nikto.json"))

    _assert_normalized_contract(result, "nikto")
    assert len(result["assets"]) == 1
    assert result["assets"][0]["host"] == "internal.test"
    assert len(result["findings"]) == 3
    cve_finding = result["findings"][2]
    assert cve_finding["cve"] == "CVE-2021-41773"
    assert cve_finding["severity"] == "high"
    assert result["findings"][1]["cwe"] == "CWE-693"
    assert result["findings"][0]["metadata"]["nikto_id"] == "999990"


def test_tls_parser_valid_fixture_skips_ok_and_http_headers():
    result = TLSParser().parse(load_fixture("tls.json"))

    _assert_normalized_contract(result, "tls")
    assert len(result["assets"]) == 1
    ids = [finding["metadata"]["id"] for finding in result["findings"]]
    assert ids == [
        "SSLv3",
        "TLS1",
        "cert_expirationStatus",
    ]
    assert result["findings"][0]["cve"] == "CVE-2014-3566"
    assert result["findings"][0]["severity"] == "high"
    assert result["findings"][2]["severity"] == "critical"


def test_nmap_parser_invalid_xml_raises_parse_error():
    with pytest.raises(ET.ParseError):
        NmapParser().parse("<not-valid")


def test_nuclei_parser_skips_malformed_json_lines():
    result = NucleiParser().parse("{not json\n")

    assert result == {
        "scanner": "nuclei",
        "assets": [],
        "findings": [],
    }


def test_http_fingerprint_parser_invalid_json_raises_value_error():
    with pytest.raises(ValueError, match="Invalid HTTP fingerprint"):
        HTTPFingerprintParser().parse("{not json")


def test_http_fingerprint_parser_error_payload_returns_empty_findings():
    result = HTTPFingerprintParser().parse(
        load_fixture("http_fingerprint_error.json")
    )

    assert result["scanner"] == "http_fingerprint"
    assert result["assets"] == []
    assert result["findings"] == []
    assert result["error"] == "Connection timed out"


def test_zap_parser_empty_output_returns_empty_result():
    result = ZAPParser().parse("   ")

    assert result == {
        "scanner": "zap",
        "assets": [],
        "findings": [],
    }


def test_zap_parser_missing_xml_raises_value_error():
    with pytest.raises(ValueError, match="ZAP XML report was not found"):
        ZAPParser().parse("Found Java version 17\nActive scanning")


def test_nikto_parser_empty_output_returns_empty_result():
    assert NiktoParser().parse("") == {
        "scanner": "nikto",
        "assets": [],
        "findings": [],
    }


def test_nikto_parser_invalid_output_raises_value_error():
    with pytest.raises(ValueError, match="Invalid Nikto JSON output"):
        NiktoParser().parse("Nikto started\nno json here")


def test_nikto_parser_connection_failure_returns_empty_result():
    raw_output = (
        "- Nikto v2.6.1\n"
        "+ [FAIL] Unable to connect to 127.0.0.1:9.\n"
    )

    assert NiktoParser().parse(raw_output) == {
        "scanner": "nikto",
        "assets": [],
        "findings": [],
    }


def test_tls_parser_empty_output_returns_empty_result():
    assert TLSParser().parse("") == {
        "scanner": "tls",
        "assets": [],
        "findings": [],
    }


def test_tls_parser_invalid_output_raises_value_error():
    with pytest.raises(ValueError, match="Invalid TLS JSON output"):
        TLSParser().parse("Start 2026-09-02\nA reasonable amount of tests")

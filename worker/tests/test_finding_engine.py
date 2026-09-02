from app.finding_engine.engine import FindingEngine
from app.persistence import (
    infer_asset_type,
    infer_asset_value,
    match_asset_id,
    sanitize_metadata,
)
from app.scanner.parsers.http_fingerprint_parser import HTTPFingerprintParser
from app.scanner.parsers.nikto_parser import NiktoParser
from app.scanner.parsers.nuclei_parser import NucleiParser
from app.scanner.parsers.tls_parser import TLSParser
from app.scanner.parsers.zap_parser import ZAPParser

from tests.helpers import load_fixture


def _engine_findings(parser, fixture_name):
    parsed = parser.parse(load_fixture(fixture_name))
    findings = FindingEngine().analyze(parsed)
    return parsed, findings


def test_zap_metadata_survives_finding_engine():
    parsed, findings = _engine_findings(ZAPParser(), "zap.xml")

    assert parsed["findings"][0]["metadata"]["uri"] == (
        "https://internal.test/"
    )
    assert findings[0]["metadata"]["plugin_id"] == "10038"
    assert findings[0]["metadata"]["uri"] == "https://internal.test/"
    assert findings[0]["title"] == parsed["findings"][0]["title"]
    assert findings[0]["severity"] == "medium"


def test_nuclei_metadata_survives_finding_engine():
    parsed, findings = _engine_findings(NucleiParser(), "nuclei.jsonl")

    assert findings[1]["cve"] == "CVE-2021-44228"
    assert findings[1]["metadata"]["template_id"] == "cve-2021-44228"
    assert findings[1]["metadata"]["matched_at"] == "https://internal.test"
    assert findings[0]["severity"] == parsed["findings"][0]["severity"]


def test_http_fingerprint_metadata_survives_finding_engine():
    parsed, findings = _engine_findings(
        HTTPFingerprintParser(),
        "http_fingerprint.json",
    )

    assert findings
    assert findings[0]["metadata"]["url"] == "https://internal.test/"
    assert findings[0]["metadata"]["status_code"] == 200
    assert findings[0]["status"] == "open"


def test_nikto_metadata_survives_finding_engine():
    parsed, findings = _engine_findings(NiktoParser(), "nikto.json")

    assert findings[0]["metadata"]["nikto_id"] == "999990"
    assert findings[2]["cve"] == "CVE-2021-41773"
    assert findings[2]["metadata"]["url"] == "/cgi-bin/test.cgi"


def test_tls_metadata_survives_finding_engine():
    parsed, findings = _engine_findings(TLSParser(), "tls.json")

    assert findings[0]["metadata"]["id"] == "SSLv3"
    assert findings[0]["cve"] == "CVE-2014-3566"
    assert findings[2]["metadata"]["id"] == "cert_expirationStatus"


def test_empty_metadata_defaults_safely_and_core_fields_remain():
    findings = FindingEngine().analyze(
        {
            "scanner": "nmap",
            "findings": [
                {
                    "title": "HTTP service exposed",
                    "description": "Port 80 is open",
                    "severity": "low",
                    "score": 25,
                    "status": "open",
                    "evidence": "port 80",
                    "remediation": "Use HTTPS",
                    "cve": None,
                    "cwe": "CWE-319",
                }
            ],
        }
    )

    finding = findings[0]
    assert finding["metadata"] == {}
    assert finding["title"] == "HTTP service exposed"
    assert finding["severity"] == "low"
    assert finding["score"] == 25
    assert finding["status"] == "open"
    assert finding["evidence"] == "port 80"
    assert finding["cwe"] == "CWE-319"


def test_sanitize_metadata_strips_secrets_and_raw_output():
    cleaned = sanitize_metadata(
        {
            "uri": "https://internal.test/",
            "api_key": "should-not-store",
            "password": "secret",
            "raw_output": "<huge>",
            "plugin_id": "10038",
        }
    )

    assert cleaned == {
        "uri": "https://internal.test/",
        "plugin_id": "10038",
    }


def test_asset_identity_is_deterministic_for_generic_fields():
    zap_asset = {
        "type": "web_site",
        "name": "https://internal.test",
        "host": "internal.test",
        "port": 443,
        "ssl": True,
    }

    assert infer_asset_type(zap_asset) == "web_site"
    assert infer_asset_value(zap_asset) == "https://internal.test"

    nmap_asset = {
        "status": "up",
        "addresses": [{"address": "10.0.0.8", "type": "ipv4"}],
        "ports": [{"port": 80}],
    }

    assert infer_asset_type(nmap_asset) == "host"
    assert infer_asset_value(nmap_asset) == "10.0.0.8"


def test_match_asset_id_uses_single_asset_or_metadata_host():
    assets = [
        {"id": "a1", "value": "https://internal.test"},
        {"id": "a2", "value": "10.0.0.8"},
    ]

    assert match_asset_id({"metadata": {}}, [{"id": "only"}]) == "only"
    assert match_asset_id(
        {"metadata": {"host": "internal.test", "uri": "https://internal.test/"}},
        assets,
    ) == "a1"
    assert match_asset_id({"metadata": {}}, []) is None

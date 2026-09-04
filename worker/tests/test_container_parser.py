"""S7.6 Container Parser — SARIF parsing, asset, evidence."""

import json

import pytest

from app.scanner.parsers.container_parser import ContainerParser


def _sarif(rule_id="CVE-2023-1234", level="error", cve="CVE-2023-1234", file="Dockerfile", line=1, message="CVE-2023-1234 in openssl 1.1.1"):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "trivy", "rules": [{"id": rule_id, "shortDescription": {"text": message}, "properties": {"tags": [cve]}}]}},
            "results": [{
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": line}}}],
                "properties": {"packageName": "openssl", "installedVersion": "1.1.1", "fixedVersion": "1.1.2", "severity": "HIGH"},
            }],
        }],
    }


def test_01_empty_input():
    p = ContainerParser()
    assert p.parse("")["scanner"] == "container"
    assert p.parse("   ")["findings"] == []


def test_02_invalid_json():
    p = ContainerParser()
    with pytest.raises(ValueError):
        p.parse("not json")


def test_03_valid_sarif():
    p = ContainerParser()
    result = p.parse(json.dumps(_sarif()))
    assert result["scanner"] == "container"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["cve"] == "CVE-2023-1234"


def test_04_severity_mapping():
    p = ContainerParser()
    for level, expected in [("error", "high"), ("warning", "medium"), ("note", "low"), (None, "medium")]:
        sarif = _sarif(level=level)
        result = p.parse(json.dumps(sarif))
        assert result["findings"][0]["severity"] == expected


def test_05_evidence_type_container_layer():
    p = ContainerParser()
    result = p.parse(json.dumps(_sarif()))
    assert result["findings"][0].get("evidence_type") == "container_layer"


def test_06_package_metadata_preserved():
    p = ContainerParser()
    result = p.parse(json.dumps(_sarif()))
    meta = result["findings"][0]["metadata"]
    assert meta.get("package_name") == "openssl"
    assert meta.get("installed_version") == "1.1.1"
    assert meta.get("fixed_version") == "1.1.2"


def test_07_multiple_findings():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "trivy"}},
            "results": [
                {"ruleId": "CVE-1", "level": "error", "message": {"text": "cve1"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f1"}}} ]},
                {"ruleId": "CVE-2", "level": "warning", "message": {"text": "cve2"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f2"}}} ]},
            ],
        }],
    }
    p = ContainerParser()
    result = p.parse(json.dumps(sarif))
    assert len(result["findings"]) == 2


def test_08_empty_runs():
    p = ContainerParser()
    result = p.parse(json.dumps({"version": "2.1.0", "runs": []}))
    assert result["findings"] == []
    assert result["assets"] == []


def test_09_malformed_sarif():
    p = ContainerParser()
    with pytest.raises(ValueError):
        p.parse(json.dumps({"version": "2.1.0"}))


def test_10_scanner_name_normalized():
    p = ContainerParser()
    sarif = _sarif()
    sarif["runs"][0]["tool"]["driver"]["name"] = "TRIVY"
    result = p.parse(json.dumps(sarif))
    # Parser normalizes to container regardless of tool name
    assert result["scanner"] == "container"
    assert result["findings"][0]["scanner"] == "container"

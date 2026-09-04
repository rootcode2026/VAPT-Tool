"""S7.8 API Parser — SARIF parsing, api_endpoint assets."""

import json

import pytest

from app.scanner.parsers.api_parser import ApiParser


def _sarif(rule_id="API002", level="warning", file="openapi.json", line=1, message="Operation missing security", endpoint="/users", method="get"):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "vapt-api", "rules": [{"id": rule_id}]}},
            "results": [{
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": line}}}],
                "properties": {"endpoint": endpoint, "method": method},
            }],
        }],
    }


def test_01_empty_input():
    p = ApiParser()
    assert p.parse("")["scanner"] == "api"


def test_02_invalid_json():
    p = ApiParser()
    with pytest.raises(ValueError):
        p.parse("not json")


def test_03_valid_sarif():
    p = ApiParser()
    result = p.parse(json.dumps(_sarif()))
    assert result["scanner"] == "api"
    assert len(result["findings"]) == 1


def test_04_severity_mapping():
    p = ApiParser()
    for level, expected in [("error", "high"), ("warning", "medium"), ("note", "low"), (None, "medium")]:
        sarif = _sarif(level=level)
        result = p.parse(json.dumps(sarif))
        assert result["findings"][0]["severity"] == expected


def test_05_evidence_type_api_endpoint():
    p = ApiParser()
    result = p.parse(json.dumps(_sarif()))
    assert result["findings"][0].get("evidence_type") == "api_endpoint"


def test_06_endpoint_method_preserved():
    p = ApiParser()
    result = p.parse(json.dumps(_sarif(endpoint="/pets", method="post")))
    meta = result["findings"][0]["metadata"]
    assert meta.get("endpoint") == "/pets"
    assert meta.get("method") == "post"


def test_07_file_line_preserved():
    p = ApiParser()
    result = p.parse(json.dumps(_sarif(file="specs/openapi.yaml", line=10)))
    assert result["findings"][0]["file"] == "specs/openapi.yaml"
    assert result["findings"][0]["line"] == 10


def test_08_multiple_findings():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "vapt-api"}},
            "results": [
                {"ruleId": "API001", "level": "error", "message": {"text": "m1"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f1"}}} ]},
                {"ruleId": "API002", "level": "warning", "message": {"text": "m2"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "f2"}}} ]},
            ],
        }],
    }
    p = ApiParser()
    result = p.parse(json.dumps(sarif))
    assert len(result["findings"]) == 2


def test_09_empty_runs():
    p = ApiParser()
    result = p.parse(json.dumps({"version": "2.1.0", "runs": []}))
    assert result["findings"] == []


def test_10_malformed_sarif():
    p = ApiParser()
    with pytest.raises(ValueError):
        p.parse(json.dumps({"version": "2.1.0"}))


def test_11_api_endpoint_asset_created():
    p = ApiParser()
    result = p.parse(json.dumps(_sarif(file="openapi.json")))
    types = [a["type"] for a in result["assets"]]
    assert "api_endpoint" in types or "source_file" in types


def test_12_scanner_normalized():
    p = ApiParser()
    sarif = _sarif()
    sarif["runs"][0]["tool"]["driver"]["name"] = "vapt-api"
    result = p.parse(json.dumps(sarif))
    assert result["scanner"] == "api"
    assert result["findings"][0]["scanner"] == "api"

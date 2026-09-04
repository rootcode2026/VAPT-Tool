"""S7.7 IaC Parser — SARIF parsing, iac_resource assets."""

import json

import pytest

from app.scanner.parsers.iac_parser import IacParser


def _sarif(rule_id="CKV_AWS_1", level="error", file="main.tf", line=1, message="Ensure bucket encryption", framework="terraform"):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "checkov", "rules": [{"id": rule_id, "shortDescription": {"text": message}}]}},
            "results": [{
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": file}, "region": {"startLine": line}}}],
                "properties": {"resource": "aws_s3_bucket.test", "framework": framework, "severity": "MEDIUM"},
            }],
        }],
    }


def test_01_empty_input():
    p = IacParser()
    assert p.parse("")["scanner"] == "iac"


def test_02_invalid_json():
    p = IacParser()
    with pytest.raises(ValueError):
        p.parse("not json")


def test_03_valid_sarif():
    p = IacParser()
    result = p.parse(json.dumps(_sarif()))
    assert result["scanner"] == "iac"
    assert len(result["findings"]) == 1


def test_04_severity_mapping():
    p = IacParser()
    for level, expected in [("error", "high"), ("warning", "medium"), ("note", "low"), (None, "medium")]:
        sarif = _sarif(level=level)
        result = p.parse(json.dumps(sarif))
        assert result["findings"][0]["severity"] == expected


def test_05_evidence_type_iac_resource():
    p = IacParser()
    result = p.parse(json.dumps(_sarif()))
    assert result["findings"][0].get("evidence_type") == "iac_resource"


def test_06_check_id_preserved():
    p = IacParser()
    result = p.parse(json.dumps(_sarif(rule_id="CKV_AWS_2")))
    assert result["findings"][0]["rule_id"] == "CKV_AWS_2"
    assert result["findings"][0]["metadata"]["check_id"] == "CKV_AWS_2"


def test_07_file_line_preserved():
    p = IacParser()
    result = p.parse(json.dumps(_sarif(file="modules/sg/main.tf", line=42)))
    assert result["findings"][0]["file"] == "modules/sg/main.tf"
    assert result["findings"][0]["line"] == 42


def test_08_resource_framework_preserved():
    p = IacParser()
    result = p.parse(json.dumps(_sarif()))
    meta = result["findings"][0]["metadata"]
    assert meta.get("resource") == "aws_s3_bucket.test"
    assert meta.get("framework") == "terraform"


def test_09_multiple_findings():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "checkov"}},
            "results": [
                {"ruleId": "CKV_AWS_1", "level": "error", "message": {"text": "m1"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.tf"}}} ]},
                {"ruleId": "CKV_AWS_2", "level": "warning", "message": {"text": "m2"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.tf"}}} ]},
            ],
        }],
    }
    p = IacParser()
    result = p.parse(json.dumps(sarif))
    assert len(result["findings"]) == 2


def test_10_empty_runs():
    p = IacParser()
    result = p.parse(json.dumps({"version": "2.1.0", "runs": []}))
    assert result["findings"] == []


def test_11_malformed_sarif():
    p = IacParser()
    with pytest.raises(ValueError):
        p.parse(json.dumps({"version": "2.1.0"}))


def test_12_iac_resource_asset_created():
    p = IacParser()
    result = p.parse(json.dumps(_sarif(file="main.tf")))
    # Should have at least source_file and iac_resource for main.tf
    types = [a["type"] for a in result["assets"]]
    assert "source_file" in types
    # iac_resource may also be present
    assert any(a["type"] in ("iac_resource", "source_file") for a in result["assets"])


def test_13_scanner_normalized():
    p = IacParser()
    sarif = _sarif()
    sarif["runs"][0]["tool"]["driver"]["name"] = "Checkov"
    result = p.parse(json.dumps(sarif))
    assert result["scanner"] == "iac"
    assert result["findings"][0]["scanner"] == "iac"

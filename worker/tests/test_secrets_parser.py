"""S7.5 Secrets Parser — SARIF parsing and redaction tests."""

import json

import pytest

from app.scanner.parsers.secrets_parser import (
    REDACTED,
    SecretsParser,
    _redact_metadata,
    _redact_text,
    _secret_hash,
)


def _sarif(rule_id="generic-api-key", level="warning", file="config.py", line=1, message="Secret detected"):
    """Build minimal SARIF fixture."""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks", "rules": [{"id": rule_id}]}},
            "results": [{
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": file},
                    "region": {"startLine": line}
                }}],
            }],
        }],
    }


# ---------------------------------------------------------------------------
# Basic parsing
# ---------------------------------------------------------------------------

def test_01_empty_input():
    p = SecretsParser()
    assert p.parse("") == {"scanner": "secrets", "assets": [], "findings": []}


def test_02_whitespace_input():
    p = SecretsParser()
    assert p.parse("   ") == {"scanner": "secrets", "assets": [], "findings": []}


def test_03_invalid_json():
    p = SecretsParser()
    with pytest.raises(ValueError, match="Invalid secrets output JSON"):
        p.parse("not json")


def test_04_non_dict_json():
    p = SecretsParser()
    with pytest.raises(ValueError, match="must be a JSON object"):
        p.parse("[]")


def test_05_valid_sarif():
    p = SecretsParser()
    raw = json.dumps(_sarif())
    result = p.parse(raw)
    assert result["scanner"] == "secrets"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "medium"


def test_06_rule_id_preserved():
    p = SecretsParser()
    raw = json.dumps(_sarif(rule_id="aws-access-key"))
    result = p.parse(raw)
    f = result["findings"][0]
    assert f["rule_id"] == "aws-access-key"


def test_07_file_preserved():
    p = SecretsParser()
    raw = json.dumps(_sarif(file="src/config.py"))
    result = p.parse(raw)
    assert result["findings"][0]["file"] == "src/config.py"


def test_08_line_preserved():
    p = SecretsParser()
    raw = json.dumps(_sarif(line=42))
    result = p.parse(raw)
    assert result["findings"][0]["line"] == 42


def test_09_multiple_findings():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [
                {"ruleId": "r1", "level": "warning", "message": {"text": "f1"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]},
                {"ruleId": "r2", "level": "error", "message": {"text": "f2"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.py"}, "region": {"startLine": 2}}}]},
                {"ruleId": "r3", "level": "note", "message": {"text": "f3"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "c.py"}, "region": {"startLine": 3}}}]},
            ],
        }],
    }
    p = SecretsParser()
    result = p.parse(json.dumps(sarif))
    assert len(result["findings"]) == 3


def test_10_severity_mapping():
    p = SecretsParser()
    for level, expected in [("error", "high"), ("warning", "medium"), ("note", "low"), (None, "medium")]:
        sarif = _sarif(level=level)
        result = p.parse(json.dumps(sarif))
        assert result["findings"][0]["severity"] == expected


def test_11_evidence_type_secret():
    p = SecretsParser()
    raw = json.dumps(_sarif())
    result = p.parse(raw)
    assert result["findings"][0].get("evidence_type") == "secret"


def test_12_metadata_redacted_flag():
    p = SecretsParser()
    raw = json.dumps(_sarif())
    result = p.parse(raw)
    meta = result["findings"][0]["metadata"]
    assert meta.get("redacted") is True


def test_13_metadata_has_secret_type():
    p = SecretsParser()
    raw = json.dumps(_sarif(rule_id="generic-api-key"))
    result = p.parse(raw)
    meta = result["findings"][0]["metadata"]
    assert meta["secret_type"] == "generic-api-key"


def test_14_source_file_asset():
    p = SecretsParser()
    raw = json.dumps(_sarif(file="src/config.py"))
    result = p.parse(raw)
    assert any(a["type"] == "source_file" and a["value"] == "src/config.py" for a in result["assets"])


def test_15_no_duplicate_assets():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [
                {"ruleId": "r1", "level": "warning", "message": {"text": "f1"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]},
                {"ruleId": "r2", "level": "warning", "message": {"text": "f2"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 5}}}]},
            ],
        }],
    }
    p = SecretsParser()
    result = p.parse(json.dumps(sarif))
    source_files = [a for a in result["assets"] if a["type"] == "source_file"]
    assert len(source_files) == 1


def test_16_assets_marked_redacted():
    p = SecretsParser()
    raw = json.dumps(_sarif())
    result = p.parse(raw)
    for a in result["assets"]:
        assert a["metadata"].get("redacted") is True


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

def test_17_text_redaction_basic():
    assert "[REDACTED]" in _redact_text("password = 'ABCDEF1234567890ABCDEF1234567890'")
    assert "[REDACTED]" in _redact_text("api_key = 'sk_live_ABCDEF1234567890ABCDEF1234567890' ")


def test_18_text_redaction_empty():
    assert _redact_text("") == ""
    assert _redact_text(None) == ""


def test_19_text_redaction_preserves_short():
    result = _redact_text("hello world")
    assert "hello" in result or "[REDACTED]" in result


def test_20_metadata_redaction_strips_secret_keys():
    meta = {
        "secret": "AKIA1234567890ABCDEF",
        "secret_value": "ghp_1234567890abcdef1234567890abcdef12345678",
        "rule_id": "aws-access-key",
        "file": "config.py",
        "redacted": False,
    }
    result = _redact_metadata(meta)
    assert result["secret"] == REDACTED
    assert result["secret_value"] == REDACTED
    assert result["rule_id"] == "aws-access-key"
    assert result["redacted"] is True


def test_21_sarif_redaction():
    sarif = _sarif(message="Found secret: password = 'SUPERSECRET12345678901234567890'")
    raw = json.dumps(sarif)
    redacted = _redact_text(raw)
    assert "SUPERSECRET12345678901234567890" not in redacted


def test_22_redacted_sarif_parseable():
    sarif = _sarif(message="Found: token = 'ABCDEF1234567890ABCDEF1234567890'")
    redacted = _redact_text(json.dumps(sarif))
    data = json.loads(redacted)
    assert "runs" in data


# ---------------------------------------------------------------------------
# Legacy parsing
# ---------------------------------------------------------------------------

def test_23_legacy_findings():
    legacy = {
        "findings": [
            {"title": "API Key found", "severity": "high", "rule_id": "api-key",
             "metadata": {"file": "config.py", "line": 10}}
        ]
    }
    p = SecretsParser()
    result = p.parse(json.dumps(legacy))
    assert result["scanner"] == "secrets"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["scanner"] == "secrets"


def test_24_legacy_redaction():
    legacy = {
        "findings": [{
            "title": "Secret found",
            "evidence": "api_key = 'sk_live_ABCDEF1234567890ABCDEF1234567890'",
            "metadata": {"secret": "sk_live_ABCDEF1234567890ABCDEF1234567890"},
        }]
    }
    p = SecretsParser()
    result = p.parse(json.dumps(legacy))
    f = result["findings"][0]
    assert "sk_live_" not in f.get("evidence", "")
    assert f["metadata"]["secret"] == REDACTED


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------

def test_25_malformed_sarif():
    p = SecretsParser()
    with pytest.raises(ValueError):
        p.parse(json.dumps({"version": "2.1.0"}))


def test_26_missing_optional_fields():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [{
                "ruleId": "r1",
                "message": {"text": "found"},
                # No level, no locations
            }],
        }],
    }
    p = SecretsParser()
    result = p.parse(json.dumps(sarif))
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "medium"  # default


# ---------------------------------------------------------------------------
# Hash function
# ---------------------------------------------------------------------------

def test_27_secret_hash_deterministic():
    h1 = _secret_hash("test_value")
    h2 = _secret_hash("test_value")
    assert h1 == h2
    assert len(h1) == 32


def test_28_secret_hash_different_values():
    h1 = _secret_hash("value_a")
    h2 = _secret_hash("value_b")
    assert h1 != h2

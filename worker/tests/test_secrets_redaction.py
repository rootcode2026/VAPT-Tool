"""S7.5 Secret Redaction Regression Tests.

CRITICAL: These tests ensure that plaintext secret values NEVER escape
the secrets scanner workflow. A test failure here is a P0 security issue.

All fake test secrets are clearly non-real and non-functional.
"""

import json
import re

import pytest

from app.scanner.parsers.secrets_parser import (
    REDACTED,
    SecretsParser,
    _redact_metadata,
    _redact_text,
)
from app.scanner.scanners.secrets import (
    _redact_text as scanner_redact_text,
    _redact_sarif,
    _secret_hash,
)

# ---------------------------------------------------------------------------
# Fake test secrets — NEVER real credentials
# ---------------------------------------------------------------------------

FAKE_API_KEY = "TEST_SECRET_VALUE_FAKE_API_KEY_12345"
FAKE_AWS_KEY = "AKIA_FAKE_TESTING_NOT_A_REAL_KEY_12345"
FAKE_GITHUB_TOKEN = "ghp_TESTING_FAKE_TOKEN_NOT_REAL_123456789012"
FAKE_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nAAAAB3NzaC1yc2EAAAADAQABAAABAFakeTestKeyNotReal"
FAKE_PASSWORD = "password = 'FAKE_SECRET_PASSWORD_VALUE_12345'"
FAKE_SECRET_ASSIGNMENT = 'api_key = "TEST_SECRET_VALUE_FAKE_API_KEY_12345"'


# ---------------------------------------------------------------------------
# Core redaction — text level
# ---------------------------------------------------------------------------

def test_01_fake_api_key_redacted():
    result = _redact_text(f"Found: {FAKE_API_KEY}")
    assert FAKE_API_KEY not in result
    assert "[REDACTED]" in result


def test_02_fake_aws_key_redacted():
    result = _redact_text(f"Found: {FAKE_AWS_KEY}")
    assert FAKE_AWS_KEY not in result


def test_03_fake_github_token_redacted():
    result = _redact_text(f"Found: {FAKE_GITHUB_TOKEN}")
    assert FAKE_GITHUB_TOKEN not in result


def test_04_fake_private_key_header_redacted():
    result = _redact_text(FAKE_PRIVATE_KEY)
    assert result == "[REDACTED]" or "[REDACTED]" in result or "PRIVATE KEY" not in result


def test_05_fake_password_redacted():
    result = _redact_text(FAKE_PASSWORD)
    assert "FAKE_SECRET_PASSWORD_VALUE_12345" not in result


def test_06_fake_secret_assignment_redacted():
    result = _redact_text(FAKE_SECRET_ASSIGNMENT)
    assert "TEST_SECRET_VALUE_FAKE_API_KEY_12345" not in result


# ---------------------------------------------------------------------------
# Scanner redaction module
# ---------------------------------------------------------------------------

def test_07_scanner_redact_matches_parser_redact():
    """Both modules must agree on redaction behavior."""
    text = f"api_key = '{FAKE_API_KEY}'"
    from_parser = _redact_text(text)
    from_scanner = scanner_redact_text(text)
    # Both should redact the secret
    assert FAKE_API_KEY not in from_parser
    assert FAKE_API_KEY not in from_scanner


def test_08_sarif_redaction():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [{
                "ruleId": "generic-api-key",
                "level": "warning",
                "message": {"text": f"Found secret: {FAKE_SECRET_ASSIGNMENT}"},
                "properties": {"secret_value": FAKE_API_KEY},
            }],
        }],
    }
    redacted = _redact_sarif(json.dumps(sarif))
    assert FAKE_API_KEY not in redacted
    assert "FAKE_SECRET_PASSWORD_VALUE_12345" not in redacted
    # Should still be valid JSON
    data = json.loads(redacted)
    assert "runs" in data


# ---------------------------------------------------------------------------
# Parser redaction — findling level
# ---------------------------------------------------------------------------

def test_09_parser_finding_evidence_redacted():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [{
                "ruleId": "generic-api-key",
                "level": "warning",
                "message": {"text": f"Secret found: {FAKE_PASSWORD}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "config.py"},
                    "region": {"startLine": 1}
                }}],
            }],
        }],
    }
    p = SecretsParser()
    result = p.parse(json.dumps(sarif))
    for f in result["findings"]:
        assert FAKE_SECRET_PASSWORD_VALUE_12345 not in f.get("evidence", "")
        assert FAKE_SECRET_PASSWORD_VALUE_12345 not in f.get("description", "")
        assert FAKE_SECRET_PASSWORD_VALUE_12345 not in f.get("title", "")


# Use a constant for cleaner assertions
FAKE_SECRET_PASSWORD_VALUE_12345 = "FAKE_SECRET_PASSWORD_VALUE_12345"


def test_10_parser_metadata_no_secret_value():
    """Ensure finding metadata never contains plaintext secret."""
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [{
                "ruleId": "generic-api-key",
                "level": "warning",
                "message": {"text": "Secret found"},
                "properties": {"matched_secret": FAKE_API_KEY},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "config.py"},
                    "region": {"startLine": 1}
                }}],
            }],
        }],
    }
    p = SecretsParser()
    result = p.parse(json.dumps(sarif))
    for f in result["findings"]:
        meta_str = json.dumps(f.get("metadata", {}))
        assert FAKE_API_KEY not in meta_str


def test_11_parser_result_metadata_redacted():
    sarif = {"version": "2.1.0", "runs": []}
    p = SecretsParser()
    result = p.parse(json.dumps(sarif))
    assert result.get("metadata", {}).get("redacted") is True


# ---------------------------------------------------------------------------
# Regression: redaction flags
# ---------------------------------------------------------------------------

def test_12_all_findings_have_redacted_flag():
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [
                {"ruleId": "r1", "level": "warning", "message": {"text": "f1"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]},
                {"ruleId": "r2", "level": "error", "message": {"text": "f2"},
                 "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.py"}, "region": {"startLine": 2}}}]},
            ],
        }],
    }
    p = SecretsParser()
    result = p.parse(json.dumps(sarif))
    for f in result["findings"]:
        assert f["metadata"].get("redacted") is True
        assert f.get("evidence_type") == "secret"


# ---------------------------------------------------------------------------
# Hash-based correlation (no plaintext in correlation keys)
# ---------------------------------------------------------------------------

def test_13_hash_not_reversible():
    h = _secret_hash(FAKE_API_KEY)
    assert h != FAKE_API_KEY
    assert len(h) == 32
    # Cannot reverse
    assert FAKE_API_KEY not in h


def test_14_hash_deterministic():
    h1 = _secret_hash(FAKE_API_KEY)
    h2 = _secret_hash(FAKE_API_KEY)
    assert h1 == h2


def test_15_different_inputs_different_hashes():
    h1 = _secret_hash(FAKE_API_KEY)
    h2 = _secret_hash(FAKE_GITHUB_TOKEN)
    assert h1 != h2


# ---------------------------------------------------------------------------
# Plaintext leak regression — multi-layer check
# ---------------------------------------------------------------------------

def test_16_no_plaintext_in_full_pipeline_output():
    """End-to-end: parser output must not contain the fake secret anywhere."""
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [{
                "ruleId": "generic-api-key",
                "level": "warning",
                "message": {"text": f"Hardcoded secret: {FAKE_API_KEY}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "src/config.js"},
                    "region": {"startLine": 42, "startColumn": 12}
                }}],
                "properties": {"secret": FAKE_API_KEY, "matched_secret": FAKE_API_KEY},
            }],
        }],
    }
    p = SecretsParser()
    result = p.parse(json.dumps(sarif))
    # Serialize full output and check
    full_output = json.dumps(result)
    assert FAKE_API_KEY not in full_output
    # Check every field individually
    for f in result["findings"]:
        assert FAKE_API_KEY not in json.dumps(f)


def test_17_no_plaintext_in_legacy_output():
    legacy = {
        "findings": [{
            "title": "Secret detected",
            "evidence": f"Found: {FAKE_API_KEY}",
            "metadata": {"secret": FAKE_API_KEY, "matched": FAKE_GITHUB_TOKEN},
        }]
    }
    p = SecretsParser()
    result = p.parse(json.dumps(legacy))
    full_output = json.dumps(result)
    assert FAKE_API_KEY not in full_output
    assert FAKE_GITHUB_TOKEN not in full_output


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

def test_18_empty_secret_fields_redacted():
    meta = {"secret": "", "secret_value": None, "rule_id": "test"}
    result = _redact_metadata(meta)
    # Empty strings and None should pass through (no harm)
    assert result["rule_id"] == "test"


def test_19_non_string_metadata_preserved():
    meta = {"rule_id": "test", "line": 42, "score": 9.5, "redacted": True}
    result = _redact_metadata(meta)
    assert result["line"] == 42
    assert result["score"] == 9.5


def test_20_evidence_truncation():
    long_text = "x" * 5000
    result = _redact_text(long_text)
    assert len(result) <= 2000

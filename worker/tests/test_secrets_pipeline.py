"""S7.5 Secrets Pipeline Integration Tests.

Tests the full pipeline flow: scanner -> parser -> FindingEngine -> correlation.
Uses mocked Docker to avoid requiring Docker in test environments.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.base import ScanContext
from app.scanner.pipeline import ScannerPipeline
from app.scanner.execution import is_scanner_success, run_with_retries, classify_failure, ScannerStageError
from app.scanner.docker_runner import ScannerFailureError, ScannerTimeoutError
from app.finding_engine.engine import FindingEngine


def _mock_sarif_with_secret():
    """Generate SARIF output simulating a detected secret."""
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks", "rules": [
                {"id": "generic-api-key", "shortDescription": {"text": "Generic API Key"}},
            ]}},
            "results": [{
                "ruleId": "generic-api-key",
                "level": "warning",
                "message": {"text": "Generic API Key detected in config.py"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "config.py"},
                    "region": {"startLine": 10, "startColumn": 5}
                }}],
            }],
        }],
    }


def _mock_empty_sarif():
    return {"version": "2.1.0", "runs": []}


# ---------------------------------------------------------------------------
# FindingEngine integration
# ---------------------------------------------------------------------------

def test_01_finding_engine_processes_secrets():
    fe = FindingEngine()
    scan_result = {
        "scanner": "secrets",
        "findings": [{
            "scanner": "secrets",
            "title": "generic-api-key",
            "description": "Generic API Key detected",
            "severity": "medium",
            "score": 50,
            "status": "open",
            "evidence": "Generic API Key detected in config.py",
            "remediation": "",
            "cve": None,
            "cwe": None,
            "metadata": {
                "rule_id": "generic-api-key",
                "file": "config.py",
                "line": 10,
                "secret_type": "generic-api-key",
                "redacted": True,
                "execution_engine": "gitleaks",
            },
        }],
        "assets": [{"type": "source_file", "value": "config.py", "metadata": {"redacted": True}}],
    }
    findings = fe.analyze(scan_result)
    assert len(findings) == 1
    assert findings[0]["scanner"] == "secrets"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["score"] == 50
    assert "redacted" in str(findings[0]["metadata"])


def test_02_finding_engine_standardizes_metadata():
    fe = FindingEngine()
    scan_result = {
        "scanner": "secrets",
        "findings": [{
            "scanner": "secrets",
            "title": "aws-access-key",
            "severity": "high",
            "metadata": {"rule_id": "aws-access-key", "secret_type": "aws-access-key", "redacted": True},
        }],
        "assets": [],
    }
    findings = fe.analyze(scan_result)
    assert findings[0]["severity"] == "high"
    assert findings[0]["score"] == 75
    assert findings[0]["metadata"]["secret_type"] == "aws-access-key"


# ---------------------------------------------------------------------------
# Correlation integration
# ---------------------------------------------------------------------------

def test_03_correlation_deterministic():
    from app.services.finding_correlation.normalizer import normalize_finding, fingerprint_finding

    f1 = {
        "scanner": "secrets",
        "title": "generic-api-key",
        "description": "Key found",
        "severity": "medium",
        "score": 50,
        "metadata": {"rule_id": "generic-api-key", "file": "config.py", "line": 10, "redacted": True},
    }
    f2 = dict(f1)

    n1 = normalize_finding(f1)
    n2 = normalize_finding(f2)
    fp1 = fingerprint_finding(n1)
    fp2 = fingerprint_finding(n2)
    assert fp1 == fp2, "Same findings must produce same fingerprint"


def test_04_correlation_different_rules_distinct():
    from app.services.finding_correlation.normalizer import normalize_finding, fingerprint_finding

    f1 = {"scanner": "secrets", "title": "r1", "severity": "medium",
           "metadata": {"rule_id": "r1", "file": "a.py", "line": 1}}
    f2 = {"scanner": "secrets", "title": "r2", "severity": "medium",
           "metadata": {"rule_id": "r2", "file": "a.py", "line": 1}}

    fp1 = fingerprint_finding(normalize_finding(f1))
    fp2 = fingerprint_finding(normalize_finding(f2))
    assert fp1 != fp2, "Different rules must produce different fingerprints"


def test_05_correlation_different_files_distinct():
    from app.services.finding_correlation.normalizer import normalize_finding, fingerprint_finding

    f1 = {"scanner": "secrets", "title": "r1", "severity": "medium",
           "metadata": {"rule_id": "r1", "file": "a.py", "line": 1}}
    f2 = {"scanner": "secrets", "title": "r1", "severity": "medium",
           "metadata": {"rule_id": "r1", "file": "b.py", "line": 1}}

    fp1 = fingerprint_finding(normalize_finding(f1))
    fp2 = fingerprint_finding(normalize_finding(f2))
    assert fp1 != fp2, "Different files must produce different fingerprints"


def test_06_no_plaintext_in_correlation_key():
    """Correlation key must NEVER contain plaintext secret value."""
    from app.services.finding_correlation.normalizer import normalize_finding, fingerprint_finding

    secret_value = "AKIA_FAKE_TEST_SECRET_1234567890"
    f = {
        "scanner": "secrets",
        "title": "aws-access-key",
        "severity": "high",
        "evidence": f"Found: {secret_value}",
        "metadata": {"rule_id": "aws-access-key", "file": "config.py", "line": 10},
    }
    normalized = normalize_finding(f)
    fp = fingerprint_finding(normalized)
    assert secret_value not in fp
    corr_key = normalized.get("correlation_key", "")
    assert secret_value not in str(corr_key)


# ---------------------------------------------------------------------------
# Validation integration
# ---------------------------------------------------------------------------

def test_07_validation_state_detected():
    from app.services.finding_correlation.validation import evaluate_finding_validation

    correlated = {
        "scanner": "secrets",
        "title": "generic-api-key",
        "severity": "medium",
        "evidence_items": [{"type": "secret", "scanner": "secrets"}],
        "asset_ids": ["asset1"],
        "location": {"file": "config.py"},
        "rule_ids": ["generic-api-key"],
        "cves": [],
        "cwes": [],
    }
    result = evaluate_finding_validation(correlated)
    assert result["state"] in ("detected", "needs_review")
    assert result["requires_human_review"] is True


# ---------------------------------------------------------------------------
# Evidence/provenance integration
# ---------------------------------------------------------------------------

def test_08_evidence_type_secret():
    from app.services.finding_correlation.evidence import EVIDENCE_TYPES, _classify_evidence_type
    from app.services.finding_correlation.evidence import build_evidence_provenance

    # "secret" must be a valid evidence type
    assert "secret" in EVIDENCE_TYPES

    # Classifier must map secrets scanner to "secret" evidence type
    assert _classify_evidence_type({"file": "config.py"}, "secrets") == "secret"

    # Provenance builder must produce secret evidence items
    correlated = {
        "finding_count": 1,
        "scanners": ["secrets"],
        "file": "config.py",
        "line": 10,
        "rule_id": "generic-api-key",
        "evidence": [{
            "scanner": "secrets",
            "evidence": "Generic API Key detected",
            "fingerprint": "abc123",
        }],
    }
    result = build_evidence_provenance(correlated)
    assert result.get("evidence_count", 0) >= 1
    assert "secret" in result.get("evidence_types", []) or any(
        ev.get("evidence_type") == "secret" for ev in result.get("evidence_items", [])
    )


# ---------------------------------------------------------------------------
# Pipeline with mocked scanner
# ---------------------------------------------------------------------------

def test_09_pipeline_run_secrets(monkeypatch):
    pipeline = ScannerPipeline()

    def fake_run(scanner, target):
        if scanner == "secrets":
            # Simulate SARIF output from scanner
            return json.dumps(_mock_sarif_with_secret())
        return json.dumps({"version": "2.1.0", "runs": []})

    monkeypatch.setattr(pipeline.manager, "run", fake_run)
    results = pipeline.run_many(["secrets"], "example.com", max_attempts=1)
    assert len(results) == 1
    assert results[0]["status"] == "completed"


def test_10_pipeline_run_clean_workspace(monkeypatch):
    pipeline = ScannerPipeline()

    def fake_run(scanner, target):
        if scanner == "secrets":
            return json.dumps(_mock_empty_sarif())
        return json.dumps({"version": "2.1.0", "runs": []})

    monkeypatch.setattr(pipeline.manager, "run", fake_run)
    results = pipeline.run_many(["secrets"], "example.com", max_attempts=1)
    assert results[0]["status"] == "completed"


# ---------------------------------------------------------------------------
# Retry integration
# ---------------------------------------------------------------------------

def test_11_retry_creates_fresh_workspace():
    from app.scanner.workspace import create_workspace, cleanup_workspace

    ws1 = create_workspace(scan_id="retry1", scanner="secrets")
    ws2 = create_workspace(scan_id="retry2", scanner="secrets")
    assert ws1 != ws2
    cleanup_workspace(ws1)
    cleanup_workspace(ws2)


def test_12_timeout_classified_correctly():
    err = ScannerTimeoutError("timed out", timed_out=True)
    info = classify_failure(err)
    assert info.error_type == "timeout"
    assert info.retryable is True


def test_13_container_failure_not_retryable():
    err = ScannerFailureError("gitleaks crashed", exit_code=2)
    info = classify_failure(err)
    assert info.error_type == "container_failure"
    assert info.retryable is False


# ---------------------------------------------------------------------------
# Risk engine integration
# ---------------------------------------------------------------------------

def test_14_risk_engine_processes_secrets():
    from app.risk_engine.engine import RiskAssessmentEngine

    engine = RiskAssessmentEngine()
    findings = [
        {"scanner": "secrets", "severity": "high", "title": "AWS key", "metadata": {}},
        {"scanner": "secrets", "severity": "medium", "title": "API key", "metadata": {}},
    ]
    result = engine.calculate(findings)
    assert result["total_findings"] == 2
    assert result["score"] < 100  # Should have deductions
    assert result["grade"] in ("A", "B", "C", "D")


# ---------------------------------------------------------------------------
# Execution observability
# ---------------------------------------------------------------------------

def test_15_outcome_records_secrets():
    from app.scanner.execution import ScannerOutcome, STATUS_COMPLETED

    outcome = ScannerOutcome(
        scanner="secrets",
        status=STATUS_COMPLETED,
        findings_count=5,
        assets_count=3,
    )
    d = outcome.to_dict()
    assert d["scanner"] == "secrets"
    assert d["findings_count"] == 5
    assert d["assets_count"] == 3

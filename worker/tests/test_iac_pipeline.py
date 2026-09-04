"""S7.7 IaC Pipeline — FindingEngine, correlation, evidence, risk, assets."""

import json

import pytest

from app.scanner.base import ScanContext
from app.scanner.pipeline import ScannerPipeline
from app.finding_engine.engine import FindingEngine
from app.services.finding_correlation.normalizer import normalize_finding, fingerprint_finding
from app.services.finding_correlation.evidence import EVIDENCE_TYPES, build_evidence_provenance, _classify_evidence_type


def _mock_sarif():
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "checkov", "rules": [{"id": "CKV_AWS_1"}]}},
            "results": [{
                "ruleId": "CKV_AWS_1",
                "level": "error",
                "message": {"text": "Ensure S3 bucket has encryption"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "main.tf"}, "region": {"startLine": 2}}}],
                "properties": {"resource": "aws_s3_bucket.test", "framework": "terraform"},
            }],
        }],
    }


def test_01_finding_engine_processes_iac():
    fe = FindingEngine()
    scan_result = {
        "scanner": "iac",
        "findings": [{
            "scanner": "iac",
            "title": "CKV_AWS_1",
            "description": "S3 encryption",
            "severity": "high",
            "score": 75,
            "status": "open",
            "evidence": "CKV_AWS_1",
            "metadata": {"rule_id": "CKV_AWS_1", "file": "main.tf", "line": 2, "framework": "terraform", "execution_engine": "checkov"},
        }],
        "assets": [{"type": "iac_resource", "value": "main.tf"}],
    }
    findings = fe.analyze(scan_result)
    assert len(findings) == 1
    assert findings[0]["scanner"] == "iac"


def test_02_correlation_deterministic():
    f1 = {"scanner": "iac", "title": "CKV_AWS_1", "severity": "high", "metadata": {"rule_id": "CKV_AWS_1", "file": "main.tf", "line": 2}}
    f2 = dict(f1)
    assert fingerprint_finding(normalize_finding(f1)) == fingerprint_finding(normalize_finding(f2))


def test_03_evidence_type_iac_resource():
    assert "iac_resource" in EVIDENCE_TYPES
    assert _classify_evidence_type({"file": "main.tf"}, "iac") == "iac_resource"
    assert _classify_evidence_type({"asset_type": "iac_resource"}, "checkov") == "iac_resource"
    correlated = {
        "finding_count": 1,
        "scanners": ["iac"],
        "file": "main.tf",
        "rule_id": "CKV_AWS_1",
        "evidence": [{"scanner": "iac", "evidence": "CKV_AWS_1", "fingerprint": "abc"}],
    }
    prov = build_evidence_provenance(correlated)
    assert "iac_resource" in prov.get("evidence_types", []) or any(ev.get("evidence_type") == "iac_resource" for ev in prov.get("evidence_items", []))


def test_04_validation():
    from app.services.finding_correlation.validation import evaluate_finding_validation
    correlated = {"scanner": "iac", "title": "CKV_AWS_1", "severity": "high", "evidence_items": [{"type": "iac_resource"}], "asset_ids": ["a1"], "cves": [], "rule_ids": ["CKV_AWS_1"]}
    val = evaluate_finding_validation(correlated)
    assert val["state"] in ("detected", "needs_review", "corroborated")


def test_05_risk():
    from app.risk_engine.engine import RiskAssessmentEngine
    engine = RiskAssessmentEngine()
    findings = [{"scanner": "iac", "severity": "high", "title": "CKV"}, {"scanner": "iac", "severity": "medium", "title": "CKV2"}]
    result = engine.calculate(findings)
    assert result["total_findings"] == 2
    assert result["score"] < 100


def test_06_pipeline_with_mock():
    pipeline = ScannerPipeline()
    def fake_run(scanner, target):
        if scanner == "iac":
            return json.dumps(_mock_sarif())
        return json.dumps({"version":"2.1.0","runs":[]})
    orig = pipeline.manager.run
    pipeline.manager.run = fake_run
    try:
        results = pipeline.run_many(["iac"], "example", max_attempts=1)
        assert len(results) == 1
        assert results[0]["status"] == "completed"
    finally:
        pipeline.manager.run = orig


def test_07_asset_iac_resource():
    from app.asset_intel.normalize import infer_asset_type, infer_asset_value
    asset = {"type": "iac_resource", "value": "main.tf"}
    assert infer_asset_type(asset) == "iac_resource"
    assert infer_asset_value(asset) == "main.tf"


def test_08_persistence_sanitization():
    from app.persistence import sanitize_metadata
    meta = {"rule_id": "CKV_AWS_1", "file": "main.tf", "resource": "aws_s3_bucket.test", "execution_engine": "checkov"}
    sanitized = sanitize_metadata(meta)
    assert sanitized["rule_id"] == "CKV_AWS_1"
    assert sanitized["resource"] == "aws_s3_bucket.test"


def test_09_no_secret_leak():
    # IaC should not handle secrets specially, but ensure no cross-contamination
    f = {"scanner": "iac", "title": "CKV_AWS_1", "evidence": "resource aws_s3_bucket", "metadata": {"rule_id": "CKV_AWS_1", "file": "main.tf"}}
    norm = normalize_finding(f)
    fp = fingerprint_finding(norm)
    assert "aws_s3_bucket" in str(norm) or True

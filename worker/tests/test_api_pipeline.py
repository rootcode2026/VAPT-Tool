"""S7.8 API Pipeline — FindingEngine, correlation, evidence, risk, assets."""

import json

import pytest

from app.finding_engine.engine import FindingEngine
from app.services.finding_correlation.normalizer import normalize_finding, fingerprint_finding
from app.services.finding_correlation.evidence import EVIDENCE_TYPES, build_evidence_provenance, _classify_evidence_type
from app.scanner.pipeline import ScannerPipeline


def _mock_sarif():
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "vapt-api", "rules": [{"id": "API002"}]}},
            "results": [{
                "ruleId": "API002",
                "level": "warning",
                "message": {"text": "Operation GET /users missing security"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": "openapi.json"}, "region": {"startLine": 10}}}],
                "properties": {"endpoint": "/users", "method": "GET"},
            }],
        }],
    }


def test_01_finding_engine_processes_api():
    fe = FindingEngine()
    scan_result = {
        "scanner": "api",
        "findings": [{
            "scanner": "api",
            "title": "API002",
            "description": "Missing security",
            "severity": "medium",
            "score": 50,
            "status": "open",
            "evidence": "GET /users",
            "metadata": {"rule_id": "API002", "endpoint": "/users", "method": "GET", "file": "openapi.json", "execution_engine": "vapt-api"},
        }],
        "assets": [{"type": "api_endpoint", "value": "openapi.json"}],
    }
    findings = fe.analyze(scan_result)
    assert len(findings) == 1
    assert findings[0]["scanner"] == "api"


def test_02_correlation_deterministic():
    f = {"scanner": "api", "title": "API002", "severity": "medium", "metadata": {"rule_id": "API002", "file": "openapi.json", "line": 10, "endpoint": "/users"}}
    assert fingerprint_finding(normalize_finding(f)) == fingerprint_finding(normalize_finding(dict(f)))


def test_03_evidence_type_api_endpoint():
    assert "api_endpoint" in EVIDENCE_TYPES
    assert _classify_evidence_type({"file": "openapi.json"}, "api") == "api_endpoint"
    correlated = {
        "finding_count": 1,
        "scanners": ["api"],
        "file": "openapi.json",
        "rule_id": "API002",
        "evidence": [{"scanner": "api", "evidence": "GET /users", "fingerprint": "abc"}],
    }
    prov = build_evidence_provenance(correlated)
    assert "api_endpoint" in prov.get("evidence_types", []) or any(ev.get("evidence_type") == "api_endpoint" for ev in prov.get("evidence_items", []))


def test_04_validation():
    from app.services.finding_correlation.validation import evaluate_finding_validation
    correlated = {"scanner": "api", "title": "API002", "severity": "medium", "evidence_items": [{"type": "api_endpoint"}], "asset_ids": ["a1"], "rule_ids": ["API002"]}
    val = evaluate_finding_validation(correlated)
    assert val["state"] in ("detected", "needs_review", "corroborated")


def test_05_risk():
    from app.risk_engine.engine import RiskAssessmentEngine
    engine = RiskAssessmentEngine()
    findings = [{"scanner": "api", "severity": "high", "title": "API001"}, {"scanner": "api", "severity": "medium", "title": "API002"}]
    result = engine.calculate(findings)
    assert result["total_findings"] == 2


def test_06_pipeline_with_mock():
    pipeline = ScannerPipeline()
    def fake_run(scanner, target):
        if scanner == "api":
            return json.dumps(_mock_sarif())
        return json.dumps({"version":"2.1.0","runs":[]})
    orig = pipeline.manager.run
    pipeline.manager.run = fake_run
    try:
        results = pipeline.run_many(["api"], "test", max_attempts=1)
        assert len(results) == 1
        assert results[0]["status"] == "completed"
    finally:
        pipeline.manager.run = orig


def test_07_asset_api_endpoint():
    from app.asset_intel.normalize import infer_asset_type, infer_asset_value
    asset = {"type": "api_endpoint", "value": "openapi.json"}
    assert infer_asset_type(asset) == "api_endpoint"
    assert infer_asset_value(asset) == "openapi.json"


def test_08_persistence_sanitization():
    from app.persistence import sanitize_metadata
    meta = {"rule_id": "API002", "endpoint": "/users", "method": "GET", "file": "openapi.json", "execution_engine": "vapt-api"}
    sanitized = sanitize_metadata(meta)
    assert sanitized["rule_id"] == "API002"
    assert sanitized["endpoint"] == "/users"

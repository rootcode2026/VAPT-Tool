import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from app.scanner.pipeline import ScannerPipeline
from app.scanner.execution import is_scanner_success

def _write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")

def test_sca_executes_with_nmap_together(monkeypatch):
    pipeline = ScannerPipeline()
    # Mock manager to return SCA and Nmap outputs
    def fake_run(scanner, target):
        if scanner == "sca":
            # Simulate SCA raw output via temp dir
            return json.dumps({
                "scanner": "sca",
                "dependencies": [{"ecosystem":"npm","name":"lodash","version":"4.17.20","manifest":"package-lock.json","dependency_type":"runtime","version_resolved":True}],
                "vulnerabilities": [],
                "findings": [{"scanner":"sca","title":"Vulnerable npm dependency: lodash 4.17.20","description":"test","severity":"high","score":7.2,"status":"open","evidence":"test","remediation":"upgrade","cve":"CVE-2021-23337","metadata":{}}],
                "errors": []
            })
        else:
            # Return Nmap fixture
            from tests.helpers import load_fixture
            return load_fixture("nmap.xml")
    monkeypatch.setattr(pipeline.manager, "run", fake_run)
    results = pipeline.run_many(["sca", "nmap"], "example.com", max_attempts=1)
    assert len(results) == 2
    assert any(r["scanner"] == "sca" and r["status"] == "completed" for r in results)
    assert any(r["scanner"] == "nmap" and r["status"] == "completed" for r in results)

def test_partial_success_preserved(monkeypatch):
    pipeline = ScannerPipeline()
    def fake_run(scanner, target):
        if scanner == "sca":
            raise RuntimeError("sca failed")
        from tests.helpers import load_fixture
        return load_fixture("nmap.xml")
    monkeypatch.setattr(pipeline.manager, "run", fake_run)
    results = pipeline.run_many(["sca", "nmap"], "example.com", max_attempts=1)
    assert results[0]["status"] == "failed"
    assert results[1]["status"] == "completed"

def test_sca_failure_does_not_abort_nmap(monkeypatch):
    pipeline = ScannerPipeline()
    calls = []
    def fake_run(scanner, target):
        calls.append(scanner)
        if scanner == "sca":
            raise RuntimeError("fail")
        from tests.helpers import load_fixture
        return load_fixture("nmap.xml")
    monkeypatch.setattr(pipeline.manager, "run", fake_run)
    results = pipeline.run_many(["sca", "nmap"], "example.com", max_attempts=1)
    assert calls == ["sca", "nmap"]
    assert results[1]["status"] == "completed"

def test_progress_increments_correctly(monkeypatch):
    from app.scanner.execution import calculate_progress
    assert calculate_progress(["completed", "failed", "pending"], 3) == 66
    assert calculate_progress(["completed", "completed"], 2) == 100

def test_scanner_summary_includes_sca(monkeypatch):
    from app.scanner.execution import scanner_summary
    pipeline = ScannerPipeline()
    def fake_run(scanner, target):
        if scanner == "sca":
            return json.dumps({"scanner":"sca","dependencies":[],"vulnerabilities":[],"findings":[],"errors":[]})
        from tests.helpers import load_fixture
        return load_fixture("nmap.xml")
    monkeypatch.setattr(pipeline.manager, "run", fake_run)
    results = pipeline.run_many(["sca", "nmap"], "example.com", max_attempts=1)
    summary = scanner_summary(results)
    assert "sca" in summary
    assert summary["sca"]["status"] == "completed"

def test_retryable_provider_timeout(monkeypatch):
    from app.scanner.execution import classify_failure
    from app.services.sca.vuln.osv import OSVProviderError
    err = OSVProviderError("OSV timeout")
    info = classify_failure(err)
    assert info.error_type == "provider_timeout"
    assert info.retryable is True

def test_non_retry_parser_error(monkeypatch):
    from app.scanner.execution import classify_failure, ScannerStageError
    err = ScannerStageError("parsing", ValueError("Invalid JSON in package.json"))
    info = classify_failure(err)
    assert info.error_type == "parser_failure"
    assert info.retryable is False

def test_duration_recorded(monkeypatch):
    pipeline = ScannerPipeline()
    def fake_run(scanner, target):
        return json.dumps({"scanner":"sca","dependencies":[],"findings":[],"vulnerabilities":[],"errors":[]})
    monkeypatch.setattr(pipeline.manager, "run", fake_run)
    from app.scanner.execution import run_with_retries
    result = run_with_retries(pipeline.run, "sca", "/tmp", max_attempts=1)
    assert result["duration_ms"] >= 0
    assert result["findings_count"] == 0

def test_attempt_increments(monkeypatch):
    from app.scanner.execution import run_with_retries
    from app.scanner.docker_runner import ScannerTimeoutError
    calls = []
    def flaky(scanner, target):
        calls.append(1)
        if len(calls) < 2:
            raise ScannerTimeoutError("timeout", timed_out=True, duration=1)
        return {"scanner": "sca", "status": "completed", "raw_output": "{}", "parsed_result": {"assets": [], "findings": []}, "findings": []}
    result = run_with_retries(flaky, "sca", "/tmp", max_attempts=2)
    assert result["status"] == "completed"
    assert result["attempt"] == 2

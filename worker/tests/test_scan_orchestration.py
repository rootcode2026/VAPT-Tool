from unittest.mock import MagicMock

from app.scanner.docker_runner import DockerRunnerError, ScannerTimeoutError
from app.scanner.execution import (
    failed_scanner_result,
    overall_scan_status,
    scanner_summary,
)
from app.scanner.pipeline import ScannerPipeline

from tests.helpers import load_fixture


def test_successful_scanner_includes_completed_status(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(
        pipeline.manager,
        "run",
        lambda scanner, target: load_fixture("nmap.xml"),
    )

    result = pipeline.run("nmap", "10.0.0.8")

    assert result["status"] == "completed"
    assert result["findings"]


def test_run_many_continues_after_scanner_failure(monkeypatch):
    pipeline = ScannerPipeline()
    calls = []

    def fake_run(scanner, target):
        calls.append(scanner)
        if scanner == "tls":
            raise DockerRunnerError(
                "Failed while waiting for scanner: ChunkedEncodingError: "
                "Response ended prematurely "
                "(scanner=vapt-tls:latest, target=example.com, "
                "phase=waiting, elapsed=600s, error_type=ChunkedEncodingError)",
                scanner="vapt-tls:latest",
                target=target,
                phase="waiting",
                error_type="ChunkedEncodingError",
                original_error="ChunkedEncodingError: Response ended prematurely",
                duration=600,
            )
        return load_fixture("nmap.xml")

    monkeypatch.setattr(pipeline.manager, "run", fake_run)

    results = pipeline.run_many(
        ["tls", "nmap"],
        "example.com",
        max_attempts=1,
    )

    assert calls == ["tls", "nmap"]
    assert results[0]["status"] == "failed"
    assert results[0]["error_type"] == "docker_transport"
    assert "Response ended prematurely" in results[0]["error"]
    assert results[1]["status"] == "completed"
    assert results[1]["findings"]


def test_run_many_records_multiple_failures_then_success(monkeypatch):
    pipeline = ScannerPipeline()

    def fake_run(scanner, target):
        if scanner in {"tls", "zap"}:
            raise RuntimeError(f"{scanner} exploded")
        return load_fixture("nmap.xml")

    monkeypatch.setattr(pipeline.manager, "run", fake_run)

    results = pipeline.run_many(
        ["tls", "zap", "nmap"],
        "example.com",
        max_attempts=1,
    )

    assert [item["status"] for item in results] == [
        "failed",
        "failed",
        "completed",
    ]
    summary = scanner_summary(results)
    assert summary["tls"]["status"] == "failed"
    assert summary["zap"]["status"] == "failed"
    assert summary["nmap"]["status"] == "completed"
    assert overall_scan_status(results) == "completed"


def test_all_scanners_failing_marks_scan_failed(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(
        pipeline.manager,
        "run",
        MagicMock(side_effect=RuntimeError("offline")),
    )

    results = pipeline.run_many(
        ["nmap", "tls"],
        "example.com",
        max_attempts=1,
    )

    assert all(item["status"] == "failed" for item in results)
    assert overall_scan_status(results) == "failed"
    summary = scanner_summary(results)
    assert summary["nmap"]["error_type"] == "unknown"
    assert summary["tls"]["status"] == "failed"


def test_timeout_failure_payload_keeps_timeout_details():
    error = ScannerTimeoutError(
        "Scanner timed out after 900 seconds.",
        timed_out=True,
        duration=900,
        scanner="vapt-tls:latest",
        target="example.com",
        phase="waiting",
        error_type="TimeoutError",
        original_error="TimeoutError: Scanner timed out after 900 seconds.",
    )

    result = failed_scanner_result("tls", "example.com", error)

    assert result["status"] == "failed"
    assert result["error_type"] == "timeout"
    assert result["error_phase"] == "execution"
    summary = scanner_summary([result])
    assert summary["tls"]["status"] == "failed"
    assert "timed out" in summary["tls"]["error"].lower()


def test_chunked_encoding_failure_payload_preserves_error_type():
    error = DockerRunnerError(
        "Failed while waiting for scanner: ChunkedEncodingError: "
        "Response ended prematurely",
        phase="waiting",
        scanner="vapt-tls:latest",
        target="example.com",
        error_type="ChunkedEncodingError",
        original_error="ChunkedEncodingError: Response ended prematurely",
    )

    result = failed_scanner_result("tls", "example.com", error)
    summary = scanner_summary([result])

    assert summary["tls"]["error_type"] == "docker_transport"
    assert "Response ended prematurely" in summary["tls"]["error"]
    assert '"status": "failed"' in result["raw_output"]


def test_empty_outcomes_cannot_complete():
    assert overall_scan_status([]) == "failed"

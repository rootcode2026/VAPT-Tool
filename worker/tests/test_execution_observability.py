from app.scanner.docker_runner import (
    DockerRunnerError,
    ScannerFailureError,
    ScannerTimeoutError,
)
from app.scanner.execution import (
    ScannerStageError,
    calculate_progress,
    classify_failure,
    duration_ms,
    failed_scanner_result,
    overall_scan_status,
    run_with_retries,
    scanner_summary,
)
from app.scanner.pipeline import ScannerPipeline

from tests.helpers import load_fixture


def test_lifecycle_pending_running_completed():
    states = []

    def execute(scanner, target):
        states.append("running")
        return {
            "scanner": scanner,
            "findings": [{"title": "x"}],
            "parsed_result": {"assets": [{"value": "a"}]},
            "raw_output": "ok",
        }

    def on_start(attempt):
        states.append("pending")
        states.append("running-attempt")

    result = run_with_retries(
        execute,
        "nmap",
        "10.0.0.8",
        max_attempts=2,
        on_attempt_start=on_start,
    )

    assert states[:2] == ["pending", "running-attempt"]
    assert result["status"] == "completed"
    assert result["attempt"] == 1
    assert result["started_at"] is not None
    assert result["completed_at"] is not None
    assert result["duration_ms"] >= 0
    assert result["findings_count"] == 1
    assert result["assets_count"] == 1


def test_lifecycle_pending_running_failed():
    def execute(scanner, target):
        raise ValueError("TLS target cannot be empty.")

    result = run_with_retries(
        execute,
        "tls",
        " ",
        max_attempts=2,
    )

    assert result["status"] == "failed"
    assert result["error_type"] == "invalid_target"
    assert result["attempt"] == 1
    assert result["duration_ms"] >= 0


def test_retry_then_completed():
    calls = []

    def execute(scanner, target):
        calls.append(scanner)
        if len(calls) == 1:
            raise DockerRunnerError(
                "Failed while waiting for scanner",
                error_type="ChunkedEncodingError",
                original_error="ChunkedEncodingError: Response ended prematurely",
                phase="waiting",
            )
        return {
            "scanner": scanner,
            "findings": [],
            "parsed_result": {"assets": []},
            "raw_output": "ok",
        }

    result = run_with_retries(execute, "tls", "example.com", max_attempts=2)

    assert calls == ["tls", "tls"]
    assert result["status"] == "completed"
    assert result["attempt"] == 2


def test_retry_then_failed_respects_max_attempts():
    calls = []

    def execute(scanner, target):
        calls.append(1)
        raise DockerRunnerError(
            "transport",
            error_type="ProtocolError",
            original_error="ProtocolError: Connection broken",
            phase="waiting",
        )

    failures = []
    result = run_with_retries(
        execute,
        "tls",
        "example.com",
        max_attempts=2,
        on_attempt_failure=lambda attempt, failure: failures.append(attempt),
    )

    assert len(calls) == 2
    assert failures == [1, 2]
    assert result["status"] == "failed"
    assert result["attempt"] == 2
    assert result["error_type"] == "docker_transport"
    assert result["retryable"] is True


def test_permanent_failure_does_not_retry():
    calls = []

    def execute(scanner, target):
        calls.append(1)
        raise ValueError("No parser registered for scanner 'unknown'.")

    result = run_with_retries(
        execute,
        "unknown",
        "example.com",
        max_attempts=3,
    )

    assert len(calls) == 1
    assert result["status"] == "failed"


def test_chunked_encoding_classified_as_docker_transport():
    error = DockerRunnerError(
        "Failed while waiting",
        error_type="ChunkedEncodingError",
        original_error="ChunkedEncodingError: Response ended prematurely",
        phase="waiting",
    )
    info = classify_failure(error)
    assert info.error_type == "docker_transport"
    assert info.retryable is True
    assert "ChunkedEncodingError" in info.original_error


def test_protocol_error_classified_as_docker_transport():
    info = classify_failure(
        DockerRunnerError(
            "broken",
            error_type="ProtocolError",
            original_error="ProtocolError: Connection broken",
        )
    )
    assert info.error_type == "docker_transport"


def test_docker_api_error_classified():
    info = classify_failure(
        DockerRunnerError(
            "Failed to start scanner container",
            error_type="APIError",
            original_error="APIError: 500 server error",
            phase="starting",
        )
    )
    assert info.error_type == "docker_api"
    assert info.retryable is True


def test_timeout_classified_as_timeout():
    info = classify_failure(
        ScannerTimeoutError("Scanner timed out after 30 seconds.", timed_out=True)
    )
    assert info.error_type == "timeout"
    assert info.retryable is True


def test_parser_exception_classified():
    info = classify_failure(ScannerStageError("parsing", RuntimeError("bad xml")))
    assert info.error_type == "parser_failure"
    assert info.retryable is False
    assert info.error_phase == "parsing"


def test_persistence_exception_classified():
    info = classify_failure(ScannerStageError("persistence", RuntimeError("db down")))
    assert info.error_type == "persistence_failure"
    assert info.retryable is False


def test_unknown_exception_classified():
    info = classify_failure(RuntimeError("unexpected"))
    assert info.error_type == "unknown"
    assert info.retryable is False


def test_container_failure_not_retryable():
    info = classify_failure(ScannerFailureError("exit 2", exit_code=2))
    assert info.error_type == "container_failure"
    assert info.retryable is False


def test_partial_scan_status_rules():
    def make(successes: int, failures: int):
        rows = [
            {"scanner": f"ok-{index}", "status": "completed"}
            for index in range(successes)
        ]
        rows.extend(
            {
                "scanner": f"bad-{index}",
                "status": "failed",
            }
            for index in range(failures)
        )
        return rows

    assert overall_scan_status(make(7, 1)) == "completed"
    assert overall_scan_status(make(1, 7)) == "completed"
    assert overall_scan_status(make(4, 4)) == "completed"
    assert overall_scan_status(make(0, 8)) == "failed"


def test_progress_counts_failed_as_finished():
    pending = ["pending"] * 8
    assert calculate_progress(pending, 8) == 0
    assert calculate_progress(["completed"] * 4 + ["pending"] * 4, 8) == 50
    assert calculate_progress(
        ["completed"] * 6 + ["failed"] + ["running"],
        8,
    ) == 87
    assert calculate_progress(["completed"] * 8, 8) == 100


def test_duration_ms_is_non_negative():
    assert duration_ms(10.0, 10.5) >= 0
    assert duration_ms(10.0, 9.0) == 0


def test_scanner_summary_keeps_error_and_timing():
    summary = scanner_summary(
        [
            {
                "scanner": "nmap",
                "status": "completed",
                "attempt": 1,
                "duration_ms": 4200,
                "findings_count": 3,
                "assets_count": 5,
            },
            {
                "scanner": "tls",
                "status": "failed",
                "attempt": 2,
                "duration_ms": 603000,
                "error_type": "docker_transport",
                "error_message": "ChunkedEncodingError: Response ended prematurely",
                "retryable": True,
            },
        ]
    )
    assert summary["nmap"]["status"] == "completed"
    assert summary["nmap"]["duration_ms"] == 4200
    assert summary["tls"]["retryable"] is True
    assert summary["tls"]["attempt"] == 2


def test_task_return_scanners_remain_a_list():
    scanners = ["nmap", "nuclei", "tls"]
    payload = {
        "scanners": scanners,
        "scanner_summary": scanner_summary(
            [{"scanner": name, "status": "completed"} for name in scanners]
        ),
    }
    assert payload["scanners"] == scanners
    assert isinstance(payload["scanners"], list)
    assert isinstance(payload["scanner_summary"], dict)


def test_parser_failure_is_isolated(monkeypatch):
    pipeline = ScannerPipeline()
    monkeypatch.setattr(pipeline.manager, "run", lambda scanner, target: "raw")

    class BrokenParser:
        def parse(self, raw_output):
            raise RuntimeError("cannot parse")

    monkeypatch.setattr(pipeline.parser_registry, "get", lambda scanner: BrokenParser())

    results = pipeline.run_many(["nmap"], "example.com", max_attempts=1)

    assert results[0]["error_type"] == "parser_failure"
    assert results[0]["status"] == "failed"


def test_run_many_retries_transient_then_continues(monkeypatch):
    pipeline = ScannerPipeline()
    calls = []

    def fake_run(scanner, target):
        calls.append(scanner)
        if scanner == "tls" and calls.count("tls") == 1:
            raise DockerRunnerError(
                "Failed while waiting",
                error_type="ChunkedEncodingError",
                original_error="Response ended prematurely",
                phase="waiting",
            )
        if scanner == "tls":
            return load_fixture("tls.json")
        return load_fixture("nmap.xml")

    monkeypatch.setattr(pipeline.manager, "run", fake_run)
    results = pipeline.run_many(["tls", "nmap"], "example.com", max_attempts=2)

    assert calls == ["tls", "tls", "nmap"]
    assert results[0]["status"] == "completed"
    assert results[1]["status"] == "completed"


def test_image_not_found_is_not_retryable():
    error = DockerRunnerError(
        "Scanner image was not found",
        error_type="ImageNotFound",
        phase="starting",
    )
    info = classify_failure(error)
    assert info.error_type == "docker_api"
    assert info.retryable is False

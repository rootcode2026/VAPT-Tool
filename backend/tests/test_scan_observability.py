from pathlib import Path
from types import SimpleNamespace

from app.scans.observability import calculate_progress, progress_snapshot
from app.schemas.scan import ScanProgressResponse, ScanResponse


def test_progress_endpoint_is_declared():
    source = Path(__file__).resolve().parents[1] / "app" / "api" / "routes" / "scans.py"
    text = source.read_text(encoding="utf-8")
    assert "/{scan_id}/progress" in text
    assert "ScanProgressResponse" in text


def test_progress_helpers_cover_scan_states():
    assert calculate_progress(["pending"] * 8, 8) == 0
    assert calculate_progress(["completed"] * 4 + ["pending"] * 4, 8) == 50
    assert calculate_progress(["completed"] * 6 + ["failed", "running"], 8) == 87
    assert calculate_progress(["completed"] * 8, 8) == 100


def test_progress_snapshot_uses_latest_attempt():
    rows = [
        SimpleNamespace(
            scanner="tls",
            status="failed",
            attempt=1,
            duration_ms=100,
            findings_count=0,
            assets_count=0,
            error_type="docker_transport",
            error_message="ChunkedEncodingError: Response ended prematurely",
            error_phase="execution",
            retryable=True,
        ),
        SimpleNamespace(
            scanner="tls",
            status="completed",
            attempt=2,
            duration_ms=50,
            findings_count=1,
            assets_count=1,
            error_type=None,
            error_message=None,
            error_phase=None,
            retryable=None,
        ),
        SimpleNamespace(
            scanner="nmap",
            status="completed",
            attempt=1,
            duration_ms=10,
            findings_count=3,
            assets_count=2,
            error_type=None,
            error_message=None,
            error_phase=None,
            retryable=None,
        ),
    ]
    snapshot = progress_snapshot(rows, ["nmap", "tls"])
    assert snapshot["progress"] == 100
    assert snapshot["completed"] == 2
    assert snapshot["failed"] == 0
    assert snapshot["scanners"]["tls"]["status"] == "completed"
    assert snapshot["scanners"]["tls"]["attempt"] == 2


def test_scan_response_keeps_core_fields():
    payload = ScanResponse(
        id="s1",
        target_id="t1",
        profile="web",
        status="completed",
        phase="completed",
        progress=100,
        scanners=["nmap", "tls"],
        scanner_summary={
            "nmap": {"status": "completed", "attempt": 1, "duration_ms": 12},
            "tls": {
                "status": "failed",
                "attempt": 2,
                "error_type": "docker_transport",
                "error_message": "transport failed",
                "retryable": True,
            },
        },
    ).model_dump()
    assert payload["scanners"] == ["nmap", "tls"]
    assert payload["scanner_summary"]["tls"]["error_type"] == "docker_transport"
    assert payload["id"] == "s1"


def test_progress_response_schema():
    payload = ScanProgressResponse(
        scan_id="s1",
        status="running",
        progress=62,
        total_scanners=8,
        completed=4,
        failed=1,
        running=1,
        pending=2,
        skipped=0,
        scanners={"nmap": {"status": "completed"}},
    ).model_dump()
    assert payload["progress"] == 62
    assert payload["failed"] == 1

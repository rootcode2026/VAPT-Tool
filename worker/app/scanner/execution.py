from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
import time
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

from app.scanner.docker_runner import (
    DockerRunnerError,
    ScannerExecutionError,
    ScannerFailureError,
    ScannerTimeoutError,
)


logger = logging.getLogger("vapt.scanner")

STATUS_PENDING = "pending"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"

FINISHED_STATUSES = {
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_SKIPPED,
}

ERROR_TIMEOUT = "timeout"
ERROR_DOCKER_TRANSPORT = "docker_transport"
ERROR_DOCKER_API = "docker_api"
ERROR_CONTAINER_FAILURE = "container_failure"
ERROR_INVALID_TARGET = "invalid_target"
ERROR_SCANNER_FAILURE = "scanner_failure"
ERROR_PARSER_FAILURE = "parser_failure"
ERROR_PERSISTENCE_FAILURE = "persistence_failure"
ERROR_UNKNOWN = "unknown"
ERROR_PROVIDER_TIMEOUT = "provider_timeout"
ERROR_PROVIDER_TRANSPORT = "provider_transport"
ERROR_PROVIDER_RATE_LIMIT = "provider_rate_limit"
ERROR_PROVIDER_ERROR = "provider_error"
ERROR_MANIFEST_PARSE = "manifest_parse_error"
ERROR_UNSUPPORTED_MANIFEST = "unsupported_manifest"

RETRYABLE_ERROR_TYPES = {
    ERROR_TIMEOUT,
    ERROR_DOCKER_TRANSPORT,
    ERROR_DOCKER_API,
    ERROR_PROVIDER_TIMEOUT,
    ERROR_PROVIDER_TRANSPORT,
    ERROR_PROVIDER_RATE_LIMIT,
    ERROR_PROVIDER_ERROR,
}

TRANSPORT_ERROR_NAMES = {
    "ChunkedEncodingError",
    "ProtocolError",
    "ConnectionResetError",
    "ConnectionError",
    "BrokenPipeError",
    "RemoteDisconnected",
    "IncompleteRead",
}

PHASE_MAP = {
    "starting": "execution",
    "running": "execution",
    "waiting": "execution",
    "log collection": "execution",
    "execution": "execution",
    "parsing": "parsing",
    "enrichment": "enrichment",
    "persistence": "persistence",
    "analysis": "analysis",
}

SECRET_MARKERS = (
    "password=",
    "secret=",
    "token=",
    "api_key",
    "authorization:",
    "bearer ",
)


class ScannerStageError(Exception):
    """Generic wrapper that records which pipeline stage failed."""

    def __init__(self, phase: str, cause: Exception):
        self.phase = phase
        self.cause = cause
        super().__init__(str(cause))


@dataclass
class FailureInfo:
    error_type: str
    error_message: str
    error_phase: str
    retryable: bool
    original_error_type: str
    original_error: str


@dataclass
class ScannerOutcome:
    scanner: str
    status: str
    attempt: int = 1
    max_attempts: int = 2
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: int = 0
    findings_count: int = 0
    assets_count: int = 0
    error_type: str | None = None
    error_message: str | None = None
    error_phase: str | None = None
    retryable: bool = False
    raw_output: str = ""
    parsed_result: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    extra_data: dict = field(default_factory=dict)
    target: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "scanner": self.scanner,
            "status": self.status,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "started_at": (
                self.started_at.isoformat() if self.started_at else None
            ),
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "duration_ms": self.duration_ms,
            "findings_count": self.findings_count,
            "assets_count": self.assets_count,
            "raw_output": self.raw_output,
            "parsed_result": self.parsed_result,
            "findings": self.findings,
            "target": self.target,
        }
        if self.status != STATUS_COMPLETED:
            payload["error_type"] = self.error_type
            payload["error_message"] = self.error_message
            payload["error"] = self.error_message
            payload["error_phase"] = self.error_phase
            payload["retryable"] = self.retryable
        return payload


def get_max_attempts(default: int = 2) -> int:
    raw = os.getenv("SCANNER_MAX_ATTEMPTS", str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(1, value)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def duration_ms(started_monotonic: float, ended_monotonic: float | None = None) -> int:
    ended = ended_monotonic if ended_monotonic is not None else time.monotonic()
    elapsed = ended - started_monotonic
    if elapsed < 0:
        return 0
    return int(elapsed * 1000)


def calculate_progress(statuses: list[str], total_scanners: int) -> int:
    if total_scanners <= 0:
        return 0
    finished = sum(1 for status in statuses if status in FINISHED_STATUSES)
    return int(finished * 100 / total_scanners)


def overall_scan_status(
    outcomes: list[dict] | list[ScannerOutcome],
    *,
    workflow_finished: bool = True,
    workflow_started: bool = True,
) -> str:
    records = [
        outcome.to_dict() if isinstance(outcome, ScannerOutcome) else outcome
        for outcome in outcomes
    ]
    if not workflow_started:
        return STATUS_PENDING
    if not workflow_finished:
        return STATUS_RUNNING
    if not records:
        return STATUS_FAILED
    if any(record.get("status") == STATUS_COMPLETED for record in records):
        return STATUS_COMPLETED
    return STATUS_FAILED


def is_scanner_success(outcome: dict | ScannerOutcome) -> bool:
    status = (
        outcome.status
        if isinstance(outcome, ScannerOutcome)
        else outcome.get("status")
    )
    return status == STATUS_COMPLETED


def scanner_summary(
    outcomes: list[dict] | list[ScannerOutcome],
) -> dict[str, dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for outcome in outcomes:
        record = (
            outcome.to_dict() if isinstance(outcome, ScannerOutcome) else outcome
        )
        name = record.get("scanner")
        if not name:
            continue
        entry: dict[str, Any] = {
            "status": record.get("status") or STATUS_FAILED,
        }
        if record.get("attempt") is not None:
            entry["attempt"] = record["attempt"]
        if record.get("duration_ms") is not None:
            entry["duration_ms"] = record["duration_ms"]
        if record.get("findings_count") is not None:
            entry["findings_count"] = record["findings_count"]
        if record.get("assets_count") is not None:
            entry["assets_count"] = record["assets_count"]
        if entry["status"] != STATUS_COMPLETED:
            if entry["status"] not in FINISHED_STATUSES and entry["status"] not in {
                STATUS_PENDING,
                STATUS_RUNNING,
            }:
                entry["status"] = STATUS_FAILED
            if record.get("error_type"):
                entry["error_type"] = record["error_type"]
            message = record.get("error_message") or record.get("error")
            if message:
                entry["error_message"] = message
                entry["error"] = message
            if record.get("error_phase"):
                entry["error_phase"] = record["error_phase"]
            if "retryable" in record:
                entry["retryable"] = bool(record["retryable"])
        summary[name] = entry
    return summary


def safe_target(target: str) -> str:
    value = str(target or "").strip()
    if "://" not in value:
        return value
    try:
        parts = urlsplit(value)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    except Exception:
        return value.split("?", 1)[0]


def sanitize_error_message(message: str) -> str:
    text = str(message or "")
    lowered = text.lower()
    for marker in SECRET_MARKERS:
        if marker in lowered:
            return "Scanner execution failed. See scanner logs for details."
    return text[:4000]


def _original_error_name(error: Exception) -> str:
    return getattr(error, "error_type", None) or type(error).__name__


def _original_error_text(error: Exception) -> str:
    return getattr(error, "original_error", None) or str(error)


def classify_failure(
    error: Exception,
    *,
    phase: str | None = None,
) -> FailureInfo:
    current: Exception = error
    recorded_phase = phase

    if isinstance(error, ScannerStageError):
        recorded_phase = error.phase
        current = error.cause or error

    raw_phase = recorded_phase or getattr(current, "phase", None)
    error_phase = PHASE_MAP.get(str(raw_phase or "").lower(), "execution")
    original_type = _original_error_name(current)
    original_message = sanitize_error_message(_original_error_text(current))
    public_message = sanitize_error_message(str(current) or original_message)

    if error_phase == "parsing":
        return FailureInfo(
            ERROR_PARSER_FAILURE,
            public_message,
            "parsing",
            False,
            original_type,
            original_message,
        )
    if error_phase == "persistence":
        return FailureInfo(
            ERROR_PERSISTENCE_FAILURE,
            public_message,
            "persistence",
            False,
            original_type,
            original_message,
        )
    if error_phase == "enrichment":
        return FailureInfo(
            ERROR_PERSISTENCE_FAILURE,
            public_message,
            "enrichment",
            False,
            original_type,
            original_message,
        )

    if isinstance(current, ScannerTimeoutError) or getattr(current, "timed_out", False):
        return FailureInfo(
            ERROR_TIMEOUT,
            public_message,
            "execution",
            True,
            original_type,
            original_message,
        )

    # SCA provider errors - retryable for network/rate limit, not for parse
    msg_lower = original_message.lower()
    type_lower = original_type.lower()
    if "provider_error" in type_lower or "osvprovidererror" in type_lower:
        if "timeout" in msg_lower:
            return FailureInfo(ERROR_PROVIDER_TIMEOUT, public_message, "execution", True, original_type, original_message)
        if "rate limited" in msg_lower or "429" in msg_lower:
            return FailureInfo(ERROR_PROVIDER_RATE_LIMIT, public_message, "execution", True, original_type, original_message)
        if "connection" in msg_lower or "transport" in msg_lower or "dns" in msg_lower:
            return FailureInfo(ERROR_PROVIDER_TRANSPORT, public_message, "execution", True, original_type, original_message)
        return FailureInfo(ERROR_PROVIDER_ERROR, public_message, "execution", True, original_type, original_message)
    if "manifest" in msg_lower and ("parse" in msg_lower or "invalid" in msg_lower):
        return FailureInfo(ERROR_MANIFEST_PARSE, public_message, "parsing", False, original_type, original_message)
    if "unsupported manifest" in msg_lower:
        return FailureInfo(ERROR_UNSUPPORTED_MANIFEST, public_message, "parsing", False, original_type, original_message)

    if isinstance(current, ScannerFailureError):
        return FailureInfo(
            ERROR_CONTAINER_FAILURE,
            public_message,
            "execution",
            False,
            original_type,
            original_message,
        )

    if isinstance(current, DockerRunnerError) or original_type in TRANSPORT_ERROR_NAMES:
        if original_type == "ImageNotFound":
            return FailureInfo(
                ERROR_DOCKER_API,
                public_message,
                "execution",
                False,
                original_type,
                original_message,
            )
        if original_type in TRANSPORT_ERROR_NAMES:
            return FailureInfo(
                ERROR_DOCKER_TRANSPORT,
                public_message,
                "execution",
                True,
                original_type,
                original_message,
            )
        return FailureInfo(
            ERROR_DOCKER_API,
            public_message,
            "execution",
            True,
            original_type,
            original_message,
        )

    if isinstance(current, ValueError) and "target" in str(current).lower():
        return FailureInfo(
            ERROR_INVALID_TARGET,
            public_message,
            error_phase,
            False,
            original_type,
            original_message,
        )

    if error_phase == "analysis":
        return FailureInfo(
            ERROR_SCANNER_FAILURE,
            public_message,
            "analysis",
            False,
            original_type,
            original_message,
        )

    if isinstance(current, ScannerExecutionError):
        return FailureInfo(
            ERROR_SCANNER_FAILURE,
            public_message,
            "execution",
            False,
            original_type,
            original_message,
        )

    return FailureInfo(
        ERROR_UNKNOWN,
        public_message,
        error_phase,
        False,
        original_type,
        original_message,
    )


def failed_scanner_result(
    scanner: str,
    target: str,
    error: Exception,
    *,
    attempt: int = 1,
    max_attempts: int = 2,
    duration_ms_value: int = 0,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    phase: str | None = None,
) -> dict:
    failure = classify_failure(error, phase=phase)
    payload = {
        "status": STATUS_FAILED,
        "error_type": failure.error_type,
        "error": failure.error_message,
        "error_message": failure.error_message,
        "error_phase": failure.error_phase,
        "original_error_type": failure.original_error_type,
        "original_error": failure.original_error,
        "phase": failure.error_phase,
        "duration_ms": duration_ms_value,
        "target": safe_target(target),
        "attempt": attempt,
        "retryable": failure.retryable,
        "stdout": getattr(error, "stdout", "") or "",
        "stderr": getattr(error, "stderr", "") or "",
    }
    return {
        "scanner": scanner,
        "status": STATUS_FAILED,
        "raw_output": json.dumps(payload, default=str),
        "parsed_result": {"assets": [], "findings": []},
        "findings": [],
        "error_type": failure.error_type,
        "error": failure.error_message,
        "error_message": failure.error_message,
        "error_phase": failure.error_phase,
        "retryable": failure.retryable,
        "phase": failure.error_phase,
        "duration": duration_ms_value / 1000 if duration_ms_value else getattr(error, "duration", None),
        "duration_ms": duration_ms_value,
        "target": target,
        "attempt": attempt,
        "max_attempts": max_attempts,
        "findings_count": 0,
        "assets_count": 0,
        "started_at": started_at,
        "completed_at": completed_at,
        "extra_data": {
            "original_error_type": failure.original_error_type,
            "original_error": failure.original_error,
        },
    }


def log_scanner_start(scan_id: str, scanner: str, target: str, attempt: int) -> None:
    logger.info(
        "scanner start scan_id=%s scanner=%s target=%s attempt=%s",
        scan_id,
        scanner,
        safe_target(target),
        attempt,
    )


def log_scanner_success(
    scan_id: str,
    scanner: str,
    duration_ms_value: int,
    findings_count: int,
    assets_count: int,
) -> None:
    logger.info(
        "scanner end scan_id=%s scanner=%s status=completed duration_ms=%s "
        "findings_count=%s assets_count=%s",
        scan_id,
        scanner,
        duration_ms_value,
        findings_count,
        assets_count,
    )


def log_scanner_failure(
    scan_id: str,
    scanner: str,
    duration_ms_value: int,
    error_type: str,
    retryable: bool,
    attempt: int,
) -> None:
    logger.info(
        "scanner end scan_id=%s scanner=%s status=failed duration_ms=%s "
        "error_type=%s retryable=%s attempt=%s",
        scan_id,
        scanner,
        duration_ms_value,
        error_type,
        retryable,
        attempt,
    )


def run_with_retries(
    execute: Callable[[str, str], dict],
    scanner: str,
    target: str,
    *,
    max_attempts: int | None = None,
    on_attempt_start: Callable[[int], None] | None = None,
    on_attempt_failure: Callable[[int, dict], None] | None = None,
) -> dict:
    attempts = max_attempts or get_max_attempts()
    last_failure: dict | None = None

    for attempt in range(1, attempts + 1):
        if on_attempt_start:
            on_attempt_start(attempt)

        started_monotonic = time.monotonic()
        started_at = utc_now()
        try:
            result = execute(scanner, target)
            elapsed = duration_ms(started_monotonic)
            completed_at = utc_now()
            findings = result.get("findings") or []
            assets = (result.get("parsed_result") or {}).get("assets") or []
            result.update(
                {
                    "status": STATUS_COMPLETED,
                    "attempt": attempt,
                    "max_attempts": attempts,
                    "started_at": started_at,
                    "completed_at": completed_at,
                    "duration_ms": elapsed,
                    "findings_count": len(findings),
                    "assets_count": len(assets),
                    "retryable": False,
                }
            )
            return result
        except Exception as exc:
            elapsed = duration_ms(started_monotonic)
            failure = failed_scanner_result(
                scanner,
                target,
                exc,
                attempt=attempt,
                max_attempts=attempts,
                duration_ms_value=elapsed,
                started_at=started_at,
                completed_at=utc_now(),
            )
            last_failure = failure
            if on_attempt_failure:
                on_attempt_failure(attempt, failure)
            if not failure.get("retryable") or attempt >= attempts:
                return failure

    return last_failure or failed_scanner_result(
        scanner,
        target,
        RuntimeError("Scanner execution failed."),
        max_attempts=attempts,
    )

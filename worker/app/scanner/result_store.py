from datetime import datetime
import json
import uuid

from sqlalchemy import text


def insert_attempt(
    db,
    *,
    scan_id: str,
    scanner: str,
    status: str,
    attempt: int,
    max_attempts: int,
    raw_output: str = "",
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    duration_ms: int | None = None,
    error_type: str | None = None,
    error_message: str | None = None,
    error_phase: str | None = None,
    retryable: bool | None = None,
    findings_count: int | None = None,
    assets_count: int | None = None,
    extra_data: dict | None = None,
) -> str:
    result_id = str(uuid.uuid4())
    db.execute(
        text(
            """
            INSERT INTO scan_results
            (
                id,
                scan_id,
                scanner,
                status,
                raw_output,
                started_at,
                completed_at,
                duration_ms,
                attempt,
                max_attempts,
                error_type,
                error_message,
                error_phase,
                retryable,
                findings_count,
                assets_count,
                metadata
            )
            VALUES
            (
                :id,
                :scan_id,
                :scanner,
                :status,
                :raw_output,
                :started_at,
                :completed_at,
                :duration_ms,
                :attempt,
                :max_attempts,
                :error_type,
                :error_message,
                :error_phase,
                :retryable,
                :findings_count,
                :assets_count,
                CAST(:metadata AS JSONB)
            )
            """
        ),
        {
            "id": result_id,
            "scan_id": scan_id,
            "scanner": scanner,
            "status": status,
            "raw_output": raw_output or "",
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_ms": duration_ms,
            "attempt": attempt,
            "max_attempts": max_attempts,
            "error_type": error_type,
            "error_message": error_message,
            "error_phase": error_phase,
            "retryable": retryable,
            "findings_count": findings_count,
            "assets_count": assets_count,
            "metadata": json.dumps(extra_data or {}),
        },
    )
    return result_id


def update_attempt(
    db,
    result_id: str,
    *,
    status: str,
    raw_output: str | None = None,
    started_at: datetime | None = None,
    completed_at: datetime | None = None,
    duration_ms: int | None = None,
    error_type: str | None = None,
    error_message: str | None = None,
    error_phase: str | None = None,
    retryable: bool | None = None,
    findings_count: int | None = None,
    assets_count: int | None = None,
    extra_data: dict | None = None,
) -> None:
    db.execute(
        text(
            """
            UPDATE scan_results
            SET
                status = :status,
                raw_output = COALESCE(:raw_output, raw_output),
                started_at = COALESCE(:started_at, started_at),
                completed_at = :completed_at,
                duration_ms = :duration_ms,
                error_type = :error_type,
                error_message = :error_message,
                error_phase = :error_phase,
                retryable = :retryable,
                findings_count = :findings_count,
                assets_count = :assets_count,
                metadata = COALESCE(CAST(:metadata AS JSONB), metadata)
            WHERE id = :id
            """
        ),
        {
            "id": result_id,
            "status": status,
            "raw_output": raw_output,
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_ms": duration_ms,
            "error_type": error_type,
            "error_message": error_message,
            "error_phase": error_phase,
            "retryable": retryable,
            "findings_count": findings_count,
            "assets_count": assets_count,
            "metadata": json.dumps(extra_data) if extra_data is not None else None,
        },
    )


def update_scan_progress(db, scan_id: str, progress: int) -> None:
    db.execute(
        text(
            """
            UPDATE scans
            SET progress = :progress
            WHERE id = :scan_id
            """
        ),
        {
            "progress": progress,
            "scan_id": scan_id,
        },
    )

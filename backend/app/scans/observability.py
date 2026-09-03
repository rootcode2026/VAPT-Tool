from __future__ import annotations

from typing import Any, Iterable


FINISHED_STATUSES = {"completed", "failed", "skipped"}


def calculate_progress(statuses: Iterable[str], total_scanners: int) -> int:
    if total_scanners <= 0:
        return 0
    status_list = list(statuses)
    finished = sum(1 for status in status_list if status in FINISHED_STATUSES)
    return int(finished * 100 / total_scanners)


def latest_attempts(rows: list[Any]) -> list[Any]:
    latest: dict[str, Any] = {}
    for row in rows:
        scanner = getattr(row, "scanner", None)
        attempt = getattr(row, "attempt", 1) or 1
        if scanner is None:
            continue
        current = latest.get(scanner)
        if current is None or attempt >= (getattr(current, "attempt", 1) or 1):
            latest[scanner] = row
    return list(latest.values())


def scanner_names(rows: list[Any]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for row in rows:
        name = getattr(row, "scanner", None)
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def build_scanner_summary(rows: list[Any]) -> dict[str, dict[str, Any]]:
    summary: dict[str, dict[str, Any]] = {}
    for row in latest_attempts(rows):
        entry: dict[str, Any] = {
            "status": row.status,
            "attempt": row.attempt,
            "duration_ms": row.duration_ms,
            "findings_count": row.findings_count,
            "assets_count": row.assets_count,
        }
        if row.status != "completed":
            if row.error_type:
                entry["error_type"] = row.error_type
            if row.error_message:
                entry["error_message"] = row.error_message
                entry["error"] = row.error_message
            if row.error_phase:
                entry["error_phase"] = row.error_phase
            if row.retryable is not None:
                entry["retryable"] = row.retryable
        summary[row.scanner] = {
            key: value for key, value in entry.items() if value is not None
        }
        summary[row.scanner]["status"] = row.status
    return summary


def progress_snapshot(rows: list[Any], requested: list[str] | None = None) -> dict[str, Any]:
    latest = latest_attempts(rows)
    names = requested or scanner_names(rows)
    by_scanner = {row.scanner: row.status for row in latest}
    statuses = [by_scanner.get(name, "pending") for name in names]
    counts = {
        "completed": statuses.count("completed"),
        "failed": statuses.count("failed"),
        "running": statuses.count("running"),
        "pending": statuses.count("pending"),
        "skipped": statuses.count("skipped"),
    }
    total = len(names)
    return {
        "total_scanners": total,
        "progress": calculate_progress(statuses, total),
        "completed": counts["completed"],
        "failed": counts["failed"],
        "running": counts["running"],
        "pending": counts["pending"],
        "skipped": counts["skipped"],
        "scanners": build_scanner_summary(rows),
    }

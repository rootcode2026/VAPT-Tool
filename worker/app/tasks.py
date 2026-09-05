import json
import os
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from .celery_app import celery_app
from .persistence import (
    get_project_id,
    match_asset_id,
    persist_parsed_bundle,
    sanitize_metadata,
)
from .risk_engine.engine import RiskAssessmentEngine
from .scanner.execution import (
    ScannerStageError,
    calculate_progress,
    failed_scanner_result,
    get_max_attempts,
    is_scanner_success,
    log_scanner_failure,
    log_scanner_start,
    log_scanner_success,
    overall_scan_status,
    run_with_retries,
    scanner_summary,
    utc_now,
)
from .scanner.base import ScanContext
from .scanner.pipeline import ScannerPipeline
from .scanner.profiles import get_scanners_for_profile
from .scanner.result_store import (
    insert_attempt,
    update_attempt,
    update_scan_progress,
)
from .scanner.workspace import cleanup_workspace, create_workspace


def _sanitize_secrets_raw(scanner: str, raw: str | None) -> str | None:
    """Defense-in-depth: redact secrets scanner raw output before persistence/logging."""
    if scanner != "secrets" or not raw:
        return raw
    try:
        from app.scanner.scanners.secrets import _redact_text as _rt

        return _rt(str(raw))
    except Exception:
        return raw


def _sanitize_secrets_error(scanner: str, msg: str | None) -> str | None:
    if scanner != "secrets" or not msg:
        return msg
    try:
        from app.scanner.scanners.secrets import _redact_text as _rt

        return _rt(str(msg))
    except Exception:
        return msg


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://security:security_password@postgres:5432/security_saas",
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)

# ---------------------------------------------------------------------------
# Audit logging for scan lifecycle (Phase 6C) — reuses existing taxonomy,
# append-only, redacted, bounded, tenant-derived from DB.
# ---------------------------------------------------------------------------

_AUDIT_EVENT_SCAN_CREATED = "SCAN_CREATED"
_AUDIT_EVENT_SCAN_STARTED = "SCAN_STARTED"
_AUDIT_EVENT_SCAN_COMPLETED = "SCAN_COMPLETED"
_AUDIT_EVENT_SCAN_FAILED = "SCAN_FAILED"
_AUDIT_EVENT_SCAN_CANCELLED = "SCAN_CANCELLED"
_AUDIT_RESOURCE_SCAN = "scan"
_AUDIT_RESULT_SUCCESS = "SUCCESS"
_AUDIT_RESULT_FAILURE = "FAILURE"
_AUDIT_METADATA_MAX_BYTES = 4096
_AUDIT_SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "api_key", "apikey", "authorization", "cookie", "private_key",
    "client_secret", "credential",
}


def _sanitize_audit_metadata(metadata: dict | None) -> dict | None:
    if metadata is None:
        return None
    if not isinstance(metadata, dict):
        return {"value": str(metadata)[:500]}
    sanitized: dict = {}
    for k, v in metadata.items():
        sk = str(k)[:100]
        lk = sk.lower()
        is_sensitive = lk in _AUDIT_SENSITIVE_KEYS or any(s in lk for s in ("password", "secret", "token", "api_key", "private_key", "credential"))
        if is_sensitive:
            sanitized[sk] = "[REDACTED]"
            continue
        if isinstance(v, dict):
            sanitized[sk] = _sanitize_audit_metadata(v)
        elif isinstance(v, list):
            sanitized[sk] = [str(x)[:500] if isinstance(x, str) else x for x in v[:20]]
        elif isinstance(v, str) and len(v) > 500:
            sanitized[sk] = v[:500]
        else:
            sanitized[sk] = v
    import json as _json
    try:
        enc = _json.dumps(sanitized).encode("utf-8")
        if len(enc) > _AUDIT_METADATA_MAX_BYTES:
            truncated = {}
            for k, v in sanitized.items():
                truncated[k] = v
                if len(_json.dumps(truncated).encode("utf-8")) > _AUDIT_METADATA_MAX_BYTES - 100:
                    truncated[k] = "[TRUNCATED]"
                    break
            sanitized = truncated
            if len(_json.dumps(sanitized).encode("utf-8")) > _AUDIT_METADATA_MAX_BYTES:
                return {"truncated": True, "keys": list(sanitized.keys())[:10]}
    except Exception:
        return {"error": "metadata serialization failed"}
    return sanitized


def _get_scan_tenant(db, target_id: str) -> tuple[str | None, str | None]:
    """Derive (organization_id, project_id) from target -> project. Returns (org, proj) or (None, None)."""
    try:
        proj_id = get_project_id(db, target_id)
        if not proj_id:
            return None, None
        row = db.execute(text("SELECT organization_id FROM projects WHERE id = :pid"), {"pid": proj_id}).fetchone()
        org_id = row[0] if row else None
        return org_id, proj_id
    except Exception:
        return None, None


def _get_finding_tenant(db, target_id: str) -> tuple[str | None, str | None]:
    """Derive tenant for finding via target_id (same as scan)."""
    return _get_scan_tenant(db, target_id)


def _audit_finding_event(
    db,
    *,
    finding_id: str,
    target_id: str,
    event_type: str,
    result: str,
    metadata: dict | None = None,
) -> None:
    """Audit FINDING_* events. Tenant derived from target, actor NULL (system). Savepoint-isolated."""
    nested = None
    try:
        org_id, proj_id = _get_finding_tenant(db, target_id)
        safe_meta = _sanitize_audit_metadata(metadata)
        meta_json = None
        if safe_meta is not None:
            import json as _json
            meta_json = _json.dumps(safe_meta)
        try:
            dialect = db.get_bind().dialect.name if hasattr(db, "get_bind") else "postgresql"
        except Exception:
            dialect = "postgresql"
        use_cast = dialect != "sqlite"
        meta_sql = "CAST(:meta AS JSONB)" if use_cast else ":meta"
        ts_sql = "NOW()" if use_cast else "CURRENT_TIMESTAMP"
        insert_sql = f"""
                    INSERT INTO audit_logs
                    (id, organization_id, project_id, actor_user_id, target_user_id, event_type, action, resource_type, resource_id, result, request_id, correlation_id, ip_address, user_agent, metadata, created_at)
                    VALUES
                    (:id, :org, :proj, NULL, NULL, :evt, :act, :rtype, :rid, :res, NULL, NULL, NULL, NULL, {meta_sql}, {ts_sql})
                    """
        try:
            nested = db.begin_nested()
        except Exception:
            nested = None
        if nested is not None:
            db.execute(text(insert_sql), {"id": str(uuid.uuid4()), "org": org_id, "proj": proj_id, "evt": event_type, "act": event_type, "rtype": "finding", "rid": finding_id, "res": result, "meta": meta_json})
            try:
                db.flush()
                nested.commit()
            except Exception as e:
                try:
                    nested.rollback()
                except Exception:
                    pass
                if "no such table" in str(e).lower() and "audit_logs" in str(e).lower():
                    return
                raise
        else:
            db.execute(text(insert_sql), {"id": str(uuid.uuid4()), "org": org_id, "proj": proj_id, "evt": event_type, "act": event_type, "rtype": "finding", "rid": finding_id, "res": result, "meta": meta_json})
            db.flush()
    except Exception:
        pass


def _audit_scan_event(
    db,
    *,
    scan_id: str,
    target_id: str,
    event_type: str,
    result: str,
    metadata: dict | None = None,
    actor_user_id: str | None = None,
) -> None:
    """Insert audit_logs row for scan lifecycle. Uses a savepoint so missing table does not abort outer scan transaction."""
    nested = None
    try:
        org_id, proj_id = _get_scan_tenant(db, target_id)
        safe_meta = _sanitize_audit_metadata(metadata)
        meta_json = None
        if safe_meta is not None:
            import json as _json
            meta_json = _json.dumps(safe_meta)
        try:
            nested = db.begin_nested()
        except Exception:
            nested = None
        # Use CAST only on Postgres; SQLite fixture tests use plain JSON/text
        try:
            dialect = db.get_bind().dialect.name if hasattr(db, "get_bind") else "postgresql"
        except Exception:
            dialect = "postgresql"
        use_cast = dialect != "sqlite"
        meta_sql = "CAST(:meta AS JSONB)" if use_cast else ":meta"
        # SQLite NOW() is not available; use CURRENT_TIMESTAMP
        ts_sql = "NOW()" if use_cast else "CURRENT_TIMESTAMP"
        insert_sql = f"""
                    INSERT INTO audit_logs
                    (id, organization_id, project_id, actor_user_id, target_user_id, event_type, action, resource_type, resource_id, result, request_id, correlation_id, ip_address, user_agent, metadata, created_at)
                    VALUES
                    (:id, :org, :proj, :actor, NULL, :evt, :act, :rtype, :rid, :res, NULL, NULL, NULL, NULL, {meta_sql}, {ts_sql})
                    """
        if nested is not None:
            db.execute(
                text(insert_sql),
                {
                    "id": str(uuid.uuid4()),
                    "org": org_id,
                    "proj": proj_id,
                    "actor": actor_user_id,
                    "evt": event_type,
                    "act": event_type,
                    "rtype": _AUDIT_RESOURCE_SCAN,
                    "rid": scan_id,
                    "res": result,
                    "meta": meta_json,
                },
            )
            try:
                db.flush()
                nested.commit()
            except Exception as e:
                try:
                    nested.rollback()
                except Exception:
                    pass
                if "no such table" in str(e).lower() and "audit_logs" in str(e).lower():
                    return
                raise
        else:
            db.execute(
                text(insert_sql),
                {
                    "id": str(uuid.uuid4()),
                    "org": org_id,
                    "proj": proj_id,
                    "actor": actor_user_id,
                    "evt": event_type,
                    "act": event_type,
                    "rtype": _AUDIT_RESOURCE_SCAN,
                    "rid": scan_id,
                    "res": result,
                    "meta": meta_json,
                },
            )
            db.flush()
    except Exception:
        # Audit must never break scan execution
        pass


def _update_scan_phase(db, scan_id: str, phase: str) -> None:
    db.execute(
        text(
            """
            UPDATE scans
            SET phase = :phase
            WHERE id = :scan_id
            """
        ),
        {
            "phase": phase,
            "scan_id": scan_id,
        },
    )
    db.commit()


def _persist_findings(
    db,
    *,
    scan_id: str,
    target_id: str,
    scanner_name: str,
    findings: list,
    persisted_assets,
    created_at,
) -> None:
    for finding in findings:
        fid = str(uuid.uuid4())
        db.execute(
            text(
                """
                INSERT INTO findings
                (
                    id,
                    scan_id,
                    target_id,
                    asset_id,
                    scanner,
                    title,
                    description,
                    severity,
                    score,
                    status,
                    evidence,
                    remediation,
                    cve,
                    cwe,
                    metadata,
                    created_at
                )
                VALUES
                (
                    :id,
                    :scan_id,
                    :target_id,
                    :asset_id,
                    :scanner,
                    :title,
                    :description,
                    :severity,
                    :score,
                    :status,
                    :evidence,
                    :remediation,
                    :cve,
                    :cwe,
                    CAST(:metadata AS JSONB),
                    :created_at
                )
                """
            ),
            {
                "id": fid,
                "scan_id": scan_id,
                "target_id": target_id,
                "asset_id": match_asset_id(
                    finding,
                    persisted_assets,
                    scanner_name,
                ),
                "scanner": finding["scanner"],
                "title": finding["title"],
                "description": finding.get(
                    "description"
                ),
                "severity": finding["severity"],
                "score": finding.get("score"),
                "status": finding["status"],
                "evidence": finding.get(
                    "evidence"
                ),
                "remediation": finding.get(
                    "remediation"
                ),
                "cve": finding.get("cve"),
                "cwe": finding.get("cwe"),
                "metadata": json.dumps(
                    sanitize_metadata(
                        finding.get("metadata")
                    )
                ),
                "created_at": created_at,
            },
        )
        # FINDING_CREATED — system actor NULL, tenant derived from target, safe metadata only
        try:
            _audit_finding_event(
                db,
                finding_id=fid,
                target_id=target_id,
                event_type="FINDING_CREATED",
                result="SUCCESS",
                metadata={
                    "severity": finding.get("severity"),
                    "scanner": finding.get("scanner") or scanner_name,
                    "status": finding.get("status"),
                },
            )
        except Exception:
            pass


def _refresh_progress(db, scan_id: str, statuses: list[str], total: int) -> int:
    progress = calculate_progress(statuses, total)
    update_scan_progress(db, scan_id, progress)
    db.commit()
    return progress


@celery_app.task
def execute_scan(
    scan_id: str,
    target_id: str,
    target: str,
    profile: str,
):
    print(f"Starting scan: {scan_id}")
    print(f"Target: {target}")
    print(f"Profile: {profile}")

    db = SessionLocal()

    try:
        db.execute(
            text(
                """
                UPDATE scans
                SET
                    status = :status,
                    phase = :phase,
                    progress = :progress
                WHERE id = :scan_id
                """
            ),
            {
                "status": "running",
                "phase": "scanning",
                "progress": 0,
                "scan_id": scan_id,
            },
        )
        # SCAN_STARTED — background worker event, actor NULL (no HTTP user), tenant from DB
        _audit_scan_event(
            db,
            scan_id=scan_id,
            target_id=target_id,
            event_type=_AUDIT_EVENT_SCAN_STARTED,
            result=_AUDIT_RESULT_SUCCESS,
            metadata={"profile": profile},
        )
        db.commit()

        print("Scan status updated: running")
        print("Scan phase updated: scanning")

        pipeline = ScannerPipeline()
        risk_engine = RiskAssessmentEngine()
        scanners = get_scanners_for_profile(profile)
        max_attempts = get_max_attempts()

        print(
            f"Scanners selected for profile '{profile}': "
            f"{scanners}"
        )

        if not scanners:
            raise ValueError(
                f"No scanners configured for profile '{profile}'"
            )

        all_findings = []
        scanner_outcomes = []
        latest_status = {name: "pending" for name in scanners}
        attempt_rows: dict[tuple[str, int], str] = {}
        project_id = get_project_id(db, target_id)

        for scanner_name in scanners:
            row_id = insert_attempt(
                db,
                scan_id=scan_id,
                scanner=scanner_name,
                status="pending",
                attempt=1,
                max_attempts=max_attempts,
            )
            attempt_rows[(scanner_name, 1)] = row_id
        db.commit()
        _refresh_progress(db, scan_id, list(latest_status.values()), len(scanners))

        for scanner_name in scanners:
            print(f"Starting scanner: {scanner_name}")
            _update_scan_phase(db, scan_id, f"{scanner_name}_running")

            def on_attempt_start(attempt: int, name=scanner_name) -> None:
                if (name, attempt) not in attempt_rows:
                    attempt_rows[(name, attempt)] = insert_attempt(
                        db,
                        scan_id=scan_id,
                        scanner=name,
                        status="pending",
                        attempt=attempt,
                        max_attempts=max_attempts,
                    )
                update_attempt(
                    db,
                    attempt_rows[(name, attempt)],
                    status="running",
                    started_at=utc_now(),
                )
                latest_status[name] = "running"
                db.commit()
                log_scanner_start(scan_id, name, target, attempt)

            def on_attempt_failure(attempt: int, failure: dict, name=scanner_name) -> None:
                update_attempt(
                    db,
                    attempt_rows[(name, attempt)],
                    status="failed",
                    raw_output=_sanitize_secrets_raw(name, failure.get("raw_output", "")),
                    completed_at=failure.get("completed_at") or utc_now(),
                    duration_ms=failure.get("duration_ms"),
                    error_type=failure.get("error_type"),
                    error_message=_sanitize_secrets_error(name, failure.get("error_message") or failure.get("error")),
                    error_phase=failure.get("error_phase"),
                    retryable=failure.get("retryable"),
                    findings_count=0,
                    assets_count=0,
                    extra_data=failure.get("extra_data") or {},
                )
                latest_status[name] = "failed"
                db.commit()
                log_scanner_failure(
                    scan_id,
                    name,
                    failure.get("duration_ms") or 0,
                    failure.get("error_type") or "unknown",
                    bool(failure.get("retryable")),
                    attempt,
                )

            # S7.2 workspace lifecycle — isolated per attempt, only when required
            scanner_instance = pipeline.manager.registry.get(scanner_name)
            requires_ws = bool(getattr(scanner_instance, "requires_workspace", False))

            if requires_ws:
                def _execute_with_workspace(s: str, t: str):
                    ws = None
                    try:
                        ws = create_workspace(scan_id=scan_id, scanner=s, project_id=project_id)
                        ctx = ScanContext(
                            target=ws,
                            target_type=None,
                            project_id=project_id,
                            scan_id=scan_id,
                            workspace=ws,
                            metadata={"original_target": t, "scanner": s},
                        )
                        return pipeline.run_with_context(s, ctx)
                    finally:
                        # Cleanup on success, failure, timeout, exception — never leak
                        cleanup_workspace(ws)

                outcome = run_with_retries(
                    _execute_with_workspace,
                    scanner_name,
                    target,
                    max_attempts=max_attempts,
                    on_attempt_start=on_attempt_start,
                    on_attempt_failure=on_attempt_failure,
                )
            else:
                outcome = run_with_retries(
                    pipeline.run,
                    scanner_name,
                    target,
                    max_attempts=max_attempts,
                    on_attempt_start=on_attempt_start,
                    on_attempt_failure=on_attempt_failure,
                )

            if is_scanner_success(outcome):
                findings = outcome.get("findings", [])
                parsed_result = outcome.get("parsed_result", {})
                assets = parsed_result.get("assets", [])
                completed_at = outcome.get("completed_at") or utc_now()
                try:
                    persisted_assets = persist_parsed_bundle(
                        db,
                        project_id=project_id,
                        scan_id=scan_id,
                        scanner=scanner_name,
                        assets=assets,
                        findings=findings,
                    )
                    _persist_findings(
                        db,
                        scan_id=scan_id,
                        target_id=target_id,
                        scanner_name=scanner_name,
                        findings=findings,
                        persisted_assets=persisted_assets,
                        created_at=completed_at,
                    )
                    update_attempt(
                        db,
                        attempt_rows[(scanner_name, outcome.get("attempt") or 1)],
                        status="completed",
                        raw_output=_sanitize_secrets_raw(scanner_name, outcome.get("raw_output", "")),
                        completed_at=completed_at,
                        duration_ms=outcome.get("duration_ms"),
                        findings_count=len(findings),
                        assets_count=len(assets),
                    )
                    db.commit()
                    latest_status[scanner_name] = "completed"
                    all_findings.extend(findings)
                    log_scanner_success(
                        scan_id,
                        scanner_name,
                        outcome.get("duration_ms") or 0,
                        len(findings),
                        len(assets),
                    )
                    _update_scan_phase(
                        db,
                        scan_id,
                        f"{scanner_name}_completed",
                    )
                except Exception as persist_error:
                    db.rollback()
                    failure = failed_scanner_result(
                        scanner_name,
                        target,
                        ScannerStageError("persistence", persist_error),
                        attempt=outcome.get("attempt") or 1,
                        max_attempts=max_attempts,
                        duration_ms_value=outcome.get("duration_ms") or 0,
                        started_at=outcome.get("started_at"),
                        completed_at=utc_now(),
                        phase="persistence",
                    )
                    update_attempt(
                        db,
                        attempt_rows[(scanner_name, outcome.get("attempt") or 1)],
                        status="failed",
                        raw_output=_sanitize_secrets_raw(scanner_name, failure.get("raw_output", "")),
                        completed_at=utc_now(),
                        duration_ms=failure.get("duration_ms"),
                        error_type=failure.get("error_type"),
                        error_message=_sanitize_secrets_error(scanner_name, failure.get("error_message")),
                        error_phase="persistence",
                        retryable=False,
                        findings_count=0,
                        assets_count=0,
                        extra_data=failure.get("extra_data") or {},
                    )
                    db.commit()
                    latest_status[scanner_name] = "failed"
                    outcome = failure
                    log_scanner_failure(
                        scan_id,
                        scanner_name,
                        failure.get("duration_ms") or 0,
                        "persistence_failure",
                        False,
                        outcome.get("attempt") or 1,
                    )
                    _update_scan_phase(
                        db,
                        scan_id,
                        f"{scanner_name}_failed",
                    )
            else:
                _update_scan_phase(
                    db,
                    scan_id,
                    f"{scanner_name}_failed",
                )

            scanner_outcomes.append(outcome)
            _refresh_progress(
                db,
                scan_id,
                list(latest_status.values()),
                len(scanners),
            )

        summary = scanner_summary(scanner_outcomes)
        final_status = overall_scan_status(scanner_outcomes)
        _refresh_progress(
            db,
            scan_id,
            list(latest_status.values()),
            len(scanners),
        )

        print(f"Total findings detected: {len(all_findings)}")

        if final_status != "completed":
            db.execute(
                text(
                    """
                    UPDATE scans
                    SET
                        status = :status,
                        phase = :phase,
                        progress = :progress
                    WHERE id = :scan_id
                    """
                ),
                {
                    "status": "failed",
                    "phase": "failed",
                    "progress": 100,
                    "scan_id": scan_id,
                },
            )
            # SCAN_FAILED — terminal failure only after retries exhausted, sanitized
            _audit_scan_event(
                db,
                scan_id=scan_id,
                target_id=target_id,
                event_type=_AUDIT_EVENT_SCAN_FAILED,
                result=_AUDIT_RESULT_FAILURE,
                metadata={"profile": profile, "scanners": scanners, "finding_count": len(all_findings)},
            )
            db.commit()
            print(f"Scan failed: {scan_id}")
            return {
                "scan_id": scan_id,
                "target": target,
                "profile": profile,
                "status": "failed",
                "phase": "failed",
                "progress": 100,
                "scanners": scanners,
                "scanner_summary": summary,
                "findings_count": len(all_findings),
                "risk_score": None,
                "risk_grade": None,
                "risk_level": None,
            }

        _update_scan_phase(db, scan_id, "analyzing")
        print("Scan phase updated: analyzing")

        risk_assessment = risk_engine.calculate(all_findings)
        print("Risk assessment:")
        print(risk_assessment)

        db.execute(
            text(
                """
                UPDATE scans
                SET
                    status = :status,
                    phase = :phase,
                    progress = :progress,
                    risk_score = :risk_score,
                    risk_grade = :risk_grade,
                    risk_level = :risk_level
                WHERE id = :scan_id
                """
            ),
            {
                "status": "completed",
                "phase": "completed",
                "progress": 100,
                "risk_score": risk_assessment["score"],
                "risk_grade": risk_assessment["grade"],
                "risk_level": risk_assessment["risk_level"],
                "scan_id": scan_id,
            },
        )
        # SCAN_COMPLETED — terminal success, safe metadata only (no stdout/stderr)
        _audit_scan_event(
            db,
            scan_id=scan_id,
            target_id=target_id,
            event_type=_AUDIT_EVENT_SCAN_COMPLETED,
            result=_AUDIT_RESULT_SUCCESS,
            metadata={"profile": profile, "scanners": scanners, "finding_count": len(all_findings), "risk_score": risk_assessment["score"]},
        )
        db.commit()

        print(f"Scan completed: {scan_id}")
        print(f"Total findings saved: {len(all_findings)}")
        print(f"Risk score: {risk_assessment['score']}")
        print(f"Risk grade: {risk_assessment['grade']}")

        return {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "status": "completed",
            "phase": "completed",
            "progress": 100,
            "scanners": scanners,
            "scanner_summary": summary,
            "findings_count": len(all_findings),
            "risk_score": risk_assessment["score"],
            "risk_grade": risk_assessment["grade"],
            "risk_level": risk_assessment["risk_level"],
        }

    except Exception as exc:
        db.rollback()
        print(f"Scan failed: {scan_id}")
        print(f"Error: {exc}")
        try:
            db.execute(
                text(
                    """
                    UPDATE scans
                    SET
                        status = :status,
                        phase = :phase
                    WHERE id = :scan_id
                    """
                ),
                {
                    "status": "failed",
                    "phase": "failed",
                    "scan_id": scan_id,
                },
            )
            _audit_scan_event(
                db,
                scan_id=scan_id,
                target_id=target_id,
                event_type=_AUDIT_EVENT_SCAN_FAILED,
                result=_AUDIT_RESULT_FAILURE,
                metadata={"profile": profile, "error": str(exc)[:500]},
            )
            db.commit()
        except Exception as status_error:
            db.rollback()
            print(f"Failed to update scan status: {status_error}")
        raise
    finally:
        db.close()

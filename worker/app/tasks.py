from datetime import datetime, timezone
import json
import os
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from .celery_app import celery_app
from .persistence import (
    get_project_id,
    match_asset_id,
    sanitize_metadata,
    upsert_assets,
)
from .risk_engine.engine import RiskAssessmentEngine
from .scanner.profiles import get_scanners_for_profile
from .scanner.pipeline import ScannerPipeline


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://security:security_password@postgres:5432/security_saas",
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


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
    started_at = datetime.now(timezone.utc)

    try:
        # ---------------------------------------------------------
        # 1. Mark scan as running
        # ---------------------------------------------------------

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
                "status": "running",
                "phase": "scanning",
                "scan_id": scan_id,
            },
        )

        db.commit()

        print("Scan status updated: running")
        print("Scan phase updated: scanning")

        # ---------------------------------------------------------
        # 2. Initialize pipeline and risk engine
        # ---------------------------------------------------------

        pipeline = ScannerPipeline()
        risk_engine = RiskAssessmentEngine()

        # ---------------------------------------------------------
        # 3. Get scanners from profile
        # ---------------------------------------------------------

        scanners = get_scanners_for_profile(profile)

        print(
            f"Scanners selected for profile '{profile}': "
            f"{scanners}"
        )

        if not scanners:
            raise ValueError(
                f"No scanners configured for profile '{profile}'"
            )

        all_findings = []
        scanner_results = []
        parsed_assets_by_scanner = []

        # ---------------------------------------------------------
        # 4. Run scanners
        # ---------------------------------------------------------

        for scanner_name in scanners:

            print(
                f"Starting scanner: {scanner_name}"
            )

            # Update current scanner phase.
            db.execute(
                text(
                    """
                    UPDATE scans
                    SET phase = :phase
                    WHERE id = :scan_id
                    """
                ),
                {
                    "phase": f"{scanner_name}_running",
                    "scan_id": scan_id,
                },
            )

            db.commit()

            # Execute scanner through the pipeline.
            pipeline_result = pipeline.run(
                scanner=scanner_name,
                target=target,
            )

            scanner_results.append(
                pipeline_result
            )

            findings = pipeline_result.get(
                "findings",
                [],
            )

            parsed_result = pipeline_result.get(
                "parsed_result",
                {},
            )

            parsed_assets_by_scanner.append(
                {
                    "scanner": scanner_name,
                    "assets": parsed_result.get(
                        "assets",
                        [],
                    ),
                    "findings": findings,
                }
            )

            print(
                f"{scanner_name} completed."
            )

            print(
                f"{scanner_name} findings detected: "
                f"{len(findings)}"
            )

            all_findings.extend(findings)

            # Update scanner completion phase.
            db.execute(
                text(
                    """
                    UPDATE scans
                    SET phase = :phase
                    WHERE id = :scan_id
                    """
                ),
                {
                    "phase": f"{scanner_name}_completed",
                    "scan_id": scan_id,
                },
            )

            db.commit()

            print(
                f"Scan phase updated: "
                f"{scanner_name}_completed"
            )

        # ---------------------------------------------------------
        # 5. Total findings
        # ---------------------------------------------------------

        print(
            f"Total findings detected: "
            f"{len(all_findings)}"
        )

        # ---------------------------------------------------------
        # 6. Mark analyzing
        # ---------------------------------------------------------

        db.execute(
            text(
                """
                UPDATE scans
                SET phase = :phase
                WHERE id = :scan_id
                """
            ),
            {
                "phase": "analyzing",
                "scan_id": scan_id,
            },
        )

        db.commit()

        print("Scan phase updated: analyzing")

        # ---------------------------------------------------------
        # 7. Risk assessment
        # ---------------------------------------------------------

        risk_assessment = risk_engine.calculate(
            all_findings
        )

        print("Risk assessment:")
        print(risk_assessment)

        for finding in all_findings:
            print(
                f"Finding: {finding['title']} "
                f"| Scanner: {finding['scanner']} "
                f"| Severity: {finding['severity']} "
                f"| Score: {finding['score']}"
            )

        completed_at = datetime.now(timezone.utc)

        # ---------------------------------------------------------
        # 8. Save raw scanner results
        # ---------------------------------------------------------

        for scanner_result in scanner_results:

            scanner_name = scanner_result["scanner"]
            raw_output = scanner_result["raw_output"]

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
                        completed_at
                    )
                    VALUES
                    (
                        :id,
                        :scan_id,
                        :scanner,
                        :status,
                        :raw_output,
                        :started_at,
                        :completed_at
                    )
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "scanner": scanner_name,
                    "status": "completed",
                    "raw_output": raw_output,
                    "started_at": started_at,
                    "completed_at": completed_at,
                },
            )

            print(
                f"Raw result saved: "
                f"{scanner_name}"
            )

        # ---------------------------------------------------------
        # 9. Save assets and findings
        # ---------------------------------------------------------

        project_id = get_project_id(
            db,
            target_id,
        )

        for parsed_bundle in parsed_assets_by_scanner:
            persisted_assets = upsert_assets(
                db,
                project_id=project_id,
                scan_id=scan_id,
                assets=parsed_bundle.get(
                    "assets",
                    [],
                ),
            )

            for finding in parsed_bundle.get(
                "findings",
                [],
            ):
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
                        "id": str(uuid.uuid4()),
                        "scan_id": scan_id,
                        "target_id": target_id,
                        "asset_id": match_asset_id(
                            finding,
                            persisted_assets,
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
                        "created_at": completed_at,
                    },
                )

        print(
            f"Findings saved: "
            f"{len(all_findings)}"
        )

        # ---------------------------------------------------------
        # 10. Update risk + completed status
        # ---------------------------------------------------------

        db.execute(
            text(
                """
                UPDATE scans
                SET
                    status = :status,
                    phase = :phase,
                    risk_score = :risk_score,
                    risk_grade = :risk_grade,
                    risk_level = :risk_level
                WHERE id = :scan_id
                """
            ),
            {
                "status": "completed",
                "phase": "completed",
                "risk_score": risk_assessment["score"],
                "risk_grade": risk_assessment["grade"],
                "risk_level": risk_assessment["risk_level"],
                "scan_id": scan_id,
            },
        )

        # ---------------------------------------------------------
        # 11. Commit everything
        # ---------------------------------------------------------

        db.commit()

        print(
            f"Scan completed: {scan_id}"
        )

        print(
            f"Total findings saved: "
            f"{len(all_findings)}"
        )

        print(
            f"Risk score: "
            f"{risk_assessment['score']}"
        )

        print(
            f"Risk grade: "
            f"{risk_assessment['grade']}"
        )

        # ---------------------------------------------------------
        # 12. Return result
        # ---------------------------------------------------------

        return {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "status": "completed",
            "phase": "completed",
            "scanners": scanners,
            "findings_count": len(all_findings),
            "risk_score": risk_assessment["score"],
            "risk_grade": risk_assessment["grade"],
            "risk_level": risk_assessment["risk_level"],
        }

    except Exception as exc:

        db.rollback()

        print(
            f"Scan failed: {scan_id}"
        )

        print(
            f"Error: {exc}"
        )

        # ---------------------------------------------------------
        # Mark scan as failed
        # ---------------------------------------------------------

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

            db.commit()

        except Exception as status_error:

            db.rollback()

            print(
                "Failed to update scan status: "
                f"{status_error}"
            )

        raise

    finally:
        db.close()
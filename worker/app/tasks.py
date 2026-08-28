from datetime import datetime, timezone
import os
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from .celery_app import celery_app
from .scanner.manager import ScannerManager
from .scanner.parsers.nmap_parser import NmapParser
from .scanner.parsers.nuclei_parser import NucleiParser
from .finding_engine.engine import FindingEngine
from .risk_engine.engine import RiskAssessmentEngine


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
                "phase": "nmap_running",
                "scan_id": scan_id,
            },
        )

        db.commit()

        print("Scan status updated: running")
        print("Scan phase updated: nmap_running")

        # ---------------------------------------------------------
        # 2. Initialize components
        # ---------------------------------------------------------

        manager = ScannerManager()
        finding_engine = FindingEngine()
        risk_engine = RiskAssessmentEngine()

        all_findings = []

        # ---------------------------------------------------------
        # 3. Run Nmap
        # ---------------------------------------------------------

        print("Running Nmap...")

        nmap_result = manager.run(
            scanner="nmap",
            target=target,
        )

        print("Nmap scan completed.")

        # ---------------------------------------------------------
        # 4. Parse Nmap
        # ---------------------------------------------------------

        nmap_parser = NmapParser()

        parsed_nmap = nmap_parser.parse(
            nmap_result
        )

        print("Parsed Nmap result:")
        print(parsed_nmap)

        # ---------------------------------------------------------
        # 5. Analyze Nmap
        # ---------------------------------------------------------

        nmap_findings = finding_engine.analyze(
            parsed_nmap
        )

        print(
            f"Nmap findings detected: "
            f"{len(nmap_findings)}"
        )

        all_findings.extend(
            nmap_findings
        )

        # ---------------------------------------------------------
        # 6. Mark Nmap completed
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
                "phase": "nmap_completed",
                "scan_id": scan_id,
            },
        )

        db.commit()

        print("Scan phase updated: nmap_completed")

        # ---------------------------------------------------------
        # 7. Mark Nuclei running
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
                "phase": "nuclei_running",
                "scan_id": scan_id,
            },
        )

        db.commit()

        print("Scan phase updated: nuclei_running")

        # ---------------------------------------------------------
        # 8. Run Nuclei
        # ---------------------------------------------------------

        print("Running Nuclei...")

        nuclei_result = manager.run(
            scanner="nuclei",
            target=target,
        )

        print("Nuclei scan completed.")

        # ---------------------------------------------------------
        # 9. Parse Nuclei
        # ---------------------------------------------------------

        nuclei_parser = NucleiParser()

        parsed_nuclei_findings = (
            nuclei_parser.parse(
                nuclei_result
            )
        )

        print(
            f"Nuclei findings detected: "
            f"{len(parsed_nuclei_findings)}"
        )

        # Nuclei parser already returns
        # normalized findings.

        nuclei_scan_result = {
            "scanner": "nuclei",
            "findings": parsed_nuclei_findings,
        }

        nuclei_findings = (
            finding_engine.analyze(
                nuclei_scan_result
            )
        )

        all_findings.extend(
            nuclei_findings
        )

        # ---------------------------------------------------------
        # 10. Mark Nuclei completed
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
                "phase": "nuclei_completed",
                "scan_id": scan_id,
            },
        )

        db.commit()

        print("Scan phase updated: nuclei_completed")

        # ---------------------------------------------------------
        # 11. Total findings
        # ---------------------------------------------------------

        print(
            f"Total findings detected: "
            f"{len(all_findings)}"
        )

        # ---------------------------------------------------------
        # 12. Mark analyzing
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
        # 13. Risk assessment
        # ---------------------------------------------------------

        risk_assessment = (
            risk_engine.calculate(
                all_findings
            )
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
        # 14. Save Nmap raw result
        # ---------------------------------------------------------

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
                "scanner": "nmap",
                "status": "completed",
                "raw_output": nmap_result,
                "started_at": started_at,
                "completed_at": completed_at,
            },
        )

        # ---------------------------------------------------------
        # 15. Save Nuclei raw result
        # ---------------------------------------------------------

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
                "scanner": "nuclei",
                "status": "completed",
                "raw_output": nuclei_result,
                "started_at": started_at,
                "completed_at": completed_at,
            },
        )

        # ---------------------------------------------------------
        # 16. Save findings
        # ---------------------------------------------------------

        for finding in all_findings:

            db.execute(
                text(
                    """
                    INSERT INTO findings
                    (
                        id,
                        scan_id,
                        target_id,
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
                        created_at
                    )
                    VALUES
                    (
                        :id,
                        :scan_id,
                        :target_id,
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
                        :created_at
                    )
                    """
                ),
                {
                    "id": str(uuid.uuid4()),
                    "scan_id": scan_id,
                    "target_id": target_id,
                    "scanner": finding["scanner"],
                    "title": finding["title"],
                    "description": finding["description"],
                    "severity": finding["severity"],
                    "score": finding["score"],
                    "status": finding["status"],
                    "evidence": finding["evidence"],
                    "remediation": finding["remediation"],
                    "cve": finding["cve"],
                    "cwe": finding["cwe"],
                    "created_at": completed_at,
                },
            )

        # ---------------------------------------------------------
        # 17. Update risk + completed status
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
        # 18. Commit everything
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

        return {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "status": "completed",
            "phase": "completed",
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
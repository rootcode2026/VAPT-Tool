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
                SET status = 'running'
                WHERE id = :scan_id
                """
            ),
            {
                "scan_id": scan_id,
            },
        )

        db.commit()

        # ---------------------------------------------------------
        # 2. Initialize scanner manager
        # ---------------------------------------------------------

        manager = ScannerManager()

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

        nmap_parsed = nmap_parser.parse(
            nmap_result
        )

        print("Parsed Nmap result:")
        print(nmap_parsed)

        # ---------------------------------------------------------
        # 5. Analyze Nmap
        # ---------------------------------------------------------

        finding_engine = FindingEngine()

        nmap_findings = finding_engine.analyze(
            nmap_parsed
        )

        print(
            f"Nmap findings detected: "
            f"{len(nmap_findings)}"
        )

        # ---------------------------------------------------------
        # 6. Save Nmap raw result
        # ---------------------------------------------------------

        completed_at = datetime.now(timezone.utc)

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
        # 7. Run Nuclei
        # ---------------------------------------------------------

        print("Running Nuclei...")

        nuclei_result = manager.run(
            scanner="nuclei",
            target=target,
        )

        print("Nuclei scan completed.")

        # ---------------------------------------------------------
        # 8. Parse Nuclei
        # ---------------------------------------------------------

        nuclei_parser = NucleiParser()

        nuclei_findings = nuclei_parser.parse(
            nuclei_result
        )

        print(
            f"Nuclei findings detected: "
            f"{len(nuclei_findings)}"
        )

        # ---------------------------------------------------------
        # 9. Convert Nuclei findings
        # ---------------------------------------------------------

        nuclei_parsed = {
            "scanner": "nuclei",
            "findings": nuclei_findings,
        }

        nuclei_findings = finding_engine.analyze(
            nuclei_parsed
        )

        # ---------------------------------------------------------
        # 10. Combine findings
        # ---------------------------------------------------------

        findings = (
            nmap_findings +
            nuclei_findings
        )

        print(
            f"Total findings detected: "
            f"{len(findings)}"
        )

        # ---------------------------------------------------------
        # 11. Save Nuclei raw result
        # ---------------------------------------------------------

        completed_at = datetime.now(timezone.utc)

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
        # 12. Save findings
        # ---------------------------------------------------------

        for finding in findings:

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
        # 13. Calculate risk
        # ---------------------------------------------------------

        risk_engine = RiskAssessmentEngine()

        risk_assessment = risk_engine.calculate(
            findings
        )

        print("Risk assessment:")
        print(risk_assessment)

        # ---------------------------------------------------------
        # 14. Update scan
        # ---------------------------------------------------------

        db.execute(
            text(
                """
                UPDATE scans
                SET
                    status = 'completed',
                    risk_score = :risk_score,
                    risk_grade = :risk_grade,
                    risk_level = :risk_level
                WHERE id = :scan_id
                """
            ),
            {
                "risk_score": risk_assessment["score"],
                "risk_grade": risk_assessment["grade"],
                "risk_level": risk_assessment["risk_level"],
                "scan_id": scan_id,
            },
        )

        # ---------------------------------------------------------
        # 15. Commit everything
        # ---------------------------------------------------------

        db.commit()

        print(
            f"Scan completed: {scan_id}"
        )

        print(
            f"Findings saved: {len(findings)}"
        )

        return {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "status": "completed",
            "findings_count": len(findings),
            "risk_score": risk_assessment["score"],
            "risk_grade": risk_assessment["grade"],
            "risk_level": risk_assessment["risk_level"],
        }

    except Exception as exc:

        db.rollback()

        # ---------------------------------------------------------
        # Mark scan as failed
        # ---------------------------------------------------------

        try:
            db.execute(
                text(
                    """
                    UPDATE scans
                    SET status = 'failed'
                    WHERE id = :scan_id
                    """
                ),
                {
                    "scan_id": scan_id,
                },
            )

            db.commit()

        except Exception:
            db.rollback()

        print(
            f"Scan failed: {scan_id}"
        )

        print(
            f"Error: {exc}"
        )

        raise

    finally:
        db.close()
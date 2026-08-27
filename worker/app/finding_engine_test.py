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
        # 1. Initialize components
        # ---------------------------------------------------------

        manager = ScannerManager()
        finding_engine = FindingEngine()
        risk_engine = RiskAssessmentEngine()

        all_findings = []

        # ---------------------------------------------------------
        # 2. Run Nmap
        # ---------------------------------------------------------

        print("Starting Nmap scan...")

        nmap_result = manager.run(
            scanner="nmap",
            target=target,
        )

        nmap_parser = NmapParser()

        parsed_nmap = nmap_parser.parse(
            nmap_result
        )

        print("Parsed Nmap result:")
        print(parsed_nmap)

        nmap_findings = finding_engine.analyze(
            parsed_nmap
        )

        print(
            f"Nmap findings detected: "
            f"{len(nmap_findings)}"
        )

        all_findings.extend(nmap_findings)

        # ---------------------------------------------------------
        # 3. Run Nuclei
        # ---------------------------------------------------------

        print("Starting Nuclei scan...")

        nuclei_result = manager.run(
            scanner="nuclei",
            target=target,
        )

        nuclei_parser = NucleiParser()

        nuclei_findings = nuclei_parser.parse(
            nuclei_result
        )

        print(
            f"Nuclei findings parsed: "
            f"{len(nuclei_findings)}"
        )

        # Nuclei parser already produces normalized findings.
        nuclei_scan_result = {
            "scanner": "nuclei",
            "findings": nuclei_findings,
        }

        nuclei_findings = finding_engine.analyze(
            nuclei_scan_result
        )

        print(
            f"Nuclei findings analyzed: "
            f"{len(nuclei_findings)}"
        )

        all_findings.extend(nuclei_findings)

        # ---------------------------------------------------------
        # 4. Combined findings
        # ---------------------------------------------------------

        print(
            f"Total findings detected: "
            f"{len(all_findings)}"
        )

        for finding in all_findings:
            print(
                f"Finding: {finding['title']} "
                f"| Scanner: {finding['scanner']} "
                f"| Severity: {finding['severity']} "
                f"| Score: {finding['score']}"
            )

        # ---------------------------------------------------------
        # 5. Risk assessment
        # ---------------------------------------------------------

        risk_assessment = risk_engine.calculate(
            all_findings
        )

        print("Risk assessment:")
        print(risk_assessment)

        # ---------------------------------------------------------
        # 6. Complete scan timestamp
        # ---------------------------------------------------------

        completed_at = datetime.now(timezone.utc)

        # ---------------------------------------------------------
        # 7. Save Nmap raw result
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
        # 8. Save Nuclei raw result
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
        # 9. Save findings
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
        # 10. Save risk assessment
        # ---------------------------------------------------------

        db.execute(
            text(
                """
                UPDATE scans
                SET
                    status = :status,
                    risk_score = :risk_score,
                    risk_grade = :risk_grade,
                    risk_level = :risk_level
                WHERE id = :scan_id
                """
            ),
            {
                "status": "completed",
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

        print(f"Scan completed: {scan_id}")
        print("Nmap result saved.")
        print("Nuclei result saved.")
        print(
            f"Total findings saved: "
            f"{len(all_findings)}"
        )

        return {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "status": "completed",
            "findings_count": len(all_findings),
            "risk_score": risk_assessment["score"],
            "risk_grade": risk_assessment["grade"],
            "risk_level": risk_assessment["risk_level"],
        }

    except Exception as exc:
        db.rollback()

        print(f"Scan failed: {scan_id}")
        print(f"Error: {exc}")

        raise

    finally:
        db.close()
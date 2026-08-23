from datetime import datetime, timezone
import os
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from .celery_app import celery_app
from .scanner.manager import ScannerManager
from .scanner.parsers.nmap_parser import NmapParser
from .finding_engine.engine import FindingEngine


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://security:security_password@postgres:5432/security_saas",
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


@celery_app.task
def execute_scan(
    scan_id: str,
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
        # 1. Run scanner
        # ---------------------------------------------------------

        manager = ScannerManager()

        result = manager.run(
            scanner="nmap",
            target=target,
        )

        # ---------------------------------------------------------
        # 2. Parse scanner output
        # ---------------------------------------------------------

        parser = NmapParser()

        parsed_result = parser.parse(result)

        print("Parsed Nmap result:")
        print(parsed_result)

        # ---------------------------------------------------------
        # 3. Analyze parsed result
        # ---------------------------------------------------------

        finding_engine = FindingEngine()

        findings = finding_engine.analyze(
            parsed_result
        )

        print(f"Findings detected: {len(findings)}")

        for finding in findings:
            print(
                f"Finding: {finding['title']} "
                f"| Severity: {finding['severity']} "
                f"| Score: {finding['score']}"
            )

        # ---------------------------------------------------------
        # 4. Complete scan timestamp
        # ---------------------------------------------------------

        completed_at = datetime.now(timezone.utc)

        # ---------------------------------------------------------
        # 5. Save raw scanner result
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
                "raw_output": result,
                "started_at": started_at,
                "completed_at": completed_at,
            },
        )

        # ---------------------------------------------------------
        # 6. Save findings
        # ---------------------------------------------------------

        target_row = db.execute(
            text(
                """
                SELECT id
                FROM targets
                WHERE value = :target
                LIMIT 1
                """
            ),
            {
                "target": target,
            },
        ).fetchone()

        if target_row is None:
            raise RuntimeError(
                f"Target not found in database: {target}"
            )

        target_id = target_row[0]

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

        db.commit()

        print(f"Scan completed: {scan_id}")
        print(f"Nmap result saved to database.")
        print(f"Findings saved: {len(findings)}")

        return {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "status": "completed",
            "findings_count": len(findings),
        }

    except Exception as exc:
        db.rollback()

        print(f"Scan failed: {scan_id}")
        print(f"Error: {exc}")

        raise

    finally:
        db.close()
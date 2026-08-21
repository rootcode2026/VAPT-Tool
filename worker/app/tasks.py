from .celery_app import celery_app
from .scanner.manager import ScannerManager


@celery_app.task
def execute_scan(
    scan_id: str,
    target: str,
    profile: str,
):
    print(f"Starting scan: {scan_id}")
    print(f"Target: {target}")
    print(f"Profile: {profile}")

    manager = ScannerManager()

    try:
        result = manager.run(
            scanner="nmap",
            target=target,
        )

        print(
            f"Scan completed: {scan_id}"
        )

        print(
            f"Nmap result:\n{result}"
        )

        return {
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "status": "completed",
            "result": result,
        }

    except Exception as exc:
        print(
            f"Scan failed: {scan_id}"
        )

        print(
            f"Error: {exc}"
        )

        raise
import time

from .celery_app import celery_app


@celery_app.task
def execute_scan(scan_id: str):
    print(f"Starting scan: {scan_id}")

    time.sleep(5)

    print(f"Scan completed: {scan_id}")

    return {
        "scan_id": scan_id,
        "status": "completed",
    }
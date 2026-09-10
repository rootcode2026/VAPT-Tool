import os

from celery import Celery


celery_app = Celery(
    "security_worker",
    broker=os.getenv(
        "CELERY_BROKER_URL",
        "amqp://guest:guest@rabbitmq:5672//",
    ),
    backend=os.getenv(
        "CELERY_RESULT_BACKEND",
        "redis://redis:6379/0",
    ),
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # The beat schedule references the monitoring tick by name, but nothing
    # imports app.monitoring_scheduler at worker startup (tasks.py imports it
    # lazily), so without this the worker rejects each tick as unregistered.
    include=["app.monitoring_scheduler", "app.notifications"],
    beat_schedule={
        "monitoring-tick": {
            "task": "app.monitoring_scheduler.monitoring_tick",
            "schedule": int(os.getenv("MONITORING_SCHEDULER_INTERVAL_SECONDS", "60")),
        },
    },
)

celery_app.autodiscover_tasks(["app"])
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
)
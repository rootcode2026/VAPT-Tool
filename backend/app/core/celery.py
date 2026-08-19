import os

from celery import Celery


celery_app = Celery(
    "security_api",
    broker=os.getenv(
        "CELERY_BROKER_URL",
        "amqp://guest:guest@rabbitmq:5672//",
    ),
    backend=os.getenv(
        "CELERY_RESULT_BACKEND",
        "redis://redis:6379/0",
    ),
)
from .celery_app import celery_app


@celery_app.task
def test_task():
    return {
        "status": "success",
        "message": "Celery worker is working",
    }
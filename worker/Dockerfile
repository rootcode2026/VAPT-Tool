FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN addgroup --system appgroup && \
    adduser --system --ingroup appgroup appuser

# Create a docker group.
# The actual socket group will be handled at runtime.
RUN groupadd -f docker && \
    usermod -aG docker appuser

COPY --chown=appuser:appgroup app ./app

USER appuser

CMD ["celery", "-A", "app.celery_app", "worker", "--loglevel=info"]
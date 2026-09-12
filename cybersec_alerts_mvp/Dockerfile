FROM python:3.12-slim

# Non-root user (Render best practice)
RUN addgroup --system app && adduser --system --ingroup app app

WORKDIR /app

# Copy project files
COPY cybersec_alerts_mvp/pyproject.toml ./
COPY cybersec_alerts_mvp/src ./src

# Install with web deps
RUN pip install --no-cache-dir -e ".[web]"

# Create persistent data dir (mount point for Render disk)
RUN mkdir -p /data && chown app:app /data

USER app

ENV CYBERSEC_DB_PATH=/data/cybersec_alerts.db
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "cybersec_alerts.api:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.12-slim

RUN addgroup --system app && adduser --system --ingroup app app

WORKDIR /app

COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir -e ".[web]"

RUN mkdir -p /data && chown app:app /data

USER app

ENV CYBERSEC_DB_PATH=/data/cybersec_alerts.db
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "cybersec_alerts.api:app", "--host", "0.0.0.0", "--port", "8000"]

FROM python:3.12-slim

WORKDIR /app
COPY api /app/api
COPY worker /app/worker
RUN pip install --no-cache-dir -e /app/api -e /app/worker
ENV PYTHONPATH=/app/api/src:/app/worker/src
CMD ["uvicorn", "sentinel_api.main:app", "--host", "0.0.0.0", "--port", "8000"]

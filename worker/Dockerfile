FROM python:3.12-slim
WORKDIR /app
COPY worker /app/worker
RUN pip install --no-cache-dir -e /app/worker
ENV PYTHONPATH=/app/worker/src
CMD ["sentinel-worker"]

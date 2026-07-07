FROM python:3.12-slim
WORKDIR /app
COPY worker /app/worker
RUN pip install --no-cache-dir -e /app/worker
# sentinel-worker entrypoint
CMD ["sentinel-worker"]

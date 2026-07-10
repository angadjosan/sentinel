FROM python:3.12-slim

# Sandbox tooling for local_worker pentest mode: the docker CLI (talks to an
# embedded or a mounted host daemon), gVisor `runsc` (userspace-kernel isolation
# for the target), and iptables (optional hard egress). Absent a usable daemon
# these sit unused and the worker runs staging-only — so one image "runs
# wherever". Install is best-effort per-arch; gVisor ships amd64/arm64 only.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl gnupg iptables; \
    install -m 0755 -d /etc/apt/keyrings; \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc; \
    chmod a+r /etc/apt/keyrings/docker.asc; \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends docker-ce-cli docker-ce containerd.io; \
    ARCH="$(dpkg --print-architecture)"; \
    if [ "$ARCH" = "amd64" ] || [ "$ARCH" = "arm64" ]; then \
      curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg; \
      echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" > /etc/apt/sources.list.d/gvisor.list; \
      apt-get update; \
      apt-get install -y --no-install-recommends runsc; \
    fi; \
    apt-get purge -y curl gnupg; apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY worker /app/worker
RUN pip install --no-cache-dir -e /app/worker

COPY worker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# The entrypoint optionally starts an embedded dockerd (SENTINEL_EMBEDDED_DOCKER=1),
# registers runsc, and pre-creates the egress network, then execs the worker.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sentinel-worker"]

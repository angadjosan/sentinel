#!/usr/bin/env bash
# Provision a HOST (a VM or bare-metal box) to run the Sentinel pentest sandbox
# when using the "host daemon" deployment shape (worker mounts /var/run/docker.sock).
# For the self-contained "embedded dockerd" shape you do NOT need this — the worker
# image carries runsc and starts its own daemon (SENTINEL_EMBEDDED_DOCKER=1).
#
# Installs gVisor (runsc), registers it with the host docker daemon, and creates
# the internal egress network. Requires root and an existing docker install.
set -euo pipefail

ARCH="$(dpkg --print-architecture 2>/dev/null || echo unknown)"
if [ "$ARCH" != "amd64" ] && [ "$ARCH" != "arm64" ]; then
  echo "gVisor supports amd64/arm64 only (got: $ARCH)" >&2
  exit 1
fi

echo "==> Installing gVisor (runsc) for $ARCH"
curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=${ARCH} signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
  > /etc/apt/sources.list.d/gvisor.list
apt-get update
apt-get install -y --no-install-recommends runsc

echo "==> Registering runsc with dockerd (/etc/docker/daemon.json)"
runsc install   # writes the runsc runtime into the docker config
systemctl restart docker || service docker restart

echo "==> Creating the internal egress network"
docker network inspect sentinel-egress >/dev/null 2>&1 \
  || docker network create --internal sentinel-egress

echo "==> Done. Verify with: docker info --format '{{json .Runtimes}}'  (should list 'runsc')"

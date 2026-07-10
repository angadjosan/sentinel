#!/usr/bin/env bash
# Worker entrypoint. For local_worker pentest mode it can bring up a container
# runtime so the sandbox "runs wherever"; for staging mode it does nothing and
# just execs the worker. All steps are best-effort and never block startup.
set -euo pipefail

log() { echo "[entrypoint] $*" >&2; }

# 1. Optionally start an embedded docker daemon with gVisor registered. Requires
#    a privileged container. Otherwise the worker uses a mounted host socket
#    (DOCKER_HOST / /var/run/docker.sock) or runs staging-only.
if [ "${SENTINEL_EMBEDDED_DOCKER:-0}" = "1" ]; then
  log "starting embedded dockerd with gVisor (runsc) registered"
  mkdir -p /etc/docker
  if [ ! -f /etc/docker/daemon.json ]; then
    cat > /etc/docker/daemon.json <<'JSON'
{ "runtimes": { "runsc": { "path": "/usr/bin/runsc" } } }
JSON
  fi
  dockerd > /var/log/dockerd.log 2>&1 &
  for _ in $(seq 1 30); do
    if docker info >/dev/null 2>&1; then break; fi
    sleep 1
  done
  docker info >/dev/null 2>&1 && log "dockerd ready" || log "dockerd did not become ready (sandbox tasks will fail preflight)"
fi

# 2. Best-effort: pre-create the internal egress network (the worker also ensures
#    it per run). Internal => the target has no direct external route.
if docker info >/dev/null 2>&1; then
  docker network inspect sentinel-egress >/dev/null 2>&1 \
    || docker network create --internal sentinel-egress >/dev/null 2>&1 \
    || log "could not pre-create sentinel-egress network"
fi

exec "$@"

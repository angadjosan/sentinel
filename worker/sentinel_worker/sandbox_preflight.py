from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

import structlog

from .vm import LocalSubprocessSandboxExecutor, SandboxExecutor

log = structlog.get_logger(__name__)


class SandboxUnavailable(RuntimeError):
    """Raised ONLY when a specific container runtime was explicitly required
    (``SENTINEL_SANDBOX_RUNTIME=gvisor`` or ``=runc``) but cannot be satisfied.

    In the default ``auto`` mode a missing Docker/gVisor is NOT a hard failure:
    the sandbox layer degrades one rung at a time (see the module docstring's
    ladder) and, when there is no container runtime at all, falls back to booting
    the target directly as a subprocess (``runtime="subprocess"``) with a loud,
    logged warning rather than raising."""


# ---------------------------------------------------------------------------
# Docker / gVisor sandbox ladder (heavily documented on purpose — this governs
# how isolated a local pentest is on a given machine).
#
# A local pentest boots the target application and fires payloads at it. To keep
# a possibly-malicious target from touching the host or exfiltrating over the
# network, Sentinel prefers to run it inside a container under gVisor with a
# token-scoped egress proxy. gVisor (the ``runsc`` OCI runtime) is a user-space
# kernel that intercepts the target's syscalls — the strongest isolation tier.
# It runs UNDER Docker (``docker run --runtime=runsc``); "Docker" and "gVisor"
# are therefore a pair — no Docker means no gVisor either — which is why user
# messaging says "Docker/gVisor" as one unit.
#
# The rungs, strongest -> weakest, chosen automatically in ``auto`` mode:
#
#   1. runsc  — Docker + gVisor. Full syscall isolation + egress proxy (+ iptables
#               hard-egress when NET_ADMIN is present). The default when available.
#   2. runc   — Docker without gVisor. Standard container isolation + egress proxy.
#               Used automatically when Docker is present but gVisor isn't.
#   3. subprocess — no Docker at all. The target boots directly on the host as a
#               plain subprocess; no container, no egress proxy. Reduced isolation,
#               but the pentest still runs. Chosen automatically (with a warning)
#               when Docker/gVisor is not found, so a machine WITHOUT Docker can
#               still run pentests. This is also what ``--no-sandbox`` forces.
#
# Feature flag (``SENTINEL_SANDBOX_RUNTIME``, or the CLI ``--no-sandbox``):
#   * ``auto`` (default) — gVisor on if found, else degrade down the ladder,
#     logging each downgrade. Never hard-fails on a missing runtime.
#   * ``gvisor`` — REQUIRE gVisor; raise ``SandboxUnavailable`` if runsc absent.
#   * ``runc``   — REQUIRE Docker; raise ``SandboxUnavailable`` if Docker absent.
#   * ``off`` / ``none`` — sandbox explicitly disabled; boot the target directly
#     (subprocess), skipping the container/proxy entirely.
# ---------------------------------------------------------------------------


# Runtimes that denote a real container sandbox (Docker-backed). "subprocess" and
# "none" are the degraded, container-less rungs.
CONTAINER_RUNTIMES = ("runsc", "runc")


@dataclass(frozen=True)
class SandboxCapabilities:
    docker: bool
    runsc: bool
    net_admin: bool
    runtime: str  # "runsc" (gVisor) | "runc" (Docker) | "subprocess" | "none"
    hard_egress: bool  # can apply iptables FORWARD-DROP rules (NET_ADMIN present)
    summary: str

    @property
    def sandboxed(self) -> bool:
        """True when a real container sandbox is in force (runsc/runc). False for
        the degraded ``subprocess``/``none`` rungs (no container, no egress proxy)."""
        return self.runtime in CONTAINER_RUNTIMES


async def _ok(executor: SandboxExecutor, argv: list[str]) -> tuple[bool, str]:
    # A missing binary (e.g. no `docker` on PATH) must read as "not available",
    # not blow up the probe — that's the whole point of the graceful ladder.
    try:
        result = await executor.run(argv, timeout_seconds=10)
    except (FileNotFoundError, OSError):
        return False, ""
    return result.exit_code == 0, (result.stdout or "")


async def detect_capabilities(
    executor: SandboxExecutor | None = None,
    *,
    requested_runtime: str = "auto",
    environ: Mapping[str, str] | None = None,
) -> SandboxCapabilities:
    """Probe the host for what the sandbox can actually do, and resolve the
    runtime to use. Layered + graceful (see the ladder above): prefer gVisor +
    iptables, fall back to runc + network/proxy, and — when Docker is absent —
    fall back to a container-less subprocess boot with a loud warning instead of
    hard-failing. gVisor is ON by default and degrades automatically; it only
    hard-fails when a specific runtime was EXPLICITLY required.

    Env overrides: ``SENTINEL_SANDBOX_RUNTIME`` (auto|gvisor|runc|off|none),
    ``SENTINEL_SANDBOX_HARD_EGRESS`` (1 forces iptables on, 0 forces off).
    """
    executor = executor or LocalSubprocessSandboxExecutor()
    environ = environ if environ is not None else os.environ
    requested = (environ.get("SENTINEL_SANDBOX_RUNTIME") or requested_runtime or "auto").lower()

    # Feature flag: sandbox explicitly disabled — do not even probe Docker.
    if requested in ("off", "none"):
        log.warning(
            "sandbox.disabled",
            message="Sandbox disabled (--no-sandbox / SENTINEL_SANDBOX_RUNTIME=off) — booting the target directly on this host with NO container isolation and no egress proxy.",
        )
        return SandboxCapabilities(docker=False, runsc=False, net_admin=False, runtime="none", hard_egress=False, summary="runtime=none (sandbox disabled)")

    docker, _ = await _ok(executor, ["docker", "version", "--format", "{{.Server.Version}}"])
    if not docker:
        # Explicitly-required runtime that cannot be satisfied -> hard fail.
        if requested in ("gvisor", "runc"):
            raise SandboxUnavailable(
                f"SENTINEL_SANDBOX_RUNTIME={requested} was required but Docker is not available on this host. "
                "Install Docker (and gVisor for runtime=gvisor), or use the default auto mode / --no-sandbox."
            )
        # auto (default): degrade gracefully to a container-less subprocess boot.
        log.warning(
            "sandbox.docker.absent",
            message="Docker/gVisor not found — running the pentest WITHOUT a container sandbox (the target boots directly on this host; reduced isolation, no egress proxy). Install Docker + gVisor for full isolation, or pass --no-sandbox to silence this.",
        )
        return SandboxCapabilities(docker=False, runsc=False, net_admin=False, runtime="subprocess", hard_egress=False, summary="runtime=subprocess (Docker/gVisor absent)")

    runsc = False
    info_ok, runtimes = await _ok(executor, ["docker", "info", "--format", "{{json .Runtimes}}"])
    if info_ok:
        runsc = "runsc" in runtimes

    # NET_ADMIN probe (best-effort): listing rules requires the capability.
    hard_override = environ.get("SENTINEL_SANDBOX_HARD_EGRESS")
    if hard_override == "0":
        net_admin = False
    elif hard_override == "1":
        net_admin = True
    else:
        net_admin, _ = await _ok(executor, ["iptables", "-S"])

    if requested == "gvisor" and not runsc:
        raise SandboxUnavailable(
            "SENTINEL_SANDBOX_RUNTIME=gvisor but the runsc runtime is not registered with docker; "
            "install gVisor and add it to /etc/docker/daemon.json, or use runtime=auto"
        )
    if requested == "runc":
        runtime = "runc"
    elif requested == "gvisor":
        runtime = "runsc"
    else:  # auto
        runtime = "runsc" if runsc else "runc"

    if runtime == "runsc":
        log.info("sandbox.runtime.gvisor", message="Docker/gVisor: using gVisor (runsc) — full syscall isolation.")
    elif runtime == "runc":
        log.warning("sandbox.runtime.degraded", message="Docker/gVisor: gVisor (runsc) runtime not found — defaulting to standard Docker isolation (runc) + egress proxy. Install gVisor and register it in /etc/docker/daemon.json for full isolation.")
    if not net_admin:
        log.info("sandbox.egress.soft", message="NET_ADMIN unavailable — relying on the internal Docker network + egress proxy (no iptables hard-egress).")

    summary = f"runtime={runtime} runsc={runsc} net_admin={net_admin}"
    return SandboxCapabilities(
        docker=docker,
        runsc=runsc,
        net_admin=net_admin,
        runtime=runtime,
        hard_egress=net_admin,
        summary=summary,
    )

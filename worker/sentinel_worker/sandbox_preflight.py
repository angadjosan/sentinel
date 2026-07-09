from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

import structlog

from .vm import LocalSubprocessSandboxExecutor, SandboxExecutor

log = structlog.get_logger(__name__)


class SandboxUnavailable(RuntimeError):
    """Raised when a local_worker task cannot run because Docker is unavailable.

    This is a hard failure (there is no container runtime at all), distinct from
    the soft degradations below (gVisor -> runc, iptables -> network+proxy)."""


@dataclass(frozen=True)
class SandboxCapabilities:
    docker: bool
    runsc: bool
    net_admin: bool
    runtime: str  # resolved container runtime: "runsc" (gVisor) or "runc"
    hard_egress: bool  # can apply iptables FORWARD-DROP rules (NET_ADMIN present)
    summary: str


async def _ok(executor: SandboxExecutor, argv: list[str]) -> tuple[bool, str]:
    result = await executor.run(argv, timeout_seconds=10)
    return result.exit_code == 0, (result.stdout or "")


async def detect_capabilities(
    executor: SandboxExecutor | None = None,
    *,
    requested_runtime: str = "auto",
    environ: Mapping[str, str] | None = None,
) -> SandboxCapabilities:
    """Probe the host for what the sandbox can actually do, and resolve the
    runtime to use. Layered + graceful (per the plan): prefer gVisor + iptables,
    fall back to runc + network/proxy, hard-fail only when Docker is absent.

    Env overrides: ``SENTINEL_SANDBOX_RUNTIME`` (auto|gvisor|runc),
    ``SENTINEL_SANDBOX_HARD_EGRESS`` (1 forces iptables on, 0 forces off).
    """
    executor = executor or LocalSubprocessSandboxExecutor()
    environ = environ if environ is not None else os.environ
    requested = (environ.get("SENTINEL_SANDBOX_RUNTIME") or requested_runtime or "auto").lower()

    docker, _ = await _ok(executor, ["docker", "version", "--format", "{{.Server.Version}}"])
    if not docker:
        raise SandboxUnavailable(
            "docker is not available on the worker host; local_worker pentest requires a container runtime "
            "(set pentest_mode=staging, or run the sandbox-capable worker image)"
        )

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

    if runtime == "runc":
        log.warning("sandbox.runtime.degraded", reason="gVisor (runsc) unavailable; using runc + network/proxy isolation")
    if not net_admin:
        log.info("sandbox.egress.soft", reason="NET_ADMIN unavailable; relying on internal network + proxy (no iptables)")

    summary = f"runtime={runtime} runsc={runsc} net_admin={net_admin}"
    return SandboxCapabilities(
        docker=docker,
        runsc=runsc,
        net_admin=net_admin,
        runtime=runtime,
        hard_egress=net_admin,
        summary=summary,
    )

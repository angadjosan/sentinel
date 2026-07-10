from __future__ import annotations

import asyncio
import contextlib
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlparse

import structlog

log = structlog.get_logger(__name__)


FORBIDDEN_SHELL_TOKENS = {"|", "||", "&", "&&", ";", ">", ">>", "<", "$(", "`"}


@dataclass(frozen=True)
class TargetSpec:
    """How the target app is declared (rec #3 — support both units).

    `image` (OCI image, ideally pinned by ``@sha256`` digest) is the hermetic,
    recommended tier. `compose`/`boot` are the less-reproducible tiers kept for
    compose-based targets.
    """

    image: str | None = None
    entrypoint: tuple[str, ...] = ()
    compose: str | None = None
    boot: str | None = None


@dataclass(frozen=True)
class ResourceLimits:
    """Hard caps enforced on the sandbox (cgroups v2 + wall clock).

    ``pids_max`` is the anti-fork-bomb control (PIDs cgroup controller); a boot
    command that fork-bombs is capped here rather than taking down the host.
    """

    vcpus: float = 1.0
    memory_mb: int = 2048
    pids_max: int = 256
    wall_clock_seconds: int = 1800


@dataclass(frozen=True)
class EgressPolicy:
    """Default-deny, token-scoped egress (rec #7 — cuts the exfiltration leg).

    A bare hostname allowlist is bypassable (an attacker can exfiltrate through
    an allowlisted domain using their own key). ``token_scoped`` marks that the
    egress proxy binds each request to the sandbox's own provisioned token, so
    an attacker-embedded credential to an allowlisted host is still rejected.
    """

    default: str = "deny"
    allow_hosts: tuple[str, ...] = ()
    token_scoped: bool = True


@dataclass(frozen=True)
class PentestSandboxConfig:
    boot: str | None = None
    healthcheck: str | None = None
    egress_allowlist: list[str] = field(default_factory=list)
    vm_ip: str = "172.16.0.2"
    # gVisor substrate (rec #2). Existing callers that pass only boot/healthcheck
    # keep working; these add the image tier, resource caps, egress policy, and
    # the env injected into the target (synthetic secrets + canaries).
    runtime: str = "gvisor"
    target: TargetSpec | None = None
    resources: ResourceLimits = field(default_factory=ResourceLimits)
    egress: EgressPolicy | None = None
    env: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MicroVMPlan:
    boot_argv: list[str]
    healthcheck_argv: list[str]
    egress_rules: list[str]


@dataclass(frozen=True)
class CommandResult:
    argv: list[str]
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


class SandboxExecutor:
    async def run(self, argv: list[str], *, timeout_seconds: int = 30, stdin: str | None = None) -> CommandResult:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class DryRunSandboxExecutor(SandboxExecutor):
    async def run(self, argv: list[str], *, timeout_seconds: int = 30, stdin: str | None = None) -> CommandResult:
        return CommandResult(argv=argv, exit_code=0, stdout="dry-run")


class LocalSubprocessSandboxExecutor(SandboxExecutor):
    async def run(self, argv: list[str], *, timeout_seconds: int = 30, stdin: str | None = None) -> CommandResult:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdin_bytes = stdin.encode() if stdin is not None else None
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(input=stdin_bytes), timeout=timeout_seconds)
            return CommandResult(argv=argv, exit_code=process.returncode or 0, stdout=stdout.decode(errors="replace"), stderr=stderr.decode(errors="replace"))
        except asyncio.TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            return CommandResult(argv=argv, exit_code=-1, stdout=stdout.decode(errors="replace"), stderr=stderr.decode(errors="replace"), timed_out=True)


def build_microvm_plan(config: PentestSandboxConfig) -> MicroVMPlan:
    boot_argv = parse_safe_command(config.boot) if config.boot else []
    healthcheck_argv = parse_safe_command(config.healthcheck) if config.healthcheck else []
    hosts = []
    if config.healthcheck:
        host = _host_from_healthcheck(config.healthcheck)
        if host:
            hosts.append(host)
    hosts.extend(config.egress_allowlist)
    return MicroVMPlan(
        boot_argv=boot_argv,
        healthcheck_argv=healthcheck_argv,
        egress_rules=egress_rules(config.vm_ip, hosts),
    )


def parse_safe_command(command: str) -> list[str]:
    for token in FORBIDDEN_SHELL_TOKENS:
        if token in command:
            raise ValueError("command contains shell metacharacters")
    return shlex.split(command)


def egress_rules(vm_ip: str, hosts: list[str]) -> list[str]:
    unique_hosts = []
    for host in hosts:
        if host and host not in unique_hosts:
            unique_hosts.append(host)
    return [
        "*filter",
        ":FORWARD DROP [0:0]",
        *[f"-A FORWARD -s {vm_ip} -d {host} -j ACCEPT" for host in unique_hosts],
        "COMMIT",
    ]


# --- gVisor sandbox substrate (rec #2) ---------------------------------------
# The shipped isolation substrate for the `local_worker` path: gVisor (runsc),
# which needs no nested virtualization and runs on ordinary worker hosts.

DEFAULT_EGRESS_NETWORK = "sentinel-egress"


@dataclass(frozen=True)
class GvisorLaunchPlan:
    """A fully-resolved, side-effect-free plan to launch the target under gVisor.

    ``container_argv`` is populated for the hermetic OCI-image tier; ``boot_argv``
    for the compose/boot tier. ``egress_rules`` is default-deny with per-host
    allows; ``env`` is what gets injected into the target — synthetic secrets and
    canary decoys only. Real third-party credentials never enter ``env``; they
    are injected per-request by the credential broker (see credential_broker.py).
    """

    container_argv: list[str]
    boot_argv: list[str]
    healthcheck_argv: list[str]
    egress_rules: list[str]
    env: dict[str, str]
    container_name: str = ""


def build_gvisor_plan(
    config: PentestSandboxConfig,
    *,
    network: str = DEFAULT_EGRESS_NETWORK,
    runtime: str = "runsc",
    name: str = "sentinel-pentest",
) -> GvisorLaunchPlan:
    """Resolve a PentestSandboxConfig into a launchable gVisor plan.

    Image tier (hermetic, recommended) → ``docker run --runtime <runtime>`` argv
    with cgroup caps, a stable ``--name`` (for teardown), and a host-gateway route
    so outbound traffic can reach the egress proxy. Compose/boot tier → a parsed
    argv. No shell is ever invoked (parse_safe_command rejects metacharacters).

    ``runtime`` is the resolved container runtime ("runsc" for gVisor, "runc" as
    the graceful fallback when gVisor is unavailable — see sandbox_preflight).
    """
    resources = config.resources
    env = dict(config.env)

    allow_hosts: list[str] = []
    hc_host = _host_from_healthcheck(config.healthcheck) if config.healthcheck else None
    if hc_host:
        allow_hosts.append(hc_host)
    if config.egress:
        allow_hosts.extend(config.egress.allow_hosts)
    allow_hosts.extend(config.egress_allowlist)

    container_argv: list[str] = []
    boot_argv: list[str] = []
    container_name = ""
    target = config.target
    if target and target.image:
        container_name = name
        container_argv = _docker_runsc_argv(target, resources, env, network, runtime, name)
    elif target and target.boot:
        boot_argv = parse_safe_command(target.boot)
    elif config.boot:
        boot_argv = parse_safe_command(config.boot)

    healthcheck_argv = parse_safe_command(config.healthcheck) if config.healthcheck else []
    return GvisorLaunchPlan(
        container_argv=container_argv,
        boot_argv=boot_argv,
        healthcheck_argv=healthcheck_argv,
        egress_rules=egress_rules(config.vm_ip, allow_hosts),
        env=env,
        container_name=container_name,
    )


def _docker_runsc_argv(
    target: TargetSpec,
    resources: ResourceLimits,
    env: dict[str, str],
    network: str,
    runtime: str,
    name: str,
) -> list[str]:
    argv = [
        "docker", "run", "--rm", "-d",
        "--name", name,  # stable name so the container can be torn down
        "--runtime", runtime,  # "runsc" (gVisor) or "runc" fallback
        "--network", network,  # attached to the egress-restricted network only
        # Route to the worker host so the target reaches the egress proxy; on Linux
        # host-gateway resolves to the docker bridge gateway (the worker host).
        "--add-host", "host.docker.internal:host-gateway",
        "--memory", f"{resources.memory_mb}m",
        "--cpus", f"{resources.vcpus}",
        "--pids-limit", str(resources.pids_max),  # anti-fork-bomb (PIDs cgroup)
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
    ]
    for key in sorted(env):  # decoys/synthetic only — never real creds
        argv.extend(["-e", f"{key}={env[key]}"])
    if target.image:
        argv.append(target.image)
    argv.extend(target.entrypoint)
    return argv


DEFAULT_PROXY_HOST_FROM_SANDBOX = "host.docker.internal"


async def ensure_egress_network(executor: SandboxExecutor, name: str = DEFAULT_EGRESS_NETWORK) -> bool:
    """Idempotently ensure the internal egress network exists (gap #2).

    ``--internal`` means the target has no direct external route — outbound
    traffic can only reach the worker-host egress proxy. Returns True if the
    network is present/created, False if docker is unavailable.
    """
    inspect = await executor.run(["docker", "network", "inspect", name], timeout_seconds=15)
    if inspect.exit_code == 0:
        return True
    created = await executor.run(["docker", "network", "create", "--internal", name], timeout_seconds=30)
    if created.exit_code != 0 and "already exists" not in (created.stderr or ""):
        log.warning("sandbox.network.create_failed", network=name, stderr=created.stderr[-200:])
        return False
    return True


async def apply_egress_rules(executor: SandboxExecutor, rules: list[str]) -> bool:
    """Apply the computed iptables FORWARD-DROP rules via iptables-restore (gap #5).

    This is the hard-enforcement layer: even a target that ignores HTTP(S)_PROXY
    can only reach allowlisted hosts. Requires NET_ADMIN; callers should gate on
    the preflight capability check and treat False as "degrade to network+proxy".
    """
    payload = "\n".join(rules) + "\n"
    result = await executor.run(["iptables-restore", "--noflush", "--stdin"], timeout_seconds=15, stdin=payload)
    if result.exit_code != 0:
        log.warning("sandbox.egress_rules.apply_failed", stderr=result.stderr[-200:])
        return False
    return True


def _container_id_from_run(argv: list[str], result: CommandResult) -> str | None:
    """If argv was a detached `docker run -d`, return the container name/id to
    stop later. Prefers the explicit --name; falls back to the printed id."""
    if result.exit_code != 0 or "run" not in argv or "-d" not in argv:
        return None
    if "--name" in argv:
        idx = argv.index("--name")
        if idx + 1 < len(argv):
            return argv[idx + 1]
    printed = (result.stdout or "").strip().splitlines()
    return printed[-1].strip() if printed and printed[-1].strip() else None


class GvisorSandboxExecutor(SandboxExecutor):
    """Runs argv under gVisor by delegating to a command executor, and tears down
    any detached containers it started (gap #4).

    In production the injected executor shells out to ``docker`` on the worker
    host; in dev/tests a recording or subprocess executor makes this functional
    without docker/runsc installed. Replaces ``executor=None`` on local_worker.
    """

    def __init__(self, *, command_executor: SandboxExecutor | None = None) -> None:
        self._command_executor = command_executor or LocalSubprocessSandboxExecutor()
        self._owns_command_executor = command_executor is None
        self._containers: list[str] = []

    async def run(self, argv: list[str], *, timeout_seconds: int = 30, stdin: str | None = None) -> CommandResult:
        result = await self._command_executor.run(argv, timeout_seconds=timeout_seconds, stdin=stdin)
        container = _container_id_from_run(argv, result)
        if container:
            self._containers.append(container)
        return result

    async def close(self) -> None:
        # Stop (and, via --rm, remove) every container we started, newest first.
        for container in reversed(self._containers):
            with contextlib.suppress(Exception):
                await self._command_executor.run(["docker", "stop", "--time", "5", container], timeout_seconds=20)
        self._containers.clear()
        if self._owns_command_executor:
            await self._command_executor.close()


@dataclass(frozen=True)
class EgressProxyPolicy:
    """Policy enforced by the token-scoped egress proxy.

    Encodes the "allowlist is necessary but not sufficient" lesson: a request is
    permitted only if the destination host is allowlisted AND it carries the
    sandbox's own provisioned token. An attacker who embeds their own key to an
    allowlisted host is rejected on the token check.
    """

    allow_hosts: tuple[str, ...]
    sandbox_token: str
    token_scoped: bool = True


def proxy_allows(policy: EgressProxyPolicy, host: str, presented_token: str | None) -> tuple[bool, str | None]:
    if host not in policy.allow_hosts:
        return False, "host_not_allowlisted"
    if policy.token_scoped and presented_token != policy.sandbox_token:
        return False, "token_mismatch"
    return True, None


def build_egress_proxy_env(port: int, host: str = "127.0.0.1") -> dict[str, str]:
    """HTTP(S)_PROXY env pointing the sandbox's outbound traffic at the host proxy.

    Mirrors the sandbox-runtime pattern: the sandbox has no direct egress (the
    egress network is ``--internal``); all outbound traffic is forced through the
    proxy, which enforces the default-deny, token-scoped policy above. From inside
    a container ``host`` is ``host.docker.internal`` (the worker host / bridge
    gateway); the default suits host-local callers and tests.
    """
    endpoint = f"http://{host}:{port}"
    return {
        "HTTP_PROXY": endpoint,
        "HTTPS_PROXY": endpoint,
        "http_proxy": endpoint,
        "https_proxy": endpoint,
    }


def _host_from_healthcheck(command: str) -> str | None:
    for part in shlex.split(command):
        parsed = urlparse(part)
        if parsed.hostname:
            return parsed.hostname
    return None

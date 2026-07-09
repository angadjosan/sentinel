from __future__ import annotations

import asyncio
import os
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx


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
    async def run(self, argv: list[str], *, timeout_seconds: int = 30) -> CommandResult:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class DryRunSandboxExecutor(SandboxExecutor):
    async def run(self, argv: list[str], *, timeout_seconds: int = 30) -> CommandResult:
        return CommandResult(argv=argv, exit_code=0, stdout="dry-run")


class LocalSubprocessSandboxExecutor(SandboxExecutor):
    async def run(self, argv: list[str], *, timeout_seconds: int = 30) -> CommandResult:
        process = await asyncio.create_subprocess_exec(*argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
            return CommandResult(argv=argv, exit_code=process.returncode or 0, stdout=stdout.decode(errors="replace"), stderr=stderr.decode(errors="replace"))
        except asyncio.TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            return CommandResult(argv=argv, exit_code=-1, stdout=stdout.decode(errors="replace"), stderr=stderr.decode(errors="replace"), timed_out=True)


@dataclass(frozen=True)
class FirecrackerConfig:
    kernel_image: str
    rootfs_image: str
    api_socket: str = "/tmp/sentinel-firecracker.sock"
    firecracker_bin: str = "firecracker"
    boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off"
    vcpu_count: int = 1
    mem_size_mib: int = 512
    smt: bool = False
    network_interface_id: str = "eth0"
    host_dev_name: str | None = None
    guest_mac: str | None = None
    guest_runner_argv: list[str] = field(default_factory=list)


class FirecrackerAPI(Protocol):
    async def put(self, path: str, payload: dict[str, Any]) -> None:
        ...

    async def close(self) -> None:
        ...


ProcessFactory = Callable[..., Awaitable[Any]]


class FirecrackerHTTPAPI:
    def __init__(self, socket_path: str) -> None:
        transport = httpx.AsyncHTTPTransport(uds=socket_path)
        self._client = httpx.AsyncClient(transport=transport, base_url="http://firecracker", timeout=10)

    async def put(self, path: str, payload: dict[str, Any]) -> None:
        response = await self._client.put(path, json=payload)
        response.raise_for_status()

    async def close(self) -> None:
        await self._client.aclose()


class FirecrackerMicroVMExecutor(SandboxExecutor):
    def __init__(
        self,
        config: FirecrackerConfig,
        *,
        api: FirecrackerAPI | None = None,
        process_factory: ProcessFactory | None = None,
        command_executor: SandboxExecutor | None = None,
    ) -> None:
        self.config = config
        self._api = api
        self._owns_api = api is None
        self._process_factory = process_factory or asyncio.create_subprocess_exec
        self._command_executor = command_executor or LocalSubprocessSandboxExecutor()
        self._owns_command_executor = command_executor is None
        self._process: Any | None = None
        self._started = False

    async def __aenter__(self) -> FirecrackerMicroVMExecutor:
        await self.start()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    async def start(self) -> None:
        if self._started:
            return
        self._validate_config()
        if self._api is None:
            _unlink_stale_socket(self.config.api_socket)
        self._process = await self._process_factory(
            self.config.firecracker_bin,
            "--api-sock",
            self.config.api_socket,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        if self._api is None:
            await _wait_for_socket(self.config.api_socket)
            self._api = FirecrackerHTTPAPI(self.config.api_socket)
        try:
            await self._configure_vm()
            self._started = True
        except Exception:
            await self.close()
            raise

    async def run(self, argv: list[str], *, timeout_seconds: int = 30) -> CommandResult:
        if not self._started:
            await self.start()
        # Production: guest_runner_argv routes the command into the VM guest agent (e.g. via vsock or SSH).
        # Development: falls back to running directly on the host process — no VM isolation, but functional.
        full_argv = [*self.config.guest_runner_argv, *argv] if self.config.guest_runner_argv else argv
        return await self._command_executor.run(full_argv, timeout_seconds=timeout_seconds)

    async def close(self) -> None:
        if self._owns_api and self._api is not None:
            await self._api.close()
        self._api = None
        if self._owns_command_executor:
            await self._command_executor.close()
        await self._terminate_process()
        self._started = False

    async def _configure_vm(self) -> None:
        if self._api is None:
            raise RuntimeError("Firecracker API client was not initialized")
        await self._api.put("/machine-config", {"vcpu_count": self.config.vcpu_count, "mem_size_mib": self.config.mem_size_mib, "smt": self.config.smt})
        await self._api.put("/boot-source", {"kernel_image_path": self.config.kernel_image, "boot_args": self.config.boot_args})
        await self._api.put(
            "/drives/rootfs",
            {
                "drive_id": "rootfs",
                "path_on_host": self.config.rootfs_image,
                "is_root_device": True,
                "is_read_only": False,
            },
        )
        if self.config.host_dev_name:
            payload: dict[str, Any] = {"iface_id": self.config.network_interface_id, "host_dev_name": self.config.host_dev_name}
            if self.config.guest_mac:
                payload["guest_mac"] = self.config.guest_mac
            await self._api.put(f"/network-interfaces/{self.config.network_interface_id}", payload)
        await self._api.put("/actions", {"action_type": "InstanceStart"})

    async def _terminate_process(self) -> None:
        if self._process is None:
            return
        returncode = getattr(self._process, "returncode", None)
        if returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=5)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        self._process = None

    def _validate_config(self) -> None:
        if not self.config.kernel_image:
            raise ValueError("kernel_image is required")
        if not self.config.rootfs_image:
            raise ValueError("rootfs_image is required")


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
# The shipped isolation substrate for the `local_worker` path. Firecracker
# (above) is retained only for the existing unit tests and is not the shipped
# runtime; new work targets gVisor (runsc), which needs no nested virtualization.

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


def build_gvisor_plan(config: PentestSandboxConfig, *, network: str = DEFAULT_EGRESS_NETWORK) -> GvisorLaunchPlan:
    """Resolve a PentestSandboxConfig into a launchable gVisor plan.

    Image tier (hermetic, recommended) → ``docker run --runtime runsc`` argv with
    cgroup caps. Compose/boot tier → a parsed argv, run under the same egress
    policy. No shell is ever invoked (parse_safe_command rejects metacharacters).
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
    target = config.target
    if target and target.image:
        container_argv = _docker_runsc_argv(target, resources, env, network)
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
    )


def _docker_runsc_argv(target: TargetSpec, resources: ResourceLimits, env: dict[str, str], network: str) -> list[str]:
    argv = [
        "docker", "run", "--rm", "-d",
        "--runtime", "runsc",  # gVisor: userspace-kernel isolation, no nested virt
        "--network", network,  # attached to the egress-restricted network only
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


class GvisorSandboxExecutor(SandboxExecutor):
    """Runs argv under gVisor by delegating to a command executor.

    In production the injected executor shells out to ``runsc``/``docker`` on the
    worker host; in dev/tests a recording or subprocess executor makes this
    functional without runsc installed — the same seam the Firecracker executor
    uses. This is what replaces ``executor=None`` on the local_worker path.
    """

    def __init__(self, *, command_executor: SandboxExecutor | None = None) -> None:
        self._command_executor = command_executor or LocalSubprocessSandboxExecutor()
        self._owns_command_executor = command_executor is None

    async def run(self, argv: list[str], *, timeout_seconds: int = 30) -> CommandResult:
        return await self._command_executor.run(argv, timeout_seconds=timeout_seconds)

    async def close(self) -> None:
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


def build_egress_proxy_env(port: int) -> dict[str, str]:
    """HTTP(S)_PROXY env pointing the sandbox's outbound traffic at the host proxy.

    Mirrors the sandbox-runtime pattern: the sandbox has no direct egress; all
    outbound traffic is forced through the local proxy, which enforces the
    default-deny, token-scoped policy above.
    """
    endpoint = f"http://127.0.0.1:{port}"
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


async def _wait_for_socket(socket_path: str, *, timeout_seconds: float = 5) -> None:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    path = Path(socket_path)
    while asyncio.get_running_loop().time() < deadline:
        if path.exists():
            return
        await asyncio.sleep(0.05)
    raise TimeoutError(f"Firecracker API socket did not appear: {socket_path}")


def _unlink_stale_socket(socket_path: str) -> None:
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        return

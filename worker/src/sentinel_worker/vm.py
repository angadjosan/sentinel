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
class PentestSandboxConfig:
    boot: str | None = None
    healthcheck: str | None = None
    egress_allowlist: list[str] = field(default_factory=list)
    vm_ip: str = "172.16.0.2"


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
        if not self.config.guest_runner_argv:
            return CommandResult(
                argv=argv,
                exit_code=-1,
                stderr="Firecracker guest command runner is not configured; provide guest_runner_argv for the VM image agent.",
            )
        return await self._command_executor.run([*self.config.guest_runner_argv, *argv], timeout_seconds=timeout_seconds)

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

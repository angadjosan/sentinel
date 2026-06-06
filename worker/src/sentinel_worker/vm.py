from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from urllib.parse import urlparse


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

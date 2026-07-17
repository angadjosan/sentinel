"""Preflight capability detection + egress network / iptables helpers."""
import pytest

from sentinel_worker.sandbox_preflight import SandboxUnavailable, detect_capabilities
from sentinel_worker.vm import CommandResult, SandboxExecutor, apply_egress_rules, egress_rules, ensure_egress_network


class FakeExec(SandboxExecutor):
    """Executor returning canned results by matching a substring of the argv."""

    def __init__(self, rules: list[tuple[str, CommandResult]]):
        self._rules = rules
        self.calls: list[tuple[list[str], str | None]] = []

    async def run(self, argv, *, timeout_seconds=30, stdin=None):
        self.calls.append((argv, stdin))
        joined = " ".join(argv)
        for needle, result in self._rules:
            if needle in joined:
                return CommandResult(argv=argv, exit_code=result.exit_code, stdout=result.stdout, stderr=result.stderr)
        return CommandResult(argv=argv, exit_code=127, stderr="not found")


def _ok(stdout=""):
    return CommandResult(argv=[], exit_code=0, stdout=stdout)


def _fail():
    return CommandResult(argv=[], exit_code=1)


# --- preflight -----------------------------------------------------------------

@pytest.mark.asyncio
async def test_detect_prefers_gvisor_and_hard_egress_when_available():
    ex = FakeExec([
        ("docker version", _ok("27.0")),
        ("docker info", _ok('{"runc":{},"runsc":{}}')),
        ("iptables -S", _ok()),
    ])
    caps = await detect_capabilities(ex, environ={})
    assert caps.runtime == "runsc"
    assert caps.runsc is True
    assert caps.hard_egress is True


@pytest.mark.asyncio
async def test_detect_falls_back_to_runc_without_runsc():
    ex = FakeExec([("docker version", _ok("27.0")), ("docker info", _ok("{\"runc\":{}}")), ("iptables -S", _fail())])
    caps = await detect_capabilities(ex, environ={})
    assert caps.runtime == "runc"
    assert caps.hard_egress is False  # no NET_ADMIN


@pytest.mark.asyncio
async def test_detect_auto_degrades_to_subprocess_without_docker():
    """auto mode (default): Docker absent is NOT fatal — degrade to the
    container-less subprocess rung with a warning, so a machine without Docker
    can still run pentests."""
    ex = FakeExec([("docker version", _fail())])
    caps = await detect_capabilities(ex, environ={})
    assert caps.runtime == "subprocess"
    assert caps.docker is False
    assert caps.sandboxed is False
    assert caps.hard_egress is False


@pytest.mark.asyncio
async def test_detect_explicit_runc_still_hard_fails_without_docker():
    """Opting out of the graceful ladder: an explicit runtime request that can't
    be met still raises."""
    ex = FakeExec([("docker version", _fail())])
    with pytest.raises(SandboxUnavailable):
        await detect_capabilities(ex, environ={"SENTINEL_SANDBOX_RUNTIME": "runc"})


@pytest.mark.asyncio
async def test_detect_off_flag_disables_sandbox_without_probing():
    """The --no-sandbox flag (SENTINEL_SANDBOX_RUNTIME=off) returns the disabled
    rung and never even probes Docker."""
    ex = FakeExec([("docker version", _ok("27.0"))])
    caps = await detect_capabilities(ex, environ={"SENTINEL_SANDBOX_RUNTIME": "off"})
    assert caps.runtime == "none"
    assert caps.sandboxed is False
    assert ex.calls == []  # no probing at all


@pytest.mark.asyncio
async def test_explicit_gvisor_request_fails_without_runsc():
    ex = FakeExec([("docker version", _ok("27.0")), ("docker info", _ok("{\"runc\":{}}"))])
    with pytest.raises(SandboxUnavailable):
        await detect_capabilities(ex, environ={"SENTINEL_SANDBOX_RUNTIME": "gvisor"})


@pytest.mark.asyncio
async def test_hard_egress_env_override_forces_off():
    ex = FakeExec([("docker version", _ok("27.0")), ("docker info", _ok('{"runsc":{}}')), ("iptables -S", _ok())])
    caps = await detect_capabilities(ex, environ={"SENTINEL_SANDBOX_HARD_EGRESS": "0"})
    assert caps.hard_egress is False  # forced off despite iptables succeeding


# --- network + iptables --------------------------------------------------------

@pytest.mark.asyncio
async def test_ensure_network_is_idempotent_when_present():
    ex = FakeExec([("network inspect", _ok())])
    assert await ensure_egress_network(ex, "sentinel-egress") is True
    assert not any("network create" in " ".join(a) for a, _ in ex.calls)  # no create


@pytest.mark.asyncio
async def test_ensure_network_creates_internal_when_absent():
    ex = FakeExec([("network inspect", _fail()), ("network create", _ok())])
    assert await ensure_egress_network(ex, "sentinel-egress") is True
    create = next(a for a, _ in ex.calls if "network create" in " ".join(a))
    assert "--internal" in create and "sentinel-egress" in create


@pytest.mark.asyncio
async def test_apply_egress_rules_pipes_iptables_restore_via_stdin():
    ex = FakeExec([("iptables-restore", _ok())])
    rules = egress_rules("172.16.0.2", [])
    assert await apply_egress_rules(ex, rules) is True
    argv, stdin = next((a, s) for a, s in ex.calls if "iptables-restore" in " ".join(a))
    assert ":FORWARD DROP [0:0]" in stdin  # the drop rule was piped in
    assert stdin.endswith("\n")

import pytest

from sentinel_worker.vm import (
    CommandResult,
    FirecrackerConfig,
    FirecrackerMicroVMExecutor,
    LocalSubprocessSandboxExecutor,
    PentestSandboxConfig,
    build_microvm_plan,
    egress_rules,
    parse_safe_command,
)


class FakeFirecrackerAPI:
    def __init__(self, fail_path=None):
        self.puts = []
        self.closed = False
        self.fail_path = fail_path

    async def put(self, path, payload):
        if path == self.fail_path:
            raise RuntimeError(f"failed {path}")
        self.puts.append((path, payload))

    async def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self):
        self.returncode = None
        self.terminated = False
        self.killed = False
        self.waited = False

    def terminate(self):
        self.terminated = True
        self.returncode = 0

    def kill(self):
        self.killed = True
        self.returncode = -9

    async def wait(self):
        self.waited = True
        return self.returncode


class FakeCommandExecutor:
    def __init__(self):
        self.calls = []

    async def run(self, argv, *, timeout_seconds=30):
        self.calls.append((argv, timeout_seconds))
        return CommandResult(argv=argv, exit_code=0, stdout="guest ok")


def test_parse_safe_command_rejects_shell_metacharacters():
    assert parse_safe_command("docker compose up -d") == ["docker", "compose", "up", "-d"]
    with pytest.raises(ValueError):
        parse_safe_command("docker compose up -d && curl http://evil.test")


def test_build_microvm_plan_extracts_healthcheck_host_and_allowlist():
    plan = build_microvm_plan(
        PentestSandboxConfig(
            boot="docker compose up -d",
            healthcheck="curl -sf http://localhost:3000/health",
            egress_allowlist=["api.example.com"],
            vm_ip="172.16.0.9",
        )
    )

    assert plan.boot_argv == ["docker", "compose", "up", "-d"]
    assert plan.healthcheck_argv == ["curl", "-sf", "http://localhost:3000/health"]
    assert "-A FORWARD -s 172.16.0.9 -d localhost -j ACCEPT" in plan.egress_rules
    assert "-A FORWARD -s 172.16.0.9 -d api.example.com -j ACCEPT" in plan.egress_rules


def test_egress_rules_deduplicate_hosts():
    rules = egress_rules("172.16.0.2", ["api.example.com", "api.example.com"])

    assert rules.count("-A FORWARD -s 172.16.0.2 -d api.example.com -j ACCEPT") == 1


@pytest.mark.asyncio
async def test_local_subprocess_executor_runs_and_times_out():
    executor = LocalSubprocessSandboxExecutor()

    ok = await executor.run(["python", "-c", "print('ok')"], timeout_seconds=5)
    timed_out = await executor.run(["python", "-c", "import time; time.sleep(2)"], timeout_seconds=1)

    assert ok.exit_code == 0
    assert ok.stdout.strip() == "ok"
    assert timed_out.exit_code == -1
    assert timed_out.timed_out is True


@pytest.mark.asyncio
async def test_firecracker_executor_configures_and_starts_microvm():
    api = FakeFirecrackerAPI()
    process = FakeProcess()
    launched = []

    async def process_factory(*argv, **kwargs):
        launched.append((list(argv), kwargs))
        return process

    executor = FirecrackerMicroVMExecutor(
        FirecrackerConfig(
            kernel_image="/var/lib/sentinel/vmlinux",
            rootfs_image="/var/lib/sentinel/rootfs.ext4",
            api_socket="/tmp/sentinel-test-firecracker.sock",
            firecracker_bin="/usr/bin/firecracker",
            vcpu_count=2,
            mem_size_mib=1024,
            host_dev_name="tap0",
            guest_mac="02:FC:00:00:00:01",
        ),
        api=api,
        process_factory=process_factory,
    )

    await executor.start()
    await executor.close()

    assert launched[0][0] == ["/usr/bin/firecracker", "--api-sock", "/tmp/sentinel-test-firecracker.sock"]
    assert api.puts[0] == ("/machine-config", {"vcpu_count": 2, "mem_size_mib": 1024, "smt": False})
    assert api.puts[1][0] == "/boot-source"
    assert api.puts[1][1]["kernel_image_path"] == "/var/lib/sentinel/vmlinux"
    assert api.puts[2] == (
        "/drives/rootfs",
        {
            "drive_id": "rootfs",
            "path_on_host": "/var/lib/sentinel/rootfs.ext4",
            "is_root_device": True,
            "is_read_only": False,
        },
    )
    assert api.puts[3] == ("/network-interfaces/eth0", {"iface_id": "eth0", "host_dev_name": "tap0", "guest_mac": "02:FC:00:00:00:01"})
    assert api.puts[4] == ("/actions", {"action_type": "InstanceStart"})
    assert process.terminated is True
    assert process.waited is True
    assert api.closed is False


@pytest.mark.asyncio
async def test_firecracker_executor_runs_guest_command_through_runner():
    api = FakeFirecrackerAPI()
    process = FakeProcess()
    command_executor = FakeCommandExecutor()

    async def process_factory(*argv, **kwargs):
        return process

    executor = FirecrackerMicroVMExecutor(
        FirecrackerConfig(
            kernel_image="/kernel",
            rootfs_image="/rootfs",
            guest_runner_argv=["sentinel-vsock-exec", "--socket", "/tmp/vsock.sock", "--"],
        ),
        api=api,
        process_factory=process_factory,
        command_executor=command_executor,
    )

    result = await executor.run(["curl", "-sf", "http://127.0.0.1:3000/health"], timeout_seconds=9)
    await executor.close()

    assert result.exit_code == 0
    assert command_executor.calls == [
        (
            ["sentinel-vsock-exec", "--socket", "/tmp/vsock.sock", "--", "curl", "-sf", "http://127.0.0.1:3000/health"],
            9,
        )
    ]


@pytest.mark.asyncio
async def test_firecracker_executor_reports_missing_guest_runner():
    api = FakeFirecrackerAPI()

    async def process_factory(*argv, **kwargs):
        return FakeProcess()

    executor = FirecrackerMicroVMExecutor(FirecrackerConfig(kernel_image="/kernel", rootfs_image="/rootfs"), api=api, process_factory=process_factory)

    result = await executor.run(["id"], timeout_seconds=1)
    await executor.close()

    assert result.exit_code == -1
    assert "guest command runner is not configured" in result.stderr


@pytest.mark.asyncio
async def test_firecracker_executor_tears_down_process_on_configuration_failure():
    api = FakeFirecrackerAPI(fail_path="/boot-source")
    process = FakeProcess()

    async def process_factory(*argv, **kwargs):
        return process

    executor = FirecrackerMicroVMExecutor(FirecrackerConfig(kernel_image="/kernel", rootfs_image="/rootfs"), api=api, process_factory=process_factory)

    with pytest.raises(RuntimeError, match="failed /boot-source"):
        await executor.start()

    assert process.terminated is True
    assert process.waited is True

"""gVisor sandbox substrate: launch-plan construction + token-scoped egress."""
from sentinel_worker.vm import (
    DEFAULT_EGRESS_NETWORK,
    EgressPolicy,
    EgressProxyPolicy,
    GvisorSandboxExecutor,
    PentestSandboxConfig,
    ResourceLimits,
    TargetSpec,
    build_egress_proxy_env,
    build_gvisor_plan,
    proxy_allows,
)


def test_image_tier_builds_runsc_argv_with_caps_and_env():
    config = PentestSandboxConfig(
        healthcheck="curl -sf http://localhost:3000/health",
        target=TargetSpec(image="ghcr.io/acme/app@sha256:abc", entrypoint=("node", "server.js")),
        resources=ResourceLimits(vcpus=2, memory_mb=1024, pids_max=128),
        env={"SENTINEL_CANARY_0": "decoy"},
    )
    plan = build_gvisor_plan(config)
    argv = plan.container_argv
    assert argv[:5] == ["docker", "run", "--rm", "-d", "--runtime"]
    assert "runsc" in argv
    assert "--memory" in argv and "1024m" in argv
    assert "--pids-limit" in argv and "128" in argv  # anti-fork-bomb
    assert "--cap-drop" in argv and "ALL" in argv
    assert "no-new-privileges" in argv
    assert "ghcr.io/acme/app@sha256:abc" in argv
    assert argv[-2:] == ["node", "server.js"]  # entrypoint appended after image
    assert "-e" in argv and "SENTINEL_CANARY_0=decoy" in argv
    assert DEFAULT_EGRESS_NETWORK in argv
    assert plan.boot_argv == []


def test_boot_tier_parses_argv_and_has_no_container():
    config = PentestSandboxConfig(target=TargetSpec(boot="docker compose up -d"))
    plan = build_gvisor_plan(config)
    assert plan.container_argv == []
    assert plan.boot_argv == ["docker", "compose", "up", "-d"]


def test_egress_is_default_deny_with_allowlist():
    config = PentestSandboxConfig(
        healthcheck="curl -sf http://app.internal:8080/health",
        egress=EgressPolicy(allow_hosts=("registry.npmjs.org",)),
        target=TargetSpec(image="img@sha256:x"),
    )
    plan = build_gvisor_plan(config)
    assert ":FORWARD DROP [0:0]" in plan.egress_rules  # default-deny
    assert any("app.internal" in rule for rule in plan.egress_rules)  # healthcheck host allowed
    assert any("registry.npmjs.org" in rule for rule in plan.egress_rules)


def test_proxy_requires_both_allowlist_and_token():
    policy = EgressProxyPolicy(allow_hosts=("api.example.com",), sandbox_token="tok-123")
    assert proxy_allows(policy, "api.example.com", "tok-123") == (True, None)
    # allowlisted host but attacker-embedded (wrong) token -> rejected
    assert proxy_allows(policy, "api.example.com", "attacker-key") == (False, "token_mismatch")
    # not allowlisted at all
    assert proxy_allows(policy, "evil.test", "tok-123") == (False, "host_not_allowlisted")


def test_proxy_env_forces_outbound_through_local_proxy():
    env = build_egress_proxy_env(8080)
    assert env["HTTPS_PROXY"] == "http://127.0.0.1:8080"
    assert env["http_proxy"] == "http://127.0.0.1:8080"


async def test_gvisor_executor_delegates_to_command_executor():
    from sentinel_worker.vm import CommandResult, SandboxExecutor

    class Recording(SandboxExecutor):
        def __init__(self):
            self.calls = []

        async def run(self, argv, *, timeout_seconds=30):
            self.calls.append(argv)
            return CommandResult(argv=argv, exit_code=0)

    rec = Recording()
    executor = GvisorSandboxExecutor(command_executor=rec)
    result = await executor.run(["echo", "hi"])
    assert result.exit_code == 0
    assert rec.calls == [["echo", "hi"]]
    await executor.close()

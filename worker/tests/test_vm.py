import pytest

from sentinel_worker.vm import PentestSandboxConfig, build_microvm_plan, egress_rules, parse_safe_command


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

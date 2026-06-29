"""Tests for the CI-native standalone scanner (sentinel-scan).

These exercise the full local pipeline (ephemeral SQLite -> findings) without
any network or LLM dependency, plus the output formatting and CLI wiring.
"""

import json
from pathlib import Path

import pytest

from sentinel_worker.agent import SentinelLLMClient
from sentinel_worker import standalone
from sentinel_worker.standalone import (
    ScanFinding,
    ScanResult,
    _scan,
    _severity_rank,
    resolve_llm,
    to_findings_json,
    to_sarif,
)

SECRET_DIFF = """diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,2 +1,3 @@
 import os
+AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
"""

CLEAN_DIFF = """diff --git a/readme.md b/readme.md
--- a/readme.md
+++ b/readme.md
@@ -1 +1,2 @@
 hello
+world
"""


# ── packaging: prompt templates must ship with the package ─────────────────
def test_prompt_templates_present():
    """Prompts are loaded at runtime via Path(__file__).parent/'prompts'.

    They must be declared as package-data in pyproject.toml, otherwise a
    non-editable install (pip install ./worker, as in the GitHub Action) omits
    them and the scan crashes with FileNotFoundError. This guards that the
    files exist where the loaders expect them.
    """
    import sentinel_worker

    prompts = Path(sentinel_worker.__file__).parent / "prompts"
    for name in ("sast.txt", "pentest.txt", "remediation.txt", "enrich.txt"):
        assert (prompts / name).is_file(), f"missing prompt template: {name}"


# ── severity / threshold logic ─────────────────────────────────────────────
def test_severity_rank_ordering():
    assert _severity_rank("critical") > _severity_rank("high") > _severity_rank("medium")
    assert _severity_rank("low") < _severity_rank("medium")
    # Unknown severities default to medium, never crash.
    assert _severity_rank("bogus") == _severity_rank("medium")


def test_scan_result_max_severity_rank_empty():
    assert ScanResult(repo_name="x").max_severity_rank == -1


# ── SARIF formatting ───────────────────────────────────────────────────────
def test_to_sarif_is_valid_2_1_0():
    result = ScanResult(repo_name="x")
    result.findings.append(
        ScanFinding(
            vuln_type="sql_injection",
            severity="critical",
            title="SQLi",
            description="bad",
            remediation="fix",
            fingerprint="abc",
            file="app.py",
            line=42,
        )
    )
    sarif = to_sarif(result)
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "Sentinel"
    res = run["results"][0]
    assert res["ruleId"] == "sql_injection"
    assert res["level"] == "error"  # critical -> error
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app.py"
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
    assert res["partialFingerprints"]["sentinelFingerprint"] == "abc"


def test_to_sarif_severity_levels():
    result = ScanResult(repo_name="x")
    for sev in ["low", "medium", "high"]:
        result.findings.append(
            ScanFinding(vuln_type="x", severity=sev, title="t", description="d", remediation="r", fingerprint=sev)
        )
    levels = {r["properties"]["severity"]: r["level"] for r in to_sarif(result)["runs"][0]["results"]}
    assert levels == {"low": "note", "medium": "warning", "high": "error"}


def test_to_sarif_no_location_when_no_file():
    result = ScanResult(repo_name="x")
    result.findings.append(
        ScanFinding(vuln_type="x", severity="high", title="t", description="d", remediation="r", fingerprint="f")
    )
    assert "locations" not in to_sarif(result)["runs"][0]["results"][0]


# ── LLM resolution ─────────────────────────────────────────────────────────
def test_resolve_llm_mock_default(monkeypatch):
    monkeypatch.delenv("SENTINEL_PROVIDER", raising=False)
    ns = _ns(provider=None, model=None, api_key=None, llm_endpoint=None)
    client = resolve_llm(ns)
    assert isinstance(client, SentinelLLMClient)
    assert client.provider_name == "mock"


def test_resolve_llm_anthropic_without_key_errors(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("SENTINEL_LLM_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        resolve_llm(_ns(provider="anthropic", model=None, api_key=None, llm_endpoint=None))


def test_resolve_llm_anthropic_with_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = resolve_llm(_ns(provider="anthropic", model=None, api_key=None, llm_endpoint=None))
    assert client.provider_name == "anthropic"
    assert client.model == "claude-sonnet-4-6"  # provider default


# ── full pipeline (no network) ─────────────────────────────────────────────
@pytest.mark.asyncio
async def test_scan_detects_secret_with_mock_provider():
    llm = SentinelLLMClient(provider="mock", model="mock")
    result = await _scan(
        repo_name="demo/repo",
        diff=SECRET_DIFF,
        llm=llm,
        run_context="ci",
        base_ref="origin/main",
        commit_sha="deadbeef",
    )
    assert any(f.vuln_type == "secret_leak" for f in result.findings)
    secret = next(f for f in result.findings if f.vuln_type == "secret_leak")
    assert secret.file == "config.py"
    assert secret.fingerprint  # populated


@pytest.mark.asyncio
async def test_scan_clean_diff_no_findings():
    llm = SentinelLLMClient(provider="mock", model="mock")
    result = await _scan(
        repo_name="demo/repo",
        diff=CLEAN_DIFF,
        llm=llm,
        run_context="ci",
        base_ref=None,
        commit_sha=None,
    )
    assert result.findings == []
    assert result.max_severity_rank == -1


# ── CLI run() integration ──────────────────────────────────────────────────
def test_run_with_diff_file_writes_sarif_and_exit_code(tmp_path, monkeypatch):
    diff_file = tmp_path / "d.diff"
    diff_file.write_text(SECRET_DIFF)
    sarif = tmp_path / "out.sarif"
    code = standalone.run(
        [
            "--repo-name", "demo/repo",
            "--diff-file", str(diff_file),
            "--provider", "mock",
            "--sarif", str(sarif),
            "--fail-on", "low",  # secret is medium -> should fail
        ]
    )
    assert code == 1
    data = json.loads(sarif.read_text())
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) >= 1


def test_run_fail_on_none_returns_zero(tmp_path):
    diff_file = tmp_path / "d.diff"
    diff_file.write_text(SECRET_DIFF)
    code = standalone.run(
        ["--repo-name", "demo/repo", "--diff-file", str(diff_file), "--provider", "mock", "--fail-on", "none", "--json", str(tmp_path / "o.json")]
    )
    assert code == 0


def test_run_empty_diff_returns_zero(tmp_path):
    diff_file = tmp_path / "empty.diff"
    diff_file.write_text("")
    sarif = tmp_path / "e.sarif"
    code = standalone.run(
        ["--repo-name", "demo/repo", "--diff-file", str(diff_file), "--provider", "mock", "--sarif", str(sarif)]
    )
    assert code == 0
    assert json.loads(sarif.read_text())["runs"][0]["results"] == []


def test_findings_json_shape():
    result = ScanResult(repo_name="r", run_context="ci", base_ref="main", commit_sha="sha")
    result.findings.append(
        ScanFinding(vuln_type="x", severity="high", title="t", description="d", remediation="rem", fingerprint="f", file="a.py", line=3)
    )
    out = to_findings_json(result)
    assert out["repo_name"] == "r"
    assert out["finding_count"] == 1
    assert out["findings"][0]["file"] == "a.py"
    assert out["findings"][0]["line"] == 3


# ── helper ─────────────────────────────────────────────────────────────────
def _ns(**kwargs):
    import argparse

    return argparse.Namespace(**kwargs)

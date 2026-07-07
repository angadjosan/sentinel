"""A local scan's real findings must survive a cloud push failure — the scan
succeeded locally; a network blip or backend mismatch on push shouldn't
discard that. Mirrors the graceful --ingest-url failure handling already in
standalone.py's post_findings call.
"""
import httpx
import pytest

from sentinel_worker.local_cli import _push_or_warn
from sentinel_worker.local_engine import GraphDelta
from sentinel_worker.standalone import ScanFinding, ScanResult


def test_push_or_warn_survives_http_error(monkeypatch):
    def failing_post(url, json=None, headers=None, timeout=None):
        request = httpx.Request("POST", url)
        return httpx.Response(404, json={"detail": "not found"}, request=request)

    monkeypatch.setattr(httpx, "post", failing_post)

    scan = ScanResult(repo_name="acme/repo", findings=[ScanFinding(
        vuln_type="secret_leak", severity="medium", title="t", description="d",
        remediation="r", fingerprint="fp1",
    )])
    result = _push_or_warn(
        api_url="https://unreachable.example", token=None, repo_name="acme/repo",
        run_context="local", commit_sha=None, base_ref=None, scan=scan, delta=GraphDelta(),
    )
    assert "error" in result


def test_push_or_warn_survives_connection_error(monkeypatch):
    def raising_post(url, json=None, headers=None, timeout=None):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", raising_post)

    result = _push_or_warn(
        api_url="https://unreachable.example", token=None, repo_name="acme/repo",
        run_context="local", commit_sha=None, base_ref=None, scan=ScanResult(repo_name="acme/repo"), delta=GraphDelta(),
    )
    assert "error" in result

"""Tests for local_engine.py — the CLI-invoked local-execution core.

These prove the three load-bearing properties of the local-AI-calls refactor:
1. A scan runs fully offline (no api_url) and reads source from `repo_dir`,
   not any cloud snapshot.
2. When `api_url` is given, existing graph context is pulled (read-only) for
   the diff's touched nodes before SAST runs, and the returned delta only
   contains genuinely new nodes/edges — not the pulled context.
3. Pushing results to the cloud sends findings + graph pointers only — never
   source text or diff content.
"""
import json
import subprocess
from pathlib import Path

import httpx
import pytest

from sentinel_worker.agent import ToolCallEvent
from sentinel_worker.local_engine import (
    GraphDelta,
    fetch_cloud_finding,
    push_pentest_result,
    push_results_to_cloud,
    run_local_init,
    run_local_pentest,
    run_local_plan_review,
    run_local_source_scan,
)
from sentinel_worker.standalone import ScanFinding, ScanResult


@pytest.fixture(autouse=True)
def _isolated_trace_home(tmp_path_factory, monkeypatch):
    """_save_local_trace writes to Path.home()/.sentinel/runs — isolate that
    from the developer's real home directory during tests."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setattr(Path, "home", lambda: home)


_DIFF = """diff --git a/app/db.py b/app/db.py
--- a/app/db.py
+++ b/app/db.py
@@ -1,2 +1,3 @@
 import os
+def query_user(): pass
"""


class _ReadThenFindLLM:
    """Reads app/db.py through the tool dispatcher, then emits a finding only
    if the content it got back came from the real local file (not the diff)."""

    def __init__(self):
        self.seen_content = None

    async def call_with_tools(self, *, system, user, tools, tool_dispatcher, max_iterations=50, **kwargs):
        read_result = await tool_dispatcher("read_file", {"file_path": "app/db.py"})
        self.seen_content = read_result.get("content")
        if "db.query(user_id)" not in (self.seen_content or ""):
            return
        result = await tool_dispatcher(
            "emit_finding",
            {
                "vuln_type": "sqli",
                "severity": "high",
                "title": "SQL Injection",
                "description": "found via local file read",
                "remediation": "use parameterized queries",
                "node_id": "file:app/db.py",
            },
        )
        yield ToolCallEvent(type="tool_call", tool_name="emit_finding", tool_input={}, result=result)


@pytest.mark.asyncio
async def test_local_source_scan_reads_repo_dir_and_produces_delta(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("def query_user(user_id):\n    return db.query(user_id)\n")

    llm = _ReadThenFindLLM()
    result = await run_local_source_scan(
        repo_name="acme/repo",
        repo_dir=str(tmp_path),
        diff=_DIFF,
        llm=llm,
    )

    # Proves the SAST tool read the real local file, not the diff snippet.
    assert "db.query(user_id)" in llm.seen_content

    assert len(result.scan.findings) == 1
    assert result.scan.findings[0].vuln_type == "sqli"

    # The diff's own node(s) should show up as a graph delta to push.
    assert any(n["is_new"] for n in result.delta.nodes)


@pytest.mark.asyncio
async def test_local_source_scan_works_fully_offline_without_api_url(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("def query_user(user_id):\n    return safe_query(user_id)\n")
    llm = _ReadThenFindLLM()
    result = await run_local_source_scan(repo_name="acme/repo", repo_dir=str(tmp_path), diff=_DIFF, llm=llm)
    assert result.scan.findings == []  # no db.query in this file -> no finding, no crash, no network needed


@pytest.mark.asyncio
async def test_local_source_scan_pulls_cloud_context_when_api_url_given(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("def query_user(user_id):\n    return db.query(user_id)\n")

    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["url"] = url
        captured["seeds"] = params.get("seeds")
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            json={
                "graph_id": "g1",
                "nodes": [
                    {
                        "id": "fn:app/other.py:caller", "kind": "FUNCTION", "name": "caller",
                        "file": "app/other.py", "line_start": 1, "line_end": 2, "language": "python",
                        "auth_required": False, "is_entry_point": False, "is_sink": False,
                        "label": "existing caller", "intent": None,
                    }
                ],
                "edges": [],
            },
            request=request,
        )

    monkeypatch.setattr(httpx, "get", fake_get)

    llm = _ReadThenFindLLM()
    result = await run_local_source_scan(
        repo_name="acme/repo", repo_dir=str(tmp_path), diff=_DIFF, llm=llm,
        api_url="https://cloud.example/api", api_token="tok",
    )

    assert captured["url"] == "https://cloud.example/api/graph/subgraph"
    assert captured["seeds"]  # build_source_graph pre-pass produced real seed ids

    # The pulled context node must NOT appear in the delta pushed back — it
    # isn't new, it's context that already exists in the cloud main graph.
    delta_ids = {n["id"] for n in result.delta.nodes}
    assert "fn:app/other.py:caller" not in delta_ids
    assert len(result.scan.findings) == 1


def test_push_results_to_cloud_sends_only_metadata(monkeypatch):
    captured_posts = []

    def fake_post(url, json=None, headers=None, timeout=None):
        captured_posts.append((url, json))
        request = httpx.Request("POST", url)
        if url.endswith("/graph/upsert"):
            return httpx.Response(200, json={"graph_id": "g1", "nodes_upserted": 1, "edges_upserted": 0}, request=request)
        return httpx.Response(200, json={"run_id": "r1", "created": 1, "updated": 0, "total": 1}, request=request)

    monkeypatch.setattr(httpx, "post", fake_post)

    scan = ScanResult(
        repo_name="acme/repo",
        findings=[
            ScanFinding(
                vuln_type="sqli", severity="high", title="SQLi", description="d",
                remediation="r", fingerprint="fp1", file="app/db.py", line=2,
            )
        ],
    )
    delta = GraphDelta(nodes=[{"id": "fn:app/db.py:query_user", "kind": "FUNCTION", "name": "query_user", "is_new": True}])

    result = push_results_to_cloud(
        api_url="https://cloud.example/api", token="tok", repo_name="acme/repo",
        run_context="local", commit_sha="abc123", base_ref="origin/main", scan=scan, delta=delta,
    )

    assert result["findings"]["created"] == 1
    urls = [u for u, _ in captured_posts]
    assert "https://cloud.example/api/graph/upsert" in urls
    assert "https://cloud.example/api/findings/ingest" in urls

    # No source/diff markers anywhere in what actually got sent.
    for _, payload in captured_posts:
        blob = json.dumps(payload)
        assert "diff --git" not in blob
        assert "+++ b/" not in blob


@pytest.mark.asyncio
async def test_local_init_builds_graph_from_tracked_files(tmp_path):
    from tests.conftest import MockLLMClient

    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("def query_user(user_id):\n    return db.query(user_id)\n")
    (tmp_path / ".env").write_text("SECRET=shh\n")
    subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)

    delta, local_run_id, local_trace_path = await run_local_init(repo_name="acme/repo", repo_dir=str(tmp_path), llm=MockLLMClient())

    assert any(n["file"] == "app/db.py" for n in delta.nodes)
    assert not any((n.get("file") or "").endswith(".env") for n in delta.nodes)
    assert local_run_id
    import os
    assert os.path.isfile(local_trace_path)


class _ConfirmingPentestLLM:
    """Reads app/db.py through the tool dispatcher (proving repo_dir wiring in
    the pentest agent loop too), then confirms via emit_pentest_result."""

    def __init__(self):
        self.seen_content = None

    async def call_with_tools(self, *, system, user, tools, tool_dispatcher, max_iterations=50, **kwargs):
        read_result = await tool_dispatcher("read_file", {"file_path": "app/db.py"})
        self.seen_content = read_result.get("content")
        await tool_dispatcher(
            "emit_pentest_result",
            {
                "payloads": ["' OR '1'='1"],
                "confirmed": True,
                "outcome": "data_exfiltrated",
                "proof_artifact": f"dumped row via payload; sink source: {self.seen_content!r}",
            },
        )
        return
        yield  # pragma: no cover — makes this an async generator


_FINDING_JSON = {
    "id": "finding-1", "vuln_type": "sqli", "severity": "high", "title": "SQLi",
    "description": "d", "remediation": "r", "status": "open", "confirmed": False,
    "evidence": None, "fingerprint": "fp1", "node_id": "fn:app/db.py:query_user",
    "file": "app/db.py", "line_start": 1, "line_end": 2,
    "created_at": "2024-01-01T00:00:00", "updated_at": "2024-01-01T00:00:00",
}
_TARGET_NODE_JSON = {
    "id": "fn:app/db.py:query_user", "kind": "FUNCTION", "name": "query_user", "file": "app/db.py",
    "line_start": 1, "line_end": 2, "language": "python", "auth_required": False,
    "is_entry_point": False, "is_sink": True, "label": None, "intent": None,
}


@pytest.mark.asyncio
async def test_local_pentest_confirms_finding_reading_repo_dir(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("def query_user(user_id):\n    return db.query(user_id)\n")

    def fake_get(url, headers=None, timeout=None, params=None):
        request = httpx.Request("GET", url)
        if url.endswith("/findings/finding-1"):
            return httpx.Response(200, json=_FINDING_JSON, request=request)
        if url.endswith("/graph/subgraph"):
            return httpx.Response(200, json={"graph_id": "g1", "nodes": [_TARGET_NODE_JSON], "edges": []}, request=request)
        raise AssertionError(f"unexpected GET {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    llm = _ConfirmingPentestLLM()
    result = await run_local_pentest(
        repo_name="acme/repo", repo_dir=str(tmp_path), finding_id="finding-1", llm=llm,
        api_url="https://cloud.example/api", api_token="tok",
    )

    assert "db.query(user_id)" in llm.seen_content  # proves repo_dir wiring reached the pentest tool loop too
    assert result.confirmed is True
    assert result.status == "confirmed"
    assert result.sink_node_id == "fn:app/db.py:query_user"


@pytest.mark.asyncio
async def test_local_pentest_not_reproducible_without_confirmation(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("def query_user(user_id):\n    return safe(user_id)\n")

    class _NoConfirmLLM:
        async def call_with_tools(self, *, system, user, tools, tool_dispatcher, max_iterations=50, **kwargs):
            return
            yield  # pragma: no cover

    def fake_get(url, headers=None, timeout=None, params=None):
        request = httpx.Request("GET", url)
        if url.endswith("/findings/finding-1"):
            return httpx.Response(200, json=_FINDING_JSON, request=request)
        if url.endswith("/graph/subgraph"):
            return httpx.Response(200, json={"graph_id": "g1", "nodes": [_TARGET_NODE_JSON], "edges": []}, request=request)
        raise AssertionError(f"unexpected GET {url}")

    monkeypatch.setattr(httpx, "get", fake_get)

    result = await run_local_pentest(
        repo_name="acme/repo", repo_dir=str(tmp_path), finding_id="finding-1", llm=_NoConfirmLLM(),
        api_url="https://cloud.example/api", api_token="tok",
    )
    assert result.confirmed is False
    assert result.status == "not_reproducible"


def test_fetch_cloud_finding_and_push_pentest_result(monkeypatch):
    def fake_get(url, headers=None, timeout=None, params=None):
        assert url == "https://cloud.example/api/findings/finding-1"
        return httpx.Response(200, json=_FINDING_JSON, request=httpx.Request("GET", url))

    captured_post = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        captured_post["url"] = url
        captured_post["json"] = json
        return httpx.Response(200, json={"id": "finding-1", "status": "confirmed", "confirmed": True}, request=httpx.Request("POST", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(httpx, "post", fake_post)

    finding = fetch_cloud_finding(api_url="https://cloud.example/api", token="tok", finding_id="finding-1")
    assert finding["id"] == "finding-1"

    from sentinel_worker.local_engine import LocalPentestResult
    result = LocalPentestResult(
        finding_id="finding-1", confirmed=True, status="confirmed", evidence="proof",
        entry_node_id="route:x", sink_node_id="fn:app/db.py:query_user",
    )
    resp = push_pentest_result(api_url="https://cloud.example/api", token="tok", result=result)
    assert resp["status"] == "confirmed"
    assert captured_post["url"] == "https://cloud.example/api/findings/finding-1/confirm"
    assert captured_post["json"]["confirmed"] is True
    # No source/diff content anywhere in what actually got sent.
    import json as _json
    assert "diff --git" not in _json.dumps(captured_post["json"])


@pytest.mark.asyncio
async def test_local_plan_review_reads_repo_dir(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("def query_user(user_id):\n    return db.query(user_id)\n")
    llm = _ReadThenFindLLM()
    # review_plan's diff is synthesized from the plan text itself, so this LLM
    # (which reads app/db.py explicitly) still proves repo_dir threading works
    # for plan review's tool calls.
    result, local_run_id, local_trace_path = await run_local_plan_review(
        repo_name="acme/repo", repo_dir=str(tmp_path), content="users query the db directly", llm=llm
    )
    assert len(result.findings) == 1
    assert local_run_id
    import os
    assert os.path.isfile(local_trace_path)

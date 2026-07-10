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
    push_results_to_cloud,
    run_local_init,
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


# NOTE: local pentest tests were removed with the local pentest code
# (AUDIT.md §3 D4). Pentest now runs on the cloud worker; its integration tests
# live in worker/tests/test_runner_pentest.py etc. (owned by W1). The CLI-side
# enqueue+poll behavior is covered by cli/tests.


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

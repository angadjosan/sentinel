"""
API test fixtures.

SAST LLM mock — quarantined (AUDIT.md §6 W4 P3.4)
-------------------------------------------------
`_PatternLLM` regex-matches the diff and emits a finding when it sees a known
vulnerable pattern. That is a *loose* mock: a test using it would pass even if
the real SAST handler were deleted, because the mock — not the engine — decides
the finding. It is therefore NOT autouse.

Opt in explicitly via the `mock_sast_llm` fixture, and only for tests that
genuinely exercise a cloud SAST path (i.e. a webhook that enqueues/runs a
`kind=source` scan). As of the target architecture:

  - SAST is local-only on the CLI machine (§1 invariant 1); the cloud worker no
    longer runs `source`/`plan`/`init` tasks.
  - The GitHub webhook no longer fetches diffs or enqueues cloud scans
    (§3 D5 / Gate 2) — see test_github_webhook.py.

So no API test currently needs this mock. It is retained, non-autouse, as a
smoke harness for any future cloud-webhook SAST path. Do not re-enable it as
autouse: the real SAST engine is covered by worker/tests/test_sast_fixture.py,
which exercises the read_file/emit_finding tool boundary rather than a regex.
"""
from __future__ import annotations

import re

import pytest

from sentinel_worker.agent import LLMCallResult, ToolCallEvent

# Ordered rules: first match wins.
_SCAN_RULES = [
    (re.compile(r"\bdb\.query\b|select\s+\S+\s+from", re.I), "sqli", "high", "SQL Injection"),
    (re.compile(r"\bexec\s*\(|\bspawn\s*\(", re.I), "cmdi", "high", "Command Injection"),
]

_FILE_RE = re.compile(r"\+\+\+ b/(\S+)")


class _PatternLLM:
    """Emits one finding per scan based on diff content patterns."""

    async def call_with_tools(
        self,
        *,
        system: str,
        user: str,
        tools: list,
        tool_dispatcher,
        max_iterations: int = 50,
        **kwargs,
    ):
        file_match = _FILE_RE.search(user)
        file_path = file_match.group(1) if file_match else "app.js"

        # Extract diff text so the description carries concrete evidence
        diff_match = re.search(r"<diff>\n(.*?)</diff>", user, re.DOTALL)
        diff_snippet = diff_match.group(1).strip()[:200] if diff_match else ""

        for pattern, vuln_type, severity, title in _SCAN_RULES:
            if not pattern.search(user):
                continue
            sink_by_type = {"sqli": "db.query", "cmdi": "exec"}
            sink = sink_by_type.get(vuln_type, vuln_type)
            node_id = f"fn:{file_path}:{sink}"
            result = await tool_dispatcher(
                "emit_finding",
                {
                    "vuln_type": vuln_type,
                    "severity": severity,
                    "title": title,
                    "description": (
                        f"Taint path confirmed from user-controlled input to {vuln_type} sink. "
                        f"Diff: {diff_snippet}"
                    ),
                    "remediation": "Use parameterized queries / escape inputs.",
                    "node_id": node_id,
                    "taint_path": [f"param:{file_path}:req", node_id],
                },
            )
            yield ToolCallEvent(
                type="tool_call",
                tool_name="emit_finding",
                tool_input={},
                result=result,
            )
            return  # one finding per scan call

    async def call(self, *, system: str, user: str | None = None, data: str | None = None, **kwargs) -> LLMCallResult:
        return LLMCallResult(
            content='{"annotations": []}',
            input_tokens=0,
            output_tokens=0,
            model="mock",
            provider="mock",
        )


_LLM = _PatternLLM()


@pytest.fixture(autouse=True)
def _dev_mode(monkeypatch):
    """Run all API tests in dev mode (no auth required, tenant isolation off)."""
    monkeypatch.setenv("SENTINEL_DEV_MODE", "1")


@pytest.fixture(autouse=True)
def _isolated_db(monkeypatch, tmp_path):
    """Give every test an isolated SQLite database in a temp file.

    Using a file (not :memory:) so multiple asyncio event loops and the
    TestClient all connect to the same database — required for tests that
    seed data with asyncio.new_event_loop() before using TestClient.
    """
    import asyncio
    from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
    from sentinel_worker.migrations import apply_migrations
    import sentinel_api.deps as deps

    db_path = tmp_path / "test.db"
    url = f"sqlite+aiosqlite:///{db_path}"
    fresh_engine = create_async_engine(url, future=True)
    fresh_sm = async_sessionmaker(fresh_engine, expire_on_commit=False)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(apply_migrations(fresh_engine))
    loop.close()

    monkeypatch.setattr(deps, "engine", fresh_engine)
    monkeypatch.setattr(deps, "SessionLocal", fresh_sm)


def seed_finding(
    client,
    *,
    repo_name: str,
    vuln_type: str = "sqli",
    severity: str = "high",
    file: str = "app.js",
    node_id: str | None = None,
    title: str | None = None,
    description: str | None = None,
    evidence: str | None = None,
    headers: dict | None = None,
) -> dict:
    """Seed a finding via POST /graph/upsert + POST /findings/ingest — the
    supported way to get a finding into the test DB now that /source and
    /plan (which took diffs and plan content) have been removed.

    Pushes a matching graph node first, same as a real local scan
    (local_engine.push_results_to_cloud always pushes the graph delta before
    ingesting findings) — without it, finding_response's file/line stay null
    because they're resolved via a join to the node, not stored on Finding.
    Returns the ingest response: {run_id, created, updated, total, finding_ids}.
    """
    node_id = node_id or f"fn:{file}:sink"
    graph_resp = client.post(
        "/graph/upsert",
        json={
            "repo_name": repo_name,
            "graph_kind": "main",
            "nodes": [{"id": node_id, "kind": "FUNCTION", "name": "sink", "file": file, "line_start": 1, "is_sink": True}],
            "edges": [],
        },
        headers=headers or {},
    )
    assert graph_resp.status_code == 200, graph_resp.text

    payload = {
        "repo_name": repo_name,
        "run_context": "local",
        "findings": [
            {
                "vuln_type": vuln_type,
                "severity": severity,
                "title": title or vuln_type.replace("_", " ").title(),
                "description": description or f"{vuln_type} finding seeded for a test",
                "remediation": "Use parameterized queries / escape inputs.",
                "node_id": node_id,
                "file": file,
                "evidence": evidence,
            }
        ],
    }
    resp = client.post("/findings/ingest", json=payload, headers=headers or {})
    assert resp.status_code == 200, resp.text
    return resp.json()



@pytest.fixture
def mock_sast_llm(monkeypatch):
    """Opt-in (NOT autouse): replace get_llm_for_graph with the quarantined
    `_PatternLLM` for tests that drive a cloud SAST path (e.g. a webhook smoke
    test). See the module docstring for why this is not autouse — a loose regex
    mock must not silently back every API test. Returns the mock for assertions."""
    async def _get_llm(*_args, **_kwargs):
        return _LLM

    monkeypatch.setattr("sentinel_worker.sast.get_llm_for_graph", _get_llm)
    return _LLM

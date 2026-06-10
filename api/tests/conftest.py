"""
API test fixtures.

All tests run without a real LLM. `_inject_mock_llm` (autouse) replaces
`get_llm_for_graph` with a pattern-based mock that emits SAST findings
whenever the diff content matches known-vulnerable patterns. This mirrors
what a real model does while keeping tests deterministic and offline.
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


@pytest.fixture(autouse=True)
def _inject_mock_llm(monkeypatch):
    """Replace get_llm_for_graph with a mock for every API test."""
    async def _get_llm(*_args, **_kwargs):
        return _LLM

    monkeypatch.setattr("sentinel_worker.sast.get_llm_for_graph", _get_llm)

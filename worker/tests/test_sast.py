"""Tests for the SAST pipeline (G4)."""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import select

from sentinel_worker.security import compute_fingerprint


@pytest.mark.asyncio
async def test_sast_suppressed_fingerprint_not_emitted(db):
    from sentinel_worker.sast import run_sast
    from sentinel_worker.models import Finding, Graph, Repo, Account
    from sentinel_worker.agent import ToolCallEvent

    # Setup
    account = Account(name="test")
    db.add(account)
    await db.flush()
    repo = Repo(account_id=account.id, name="test")
    db.add(repo)
    await db.flush()
    graph_obj = Graph(account_id=account.id, repo_id=repo.id, kind="main")
    db.add(graph_obj)
    await db.flush()

    fp = compute_fingerprint(str(repo.id), "fn:app.py:query", "sqli")
    suppressed_fps = [fp]

    class _MockLLM:
        async def call_with_tools(self, *, tool_dispatcher, **kwargs):
            # Simulate emit_finding call
            result = await tool_dispatcher("emit_finding", {
                "vuln_type": "sqli",
                "severity": "high",
                "title": "SQL Injection",
                "description": "desc",
                "remediation": "fix it",
                "node_id": "fn:app.py:query",
                "taint_path": ["param:app.py:id", "fn:app.py:query"],
            })
            yield ToolCallEvent(type="tool_call", tool_name="emit_finding", tool_input={}, result=result)

    findings = await run_sast(
        diff="+++ b/app.py\n+db.query(f'select * from t where id={req.id}')",
        bootstrap_context="[FUNCTION] query is_sink=true",
        run_id="test-run-1",
        suppressed_fps=suppressed_fps,
        graph=graph_obj,
        repo_id=str(repo.id),
        db=db,
        llm=_MockLLM(),
    )

    # Finding should be suppressed
    assert len(findings) == 0
    db_findings = list(await db.scalars(select(Finding)))
    assert len(db_findings) == 0


@pytest.mark.asyncio
async def test_sast_with_no_llm_configured_raises(db):
    """run_sast with llm=None and no account config must raise LLMNotConfiguredError."""
    from sentinel_worker.sast import run_sast, LLMNotConfiguredError
    from sentinel_worker.models import Graph, Repo, Account

    # provider="anthropic" requires an api_key; none set → must raise
    account = Account(name="test2", provider="anthropic", model="claude-3-opus")
    db.add(account)
    await db.flush()
    repo = Repo(account_id=account.id, name="test2")
    db.add(repo)
    await db.flush()
    graph_obj = Graph(account_id=account.id, repo_id=repo.id, kind="main")
    db.add(graph_obj)
    await db.flush()

    with pytest.raises(LLMNotConfiguredError):
        await run_sast(
            diff="+++ b/app.py\n+print('hello')",
            bootstrap_context="",
            run_id="test-run-2",
            suppressed_fps=[],
            graph=graph_obj,
            repo_id=str(repo.id),
            db=db,
            llm=None,
        )


@pytest.mark.asyncio
async def test_sast_emits_finding_when_not_suppressed(db):
    from sentinel_worker.sast import run_sast
    from sentinel_worker.models import Finding, Graph, Repo, Account
    from sentinel_worker.agent import ToolCallEvent
    from sqlalchemy import select

    account = Account(name="test3")
    db.add(account)
    await db.flush()
    repo = Repo(account_id=account.id, name="test3")
    db.add(repo)
    await db.flush()
    graph_obj = Graph(account_id=account.id, repo_id=repo.id, kind="main")
    db.add(graph_obj)
    await db.flush()

    class _MockLLM:
        async def call_with_tools(self, *, tool_dispatcher, **kwargs):
            result = await tool_dispatcher("emit_finding", {
                "vuln_type": "sqli",
                "severity": "high",
                "title": "SQL Injection",
                "description": "desc",
                "remediation": "fix it",
                "node_id": "fn:app.py:query",
                "taint_path": ["param:app.py:id", "fn:app.py:query"],
            })
            yield ToolCallEvent(type="tool_call", tool_name="emit_finding", tool_input={}, result=result)

    findings = await run_sast(
        diff="+++ b/app.py\n+db.query(f'select * from t where id={req.id}')",
        bootstrap_context="[FUNCTION] query is_sink=true",
        run_id="test-run-3",
        suppressed_fps=[],  # nothing suppressed
        graph=graph_obj,
        repo_id=str(repo.id),
        db=db,
        llm=_MockLLM(),
    )

    assert len(findings) == 1
    assert findings[0].vuln_type == "sqli"
    db_findings = list(await db.scalars(select(Finding)))
    assert len(db_findings) == 1

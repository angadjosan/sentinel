import json
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.agent import ToolCallEvent
from sentinel_worker.models import Base, Finding, Run, Task
from sentinel_worker.runner import run_one_task
from sentinel_worker.task_queue import enqueue_task
from tests.conftest import MockLLMClient


def _sqli_llm():
    """Mock LLM that emits a sqli finding."""
    from sentinel_worker.agent import LLMCallResult

    class _FindingLLM:
        async def call_with_tools(self, *, tool_dispatcher, **kwargs):
            result = await tool_dispatcher("emit_finding", {
                "vuln_type": "sqli",
                "severity": "high",
                "title": "SQL Injection",
                "description": "Tainted query param flows to db.query",
                "remediation": "Use parameterized queries",
                "node_id": "fn:app.js:query",
                "taint_path": ["param:app.js:id", "fn:app.js:query"],
            })
            yield ToolCallEvent(type="tool_call", tool_name="emit_finding", tool_input={}, result=result)

        async def call(self, **kwargs) -> LLMCallResult:
            return LLMCallResult(content='{"annotations": []}', input_tokens=0, output_tokens=0, model="mock", provider="mock")

    return _FindingLLM()


@pytest.mark.asyncio
async def test_runner_executes_source_task_into_queued_run():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            task = await enqueue_task(
                session,
                repo_name="repo",
                kind="source",
                payload={
                    "repo_name": "repo",
                    "diff": "+++ b/app.js\n+db.query(`select * from users where id=${req.query.id}`)",
                    "run_context": "worker",
                    "base_ref": "origin/main",
                    "paths": ["app.js"],
                },
            )
            run_id = task.run_id
            task_id = await run_one_task(session, worker_id="worker-1", _llm=_sqli_llm())
        async with session.begin():
            run = await session.get(Run, run_id)
            stored_task = await session.get(Task, task.id)
            finding = await session.scalar(select(Finding).where(Finding.run_id == run_id))

    assert task_id == task.id
    assert stored_task is not None
    assert stored_task.status == "completed"
    assert run is not None
    assert run.status == "completed"
    started = next(
        event for event in (json.loads(line) for line in run.trace.splitlines())
        if event["kind"] == "scan.started"
    )
    assert started["base_ref"] == "origin/main"
    assert started["paths"] == ["app.js"]
    assert finding is not None
    assert finding.vuln_type == "sqli"


@pytest.mark.asyncio
async def test_runner_marks_task_failed_when_no_llm_configured():
    """Cloud provider without api_key → runner catches LLMNotConfiguredError and fails the task."""
    from sentinel_worker.models import Account
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            # Pre-create a dev account with a cloud provider but no api_key.
            session.add(Account(name="dev", provider="anthropic", model="claude-3-opus"))
            await session.flush()
            task = await enqueue_task(
                session,
                repo_name="repo",
                kind="source",
                payload={
                    "repo_name": "repo",
                    "diff": "+++ b/app.js\n+console.log('x')",
                    "run_context": "local",
                },
            )
            run_id = task.run_id
            task_id = await run_one_task(session, worker_id="worker-1")
        async with session.begin():
            stored_task = await session.get(Task, task.id)

    assert task_id == task.id
    assert stored_task.status == "failed"
    assert "LLMNotConfiguredError" in (stored_task.error or "")


@pytest.mark.asyncio
async def test_runner_returns_none_when_no_task_available():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            task_id = await run_one_task(session, worker_id="worker-1")
    assert task_id is None

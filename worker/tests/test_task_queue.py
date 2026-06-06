import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.models import Base, Run
from sentinel_worker.task_queue import _claimable_task_stmt, cancel_run_tasks, cancel_task, claim_next_task, complete_task, enqueue_task, fail_task


@pytest.mark.asyncio
async def test_task_queue_claim_complete_and_fail_flow():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            task = await enqueue_task(session, repo_name="repo", kind="source", payload={"diff": "x"})
            claimed = await claim_next_task(session, worker_id="worker-1")
            assert claimed is not None
            assert claimed.task.id == task.id
            assert claimed.payload == {"diff": "x"}
            await complete_task(session, task_id=task.id, trace="done")
        async with session.begin():
            run = await session.get(Run, task.run_id)
    assert run is not None
    assert run.status == "completed"
    assert "task.claimed" in run.trace
    assert "task.completed" in run.trace
    assert "done" in run.trace

    async with sessionmaker() as session:
        async with session.begin():
            failed = await enqueue_task(session, repo_name="repo", kind="source", payload={"diff": "y"})
            await fail_task(session, task_id=failed.id, error="boom")
        async with session.begin():
            failed_run = await session.get(Run, failed.run_id)
    assert failed_run is not None
    assert failed_run.status == "failed"
    assert "task.failed" in failed_run.trace


@pytest.mark.asyncio
async def test_cancel_task_updates_run_status():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            task = await enqueue_task(session, repo_name="repo", kind="source", payload={"diff": "x"})
            await cancel_task(session, task_id=task.id)
        async with session.begin():
            run = await session.get(Run, task.run_id)
    assert run is not None
    assert run.status == "cancelled"


@pytest.mark.asyncio
async def test_cancel_run_tasks_cancels_queued_task_and_prevents_late_completion():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            task = await enqueue_task(session, repo_name="repo", kind="source", payload={"diff": "x"})
            run = await cancel_run_tasks(session, run_id=task.run_id)
        async with session.begin():
            stored_task = await session.get(type(task), task.id)
            stored_run = await session.get(Run, task.run_id)

    assert run.status == "cancelled"
    assert stored_task is not None
    assert stored_task.status == "cancelled"
    assert stored_run is not None
    assert stored_run.status == "cancelled"
    assert "run.cancelled" in stored_run.trace

    async with sessionmaker() as session:
        async with session.begin():
            completed = await complete_task(session, task_id=task.id, trace="late worker output")
        async with session.begin():
            late_run = await session.get(Run, task.run_id)

    assert completed.status == "cancelled"
    assert late_run is not None
    assert late_run.status == "cancelled"
    assert "late worker output" not in late_run.trace


@pytest.mark.asyncio
async def test_task_trace_and_error_are_scrubbed_before_persistence():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    secret = "sk-Test_1234567890abcdefghijklmnop/QRSTUV"
    async with sessionmaker() as session:
        async with session.begin():
            task = await enqueue_task(session, repo_name="repo", kind="source", payload={"diff": "x"})
            await complete_task(session, task_id=task.id, trace=f"worker saw {secret}")
        async with session.begin():
            run = await session.get(Run, task.run_id)

    assert run is not None
    assert secret not in run.trace
    assert "[REDACTED:high_entropy]" in run.trace

    async with sessionmaker() as session:
        async with session.begin():
            failed = await enqueue_task(session, repo_name="repo", kind="source", payload={"diff": "y"})
            await fail_task(session, task_id=failed.id, error=f"failed with {secret}")
        async with session.begin():
            stored_failed = await session.get(type(failed), failed.id)
            failed_run = await session.get(Run, failed.run_id)

    assert stored_failed is not None
    assert failed_run is not None
    assert secret not in (stored_failed.error or "")
    assert secret not in failed_run.trace


def test_claimable_task_query_uses_postgres_skip_locked():
    compiled = str(_claimable_task_stmt(["source", "plan"]).compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))

    assert "FOR UPDATE SKIP LOCKED" in compiled
    assert "tasks.status = 'queued'" in compiled
    assert "tasks.kind IN ('source', 'plan')" in compiled

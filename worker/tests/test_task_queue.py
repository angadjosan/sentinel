import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.models import Base, Run
from sentinel_worker.task_queue import _claimable_task_stmt, cancel_task, claim_next_task, complete_task, enqueue_task, fail_task


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


def test_claimable_task_query_uses_postgres_skip_locked():
    compiled = str(_claimable_task_stmt(["source", "plan"]).compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))

    assert "FOR UPDATE SKIP LOCKED" in compiled
    assert "tasks.status = 'queued'" in compiled
    assert "tasks.kind IN ('source', 'plan')" in compiled

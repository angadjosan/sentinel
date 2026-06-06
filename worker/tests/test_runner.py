import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.models import Base, Finding, Run, Task
from sentinel_worker.runner import run_one_task
from sentinel_worker.task_queue import enqueue_task


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
                },
            )
            run_id = task.run_id
            task_id = await run_one_task(session, worker_id="worker-1")
        async with session.begin():
            run = await session.get(Run, run_id)
            stored_task = await session.get(Task, task.id)
            finding = await session.scalar(select(Finding).where(Finding.run_id == run_id))
    assert task_id == task.id
    assert stored_task is not None
    assert stored_task.status == "completed"
    assert run is not None
    assert run.status == "completed"
    assert finding is not None
    assert finding.vuln_type == "sqli"


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

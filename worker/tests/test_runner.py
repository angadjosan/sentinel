import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.models import Base, Task
from sentinel_worker.runner import run_one_task
from sentinel_worker.task_queue import enqueue_task


@pytest.mark.parametrize("dead_kind", ["source", "plan", "init"])
@pytest.mark.asyncio
async def test_runner_rejects_legacy_cloud_sast_kinds(dead_kind):
    """AUDIT.md §1 / P2.3: the cloud worker no longer runs SAST. The legacy
    `source` / `plan` / `init` task kinds (which scanned customer diffs/source
    on the worker) are gone — a stale one must hard-fail as unsupported rather
    than silently execute a cloud scan."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            task = await enqueue_task(
                session,
                repo_name="repo",
                kind=dead_kind,
                payload={"repo_name": "repo", "diff": "+++ b/app.js\n+console.log('x')"},
            )
            task_id = await run_one_task(session, worker_id="worker-1")
        async with session.begin():
            stored_task = await session.get(Task, task.id)

    assert task_id == task.id
    assert stored_task.status == "failed"
    assert f"unsupported task kind: {dead_kind}" in (stored_task.error or "")


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

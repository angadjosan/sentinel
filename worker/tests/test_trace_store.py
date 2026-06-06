import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.models import Base, Graph, Run, RunTraceChunk
from sentinel_worker.trace_store import offload_trace_if_large, read_run_trace


@pytest.mark.asyncio
async def test_large_run_trace_is_chunked_and_reconstructed():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            run = Run(graph_id=graph.id, kind="source", status="completed", trace="a" * 25)
            session.add(run)
            await session.flush()
            await offload_trace_if_large(session, run, threshold_bytes=10, chunk_chars=8)
            assert run.trace == ""
            chunks = list(await session.scalars(select(RunTraceChunk).where(RunTraceChunk.run_id == run.id).order_by(RunTraceChunk.seq)))
            assert [chunk.seq for chunk in chunks] == [0, 1, 2, 3]
            assert await read_run_trace(session, run) == "a" * 25
            run.trace = "tail"
            assert await read_run_trace(session, run) == f"{'a' * 25}\ntail"
    await engine.dispose()


@pytest.mark.asyncio
async def test_run_trace_is_scrubbed_before_chunking_and_reading():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            secret = "sk-Test_1234567890abcdefghijklmnop/QRSTUV"
            run = Run(graph_id=graph.id, kind="source", status="completed", trace=f"leaked {secret}")
            session.add(run)
            await session.flush()
            await offload_trace_if_large(session, run, threshold_bytes=10, chunk_chars=8)
            trace = await read_run_trace(session, run)
            chunks = list(await session.scalars(select(RunTraceChunk).where(RunTraceChunk.run_id == run.id)))

    assert secret not in trace
    assert all(secret not in chunk.chunk for chunk in chunks)
    assert "[REDACTED:high_entropy]" in trace
    await engine.dispose()

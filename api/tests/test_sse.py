import asyncio

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_api.sse import stream_run_events
from sentinel_worker.models import Base, Run


class FakeConnection:
    def __init__(self):
        self.listener = None
        self.channel = None
        self.closed = False

    async def add_listener(self, channel, listener):
        self.channel = channel
        self.listener = listener

    async def remove_listener(self, channel, listener):
        assert channel == self.channel
        assert listener == self.listener

    async def close(self):
        self.closed = True


@pytest.mark.asyncio
async def test_stream_run_events_replays_completed_run_without_postgres():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            run = Run(graph_id="graph", kind="plan", status="completed", trace='{"kind":"plan.completed"}')
            session.add(run)
            await session.flush()
        events = []
        async for event in stream_run_events(session, run.id, database_url="sqlite+aiosqlite:///:memory:", poll_interval=0):
            events.append(event)

    assert events[0] == 'data: {"kind":"plan.completed"}\n\n'
    assert '"kind": "complete"' in events[-1]


@pytest.mark.asyncio
async def test_stream_run_events_listens_to_postgres_notifications():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    connection = FakeConnection()

    async def connect(_url):
        return connection

    async with sessionmaker() as session:
        async with session.begin():
            run = Run(graph_id="graph", kind="source", status="running", trace='{"kind":"task.claimed"}')
            session.add(run)
            await session.flush()

        events = []

        async def consume():
            async for event in stream_run_events(session, run.id, database_url="postgresql://db/sentinel", connect=connect):
                events.append(event)

        task = asyncio.create_task(consume())
        while connection.listener is None:
            await asyncio.sleep(0)
        connection.listener(connection, 1, connection.channel, '{"kind":"finding"}')
        async with sessionmaker() as writer:
            async with writer.begin():
                stored = await writer.get(Run, run.id)
                stored.status = "completed"
        connection.listener(connection, 1, connection.channel, '{"kind":"scan.completed"}')
        await asyncio.wait_for(task, timeout=1)

    assert connection.channel.startswith("run_")
    assert any('{"kind":"finding"}' in event for event in events)
    assert any('"kind": "complete"' in event for event in events)
    assert connection.closed is True

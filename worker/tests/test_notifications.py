from types import SimpleNamespace

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.models import Base
from sentinel_worker.notifications import notify_run_event, notify_task_available


class FakePostgresSession:
    def __init__(self):
        self.calls = []

    def get_bind(self):
        return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

    async def execute(self, statement, params):
        self.calls.append((str(statement), params))


@pytest.mark.asyncio
async def test_notifications_noop_on_sqlite():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        await notify_task_available(session, "task-1")
        await notify_run_event(session, "run-1", '{"kind":"event"}')


@pytest.mark.asyncio
async def test_notifications_emit_pg_notify_for_postgres():
    session = FakePostgresSession()

    await notify_task_available(session, "task-1")
    await notify_run_event(session, "run/with-dashes", '{"kind":"event"}')

    assert len(session.calls) == 2
    assert session.calls[0][1] == {"channel": "tasks_channel", "payload": "task-1"}
    assert session.calls[1][1] == {"channel": "run_run_with_dashes", "payload": '{"kind":"event"}'}
    assert "pg_notify" in session.calls[0][0]

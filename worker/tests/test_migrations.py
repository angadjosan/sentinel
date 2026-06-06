import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from sentinel_worker.migrations import CURRENT_SCHEMA_VERSION, applied_migrations, apply_migrations


@pytest.mark.asyncio
async def test_apply_migrations_records_version_and_is_idempotent():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    first = await apply_migrations(engine)
    second = await apply_migrations(engine)
    applied = await applied_migrations(engine)
    async with engine.begin() as conn:
        rows = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='runs'"))
        has_runs = rows.first() is not None
    await engine.dispose()
    assert first == [CURRENT_SCHEMA_VERSION]
    assert second == []
    assert applied == [CURRENT_SCHEMA_VERSION]
    assert has_runs is True

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
        cache_rows = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='advisory_cache'"))
        has_advisory_cache = cache_rows.first() is not None
        trace_rows = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='run_traces'"))
        has_run_traces = trace_rows.first() is not None
        device_rows = await conn.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='device_auth_sessions'"))
        has_device_auth_sessions = device_rows.first() is not None
        account_columns = await conn.execute(text("SELECT provider, model, source_retention_days FROM accounts LIMIT 0"))
        account_column_names = set(account_columns.keys())
    await engine.dispose()
    assert first == [CURRENT_SCHEMA_VERSION]
    assert second == []
    assert applied == [CURRENT_SCHEMA_VERSION]
    assert has_runs is True
    assert has_advisory_cache is True
    assert has_run_traces is True
    assert has_device_auth_sessions is True
    assert {"provider", "model", "source_retention_days"}.issubset(account_column_names)

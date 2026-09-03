"""SQLite dev-mode migrations must include the pentest_config column (0005)."""
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from sentinel_worker.migrations import CURRENT_SCHEMA_VERSION, _alembic_head, apply_migrations


@pytest.mark.asyncio
async def test_fresh_sqlite_has_repo_pentest_config_column():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    await apply_migrations(engine)
    async with engine.begin() as conn:
        cols = {row[1] for row in await conn.execute(text("PRAGMA table_info(repos)"))}
    assert "pentest_config" in cols
    assert "boot" in cols and "egress_allowlist" in cols
    await engine.dispose()


@pytest.mark.asyncio
async def test_preexisting_repos_table_is_upgraded_with_pentest_config():
    # Simulate an old dev DB: a repos table created before the pentest columns.
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.execute(text("CREATE TABLE repos (id TEXT PRIMARY KEY, account_id TEXT, name TEXT)"))
    await apply_migrations(engine)
    async with engine.begin() as conn:
        cols = {row[1] for row in await conn.execute(text("PRAGMA table_info(repos)"))}
    assert "pentest_config" in cols  # ALTER path added it
    await engine.dispose()


def test_current_schema_version_tracks_alembic_head():
    """The SQLite marker must name the same revision Postgres migrates to, so a
    new revision can't be added without the dev-mode schema being updated too."""
    assert CURRENT_SCHEMA_VERSION == _alembic_head()

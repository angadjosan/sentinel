"""Postgres migration path — Alembic, the production path for hosted + self-host.

Skipped unless a Postgres URL is provided via SENTINEL_TEST_PG_URL (CI sets it
from the `postgres` service container). Each test gets its own database so the
scenarios can't contaminate each other.
"""
from __future__ import annotations

import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from sentinel_worker.migrations import (
    SchemaDriftError,
    _alembic_head,
    apply_migrations,
)
from sentinel_worker.models import Base

PG_URL = os.getenv("SENTINEL_TEST_PG_URL")

pytestmark = pytest.mark.skipif(not PG_URL, reason="SENTINEL_TEST_PG_URL not set")


async def _make_db() -> str:
    """Create a uniquely-named database and return a URL pointing at it."""
    base, _, _ = PG_URL.rpartition("/")
    name = f"mig_test_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(PG_URL, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    await admin.dispose()
    return f"{base}/{name}"


async def _current_revision(engine) -> str | None:
    async with engine.connect() as conn:
        if (await conn.execute(text("SELECT to_regclass('public.alembic_version')"))).scalar() is None:
            return None
        return (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar()


@pytest.mark.asyncio
async def test_fresh_database_migrates_to_head():
    engine = create_async_engine(await _make_db())
    try:
        assert await apply_migrations(engine) == [_alembic_head()]
        assert await _current_revision(engine) == _alembic_head()
        # A table from the last revision's era must really exist, not just be stamped.
        async with engine.connect() as conn:
            assert (await conn.execute(text("SELECT to_regclass('public.accounts')"))).scalar() is not None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_untracked_database_matching_head_is_adopted():
    """A pre-Alembic database built by create_all is stamped, not replayed:
    replaying 0001 against existing tables would fail on 'already exists'."""
    engine = create_async_engine(await _make_db())
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        assert await _current_revision(engine) is None
        assert await apply_migrations(engine) == [_alembic_head()]
        assert await _current_revision(engine) == _alembic_head()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_untracked_database_with_drift_is_refused():
    """The dangerous case: a long-lived create_all database gains new tables on
    boot but never new columns, so it can sit behind head. Stamping it would
    mark a half-built schema as migrated -- refuse and name the gap instead."""
    engine = create_async_engine(await _make_db())
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.execute(text("ALTER TABLE users DROP COLUMN totp_secret_enc"))
        with pytest.raises(SchemaDriftError) as excinfo:
            await apply_migrations(engine)
        assert "users.totp_secret_enc" in str(excinfo.value)
        # Crucially, it must not have stamped anything on the way out.
        assert await _current_revision(engine) is None
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_second_boot_is_a_noop():
    engine = create_async_engine(await _make_db())
    try:
        await apply_migrations(engine)
        await apply_migrations(engine)
        assert await _current_revision(engine) == _alembic_head()
    finally:
        await engine.dispose()


@pytest.mark.asyncio
@pytest.mark.parametrize("var", ["SENTINEL_DISABLE_AUTO_MIGRATE", "VERCEL"])
async def test_auto_migrate_is_disabled_on_serverless(monkeypatch, var):
    """Serverless cold starts must not migrate: they'd race each other for the
    lock and run DDL over a pooled connection. Hosted deploys migrate out-of-band."""
    monkeypatch.setenv(var, "1")
    engine = create_async_engine(await _make_db())
    try:
        assert await apply_migrations(engine) == []
        assert await _current_revision(engine) is None
    finally:
        await engine.dispose()

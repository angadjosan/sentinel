from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.db import (
    apply_tenant_search_path,
    create_engine,
    create_sessionmaker,
    reset_account_context,
    set_account_context,
)
from sentinel_worker.migrations import apply_migrations

engine = create_engine()
SessionLocal = create_sessionmaker(engine)


async def init_schema() -> None:
    await apply_migrations(engine)


async def get_db() -> AsyncIterator[AsyncSession]:
    """DB session with automatic per-tenant SEARCH_PATH on Postgres.

    The tenant context (account_id) is set by TenantContextMiddleware from the
    JWT on every authenticated request. On SQLite (dev mode) this is a no-op.
    """
    async with SessionLocal() as session:
        async with session.begin():
            await apply_tenant_search_path(session, engine)
            yield session


async def get_tenant_db(account_id: str | None = None) -> AsyncIterator[AsyncSession]:
    """DB session with per-tenant SEARCH_PATH set to tenant_{account_id} on Postgres.

    On SQLite (dev mode) this is identical to get_db().
    """
    token = set_account_context(account_id)
    try:
        async with SessionLocal() as session:
            async with session.begin():
                await apply_tenant_search_path(session, engine)
                yield session
    finally:
        reset_account_context(token)

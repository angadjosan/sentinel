from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.db import create_engine, create_sessionmaker
from sentinel_worker.migrations import apply_migrations

engine = create_engine()
SessionLocal = create_sessionmaker(engine)


async def init_schema() -> None:
    await apply_migrations(engine)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        async with session.begin():
            yield session

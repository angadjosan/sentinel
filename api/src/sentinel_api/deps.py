from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.db import create_engine, create_sessionmaker
from sentinel_worker.models import Base

engine = create_engine()
SessionLocal = create_sessionmaker(engine)


async def init_schema() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        async with session.begin():
            yield session

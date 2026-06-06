from __future__ import annotations

import os
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine


def database_url() -> str:
    if url := os.getenv("DATABASE_URL"):
        return url
    dev_db = Path(os.getenv("SENTINEL_DEV_DB", str(Path.home() / ".sentinel" / "sentinel.dev.db")))
    try:
        dev_db.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        dev_db = Path(tempfile.gettempdir()) / "sentinel" / "sentinel.dev.db"
        dev_db.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{dev_db}"


def create_engine(url: str | None = None) -> AsyncEngine:
    return create_async_engine(url or database_url(), future=True)


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def session_scope(factory: async_sessionmaker[AsyncSession]) -> AsyncIterator[AsyncSession]:
    async with factory() as session:
        async with session.begin():
            yield session

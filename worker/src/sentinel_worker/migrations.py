from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from .models import Base

CURRENT_SCHEMA_VERSION = "0001_initial_models"


async def apply_migrations(engine: AsyncEngine) -> list[str]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                  version TEXT PRIMARY KEY,
                  applied_at TIMESTAMP NOT NULL
                )
                """
            )
        )
        await conn.run_sync(Base.metadata.create_all)
        if engine.url.get_backend_name().startswith("sqlite"):
            rows = await conn.execute(text("PRAGMA table_info(accounts)"))
            columns = {row[1] for row in rows}
            if "provider" not in columns:
                await conn.execute(text("ALTER TABLE accounts ADD COLUMN provider TEXT DEFAULT 'local'"))
            if "model" not in columns:
                await conn.execute(text("ALTER TABLE accounts ADD COLUMN model TEXT DEFAULT 'ollama'"))
            if "api_endpoint" not in columns:
                await conn.execute(text("ALTER TABLE accounts ADD COLUMN api_endpoint TEXT"))
            if "source_retention_days" not in columns:
                await conn.execute(text("ALTER TABLE accounts ADD COLUMN source_retention_days INTEGER DEFAULT 365"))
        rows = await conn.execute(text("SELECT version FROM schema_migrations"))
        applied = {row[0] for row in rows}
        if CURRENT_SCHEMA_VERSION in applied:
            return []
        await conn.execute(
            text("INSERT INTO schema_migrations (version, applied_at) VALUES (:version, :applied_at)"),
            {"version": CURRENT_SCHEMA_VERSION, "applied_at": datetime.now(UTC).isoformat()},
        )
        return [CURRENT_SCHEMA_VERSION]


async def applied_migrations(engine: AsyncEngine) -> list[str]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                  version TEXT PRIMARY KEY,
                  applied_at TIMESTAMP NOT NULL
                )
                """
            )
        )
        rows = await conn.execute(text("SELECT version FROM schema_migrations ORDER BY version"))
        return [row[0] for row in rows]

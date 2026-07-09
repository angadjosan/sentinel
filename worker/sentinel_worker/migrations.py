from __future__ import annotations

# NOTE: Alembic is the production migration path.
# The create_all fallback below is kept for SQLite dev mode only.
# Run `alembic upgrade head` (from the worker/ directory) for production.

from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from .models import Base

CURRENT_SCHEMA_VERSION = "0005_repo_pentest_config_blob"


async def apply_migrations(engine: AsyncEngine) -> list[str]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                  version TEXT PRIMARY KEY,
                  applied_at TIMESTAMPTZ NOT NULL
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
            if "pentest_api_key" not in columns:  # 0004
                await conn.execute(text("ALTER TABLE accounts ADD COLUMN pentest_api_key TEXT"))
            user_columns = {row[1] for row in await conn.execute(text("PRAGMA table_info(users)"))}
            if "name" not in user_columns:
                await conn.execute(text("ALTER TABLE users ADD COLUMN name TEXT"))
            if "password_hash" not in user_columns:
                await conn.execute(text("ALTER TABLE users ADD COLUMN password_hash TEXT"))
            if "email_verified_at" not in user_columns:
                await conn.execute(text("ALTER TABLE users ADD COLUMN email_verified_at TIMESTAMP"))
            if "totp_secret_enc" not in user_columns:
                await conn.execute(text("ALTER TABLE users ADD COLUMN totp_secret_enc TEXT"))
            if "totp_confirmed" not in user_columns:
                await conn.execute(text("ALTER TABLE users ADD COLUMN totp_confirmed BOOLEAN DEFAULT 0"))
            if "github_id" not in user_columns:
                await conn.execute(text("ALTER TABLE users ADD COLUMN github_id TEXT"))
            if "failed_login_count" not in user_columns:
                await conn.execute(text("ALTER TABLE users ADD COLUMN failed_login_count INTEGER DEFAULT 0"))
            if "locked_until" not in user_columns:
                await conn.execute(text("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP"))
            session_columns = {row[1] for row in await conn.execute(text("PRAGMA table_info(sessions)"))}
            if "user_agent" not in session_columns:
                await conn.execute(text("ALTER TABLE sessions ADD COLUMN user_agent TEXT"))
            if "ip_address" not in session_columns:
                await conn.execute(text("ALTER TABLE sessions ADD COLUMN ip_address TEXT"))
            if "refresh_token_hash" not in session_columns:
                await conn.execute(text("ALTER TABLE sessions ADD COLUMN refresh_token_hash TEXT"))
            # Repo pentest config (0004 flat columns + 0005 structured blob). create_all
            # covers fresh dev DBs; these ALTERs upgrade a pre-existing SQLite dev DB.
            repo_columns = {row[1] for row in await conn.execute(text("PRAGMA table_info(repos)"))}
            for column, ddl in (
                ("pentest_mode", "ALTER TABLE repos ADD COLUMN pentest_mode TEXT DEFAULT 'staging'"),
                ("staging_base_url", "ALTER TABLE repos ADD COLUMN staging_base_url TEXT"),
                ("healthcheck_path", "ALTER TABLE repos ADD COLUMN healthcheck_path TEXT"),
                ("boot", "ALTER TABLE repos ADD COLUMN boot TEXT"),
                ("healthcheck", "ALTER TABLE repos ADD COLUMN healthcheck TEXT"),
                ("egress_allowlist", "ALTER TABLE repos ADD COLUMN egress_allowlist TEXT"),
                ("pentest_config", "ALTER TABLE repos ADD COLUMN pentest_config TEXT"),  # 0005
            ):
                if column not in repo_columns:
                    await conn.execute(text(ddl))
        rows = await conn.execute(text("SELECT version FROM schema_migrations"))
        applied = {row[0] for row in rows}
        if CURRENT_SCHEMA_VERSION in applied:
            return []
        await conn.execute(
            text("INSERT INTO schema_migrations (version, applied_at) VALUES (:version, :applied_at)"),
            {"version": CURRENT_SCHEMA_VERSION, "applied_at": datetime.now(UTC)},
        )
        return [CURRENT_SCHEMA_VERSION]


async def applied_migrations(engine: AsyncEngine) -> list[str]:
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                  version TEXT PRIMARY KEY,
                  applied_at TIMESTAMPTZ NOT NULL
                )
                """
            )
        )
        rows = await conn.execute(text("SELECT version FROM schema_migrations ORDER BY version"))
        return [row[0] for row in rows]

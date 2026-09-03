from __future__ import annotations

# Schema management has exactly two paths, chosen by database backend:
#
#   Postgres (hosted + self-host)  -> Alembic. `_apply_alembic` runs
#       `upgrade head` on boot, guarded by a Postgres advisory lock so
#       concurrent serverless cold starts can't race each other.
#   SQLite (local engine, dev)     -> `Base.metadata.create_all` plus the
#       idempotent ALTERs below. Alembic's migrations are Postgres-shaped and
#       SQLite can't run most of them, so the local engine keeps create_all.
#
# Set SENTINEL_DISABLE_AUTO_MIGRATE=1 to skip the boot-time upgrade entirely
# (for deployments that run `alembic upgrade head` as a separate deploy step).

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from .models import Base

log = structlog.get_logger(__name__)

CURRENT_SCHEMA_VERSION = "0009_drop_pentest_api_key"

# Shipped inside the package so migrations are importable from an installed
# wheel (Vercel, Docker), not just from a source checkout.
ALEMBIC_DIR = Path(__file__).parent / "alembic_migrations"

# Arbitrary but fixed: any two processes migrating this database must agree.
_MIGRATION_LOCK_KEY = 0x5E271E


def _alembic_config():
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", str(ALEMBIC_DIR))
    # env.py reads ALEMBIC_DB_URL first; passing the URL that way avoids
    # configparser's %-interpolation mangling passwords containing '%'.
    return config


def _alembic_head() -> str:
    from alembic.script import ScriptDirectory

    return ScriptDirectory.from_config(_alembic_config()).get_current_head() or "head"


def _run_alembic(url: str, action: str, revision: str) -> None:
    """Run alembic synchronously. Called in a worker thread: env.py uses
    asyncio.run(), which raises if a loop is already running on this thread."""
    from alembic import command

    config = _alembic_config()
    previous = os.environ.get("ALEMBIC_DB_URL")
    os.environ["ALEMBIC_DB_URL"] = url
    try:
        if action == "stamp":
            command.stamp(config, revision)
        else:
            command.upgrade(config, revision)
    finally:
        if previous is None:
            os.environ.pop("ALEMBIC_DB_URL", None)
        else:
            os.environ["ALEMBIC_DB_URL"] = previous


class SchemaDriftError(RuntimeError):
    """An untracked (pre-Alembic) database whose shape doesn't match head."""


def _compare_to_models(sync_conn) -> list[str]:
    """Diff the live schema against the ORM models. Alembic's autogenerate
    comparator is the same machinery `alembic revision --autogenerate` uses."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    context = MigrationContext.configure(sync_conn)
    diffs = []
    for diff in compare_metadata(context, Base.metadata):
        # compare_metadata yields tuples like ("add_column", schema, table, Column)
        # and nested lists for multi-part changes; summarise rather than dump.
        entries = diff if isinstance(diff, list) else [diff]
        for entry in entries:
            kind = entry[0]
            # Only structural gaps matter here; ignore index/type nits that
            # differ harmlessly between create_all and migration DDL.
            if kind == "add_table":
                diffs.append(f"missing table: {entry[1].name}")
            elif kind == "add_column":
                diffs.append(f"missing column: {entry[3].table.name}.{entry[3].name}")
            elif kind == "remove_column":
                diffs.append(f"unexpected column: {entry[3].table.name}.{entry[3].name}")
    return diffs


async def _schema_drift(conn) -> list[str]:
    return await conn.run_sync(_compare_to_models)


async def _apply_alembic(engine: AsyncEngine) -> list[str]:
    url = engine.url.render_as_string(hide_password=False)
    head = await asyncio.to_thread(_alembic_head)

    async with engine.connect() as conn:
        # Only one process migrates; the rest proceed against the schema the
        # winner leaves behind. A cold start must not block on a peer's upgrade.
        acquired = (await conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": _MIGRATION_LOCK_KEY})).scalar()
        if not acquired:
            log.info("schema.migrate.skipped", reason="lock_held_by_peer")
            return []
        try:
            has_alembic = (
                await conn.execute(text("SELECT to_regclass('public.alembic_version')"))
            ).scalar() is not None
            has_tables = (
                await conn.execute(text("SELECT to_regclass('public.accounts')"))
            ).scalar() is not None

            if has_tables and not has_alembic:
                # Pre-Alembic database: tables were built by create_all, so
                # replaying 0001.. would collide with them. Adopt the schema by
                # stamping instead -- but only once we've confirmed it really
                # matches head. A long-lived create_all database drifts: boots
                # add new *tables* but never add columns to existing ones, so
                # stamping blind would permanently mark a half-built schema as
                # migrated. Refuse instead, and name the drift for the operator.
                drift = await _schema_drift(conn)
                if drift:
                    log.error(
                        "schema.migrate.drift_detected",
                        revision=head,
                        drift=drift,
                        remedy="reconcile the database with head, then `alembic stamp head`",
                    )
                    raise SchemaDriftError(
                        f"database predates Alembic and does not match {head}: {'; '.join(drift)}"
                    )
                log.warning("schema.migrate.adopting_untracked", revision=head)
                await asyncio.to_thread(_run_alembic, url, "stamp", head)
                return [head]

            await asyncio.to_thread(_run_alembic, url, "upgrade", "head")
            return [head]
        finally:
            await conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": _MIGRATION_LOCK_KEY})


def _auto_migrate_enabled() -> bool:
    """Whether this process should migrate on boot.

    A long-lived process (Docker self-host, local engine) is the right place to
    migrate: it boots once, holds a direct connection, and can take its time.

    A serverless function is the wrong place. Every cold start would race the
    others for the migration lock, the connection is a PgBouncer-pooled one that
    DDL and session-level advisory locks don't play well with, and a slow
    migration turns into a failed invocation rather than a slow boot. Hosted
    deployments migrate as an explicit step instead:

        cd worker && ALEMBIC_DB_URL=<unpooled-url> alembic upgrade head
    """
    if os.getenv("SENTINEL_DISABLE_AUTO_MIGRATE") == "1":
        return False
    # Set by Vercel on both build and runtime; also covers `vercel dev`.
    if os.getenv("VERCEL"):
        return False
    return True


async def apply_migrations(engine: AsyncEngine) -> list[str]:
    """Bring the database up to the current schema. Returns revisions applied."""
    if not _auto_migrate_enabled():
        log.info("schema.migrate.skipped", reason="auto_migrate_disabled")
        return []
    if not engine.url.get_backend_name().startswith("sqlite"):
        return await _apply_alembic(engine)
    return await _apply_sqlite_schema(engine)


async def _apply_sqlite_schema(engine: AsyncEngine) -> list[str]:
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
            node_columns = {row[1] for row in await conn.execute(text("PRAGMA table_info(nodes)"))}
            if "deleted" not in node_columns:
                await conn.execute(text("ALTER TABLE nodes ADD COLUMN deleted BOOLEAN DEFAULT 0"))
            graph_columns = {row[1] for row in await conn.execute(text("PRAGMA table_info(graphs)"))}
            if "base_graph_id" not in graph_columns:
                await conn.execute(text("ALTER TABLE graphs ADD COLUMN base_graph_id TEXT"))
            if "promoted_at" not in graph_columns:
                await conn.execute(text("ALTER TABLE graphs ADD COLUMN promoted_at TIMESTAMP"))
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

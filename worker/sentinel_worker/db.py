from __future__ import annotations

import contextvars
import os
import re
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

log = structlog.get_logger(__name__)

# Per-request contextvar: set to account_id before yielding a DB session to
# enable automatic SEARCH_PATH routing on Postgres (no-op on SQLite).
_current_account_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "_current_account_id", default=None
)

_SAFE_ID_RE = re.compile(r"^[0-9a-f\-]{36}$")  # UUID format only


def _schema_name(account_id: str) -> str | None:
    """Return the Postgres schema name for an account, or None if the ID is invalid."""
    if not account_id or not _SAFE_ID_RE.match(account_id):
        return None
    return "tenant_" + account_id.replace("-", "_")


def set_account_context(account_id: str | None) -> contextvars.Token:
    """Set the active account for per-tenant SEARCH_PATH routing.

    Returns a Token that can be passed to `reset_account_context` to restore
    the previous value (useful in finally blocks).
    """
    return _current_account_id.set(account_id)


def reset_account_context(token: contextvars.Token) -> None:
    _current_account_id.reset(token)


def _normalize_postgres_url(url: str) -> str:
    """Rewrite libpq-style Postgres URLs (e.g. from Neon) for SQLAlchemy + asyncpg.

    asyncpg's connect() rejects libpq query params like `sslmode`/`channel_binding`
    with a TypeError, so they're dropped here; SSL is still enforced via connect_args.
    """
    parts = urlsplit(url)
    scheme = "postgresql+asyncpg"
    query = parse_qs(parts.query)
    query.pop("sslmode", None)
    query.pop("channel_binding", None)
    return urlunsplit((scheme, parts.netloc, parts.path, urlencode(query, doseq=True), parts.fragment))


def database_url() -> str:
    if url := os.getenv("DATABASE_URL"):
        if url.startswith(("postgresql://", "postgres://")):
            return _normalize_postgres_url(url)
        return url
    dev_db = Path(os.getenv("SENTINEL_DEV_DB", str(Path.home() / ".sentinel" / "sentinel.dev.db")))
    try:
        dev_db.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        dev_db = Path(tempfile.gettempdir()) / "sentinel" / "sentinel.dev.db"
        dev_db.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{dev_db}"


def _is_postgres(engine: AsyncEngine) -> bool:
    return engine.dialect.name == "postgresql"


def create_engine(url: str | None = None) -> AsyncEngine:
    resolved = url or database_url()
    connect_args: dict = {}
    kwargs: dict = {}
    if "postgresql" in resolved:
        # PgBouncer (Neon's pooled endpoint) doesn't support asyncpg prepared statements.
        connect_args["statement_cache_size"] = 0
        connect_args["ssl"] = "require"
        if os.getenv("VERCEL"):
            # Serverless: Neon closes idle connections in seconds, so don't pool —
            # each request gets a fresh connection and closes it immediately.
            from sqlalchemy.pool import NullPool  # noqa: PLC0415
            kwargs["poolclass"] = NullPool
        else:
            # Persistent worker: pre-ping to detect stale connections.
            kwargs["pool_pre_ping"] = True
    return create_async_engine(resolved, future=True, connect_args=connect_args, **kwargs)


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def apply_tenant_search_path(session: AsyncSession, engine: AsyncEngine) -> None:
    """Set Postgres SEARCH_PATH to the tenant schema when running on Postgres.

    If the DATABASE_URL is SQLite (dev mode), this is a no-op.
    If the account_id context is not set, defaults to `public` only.
    """
    if not _is_postgres(engine):
        return

    account_id = _current_account_id.get()
    schema = _schema_name(account_id) if account_id else None

    if schema:
        # Ensure the tenant schema exists (idempotent)
        try:
            await session.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
        except Exception:
            pass
        search_path = f"{schema},public"
    else:
        search_path = "public"

    await session.execute(text(f"SET LOCAL search_path = {search_path}"))
    log.debug("db.tenant_context", search_path=search_path, account_id=account_id)


async def session_scope(factory: async_sessionmaker[AsyncSession], engine: AsyncEngine | None = None) -> AsyncIterator[AsyncSession]:
    async with factory() as session:
        async with session.begin():
            if engine is not None:
                await apply_tenant_search_path(session, engine)
            yield session

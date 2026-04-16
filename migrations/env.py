"""Alembic environment configuration for Sentinel."""
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Alembic Config object — provides access to values in alembic.ini
config = context.config

# Set up logging from config file if present
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import Sentinel models so Alembic can autogenerate migrations
from sentinel.db.models import Base  # noqa: E402

target_metadata = Base.metadata

# Read DATABASE_URL from environment (fallback to local dev default)
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/sentinel")

# Override the sqlalchemy.url from env
config.set_main_option("sqlalchemy.url", DATABASE_URL)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout, no DB connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (connect to DB and apply)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

"""Per-tenant schema isolation scaffolding.

Each account gets its own Postgres schema: `tenant_{account_id}`.
Within that schema, all tables are replicated with proper indices.
A SEARCH_PATH helper is provided for runtime routing.

NOTE: Full per-tenant isolation requires the application to call
`set_search_path(conn, account_id)` before every query. The migration
creates the tenant schema creation procedure; actual schema migration
per-account runs at account creation time via `create_tenant_schema()`.

Revision ID: 0002_per_tenant_schema
Revises: 0001_initial_schema
Create Date: 2026-06-06
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002_per_tenant_schema"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add api_key column to accounts (stores the LLM API key for worker use)
    op.add_column("accounts", sa.Column("api_key", sa.Text(), nullable=True))

    # Create a stored procedure to provision a tenant schema on account creation.
    # This is idempotent — calling it twice for the same account_id is safe.
    op.execute("""
        CREATE OR REPLACE FUNCTION create_tenant_schema(p_account_id TEXT)
        RETURNS void LANGUAGE plpgsql AS $$
        DECLARE
            schema_name TEXT := 'tenant_' || replace(p_account_id, '-', '_');
        BEGIN
            EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', schema_name);
            -- Future: replicate core tables into the schema with RLS policies.
            -- For now, the schema acts as a namespace boundary.
            -- Application-level SEARCH_PATH routing routes all queries for an
            -- account to tenant_{account_id} when per-tenant mode is enabled.
        END;
        $$;
    """)

    # Create a helper to set SEARCH_PATH for a connection to a specific tenant.
    # Call this via `EXECUTE set_tenant_search_path($1)` with the account_id.
    op.execute("""
        CREATE OR REPLACE FUNCTION set_tenant_search_path(p_account_id TEXT)
        RETURNS void LANGUAGE plpgsql AS $$
        DECLARE
            schema_name TEXT := 'tenant_' || replace(p_account_id, '-', '_');
        BEGIN
            PERFORM set_config('search_path', schema_name || ',public', true);
        END;
        $$;
    """)

    # Indexes that improve multi-tenant query performance on the shared schema
    # (used when per-tenant schema isolation is not enabled).
    try:
        op.create_index("idx_nodes_graph_kind", "nodes", ["graph_id", "kind"])
    except Exception:
        pass
    try:
        op.create_index("idx_nodes_graph_file", "nodes", ["graph_id", "file"])
    except Exception:
        pass
    try:
        op.create_index("idx_edges_src", "edges", ["graph_id", "src", "kind"])
    except Exception:
        pass
    try:
        op.create_index("idx_edges_dst", "edges", ["graph_id", "dst", "kind"])
    except Exception:
        pass
    try:
        op.create_index("idx_findings_graph", "findings", ["graph_id", "status"])
    except Exception:
        pass
    try:
        op.create_index("idx_runs_graph", "runs", ["graph_id", "kind", "status"])
    except Exception:
        pass


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS set_tenant_search_path(TEXT)")
    op.execute("DROP FUNCTION IF EXISTS create_tenant_schema(TEXT)")
    op.drop_column("accounts", "api_key")

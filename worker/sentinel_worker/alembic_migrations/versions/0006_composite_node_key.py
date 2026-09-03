"""Composite (graph_id, id) primary key for nodes.

Node ids are only deterministic *within* a graph (e.g. `fn:app.js:handler`).
The original single-column `nodes.id` primary key meant that a branch or
session graph could not carry its own copy of a node id that already existed
in the main graph — the git-like versioning model (main / branch / session
overlays) is inert without per-graph node copies. This migration switches
nodes to a composite (graph_id, id) primary key and drops the single-column
foreign keys that referenced `nodes.id` (edges.src, edges.dst,
findings.node_id) — a single-column FK cannot target a composite key.
Referential integrity for those columns is enforced at the application layer,
which already writes edges/findings with the same graph_id as their nodes.

Revision ID: 0006_composite_node_key
Revises: 0005_repo_pentest_config_blob
Create Date: 2026-07-09
"""
from __future__ import annotations

from alembic import op

revision = "0006_composite_node_key"
down_revision = "0005_repo_pentest_config_blob"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop FKs that reference the old single-column nodes.id PK.
    op.drop_constraint("edges_src_fkey", "edges", type_="foreignkey")
    op.drop_constraint("edges_dst_fkey", "edges", type_="foreignkey")
    op.drop_constraint("findings_node_id_fkey", "findings", type_="foreignkey")
    # Swap the nodes primary key from (id) to (graph_id, id).
    op.drop_constraint("nodes_pkey", "nodes", type_="primary")
    op.create_primary_key("nodes_pkey", "nodes", ["graph_id", "id"])


def downgrade() -> None:
    # NOTE: this will fail if any node id is duplicated across graphs (which is
    # exactly what the composite key was introduced to allow). Deduplicate
    # first if you need to roll back.
    op.drop_constraint("nodes_pkey", "nodes", type_="primary")
    op.create_primary_key("nodes_pkey", "nodes", ["id"])
    op.create_foreign_key("findings_node_id_fkey", "findings", "nodes", ["node_id"], ["id"])
    op.create_foreign_key("edges_dst_fkey", "edges", "nodes", ["dst"], ["id"])
    op.create_foreign_key("edges_src_fkey", "edges", "nodes", ["src"], ["id"])

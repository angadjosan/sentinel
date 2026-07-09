"""Merge base + promotion columns on graphs.

Adds `graphs.base_graph_id` (the immutable base snapshot a branch is merged
against, enabling a true 3-way merge) and `graphs.promoted_at` (when a dev
session graph was promoted into its branch graph).

Revision ID: 0007_merge_base_and_promotion
Revises: 0006_node_tombstone
Create Date: 2026-07-09
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_merge_base_and_promotion"
down_revision = "0006_node_tombstone"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("graphs", sa.Column("base_graph_id", sa.String(), nullable=True))
    op.add_column("graphs", sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True))
    op.create_foreign_key("graphs_base_graph_id_fkey", "graphs", "graphs", ["base_graph_id"], ["id"])


def downgrade() -> None:
    op.drop_constraint("graphs_base_graph_id_fkey", "graphs", type_="foreignkey")
    op.drop_column("graphs", "promoted_at")
    op.drop_column("graphs", "base_graph_id")

"""Node tombstone column.

Adds `nodes.deleted` so a branch/session graph can record that a node was
removed, and so merge_graph can propagate deletions onto main instead of
leaving stale nodes in the main graph forever. Deleted nodes are hidden from
all reads.

Revision ID: 0007_node_tombstone
Revises: 0006_composite_node_key
Create Date: 2026-07-09
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_node_tombstone"
down_revision = "0006_composite_node_key"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("nodes", sa.Column("deleted", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("nodes", "deleted")

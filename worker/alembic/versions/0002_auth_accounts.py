"""Password auth and revocable sessions.

Revision ID: 0002_auth_accounts
Revises: 0001_initial_schema
Create Date: 2026-07-05
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_auth_accounts"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("name", sa.String(), nullable=True))
    op.add_column("users", sa.Column("password_hash", sa.String(), nullable=True))

    op.create_table(
        "sessions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("account_id", sa.String(), sa.ForeignKey("accounts.id"), nullable=False),
        sa.Column("label", sa.String(), nullable=False, server_default="session"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_sessions_user_id", table_name="sessions")
    op.drop_table("sessions")
    op.drop_column("users", "password_hash")
    op.drop_column("users", "name")

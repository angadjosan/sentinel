"""Auth hardening: lockout, email verification/reset, MFA, OAuth, refresh tokens, session metadata.

Revision ID: 0003_auth_hardening
Revises: 0002_auth_accounts
Create Date: 2026-07-05
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_auth_hardening"
down_revision = "0002_auth_accounts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("email_verified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("users", sa.Column("totp_secret_enc", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("totp_confirmed", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("users", sa.Column("github_id", sa.String(), nullable=True))
    op.create_unique_constraint("uq_users_github_id", "users", ["github_id"])
    op.add_column("users", sa.Column("failed_login_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True))

    op.add_column("sessions", sa.Column("user_agent", sa.String(), nullable=True))
    op.add_column("sessions", sa.Column("ip_address", sa.String(), nullable=True))
    op.add_column("sessions", sa.Column("refresh_token_hash", sa.String(), nullable=True))

    op.create_table(
        "auth_tokens",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("purpose", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_auth_tokens_user_id", "auth_tokens", ["user_id"])

    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ip_address", sa.String(), nullable=False),
        sa.Column("endpoint", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_login_attempts_ip_endpoint", "login_attempts", ["ip_address", "endpoint", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_login_attempts_ip_endpoint", table_name="login_attempts")
    op.drop_table("login_attempts")
    op.drop_index("ix_auth_tokens_user_id", table_name="auth_tokens")
    op.drop_table("auth_tokens")

    op.drop_column("sessions", "refresh_token_hash")
    op.drop_column("sessions", "ip_address")
    op.drop_column("sessions", "user_agent")

    op.drop_column("users", "locked_until")
    op.drop_column("users", "failed_login_count")
    op.drop_constraint("uq_users_github_id", "users", type_="unique")
    op.drop_column("users", "github_id")
    op.drop_column("users", "totp_confirmed")
    op.drop_column("users", "totp_secret_enc")
    op.drop_column("users", "email_verified_at")

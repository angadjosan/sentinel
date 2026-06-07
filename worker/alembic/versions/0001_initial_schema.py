"""Initial schema — create all tables.

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-06-06
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic
revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # accounts
    op.create_table(
        "accounts",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("suppression_approval_required", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("monthly_token_budget", sa.Integer(), nullable=True),
        sa.Column("provider", sa.String(), nullable=False, server_default="local"),
        sa.Column("model", sa.String(), nullable=False, server_default="ollama"),
        sa.Column("api_endpoint", sa.String(), nullable=True),
        sa.Column("source_retention_days", sa.Integer(), nullable=False, server_default="365"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # users
    op.create_table(
        "users",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("account_id", sa.String(), sa.ForeignKey("accounts.id"), nullable=False),
        sa.Column("email", sa.String(), nullable=False, unique=True),
        sa.Column("role", sa.String(), nullable=False, server_default="admin"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # device_auth_sessions
    op.create_table(
        "device_auth_sessions",
        sa.Column("device_code", sa.String(), primary_key=True),
        sa.Column("user_code", sa.String(), nullable=False, unique=True),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("account_id", sa.String(), sa.ForeignKey("accounts.id"), nullable=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("role", sa.String(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # repos
    op.create_table(
        "repos",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("account_id", sa.String(), sa.ForeignKey("accounts.id"), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("remote_url", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # graphs
    op.create_table(
        "graphs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("account_id", sa.String(), sa.ForeignKey("accounts.id"), nullable=False),
        sa.Column("repo_id", sa.String(), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column("kind", sa.String(), nullable=False, server_default="main"),
        sa.Column("branch_name", sa.String(), nullable=True),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("parent_id", sa.String(), sa.ForeignKey("graphs.id"), nullable=True),
        sa.Column("base_commit", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("merged_at", sa.DateTime(timezone=True), nullable=True),
    )

    # nodes
    op.create_table(
        "nodes",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("graph_id", sa.String(), sa.ForeignKey("graphs.id"), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("file", sa.String(), nullable=True),
        sa.Column("line_start", sa.Integer(), nullable=True),
        sa.Column("line_end", sa.Integer(), nullable=True),
        sa.Column("language", sa.String(), nullable=True),
        sa.Column("trust_level", sa.String(), nullable=True),
        sa.Column("auth_required", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("privilege", sa.String(), nullable=True),
        sa.Column("is_entry_point", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_sink", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("taint_uncertain", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("parse_error", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("label", sa.String(), nullable=True),
        sa.Column("intent", sa.Text(), nullable=True),
        sa.Column("commit_hash", sa.String(), nullable=True),
        sa.Column("is_new", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # edges
    op.create_table(
        "edges",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("graph_id", sa.String(), sa.ForeignKey("graphs.id"), nullable=False),
        sa.Column("src", sa.String(), sa.ForeignKey("nodes.id"), nullable=False),
        sa.Column("dst", sa.String(), sa.ForeignKey("nodes.id"), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("tainted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sanitized", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("taint_uncertain", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("call_uncertainty", sa.String(), nullable=True),
        sa.Column("order_index", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # runs
    op.create_table(
        "runs",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("graph_id", sa.String(), sa.ForeignKey("graphs.id"), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="running"),
        sa.Column("triggered_by", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("ci_run_id", sa.String(), nullable=True),
        sa.Column("base_ref", sa.String(), nullable=True),
        sa.Column("head_commit", sa.String(), nullable=True),
        sa.Column("token_spend", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("model_used", sa.String(), nullable=True),
        sa.Column("trace", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # run_traces
    op.create_table(
        "run_traces",
        sa.Column("run_id", sa.String(), sa.ForeignKey("runs.id"), primary_key=True),
        sa.Column("seq", sa.Integer(), primary_key=True),
        sa.Column("chunk", sa.Text(), nullable=False),
    )

    # tasks
    op.create_table(
        "tasks",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("graph_id", sa.String(), sa.ForeignKey("graphs.id"), nullable=False),
        sa.Column("run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("account_id", sa.String(), sa.ForeignKey("accounts.id"), nullable=False),
        sa.Column("repo_id", sa.String(), sa.ForeignKey("repos.id"), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="queued"),
        sa.Column("payload", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("claimed_by", sa.String(), nullable=True),
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # findings
    op.create_table(
        "findings",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("graph_id", sa.String(), sa.ForeignKey("graphs.id"), nullable=False),
        sa.Column("node_id", sa.String(), sa.ForeignKey("nodes.id"), nullable=True),
        sa.Column("run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=True),
        sa.Column("vuln_type", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="open"),
        sa.Column("confirmed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("fingerprint", sa.String(), nullable=False, unique=True),
        sa.Column("suppressed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("suppressed_by", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("suppressed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppression_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # suppression_audit
    op.create_table(
        "suppression_audit",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.String(), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("actor_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # token_spend_by_component
    op.create_table(
        "token_spend_by_component",
        sa.Column("run_id", sa.String(), sa.ForeignKey("runs.id"), primary_key=True),
        sa.Column("component", sa.String(), primary_key=True),
        sa.Column("model", sa.String(), primary_key=True),
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
    )

    # source_files
    op.create_table(
        "source_files",
        sa.Column("repo_id", sa.String(), sa.ForeignKey("repos.id"), primary_key=True),
        sa.Column("commit_hash", sa.String(), primary_key=True),
        sa.Column("file_path", sa.String(), primary_key=True),
        sa.Column("content_enc", sa.Text(), nullable=False),
        sa.Column("content_sha", sa.String(), nullable=False),
        sa.Column("language", sa.String(), nullable=True),
        sa.Column("deleted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # advisory_cache
    op.create_table(
        "advisory_cache",
        sa.Column("package", sa.String(), primary_key=True),
        sa.Column("ecosystem", sa.String(), primary_key=True),
        sa.Column("version", sa.String(), primary_key=True),
        sa.Column("advisories_json", sa.Text(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )

    # trace_access_log
    op.create_table(
        "trace_access_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("run_id", sa.String(), sa.ForeignKey("runs.id"), nullable=False),
        sa.Column("actor_id", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("trace_access_log")
    op.drop_table("advisory_cache")
    op.drop_table("source_files")
    op.drop_table("token_spend_by_component")
    op.drop_table("suppression_audit")
    op.drop_table("findings")
    op.drop_table("tasks")
    op.drop_table("run_traces")
    op.drop_table("runs")
    op.drop_table("edges")
    op.drop_table("nodes")
    op.drop_table("graphs")
    op.drop_table("repos")
    op.drop_table("device_auth_sessions")
    op.drop_table("users")
    op.drop_table("accounts")

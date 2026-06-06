from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, MetaData, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    metadata = MetaData()


def now() -> datetime:
    return datetime.now(UTC)


def uuid() -> str:
    return str(uuid4())


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    name: Mapped[str] = mapped_column(String, nullable=False)
    suppression_approval_required: Mapped[bool] = mapped_column(Boolean, default=True)
    monthly_token_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    account_id: Mapped[str] = mapped_column(String, ForeignKey("accounts.id"), nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String, nullable=False, default="admin")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Repo(Base):
    __tablename__ = "repos"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    account_id: Mapped[str] = mapped_column(String, ForeignKey("accounts.id"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    remote_url: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Graph(Base):
    __tablename__ = "graphs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    account_id: Mapped[str] = mapped_column(String, ForeignKey("accounts.id"), nullable=False)
    repo_id: Mapped[str] = mapped_column(String, ForeignKey("repos.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False, default="main")
    branch_name: Mapped[str | None] = mapped_column(String, nullable=True)
    session_id: Mapped[str | None] = mapped_column(String, nullable=True)
    parent_id: Mapped[str | None] = mapped_column(String, ForeignKey("graphs.id"), nullable=True)
    base_commit: Mapped[str | None] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    merged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    graph_id: Mapped[str] = mapped_column(String, ForeignKey("graphs.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    file: Mapped[str | None] = mapped_column(String, nullable=True)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    language: Mapped[str | None] = mapped_column(String, nullable=True)
    trust_level: Mapped[str | None] = mapped_column(String, nullable=True)
    auth_required: Mapped[bool] = mapped_column(Boolean, default=False)
    privilege: Mapped[str | None] = mapped_column(String, nullable=True)
    is_entry_point: Mapped[bool] = mapped_column(Boolean, default=False)
    is_sink: Mapped[bool] = mapped_column(Boolean, default=False)
    taint_uncertain: Mapped[bool] = mapped_column(Boolean, default=False)
    parse_error: Mapped[bool] = mapped_column(Boolean, default=False)
    label: Mapped[str | None] = mapped_column(String, nullable=True)
    intent: Mapped[str | None] = mapped_column(Text, nullable=True)
    commit_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    is_new: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Edge(Base):
    __tablename__ = "edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    graph_id: Mapped[str] = mapped_column(String, ForeignKey("graphs.id"), nullable=False)
    src: Mapped[str] = mapped_column(String, ForeignKey("nodes.id"), nullable=False)
    dst: Mapped[str] = mapped_column(String, ForeignKey("nodes.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    tainted: Mapped[bool] = mapped_column(Boolean, default=False)
    sanitized: Mapped[bool] = mapped_column(Boolean, default=False)
    taint_uncertain: Mapped[bool] = mapped_column(Boolean, default=False)
    call_uncertainty: Mapped[str | None] = mapped_column(String, nullable=True)
    order_index: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    graph_id: Mapped[str] = mapped_column(String, ForeignKey("graphs.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="running")
    triggered_by: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    ci_run_id: Mapped[str | None] = mapped_column(String, nullable=True)
    base_ref: Mapped[str | None] = mapped_column(String, nullable=True)
    head_commit: Mapped[str | None] = mapped_column(String, nullable=True)
    token_spend: Mapped[int] = mapped_column(Integer, default=0)
    model_used: Mapped[str | None] = mapped_column(String, nullable=True)
    trace: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    graph_id: Mapped[str] = mapped_column(String, ForeignKey("graphs.id"), nullable=False)
    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), nullable=False)
    account_id: Mapped[str] = mapped_column(String, ForeignKey("accounts.id"), nullable=False)
    repo_id: Mapped[str] = mapped_column(String, ForeignKey("repos.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="queued")
    payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    claimed_by: Mapped[str | None] = mapped_column(String, nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    graph_id: Mapped[str] = mapped_column(String, ForeignKey("graphs.id"), nullable=False)
    node_id: Mapped[str | None] = mapped_column(String, ForeignKey("nodes.id"), nullable=True)
    run_id: Mapped[str | None] = mapped_column(String, ForeignKey("runs.id"), nullable=True)
    vuln_type: Mapped[str] = mapped_column(String, nullable=False)
    severity: Mapped[str] = mapped_column(String, nullable=False)
    title: Mapped[str] = mapped_column(String, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="open")
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    fingerprint: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    suppressed_by: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    suppressed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suppression_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class SuppressionAudit(Base):
    __tablename__ = "suppression_audit"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[str] = mapped_column(String, ForeignKey("findings.id"), nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    actor_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class TokenSpendByComponent(Base):
    __tablename__ = "token_spend_by_component"

    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), primary_key=True)
    component: Mapped[str] = mapped_column(String, primary_key=True)
    model: Mapped[str] = mapped_column(String, primary_key=True)
    provider: Mapped[str] = mapped_column(String, nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)


class SourceFileSnapshot(Base):
    __tablename__ = "source_files"

    repo_id: Mapped[str] = mapped_column(String, ForeignKey("repos.id"), primary_key=True)
    commit_hash: Mapped[str] = mapped_column(String, primary_key=True)
    file_path: Mapped[str] = mapped_column(String, primary_key=True)
    content_enc: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha: Mapped[str] = mapped_column(String, nullable=False)
    language: Mapped[str | None] = mapped_column(String, nullable=True)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

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
    provider: Mapped[str] = mapped_column(String, default="local")
    model: Mapped[str] = mapped_column(String, default="ollama")
    api_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    api_endpoint: Mapped[str | None] = mapped_column(String, nullable=True)
    # Optional server-side pentest-agent credential (AUDIT.md §3 D2). Separate
    # from the SAST `api_key` policy; set admin-only via dashboard. The worker
    # env `SENTINEL_PENTEST_LLM_API_KEY` takes precedence when present.
    pentest_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    source_retention_days: Mapped[int] = mapped_column(Integer, default=365)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    account_id: Mapped[str] = mapped_column(String, ForeignKey("accounts.id"), nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    name: Mapped[str | None] = mapped_column(String, nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    role: Mapped[str] = mapped_column(String, nullable=False, default="admin")
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    totp_secret_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    totp_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    github_id: Mapped[str | None] = mapped_column(String, unique=True, nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Session(Base):
    """A revocable login session — dashboard password login or CLI device approval.

    Bearer JWTs optionally carry this row's id as a `sid` claim; when present,
    current_principal checks it here so a session can be revoked before the JWT
    naturally expires. Tokens without a `sid` (e.g. tests using create_token
    directly) skip this check entirely and behave as plain stateless JWTs.
    """

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    account_id: Mapped[str] = mapped_column(String, ForeignKey("accounts.id"), nullable=False)
    label: Mapped[str] = mapped_column(String, nullable=False, default="session")
    user_agent: Mapped[str | None] = mapped_column(String, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String, nullable=True)
    refresh_token_hash: Mapped[str | None] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AuthToken(Base):
    """Single-use tokens for email verification and password reset."""

    __tablename__ = "auth_tokens"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"), nullable=False)
    purpose: Mapped[str] = mapped_column(String, nullable=False)  # 'email_verify' | 'password_reset'
    token_hash: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class LoginAttempt(Base):
    """IP-scoped login/signup attempts, for rate limiting independent of account lockout."""

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String, nullable=False)
    endpoint: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class DeviceAuthSession(Base):
    __tablename__ = "device_auth_sessions"

    device_code: Mapped[str] = mapped_column(String, primary_key=True)
    user_code: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String, nullable=False, default="pending")
    account_id: Mapped[str | None] = mapped_column(String, ForeignKey("accounts.id"), nullable=True)
    user_id: Mapped[str | None] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    role: Mapped[str | None] = mapped_column(String, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Repo(Base):
    __tablename__ = "repos"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=uuid)
    account_id: Mapped[str] = mapped_column(String, ForeignKey("accounts.id"), nullable=False)
    name: Mapped[str] = mapped_column(String, nullable=False)
    remote_url: Mapped[str | None] = mapped_column(String, nullable=True)
    # Pentest reachability config (AUDIT.md §3 D1 — dual mode).
    # staging (hosted default): worker sends HTTP payloads to staging_base_url.
    # local_worker (self-hosted): worker boots a subprocess sandbox on its own host.
    pentest_mode: Mapped[str] = mapped_column(String, nullable=False, default="staging")
    staging_base_url: Mapped[str | None] = mapped_column(String, nullable=True)
    healthcheck_path: Mapped[str | None] = mapped_column(String, nullable=True)
    boot: Mapped[str | None] = mapped_column(Text, nullable=True)
    healthcheck: Mapped[str | None] = mapped_column(Text, nullable=True)
    egress_allowlist: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON-encoded list[str]
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

    # Composite primary key (graph_id, id): node ids are only deterministic
    # *within* a graph (e.g. `fn:app.js:handler`), so main / branch / session
    # graphs must each be able to carry their own copy of the same id. Before
    # this, `id` was a single global PK, which meant a branch graph could not
    # override a node that already existed in main and unscoped `db.get(Node,
    # id)` could return another graph's row. All lookups are graph-scoped.
    id: Mapped[str] = mapped_column(String, primary_key=True)
    graph_id: Mapped[str] = mapped_column(String, ForeignKey("graphs.id"), primary_key=True, nullable=False)
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
    # src/dst reference nodes within the same graph_id. No FK constraint: nodes
    # now have a composite (graph_id, id) PK, which a single-column FK cannot
    # target. Referential integrity is enforced at the application layer (every
    # edge is written with the same graph_id as its endpoints).
    src: Mapped[str] = mapped_column(String, nullable=False)
    dst: Mapped[str] = mapped_column(String, nullable=False)
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


class RunTraceChunk(Base):
    __tablename__ = "run_traces"

    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), primary_key=True)
    seq: Mapped[int] = mapped_column(Integer, primary_key=True)
    chunk: Mapped[str] = mapped_column(Text, nullable=False)


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
    # No FK to nodes.id: nodes have a composite (graph_id, id) PK now. The node
    # is resolved via (finding.graph_id, finding.node_id) at read time.
    node_id: Mapped[str | None] = mapped_column(String, nullable=True)
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


class AdvisoryCache(Base):
    __tablename__ = "advisory_cache"

    package: Mapped[str] = mapped_column(String, primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String, primary_key=True)
    version: Mapped[str] = mapped_column(String, primary_key=True)
    advisories_json: Mapped[str] = mapped_column(Text, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TraceAccessLog(Base):
    __tablename__ = "trace_access_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String, ForeignKey("runs.id"), nullable=False)
    actor_id: Mapped[str] = mapped_column(String, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

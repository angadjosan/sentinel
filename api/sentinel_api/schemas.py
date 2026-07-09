from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


# NOTE: InitRequest / SourceRequest / PlanRequest were removed. They carried
# source code, unified diffs, or plan text in the request body for the legacy
# cloud-SAST routes (/init, /source, /plan), which the local-AI-calls model
# forbids (§1: source/diffs never leave the CLI machine on the scan path). The
# CLI now runs those locally and pushes back only graph deltas + findings.


class IngestFinding(BaseModel):
    vuln_type: str = Field(min_length=1)
    severity: str = Field(min_length=1)
    title: str = Field(min_length=1)
    description: str
    remediation: str = ""
    node_id: str | None = None
    file: str | None = None
    line: int | None = None
    evidence: str | None = None


class IngestRequest(BaseModel):
    repo_name: str = Field(min_length=1)
    run_context: str = "ci"
    commit_sha: str | None = None
    base_ref: str | None = None
    findings: list[IngestFinding] = Field(default_factory=list)


class IngestResponse(BaseModel):
    run_id: str
    created: int
    updated: int
    total: int
    finding_ids: list[str] = Field(default_factory=list)


class FirecrackerRequest(BaseModel):
    enabled: bool = False
    kernel_image: str | None = None
    rootfs_image: str | None = None
    api_socket: str = "/tmp/sentinel-firecracker.sock"
    firecracker_bin: str = "firecracker"
    boot_args: str = "console=ttyS0 reboot=k panic=1 pci=off"
    vcpu_count: int = Field(default=1, ge=1)
    mem_size_mib: int = Field(default=512, ge=128)
    smt: bool = False
    network_interface_id: str = "eth0"
    host_dev_name: str | None = None
    guest_mac: str | None = None
    guest_runner_argv: list[str] = Field(default_factory=list)


class PentestRequest(BaseModel):
    repo_name: str = Field(min_length=1)
    finding_id: str | None = None
    description: str | None = None
    sanitizer_output: str = ""
    behavioral_proof: str | None = None
    proof_detail: str = ""
    boot: str | None = None
    healthcheck: str | None = None
    egress_allowlist: list[str] = Field(default_factory=list)
    firecracker: FirecrackerRequest | None = None


class PentestConfirmRequest(BaseModel):
    """Result of a local pentest run — evidence text and node pointers only,
    never source or diff content. Posted by the local engine after it runs
    `sentinel pentest` against the app on the developer's own machine."""

    confirmed: bool
    status: str = Field(default="not_reproducible", min_length=1)
    evidence: str | None = None
    entry_node_id: str | None = None
    sink_node_id: str | None = None


class SuppressRequest(BaseModel):
    reason: str = Field(min_length=1)


class DeviceStartResponse(BaseModel):
    device_code: str
    user_code: str
    verification_url: str
    expires_in: int


class DeviceTokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    expires_in: int | None = None
    account_id: str
    user_id: str
    database_url: str | None = None


class DeviceApproveRequest(BaseModel):
    user_code: str = Field(min_length=1)


class ConfigResponse(BaseModel):
    api_url: str
    repo_name: str


class RunResponse(BaseModel):
    id: str
    kind: str
    status: str
    finding_count: int = 0
    token_spend: int
    model_used: str | None = None
    trace: str = ""
    created_at: str
    completed_at: str | None = None


class FindingResponse(BaseModel):
    id: str
    vuln_type: str
    severity: str
    title: str
    description: str
    remediation: str
    status: str
    confirmed: bool
    evidence: str | None = None
    fingerprint: str
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    created_at: str
    updated_at: str


class SuppressionAuditResponse(BaseModel):
    id: int
    finding_id: str
    action: str
    actor_id: str
    reason: str
    created_at: str


class TraceAccessLogResponse(BaseModel):
    id: int
    run_id: str
    actor_id: str
    created_at: str


class EnqueueResponse(BaseModel):
    task_id: str
    run: RunResponse


class TaskResponse(BaseModel):
    id: str
    run_id: str
    kind: str
    status: str
    payload: dict
    attempts: int
    claimed_by: str | None
    error: str | None


class TaskCompleteRequest(BaseModel):
    trace: str | None = None


class TaskFailRequest(BaseModel):
    error: str = Field(min_length=1)


class TokenBudgetRequest(BaseModel):
    monthly_token_budget: int | None = Field(default=None, ge=0)


class AccountConfigResponse(BaseModel):
    account_id: str
    provider: str
    model: str
    api_endpoint: str | None = None
    suppression_approval_required: bool
    monthly_token_budget: int | None = None
    source_retention_days: int


class AccountConfigPatch(BaseModel):
    provider: str | None = None
    model: str | None = None
    api_key: str | None = None
    api_endpoint: str | None = None
    suppression_approval_required: bool | None = None
    monthly_token_budget: int | None = Field(default=None, ge=0)
    source_retention_days: int | None = Field(default=None, ge=1)


class GraphMergeRequest(BaseModel):
    branch_graph_id: str = Field(min_length=1)
    main_graph_id: str = Field(min_length=1)


class NodeResponse(BaseModel):
    id: str
    kind: str
    name: str
    file: str | None
    line_start: int | None
    line_end: int | None
    language: str | None
    auth_required: bool
    is_entry_point: bool
    is_sink: bool
    label: str | None
    intent: str | None


class EdgeResponse(BaseModel):
    id: int
    src: str
    dst: str
    kind: str
    tainted: bool
    sanitized: bool
    taint_uncertain: bool
    call_uncertainty: str | None


class GraphResponse(BaseModel):
    nodes: list[NodeResponse]
    edges: list[EdgeResponse]


class GraphSubgraphResponse(BaseModel):
    graph_id: str
    nodes: list[NodeResponse]
    edges: list[EdgeResponse]


class GraphUpsertNode(BaseModel):
    """A graph node produced by a local scan.

    Deliberately has no field for source text — only pointers (file/line) and
    short structural/semantic metadata, matching what nodes have always stored
    (see non-code/README.md: "Nodes do not store source text").
    """

    id: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    name: str = Field(min_length=1)
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    language: str | None = None
    trust_level: str | None = None
    auth_required: bool = False
    privilege: str | None = None
    is_entry_point: bool = False
    is_sink: bool = False
    taint_uncertain: bool = False
    parse_error: bool = False
    label: str | None = Field(default=None, max_length=2000)
    intent: str | None = Field(default=None, max_length=2000)
    commit_hash: str | None = None
    is_new: bool = False


class GraphUpsertEdge(BaseModel):
    src: str = Field(min_length=1)
    dst: str = Field(min_length=1)
    kind: str = Field(min_length=1)
    tainted: bool = False
    sanitized: bool = False
    taint_uncertain: bool = False
    call_uncertainty: str | None = None
    order_index: int | None = None


class GraphUpsertRequest(BaseModel):
    repo_name: str = Field(min_length=1)
    graph_kind: Literal["main", "branch", "session"] = "main"
    branch_name: str | None = None
    session_id: str | None = None
    nodes: list[GraphUpsertNode] = Field(default_factory=list)
    edges: list[GraphUpsertEdge] = Field(default_factory=list)


class GraphUpsertResponse(BaseModel):
    graph_id: str
    nodes_upserted: int
    edges_upserted: int


class RepoCreateRequest(BaseModel):
    name: str = Field(min_length=1)
    remote_url: str | None = None


class RepoResponse(BaseModel):
    id: str
    name: str
    account_id: str
    remote_url: str | None = None
    created_at: str


# --- Repo pentest reachability config (AUDIT.md §3 D1 — dual mode) [W1] ---


class RepoPentestConfigResponse(BaseModel):
    repo_id: str
    pentest_mode: Literal["staging", "local_worker"]
    staging_base_url: str | None = None
    healthcheck_path: str | None = None
    boot: str | None = None
    healthcheck: str | None = None
    egress_allowlist: list[str] = Field(default_factory=list)
    # Structured config: {sandbox, egress, secrets, canary, attack_safety}.
    # The worker reads this to build the gVisor sandbox and its controls.
    pentest_config: dict | None = None


class RepoPentestConfigPatch(BaseModel):
    pentest_mode: Literal["staging", "local_worker"] | None = None
    staging_base_url: str | None = None
    healthcheck_path: str | None = None
    boot: str | None = None
    healthcheck: str | None = None
    egress_allowlist: list[str] | None = None
    pentest_config: dict | None = None


class SuppressionReviewRequest(BaseModel):
    action: Literal["approve", "reject"]
    reason: str = Field(min_length=10)


class RemediationResponse(BaseModel):
    finding: FindingResponse
    graph_context: str
    remediation_plan: list[str]


class SignupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=200)
    account_name: str | None = Field(default=None, max_length=200)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=200)


class AuthUserResponse(BaseModel):
    id: str
    email: str
    name: str | None = None
    role: str
    account_id: str
    account_name: str
    email_verified: bool = False
    mfa_enabled: bool = False


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    user: AuthUserResponse


class LoginResponse(BaseModel):
    mfa_required: bool = False
    challenge_token: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    user: AuthUserResponse | None = None


class MfaLoginRequest(BaseModel):
    challenge_token: str = Field(min_length=1)
    code: str = Field(min_length=6, max_length=8)


class MfaEnrollResponse(BaseModel):
    secret: str
    otpauth_url: str


class MfaConfirmRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class MfaDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=200)


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)


class ResetPasswordRequest(BaseModel):
    token: str = Field(min_length=1)
    password: str = Field(min_length=8, max_length=200)


class GithubOAuthRequest(BaseModel):
    code: str = Field(min_length=1)
    redirect_uri: str = Field(min_length=1)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class RefreshResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int


class SessionResponse(BaseModel):
    id: str
    label: str
    created_at: str
    expires_at: str
    last_seen_at: str
    user_agent: str | None = None
    ip_address: str | None = None
    current: bool = False



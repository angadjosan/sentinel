from __future__ import annotations

from pydantic import BaseModel, Field


class InitRequest(BaseModel):
    repo_name: str = Field(min_length=1)
    files: dict[str, str] = Field(default_factory=dict)


class SourceRequest(BaseModel):
    repo_name: str = Field(min_length=1)
    diff: str
    run_context: str = "local"


class PlanRequest(BaseModel):
    repo_name: str = Field(min_length=1)
    content: str
    with_retry: bool = False


class PentestRequest(BaseModel):
    repo_name: str = Field(min_length=1)
    finding_id: str | None = None
    description: str | None = None
    sanitizer_output: str = ""
    behavioral_proof: str | None = None
    proof_detail: str = ""


class SuppressRequest(BaseModel):
    reason: str = Field(min_length=1)


class ConfigResponse(BaseModel):
    api_url: str
    repo_name: str


class RunResponse(BaseModel):
    id: str
    kind: str
    status: str
    token_spend: int
    model_used: str | None = None
    trace: str = ""


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


class SuppressionAuditResponse(BaseModel):
    id: int
    finding_id: str
    action: str
    actor_id: str
    reason: str
    created_at: str


class SourceResponse(BaseModel):
    run: RunResponse
    findings: list[FindingResponse]


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
    api_endpoint: str | None = None
    suppression_approval_required: bool | None = None
    monthly_token_budget: int | None = Field(default=None, ge=0)
    source_retention_days: int | None = Field(default=None, ge=1)


class GraphMergeRequest(BaseModel):
    branch_graph_id: str = Field(min_length=1)
    main_graph_id: str = Field(min_length=1)


class SourceReadResponse(BaseModel):
    repo_name: str
    commit_hash: str
    file_path: str
    content: str


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

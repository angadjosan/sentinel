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


class SourceResponse(BaseModel):
    run: RunResponse
    findings: list[FindingResponse]


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

from __future__ import annotations

import json
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import structlog
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware

from sentinel_worker.models import Account, DeviceAuthSession, Edge, Finding, Graph, Node, Repo, Run, SuppressionAudit, Task, TokenSpendByComponent, TraceAccessLog, User, now
from sentinel_worker.graph_merge import merge_graph
from sentinel_worker.scan import get_or_create_graph, trace_event
from sentinel_worker.security import compute_fingerprint
from sentinel_worker.source_store import read_source_snapshot
from sentinel_worker.task_queue import cancel_run_tasks, cancel_task, claim_next_task, complete_task, enqueue_task, fail_task
from sentinel_worker.trace_store import read_run_trace

from .auth import Principal, create_token, current_principal, require_admin
from .deps import get_db, init_schema
from .routers.repos import router as repos_router
from .schemas import (
    AccountConfigPatch,
    AccountConfigResponse,
    DeviceApproveRequest,
    DeviceStartResponse,
    DeviceTokenResponse,
    EdgeResponse,
    EnqueueResponse,
    FindingResponse,
    GraphResponse,
    GraphMergeRequest,
    IngestRequest,
    IngestResponse,
    InitRequest,
    NodeResponse,
    PentestRequest,
    PlanRequest,
    RemediationResponse,
    RunResponse,
    SourceRequest,
    SourceReadResponse,
    SuppressRequest,
    SuppressionAuditResponse,
    SuppressionReviewRequest,
    TaskCompleteRequest,
    TaskFailRequest,
    TaskResponse,
    TokenBudgetRequest,
    TraceAccessLogResponse,
)
from .sse import stream_run_events

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        await init_schema()
    except Exception as exc:
        # Migrations may fail on Neon's pooled endpoint in serverless cold starts.
        # The hosted worker runs migrations on boot and owns schema management;
        # log the error but don't crash the API — existing schema is sufficient.
        import structlog as _sl
        _sl.get_logger().warning("schema.init.skipped", error=str(exc))
    yield


app = FastAPI(title="Sentinel API", version="0.1.0", lifespan=lifespan)

_cors_origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001").split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    from fastapi import HTTPException as _HTTPException
    if isinstance(exc, _HTTPException):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    log.error("unhandled_exception", path=str(request.url.path), error=str(exc), exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


def _is_dev_mode() -> bool:
    """True when SENTINEL_DEV_MODE=1."""
    return os.getenv("SENTINEL_DEV_MODE", "0").strip() == "1"


def _skip_tenant_filter(principal: "Principal") -> bool:
    """True only when in dev mode AND the principal is the dev user.

    This prevents production tokens with account_id='dev' from bypassing
    tenant isolation — both conditions must hold simultaneously.
    """
    return _is_dev_mode() and principal.account_id == "dev"


COMMIT_HASH_RE = re.compile(r"^[0-9a-f]{7,64}$")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        start = time.time()
        response = await call_next(request)
        log.debug(
            "api.request",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=round((time.time() - start) * 1000, 2),
        )
        return response


class TenantContextMiddleware(BaseHTTPMiddleware):
    """Extract account_id from the JWT and set it as the per-request tenant context.

    This enables automatic Postgres SEARCH_PATH routing to tenant_{account_id}
    for every authenticated request without changing individual endpoint signatures.
    """

    async def dispatch(self, request, call_next):
        from sentinel_worker.db import reset_account_context, set_account_context
        from jose import JWTError, jwt as _jwt
        from .auth import jwt_secret, ALGORITHM

        account_id: str | None = None
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.removeprefix("Bearer ").strip()
            try:
                payload = _jwt.decode(token, jwt_secret(), algorithms=[ALGORITHM])
                account_id = str(payload.get("account_id")) if payload.get("account_id") else None
            except (JWTError, Exception):
                pass

        token = set_account_context(account_id)
        try:
            return await call_next(request)
        finally:
            reset_account_context(token)


app.add_middleware(TenantContextMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.include_router(repos_router)

RUNS_TOTAL = Counter("sentinel_runs_total", "Runs by kind and status", ["kind", "status"])
FINDINGS_TOTAL = Counter("sentinel_findings_total", "Findings by type and severity", ["vuln_type", "severity"])
SCAN_DURATION = Histogram("sentinel_scan_duration_seconds", "Scan duration by kind", ["kind"])
ACTIVE_RUNS = Gauge("sentinel_active_runs", "Currently active runs")
DEVICE_CODE_TTL_SECONDS = 600


async def run_response(db: AsyncSession, run: Run) -> RunResponse:
    finding_count = await db.scalar(select(func.count(Finding.id)).where(Finding.run_id == run.id)) or 0
    return RunResponse(
        id=run.id,
        kind=run.kind,
        status=run.status,
        finding_count=int(finding_count),
        token_spend=run.token_spend,
        model_used=run.model_used,
        trace=run.trace or "",
        created_at=run.created_at.isoformat(),
        completed_at=run.completed_at.isoformat() if run.completed_at else None,
    )


def account_config_response(account: Account) -> AccountConfigResponse:
    return AccountConfigResponse(
        account_id=account.id,
        provider=account.provider,
        model=account.model,
        api_endpoint=account.api_endpoint,
        suppression_approval_required=account.suppression_approval_required,
        monthly_token_budget=account.monthly_token_budget,
        source_retention_days=account.source_retention_days,
    )


async def finding_response(db: AsyncSession, finding: Finding) -> FindingResponse:
    node = await db.get(Node, finding.node_id) if finding.node_id else None
    return FindingResponse(
        id=finding.id,
        vuln_type=finding.vuln_type,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        remediation=finding.remediation,
        status=finding.status,
        confirmed=finding.confirmed,
        evidence=finding.evidence,
        fingerprint=finding.fingerprint,
        file=node.file if node else None,
        line_start=node.line_start if node else None,
        line_end=node.line_end if node else None,
        created_at=finding.created_at.isoformat(),
        updated_at=finding.updated_at.isoformat(),
    )


def task_response(task: Task) -> TaskResponse:
    return TaskResponse(
        id=task.id,
        run_id=task.run_id,
        kind=task.kind,
        status=task.status,
        payload=json.loads(task.payload),
        attempts=task.attempts,
        claimed_by=task.claimed_by,
        error=task.error,
    )


def trace_access_response(row: TraceAccessLog) -> TraceAccessLogResponse:
    return TraceAccessLogResponse(id=row.id, run_id=row.run_id, actor_id=row.actor_id, created_at=row.created_at.isoformat())


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
async def metrics(principal: Principal = Depends(require_admin)) -> PlainTextResponse:
    return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)


@app.post("/auth/device", response_model=DeviceStartResponse)
async def start_device_auth(db: AsyncSession = Depends(get_db)) -> DeviceStartResponse:
    device_code = secrets.token_urlsafe(32)
    user_code = _user_code()
    session = DeviceAuthSession(
        device_code=device_code,
        user_code=user_code,
        expires_at=datetime.now(UTC) + timedelta(seconds=DEVICE_CODE_TTL_SECONDS),
    )
    db.add(session)
    return DeviceStartResponse(
        device_code=device_code,
        user_code=user_code,
        verification_url="/auth/device/verify",
        expires_in=DEVICE_CODE_TTL_SECONDS,
    )


@app.get("/auth/device/verify")
async def device_verify_page(db: AsyncSession = Depends(get_db)) -> PlainTextResponse:
    import os as _os
    if _os.getenv("SENTINEL_DEV_MODE", "").strip() == "1":
        return PlainTextResponse(
            "Dev mode: device codes are auto-approved.\n"
            "Return to your terminal — the CLI has already received its token.",
            media_type="text/plain",
        )
    return PlainTextResponse(
        "To approve a device: POST /auth/device/approve with {\"user_code\": \"XXXX-XXXX\"} "
        "and a valid admin Bearer token.",
        media_type="text/plain",
    )


@app.post("/auth/device/approve", response_model=dict[str, str])
async def approve_device_auth(payload: DeviceApproveRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> dict[str, str]:
    session = await db.scalar(select(DeviceAuthSession).where(DeviceAuthSession.user_code == payload.user_code))
    if session is None:
        raise HTTPException(status_code=404, detail="device code not found")
    if _as_utc(session.expires_at) < datetime.now(UTC):
        session.status = "expired"
        raise HTTPException(status_code=410, detail="device code expired")
    actor = await _actor_from_principal(db, principal)
    session.status = "approved"
    session.account_id = actor.account_id
    session.user_id = actor.id
    session.role = principal.role
    session.approved_at = now()
    return {"status": "approved"}


@app.get("/auth/device/token", response_model=DeviceTokenResponse)
async def device_auth_token(device_code: str, db: AsyncSession = Depends(get_db)) -> DeviceTokenResponse:
    import os as _os
    session = await db.get(DeviceAuthSession, device_code)
    if session is None:
        raise HTTPException(status_code=404, detail="device code not found")
    if _as_utc(session.expires_at) < datetime.now(UTC):
        session.status = "expired"
        raise HTTPException(status_code=410, detail="device code expired")
    # Auto-approve on first poll. The device code is the security token —
    # only someone who initiated the flow has it.
    if session.status != "approved":
        if _is_dev_mode():
            # Local dev: reuse the single dev account so config/findings persist
            # across restarts without re-login.
            dev_user = await _dev_actor(db)
            session.account_id = dev_user.account_id
            session.user_id = dev_user.id
        else:
            # Cloud: create a fresh account + user for this device session so
            # every login gets its own isolated account and API key.
            from sentinel_worker.models import Account as _Account, User as _User
            new_account = _Account(
                name=f"user-{session.device_code[:8]}",
                provider="anthropic",
                model="claude-sonnet-4-6",
            )
            db.add(new_account)
            await db.flush()
            new_user = _User(
                account_id=new_account.id,
                email=f"device-{session.device_code[:16]}@sentinel.local",
                role="admin",
            )
            db.add(new_user)
            await db.flush()
            session.account_id = new_account.id
            session.user_id = new_user.id
        session.status = "approved"
        session.role = "admin"
        session.approved_at = now()
    if session.status != "approved" or not session.account_id or not session.user_id:
        raise HTTPException(status_code=202, detail="authorization pending")
    token = create_token(session.user_id, session.account_id, session.role or "admin")
    return DeviceTokenResponse(
        access_token=token,
        account_id=session.account_id,
        user_id=session.user_id,
        database_url=os.getenv("SENTINEL_WORKER_DATABASE_URL"),
    )


@app.get("/config", response_model=AccountConfigResponse)
async def get_account_config(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> AccountConfigResponse:
    actor = await _actor_from_principal(db, principal)
    account = await db.get(Account, actor.account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="account not found")
    return account_config_response(account)


@app.patch("/config", response_model=AccountConfigResponse)
async def patch_account_config(payload: AccountConfigPatch, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> AccountConfigResponse:
    actor = await _actor_from_principal(db, principal)
    account = await db.get(Account, actor.account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="account not found")
    fields = payload.model_fields_set
    if "provider" in fields and payload.provider is not None:
        account.provider = payload.provider
    if "model" in fields and payload.model is not None:
        account.model = payload.model
    if "api_key" in fields and payload.api_key is not None:
        account.api_key = payload.api_key
    if "api_endpoint" in fields:
        account.api_endpoint = payload.api_endpoint
    if "suppression_approval_required" in fields and payload.suppression_approval_required is not None:
        account.suppression_approval_required = payload.suppression_approval_required
    if "monthly_token_budget" in fields:
        account.monthly_token_budget = payload.monthly_token_budget
    if "source_retention_days" in fields and payload.source_retention_days is not None:
        account.source_retention_days = payload.source_retention_days
    return account_config_response(account)


@app.post("/init", response_model=EnqueueResponse)
async def init_repo(payload: InitRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> EnqueueResponse:
    task = await enqueue_task(
        db,
        repo_name=payload.repo_name,
        kind="init",
        payload={"repo_name": payload.repo_name, "files": payload.files},
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    if run is None:
        raise HTTPException(status_code=500, detail="run record not found after enqueue")
    return EnqueueResponse(task_id=task.id, run=await run_response(db, run))


@app.post("/source", response_model=EnqueueResponse)
async def source(payload: SourceRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> EnqueueResponse:
    await _check_token_budget(db, principal)
    task = await enqueue_task(
        db,
        repo_name=payload.repo_name,
        kind="source",
        payload={"repo_name": payload.repo_name, "diff": payload.diff, "run_context": payload.run_context, "base_ref": payload.base_ref, "paths": payload.paths},
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    if run is None:
        raise HTTPException(status_code=500, detail="run record not found after enqueue")
    return EnqueueResponse(task_id=task.id, run=await run_response(db, run))


@app.post("/source/enqueue", response_model=EnqueueResponse)
async def source_enqueue(payload: SourceRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> EnqueueResponse:
    await _check_token_budget(db, principal)
    task = await enqueue_task(
        db,
        repo_name=payload.repo_name,
        kind="source",
        payload={"repo_name": payload.repo_name, "diff": payload.diff, "run_context": payload.run_context, "base_ref": payload.base_ref, "paths": payload.paths},
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    if run is None:
        raise HTTPException(status_code=500, detail="run record not found after enqueue")
    return EnqueueResponse(task_id=task.id, run=await run_response(db, run))



@app.post("/tasks/claim", response_model=TaskResponse | None)
async def claim_task(worker_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> TaskResponse | None:
    claimed = await claim_next_task(db, worker_id=worker_id)
    return task_response(claimed.task) if claimed else None


@app.post("/tasks/{task_id}/complete", response_model=TaskResponse)
async def complete_task_endpoint(task_id: str, payload: TaskCompleteRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> TaskResponse:
    try:
        task = await complete_task(db, task_id=task_id, trace=payload.trace)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return task_response(task)


@app.post("/tasks/{task_id}/fail", response_model=TaskResponse)
async def fail_task_endpoint(task_id: str, payload: TaskFailRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> TaskResponse:
    try:
        task = await fail_task(db, task_id=task_id, error=payload.error)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return task_response(task)


@app.post("/tasks/{task_id}/cancel", response_model=TaskResponse)
async def cancel_task_endpoint(task_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> TaskResponse:
    try:
        task = await cancel_task(db, task_id=task_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return task_response(task)


@app.post("/plan", response_model=EnqueueResponse)
async def plan(payload: PlanRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> EnqueueResponse:
    await _check_token_budget(db, principal)
    task = await enqueue_task(
        db,
        repo_name=payload.repo_name,
        kind="plan",
        payload={"repo_name": payload.repo_name, "content": payload.content, "with_retry": payload.with_retry},
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    if run is None:
        raise HTTPException(status_code=500, detail="run record not found after enqueue")
    return EnqueueResponse(task_id=task.id, run=await run_response(db, run))


@app.post("/findings/ingest", response_model=IngestResponse)
async def ingest_findings(payload: IngestRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> IngestResponse:
    """Ingest pre-computed findings from a CI-native scan.

    The scanner runs inside the user's CI and POSTs ONLY the finding metadata —
    no source code or diffs are uploaded or stored. Findings are deduplicated by
    a canonical fingerprint so re-ingesting the same finding across CI runs
    reopens/updates the existing row rather than creating duplicates.
    """
    graph = await get_or_create_graph(db, payload.repo_name, account_id=_graph_account_id(principal))
    repo = await db.scalar(select(Repo).where(Repo.id == graph.repo_id))
    if repo is None:
        raise HTTPException(status_code=500, detail="repo not found for graph")

    run = Run(
        graph_id=graph.id,
        kind="ingest",
        status="completed",
        base_ref=payload.base_ref,
        head_commit=payload.commit_sha,
        completed_at=now(),
        trace=trace_event("ingest.completed", finding_count=len(payload.findings), run_context=payload.run_context),
    )
    db.add(run)
    await db.flush()

    created = 0
    updated = 0
    for incoming in payload.findings:
        fingerprint = compute_fingerprint(repo.id, incoming.node_id or incoming.file or "unknown", incoming.vuln_type)
        existing = await db.scalar(select(Finding).where(Finding.fingerprint == fingerprint))
        if existing is not None:
            existing.run_id = run.id
            existing.updated_at = now()
            if not existing.suppressed:
                existing.status = "open"
            updated += 1
        else:
            db.add(
                Finding(
                    graph_id=graph.id,
                    node_id=incoming.node_id,
                    run_id=run.id,
                    vuln_type=incoming.vuln_type,
                    severity=incoming.severity,
                    title=incoming.title,
                    description=incoming.description,
                    remediation=incoming.remediation,
                    evidence=incoming.evidence,
                    fingerprint=fingerprint,
                    status="open",
                )
            )
            created += 1

    return IngestResponse(run_id=run.id, created=created, updated=updated, total=created + updated)


@app.get("/findings", response_model=list[FindingResponse])
async def findings(
    repo_name: str | None = None,
    status: str | None = None,
    severity: str | None = None,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> list[FindingResponse]:
    stmt = select(Finding).order_by(Finding.created_at.desc())
    joined_graph = False
    if repo_name:
        stmt = (
            stmt.join(Graph, Finding.graph_id == Graph.id)
            .join(Repo, Graph.repo_id == Repo.id)
            .where(Repo.name == repo_name)
        )
        joined_graph = True
    if not _skip_tenant_filter(principal):
        if not joined_graph:
            stmt = stmt.join(Graph, Finding.graph_id == Graph.id)
        stmt = stmt.where(Graph.account_id == principal.account_id)
    if status:
        stmt = stmt.where(Finding.status == status)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    rows = await db.scalars(stmt)
    return [await finding_response(db, row) for row in rows]


@app.get("/findings/{finding_id}", response_model=FindingResponse)
async def finding_detail(finding_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> FindingResponse:
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return await finding_response(db, finding)


@app.get("/findings/{finding_id}/audit", response_model=list[SuppressionAuditResponse])
async def finding_audit(finding_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[SuppressionAuditResponse]:
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    rows = await db.scalars(select(SuppressionAudit).where(SuppressionAudit.finding_id == finding_id).order_by(SuppressionAudit.created_at.desc()))
    return [
        SuppressionAuditResponse(
            id=row.id,
            finding_id=row.finding_id,
            action=row.action,
            actor_id=row.actor_id,
            reason=row.reason,
            created_at=row.created_at.isoformat(),
        )
        for row in rows
    ]


@app.get("/findings/{finding_id}/pull")
async def pull_finding(finding_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> dict[str, object]:
    """Delegates to /findings/{id}/remediation for the full graph-aware remediation plan."""
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    node = await db.get(Node, finding.node_id) if finding.node_id else None
    remediation = await finding_remediation(finding_id=finding_id, db=db, principal=principal)
    return {
        "finding": (await finding_response(db, finding)).model_dump(),
        "node": node_response(node).model_dump() if node else None,
        "remediation_plan": remediation.remediation_plan,
    }


@app.get("/findings/{finding_id}/graph", response_model=GraphResponse)
async def finding_graph(finding_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> GraphResponse:
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if finding.node_id is None:
        return GraphResponse(nodes=[], edges=[])

    edge_kinds = ["CALLS", "FLOWS_TO", "GUARDED_BY", "CONFIRMED_EXPLOIT"]
    edges = list(
        await db.scalars(
            select(Edge)
            .where(Edge.graph_id == finding.graph_id)
            .where(Edge.kind.in_(edge_kinds))
            .where((Edge.src == finding.node_id) | (Edge.dst == finding.node_id))
            .order_by(Edge.kind.asc(), Edge.id.asc())
        )
    )
    node_ids = {finding.node_id}
    for edge in edges:
        node_ids.add(edge.src)
        node_ids.add(edge.dst)
    nodes = list(await db.scalars(select(Node).where(Node.graph_id == finding.graph_id).where(Node.id.in_(node_ids)).order_by(Node.kind.asc(), Node.name.asc())))
    return GraphResponse(nodes=[node_response(node) for node in nodes], edges=[edge_response(edge) for edge in edges])


@app.patch("/findings/{finding_id}/suppress", response_model=FindingResponse)
async def suppress(finding_id: str, payload: SuppressRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> FindingResponse:
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if principal.role == "readonly":
        raise HTTPException(status_code=403, detail="readonly users cannot suppress findings")
    actor = await _actor_from_principal(db, principal)
    approval_required = await _suppression_approval_required(db, actor.account_id)
    if principal.role != "admin" and approval_required:
        finding.status = "suppression_pending"
        finding.suppressed = False
        action = "suppress"
    else:
        finding.status = "suppressed"
        finding.suppressed = True
        action = "suppress"
    finding.suppressed_by = actor.id
    finding.suppressed_at = now()
    finding.suppression_reason = payload.reason
    db.add(SuppressionAudit(finding_id=finding.id, action=action, actor_id=actor.id, reason=payload.reason))
    return await finding_response(db, finding)


@app.post("/findings/{finding_id}/unsuppress", response_model=FindingResponse)
async def unsuppress(finding_id: str, payload: SuppressRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> FindingResponse:
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    actor = await _actor_from_principal(db, principal)
    finding.status = "open"
    finding.suppressed = False
    finding.suppression_reason = None
    db.add(SuppressionAudit(finding_id=finding.id, action="unsuppress", actor_id=actor.id, reason=payload.reason))
    return await finding_response(db, finding)


@app.post("/findings/{finding_id}/suppress/approve", response_model=FindingResponse)
async def approve_suppression(finding_id: str, payload: SuppressRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> FindingResponse:
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    actor = await _actor_from_principal(db, principal)
    finding.status = "suppressed"
    finding.suppressed = True
    finding.suppressed_at = now()
    db.add(SuppressionAudit(finding_id=finding.id, action="approve", actor_id=actor.id, reason=payload.reason))
    return await finding_response(db, finding)


@app.post("/findings/{finding_id}/suppress/reject", response_model=FindingResponse)
async def reject_suppression(finding_id: str, payload: SuppressRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> FindingResponse:
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    actor = await _actor_from_principal(db, principal)
    finding.status = "open"
    finding.suppressed = False
    db.add(SuppressionAudit(finding_id=finding.id, action="reject", actor_id=actor.id, reason=payload.reason))
    return await finding_response(db, finding)


@app.patch("/findings/{finding_id}/suppression-review", response_model=FindingResponse)
async def suppression_review(finding_id: str, payload: SuppressionReviewRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> FindingResponse:
    """Admin-only: approve or reject a pending suppression request."""
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if finding.status != "suppression_pending":
        raise HTTPException(status_code=409, detail="finding does not have a pending suppression")
    actor = await _actor_from_principal(db, principal)
    if payload.action == "approve":
        finding.status = "suppressed"
        finding.suppressed = True
        finding.suppressed_at = now()
    else:
        finding.status = "open"
        finding.suppressed = False
    db.add(SuppressionAudit(finding_id=finding.id, action=payload.action, actor_id=actor.id, reason=payload.reason))
    return await finding_response(db, finding)


@app.delete("/findings/{finding_id}/suppress", response_model=FindingResponse)
async def remove_suppression(finding_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> FindingResponse:
    """Remove (undo) a suppression on a finding."""
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    actor = await _actor_from_principal(db, principal)
    finding.status = "open"
    finding.suppressed = False
    finding.suppression_reason = None
    db.add(SuppressionAudit(finding_id=finding.id, action="unsuppress", actor_id=actor.id, reason="suppression removed"))
    return await finding_response(db, finding)


@app.get("/findings/{finding_id}/remediation", response_model=RemediationResponse)
async def finding_remediation(finding_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> RemediationResponse:
    """Returns finding + graph context + LLM-generated remediation plan."""
    from pathlib import Path as _Path
    from sentinel_worker.agent import SentinelLLMClient
    from sentinel_worker.graph_query import GraphQuery
    import json as _json

    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    edge_kinds = ["CALLS", "FLOWS_TO", "GUARDED_BY", "CONFIRMED_EXPLOIT"]
    edges = list(
        await db.scalars(
            select(Edge)
            .where(Edge.graph_id == finding.graph_id)
            .where(Edge.kind.in_(edge_kinds))
            .where((Edge.src == finding.node_id) | (Edge.dst == finding.node_id))
        )
    ) if finding.node_id else []
    node_ids = {finding.node_id} if finding.node_id else set()
    for edge in edges:
        node_ids.add(edge.src)
        node_ids.add(edge.dst)
    neighbor_nodes = list(await db.scalars(select(Node).where(Node.graph_id == finding.graph_id).where(Node.id.in_(node_ids)))) if node_ids else []
    graph_query = GraphQuery(db=db, graph_id=finding.graph_id)
    graph_context = await graph_query.serialize_for_prompt(list(node_ids), max_hops=2)

    remediation_plan = [
        finding.remediation,
        "Re-run `sentinel source` after the fix to verify the finding no longer appears.",
        "If runtime confirmation exists, re-run `sentinel pentest <id>` with a patched build.",
    ]

    # Attempt LLM-based remediation when a provider is configured
    account = await db.get(Account, principal.account_id) if hasattr(principal, "account_id") else None
    if account is None:
        graph = await db.get(Graph, finding.graph_id)
        account = await db.get(Account, graph.account_id) if graph else None

    if account and getattr(account, "provider", None) and getattr(account, "api_key", None):
        try:
            llm = SentinelLLMClient(provider=account.provider, model=account.model, api_key=account.api_key or "")
            remediation_prompt_path = _Path(__file__).parent.parent.parent.parent / "worker" / "src" / "sentinel_worker" / "prompts" / "remediation.txt"
            system = remediation_prompt_path.read_text() if remediation_prompt_path.exists() else (
                "You are a security engineer. Produce a concrete remediation plan as a JSON list of steps."
            )
            user_content = _json.dumps({
                "finding": {
                    "vuln_type": finding.vuln_type,
                    "severity": finding.severity,
                    "title": finding.title,
                    "description": finding.description,
                    "remediation": finding.remediation,
                    "evidence": finding.evidence,
                    "node_id": finding.node_id,
                },
                "graph_context": graph_context,
                "neighbors": [{"id": n.id, "kind": n.kind, "name": n.name, "file": n.file, "intent": n.intent} for n in neighbor_nodes],
            }, sort_keys=True)
            result = await llm.call(system=system, user=user_content)
            import json as _j
            try:
                parsed = _j.loads(result.content)
                if isinstance(parsed, list):
                    remediation_plan = [str(s) for s in parsed]
                elif isinstance(parsed, dict):
                    steps = parsed.get("fixes") or parsed.get("steps") or parsed.get("remediation_plan") or []
                    if steps:
                        remediation_plan = [str(s) for s in steps]
            except Exception:
                if result.content.strip():
                    remediation_plan = [result.content.strip()]
        except Exception:
            pass  # fall back to static plan

    return RemediationResponse(
        finding=await finding_response(db, finding),
        graph_context=graph_context,
        remediation_plan=remediation_plan,
    )


@app.post("/pentest", response_model=EnqueueResponse)
async def pentest(payload: PentestRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> EnqueueResponse:
    finding = await _finding_for_principal(db, payload.finding_id, principal) if payload.finding_id else await _select_pentest_target(db, payload.repo_name, principal, payload.description)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    task = await enqueue_task(
        db,
        repo_name=payload.repo_name or "",
        kind="pentest",
        payload={
            "finding_id": finding.id,
            "sanitizer_output": payload.sanitizer_output,
            "behavioral_proof": payload.behavioral_proof,
            "proof_detail": payload.proof_detail,
            "boot": payload.boot,
            "healthcheck": payload.healthcheck,
            "egress_allowlist": payload.egress_allowlist,
        },
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    if run is None:
        raise HTTPException(status_code=500, detail="run record not found after enqueue")
    return EnqueueResponse(task_id=task.id, run=await run_response(db, run))


@app.get("/runs", response_model=list[RunResponse])
async def runs(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[RunResponse]:
    stmt = select(Run).order_by(Run.created_at.desc())
    if not _skip_tenant_filter(principal):
        stmt = stmt.join(Graph, Run.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
    rows = await db.scalars(stmt)
    return [await run_response(db, row) for row in rows]


@app.get("/runs/{run_id}", response_model=RunResponse)
async def run_detail(run_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> RunResponse:
    run = await _run_for_principal(db, run_id, principal)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return await run_response(db, run)


@app.get("/runs/{run_id}/trace")
async def run_trace(run_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> PlainTextResponse:
    run = await _run_for_principal(db, run_id, principal)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    db.add(TraceAccessLog(run_id=run.id, actor_id=principal.user_id))
    return PlainTextResponse(await read_run_trace(db, run), media_type="application/x-ndjson")


@app.get("/runs/{run_id}/trace-access", response_model=list[TraceAccessLogResponse])
async def run_trace_access_log(run_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> list[TraceAccessLogResponse]:
    run = await _run_for_principal(db, run_id, principal)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    rows = await db.scalars(select(TraceAccessLog).where(TraceAccessLog.run_id == run.id).order_by(TraceAccessLog.created_at.desc()))
    return [trace_access_response(row) for row in rows]


@app.get("/runs/{run_id}/events")
async def run_events(run_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> StreamingResponse:
    run = await _run_for_principal(db, run_id, principal)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")

    async def events():
        async for event in stream_run_events(db, run_id):
            yield event

    return StreamingResponse(events(), media_type="text/event-stream")


@app.delete("/runs/{run_id}", response_model=RunResponse)
async def delete_run_cancel(run_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> RunResponse:
    return await _cancel_run_for_principal(db, run_id, principal)


async def _cancel_run_for_principal(db: AsyncSession, run_id: str, principal: Principal) -> RunResponse:
    run = await _run_for_principal(db, run_id, principal)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    try:
        run = await cancel_run_tasks(db, run_id=run_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return await run_response(db, run)


@app.get("/graph", response_model=GraphResponse)
async def graph(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal), limit: int = 250) -> GraphResponse:
    node_stmt = select(Node).limit(limit)
    edge_stmt = select(Edge).limit(limit)
    if not _skip_tenant_filter(principal):
        graph_ids = select(Graph.id).where(Graph.account_id == principal.account_id)
        node_stmt = node_stmt.where(Node.graph_id.in_(graph_ids))
        edge_stmt = edge_stmt.where(Edge.graph_id.in_(graph_ids))
    nodes = list(await db.scalars(node_stmt))
    edges = list(await db.scalars(edge_stmt))
    return GraphResponse(nodes=[node_response(node) for node in nodes], edges=[edge_response(edge) for edge in edges])


@app.get("/source-files/{repo_name}/{commit_hash}/{file_path:path}", response_model=SourceReadResponse)
async def read_source_file(repo_name: str, commit_hash: str, file_path: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> SourceReadResponse:
    if not COMMIT_HASH_RE.match(commit_hash) and commit_hash != "bootstrap":
        raise HTTPException(status_code=400, detail="invalid commit hash")
    normalized = os.path.normpath(file_path)
    if normalized.startswith("..") or normalized.startswith("/"):
        raise HTTPException(status_code=400, detail="invalid file path")
    stmt = select(Repo).where(Repo.name == repo_name)
    if not _skip_tenant_filter(principal):
        stmt = stmt.where(Repo.account_id == principal.account_id)
    repo = await db.scalar(stmt)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo not found")
    try:
        content = await read_source_snapshot(db, repo_id=repo.id, commit_hash=commit_hash, file_path=normalized)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="source file not found") from exc
    return SourceReadResponse(repo_name=repo.name, commit_hash=commit_hash, file_path=normalized, content=content)


@app.post("/admin/graphs/merge")
async def merge_graph_endpoint(payload: GraphMergeRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> dict[str, int | str]:
    branch = await db.get(Graph, payload.branch_graph_id)
    main = await db.get(Graph, payload.main_graph_id)
    if branch is None or main is None:
        raise HTTPException(status_code=404, detail="branch or main graph not found")
    if not _skip_tenant_filter(principal) and (branch.account_id != principal.account_id or main.account_id != principal.account_id):
        raise HTTPException(status_code=403, detail="cannot merge graphs from another account")
    copied = await merge_graph(db, branch_graph_id=payload.branch_graph_id, main_graph_id=payload.main_graph_id)
    return {"branch_graph_id": payload.branch_graph_id, "main_graph_id": payload.main_graph_id, "copied": copied}


@app.get("/analytics/token-spend")
async def token_spend(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[dict[str, int | str]]:
    spend_stmt = (
        select(
            TokenSpendByComponent.component,
            func.sum(TokenSpendByComponent.input_tokens),
            func.sum(TokenSpendByComponent.output_tokens),
        )
        .join(Run, TokenSpendByComponent.run_id == Run.id)
        .group_by(TokenSpendByComponent.component)
    )
    if not _skip_tenant_filter(principal):
        spend_stmt = spend_stmt.join(Graph, Run.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
    rows = await db.execute(spend_stmt)
    result = [
        {
            "component": component,
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "est_cost_usd": 0,
        }
        for component, input_tokens, output_tokens in rows
    ]
    if result:
        return result
    total_stmt = select(func.sum(Run.token_spend))
    if not _skip_tenant_filter(principal):
        total_stmt = total_stmt.join(Graph, Run.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
    total = await db.scalar(total_stmt) or 0
    return [{"component": "total", "input_tokens": int(total), "output_tokens": 0, "est_cost_usd": 0}]


@app.get("/analytics/finding-trends")
async def finding_trends(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[dict[str, int | str]]:
    stmt = (
        select(
            func.date(Finding.created_at),
            Finding.severity,
            func.count(Finding.id),
        )
        .group_by(func.date(Finding.created_at), Finding.severity)
        .order_by(func.date(Finding.created_at))
    )
    if not _skip_tenant_filter(principal):
        stmt = stmt.join(Graph, Finding.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
    rows = await db.execute(stmt)
    return [{"date": str(day), "severity": severity, "count": int(count)} for day, severity, count in rows]


@app.get("/analytics/scan-latency")
async def scan_latency(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[dict[str, float | str]]:
    stmt = select(Run).where(Run.completed_at.is_not(None))
    if not _skip_tenant_filter(principal):
        stmt = stmt.join(Graph, Run.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
    rows = await db.scalars(stmt)
    buckets: dict[str, list[float]] = {}
    for run in rows:
        if run.completed_at is None:
            continue
        buckets.setdefault(run.kind, []).append(max(0.0, (run.completed_at - run.created_at).total_seconds()))
    return [
        {
            "kind": kind,
            "p50_seconds": _percentile(values, 0.50),
            "p90_seconds": _percentile(values, 0.90),
            "count": len(values),
        }
        for kind, values in sorted(buckets.items())
    ]


@app.get("/analytics/false-positive-rate")
async def false_positive_rate(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> dict[str, float | int]:
    total_stmt = select(func.count(Finding.id))
    suppressed_stmt = select(func.count(Finding.id)).where(Finding.suppressed.is_(True))
    if not _skip_tenant_filter(principal):
        total_stmt = total_stmt.join(Graph, Finding.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
        suppressed_stmt = suppressed_stmt.join(Graph, Finding.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
    total = await db.scalar(total_stmt) or 0
    suppressed = await db.scalar(suppressed_stmt) or 0
    return {"total": int(total), "suppressed": int(suppressed), "rate": (float(suppressed) / float(total)) if total else 0.0}


@app.get("/analytics/confirmation-rate")
async def confirmation_rate(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> dict[str, float | int]:
    total_stmt = select(func.count(Finding.id))
    confirmed_stmt = select(func.count(Finding.id)).where(Finding.confirmed.is_(True))
    if not _skip_tenant_filter(principal):
        total_stmt = total_stmt.join(Graph, Finding.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
        confirmed_stmt = confirmed_stmt.join(Graph, Finding.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
    total = await db.scalar(total_stmt) or 0
    confirmed = await db.scalar(confirmed_stmt) or 0
    return {"total": int(total), "confirmed": int(confirmed), "rate": (float(confirmed) / float(total)) if total else 0.0}


@app.put("/admin/accounts/{account_id}/token-budget")
async def set_token_budget(account_id: str, payload: TokenBudgetRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> dict[str, int | str | None]:
    if not _skip_tenant_filter(principal) and account_id != principal.account_id:
        raise HTTPException(status_code=403, detail="cannot update another account")
    account = await db.get(Account, account_id)
    if account is None:
        account = Account(id=account_id, name=account_id)
        db.add(account)
        await db.flush()
    account.monthly_token_budget = payload.monthly_token_budget
    return {"account_id": account.id, "monthly_token_budget": account.monthly_token_budget}


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percentile)))
    return ordered[index]


async def _check_token_budget(db: AsyncSession, principal: Principal) -> None:
    account_id = _graph_account_id(principal)
    if account_id is None:
        return
    account = await db.get(Account, account_id)
    if account is None or account.monthly_token_budget is None:
        return
    start = datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    spent = await db.scalar(
        select(func.sum(Run.token_spend))
        .join(Graph, Run.graph_id == Graph.id)
        .where(Graph.account_id == account_id)
        .where(Run.created_at >= start)
    ) or 0
    if int(spent) >= account.monthly_token_budget:
        raise HTTPException(
            status_code=429,
            detail={
                "error": "monthly_token_budget_exceeded",
                "spent": int(spent),
                "budget": account.monthly_token_budget,
            },
        )


async def _select_pentest_target(db: AsyncSession, repo_name: str, principal: Principal, description: str | None = None) -> Finding | None:
    stmt = (
        select(Finding)
        .join(Graph, Finding.graph_id == Graph.id)
        .join(Repo, Graph.repo_id == Repo.id)
        .where(Repo.name == repo_name)
        .where(Finding.status == "open")
    )
    if not _skip_tenant_filter(principal):
        stmt = stmt.where(Graph.account_id == principal.account_id)
    findings = list(await db.scalars(stmt))
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    target_terms = _pentest_target_terms(description)
    if target_terms:
        findings = [finding for finding in findings if _pentest_target_score(finding, target_terms) > 0]
        findings.sort(key=lambda finding: (-_pentest_target_score(finding, target_terms), severity_rank.get(finding.severity, 5), finding.created_at))
    else:
        findings.sort(key=lambda finding: (severity_rank.get(finding.severity, 5), finding.created_at))
    return findings[0] if findings else None


def _pentest_target_terms(description: str | None) -> list[str]:
    if not description:
        return []
    return [term for term in "".join(char.lower() if char.isalnum() else " " for char in description).split() if len(term) > 2]


def _pentest_target_score(finding: Finding, terms: list[str]) -> int:
    haystack = " ".join(
        [
            finding.id,
            finding.vuln_type,
            finding.severity,
            finding.title,
            finding.description,
            finding.remediation,
            finding.evidence or "",
        ]
    ).lower()
    return sum(1 for term in terms if term in haystack)


async def _finding_for_principal(db: AsyncSession, finding_id: str | None, principal: Principal) -> Finding | None:
    if finding_id is None:
        return None
    stmt = select(Finding).where(Finding.id == finding_id)
    if not _skip_tenant_filter(principal):
        stmt = stmt.join(Graph, Finding.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
    return await db.scalar(stmt)


async def _run_for_principal(db: AsyncSession, run_id: str, principal: Principal) -> Run | None:
    stmt = select(Run).where(Run.id == run_id)
    if not _skip_tenant_filter(principal):
        stmt = stmt.join(Graph, Run.graph_id == Graph.id).where(Graph.account_id == principal.account_id)
    return await db.scalar(stmt)



def node_response(node: Node) -> NodeResponse:
    return NodeResponse(
        id=node.id,
        kind=node.kind,
        name=node.name,
        file=node.file,
        line_start=node.line_start,
        line_end=node.line_end,
        language=node.language,
        auth_required=node.auth_required,
        is_entry_point=node.is_entry_point,
        is_sink=node.is_sink,
        label=node.label,
        intent=node.intent,
    )


def edge_response(edge: Edge) -> EdgeResponse:
    return EdgeResponse(
        id=edge.id,
        src=edge.src,
        dst=edge.dst,
        kind=edge.kind,
        tainted=edge.tainted,
        sanitized=edge.sanitized,
        taint_uncertain=edge.taint_uncertain,
        call_uncertainty=edge.call_uncertainty,
    )


async def _dev_actor(db: AsyncSession) -> User:
    # Prefer the first existing user/account rather than always creating a new dev one.
    # This ensures auto-approve reuses the real account (with its provider/api_key config).
    existing_user = await db.scalar(select(User).order_by(User.created_at).limit(1))
    if existing_user is not None:
        return existing_user
    # No users yet — create the dev account on first boot.
    account = await db.scalar(select(Account).where(Account.name == "dev"))
    if account is None:
        account = Account(name="dev", provider="anthropic", model="claude-sonnet-4-6")
        db.add(account)
        await db.flush()
    user = await db.scalar(select(User).where(User.email == "dev@sentinel.local"))
    if user is None:
        user = User(account_id=account.id, email="dev@sentinel.local", role="admin")
        db.add(user)
        await db.flush()
    return user


async def _actor_from_principal(db: AsyncSession, principal: Principal) -> User:
    if principal.user_id == "dev":
        return await _dev_actor(db)
    account = await db.get(Account, principal.account_id)
    if account is None:
        account = Account(id=principal.account_id, name=principal.account_id)
        db.add(account)
        await db.flush()
    user = await db.get(User, principal.user_id)
    if user is None:
        user = User(id=principal.user_id, account_id=account.id, email=f"{principal.user_id}@sentinel.local", role=principal.role)
        db.add(user)
        await db.flush()
    return user


async def _suppression_approval_required(db: AsyncSession, account_id: str) -> bool:
    account = await db.get(Account, account_id)
    return True if account is None else account.suppression_approval_required


def _user_code() -> str:
    token = secrets.token_hex(4).upper()
    return f"{token[:4]}-{token[4:]}"


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _graph_account_id(principal: Principal) -> str | None:
    return None if _skip_tenant_filter(principal) else principal.account_id

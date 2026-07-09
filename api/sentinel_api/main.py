from __future__ import annotations

import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Literal

import structlog
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware

from sentinel_worker.models import Account, DeviceAuthSession, Edge, Finding, Graph, Node, Repo, Run, SuppressionAudit, Task, TokenSpendByComponent, TraceAccessLog, User, now
from sentinel_worker.graph_merge import gc_sessions, merge_graph, promote_session_to_branch
from sentinel_worker.graph_query import LayeredGraphQuery
from sentinel_worker.payload_guard import SourcePayloadError, assert_no_source_markers
from sentinel_worker.scan import get_or_create_graph, trace_event
from sentinel_worker.security import compute_fingerprint
from sentinel_worker.task_queue import cancel_run_tasks, cancel_task, claim_next_task, complete_task, enqueue_task, fail_task
from sentinel_worker.trace_store import read_run_trace

from .auth import Principal, create_token, current_principal, require_admin
from .deps import get_db, init_schema
from .routers.auth import router as auth_router
from .routers.repos import router as repos_router
from .security import client_ip as _client_ip
from .sessions import CLI_ACCESS_MINUTES, CLI_REFRESH_MINUTES, issue_session
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
    GraphMetaResponse,
    MergeBranchRequest,
    SessionGcRequest,
    SessionPromoteRequest,
    GraphSubgraphResponse,
    GraphUpsertRequest,
    GraphUpsertResponse,
    IngestRequest,
    IngestResponse,
    NodeResponse,
    PentestConfirmRequest,
    PentestRequest,
    RemediationResponse,
    RunResponse,
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
app.include_router(auth_router)

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


async def _node_for_graph(db: AsyncSession, node_id: str | None, graph_id: str) -> Node | None:
    """Node lookup scoped to graph_id — nodes.id is a global PK, not composite
    with graph_id, so an unscoped db.get(Node, id) can return another
    tenant's node if two graphs ever produce the same deterministic id
    (e.g. two repos both have fn:app.js:handler). Always go through this."""
    if node_id is None:
        return None
    return await db.scalar(select(Node).where(Node.id == node_id).where(Node.graph_id == graph_id))


async def finding_response(db: AsyncSession, finding: Finding) -> FindingResponse:
    node = await _node_for_graph(db, finding.node_id, finding.graph_id)
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


@app.post("/webhook/github")
async def github_webhook(request: Request) -> dict[str, bool]:
    """Verifies GitHub App webhook signatures and acknowledges delivery.

    This endpoint no longer runs SAST in the cloud: the legacy path fetched the PR
    diff and enqueued a `kind=source` task, storing the customer's diff in
    `tasks.payload` and source snapshots in the cloud DB. That violates the SAST
    privacy invariant (§1: source/diffs never leave the CLI machine on the scan
    path). PR SAST + ingest now runs in CI via `action.yml` / `standalone.py`,
    which scans locally in the runner and posts back only graph deltas + findings.

    The signature check is kept so a misconfigured App install fails loudly rather
    than silently, and so we can reintroduce CI-notification behaviour later (§7).
    """
    from sentinel_worker.github_app import (
        GitHubAppNotConfiguredError,
        verify_webhook_signature,
        webhook_secret,
    )

    body = await request.body()
    try:
        secret = webhook_secret()
    except GitHubAppNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not verify_webhook_signature(secret, request.headers.get("x-hub-signature-256"), body):
        raise HTTPException(status_code=401, detail="invalid webhook signature")

    # Deliberately no diff fetch and no scan enqueue — see docstring above.
    return {"ok": True}


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
    dashboard_url = os.getenv("SENTINEL_DASHBOARD_URL", "").rstrip("/")
    verification_url = f"{dashboard_url}/device?user_code={user_code}" if dashboard_url else "/auth/device/verify"
    return DeviceStartResponse(
        device_code=device_code,
        user_code=user_code,
        verification_url=verification_url,
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
        "Set SENTINEL_DASHBOARD_URL so device logins point at the dashboard's /device page. "
        "Without it: POST /auth/device/approve with {\"user_code\": \"XXXX-XXXX\"} and a valid admin Bearer token.",
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
async def device_auth_token(device_code: str, request: Request, db: AsyncSession = Depends(get_db)) -> DeviceTokenResponse:
    session = await db.get(DeviceAuthSession, device_code)
    if session is None:
        raise HTTPException(status_code=404, detail="device code not found")
    if _as_utc(session.expires_at) < datetime.now(UTC):
        session.status = "expired"
        raise HTTPException(status_code=410, detail="device code expired")
    if session.status != "approved" and _is_dev_mode():
        # Local self-host dev mode auto-approves so `docker compose up -d`
        # requires no login — it reuses the single dev account so config and
        # findings persist across restarts without re-login.
        dev_user = await _dev_actor(db)
        session.account_id = dev_user.account_id
        session.user_id = dev_user.id
        session.status = "approved"
        session.role = "admin"
        session.approved_at = now()
    # In cloud mode this session only becomes "approved" via a real logged-in
    # user hitting /auth/device/approve from the dashboard — see approve_device_auth.
    if session.status != "approved" or not session.account_id or not session.user_id:
        raise HTTPException(status_code=202, detail="authorization pending")
    user = await db.get(User, session.user_id)
    if user is None:
        # Dev-mode pseudo-user path with no DB row (shouldn't normally happen).
        token = create_token(session.user_id, session.account_id, session.role or "admin", expires_minutes=CLI_ACCESS_MINUTES)
        return DeviceTokenResponse(access_token=token, account_id=session.account_id, user_id=session.user_id, database_url=os.getenv("SENTINEL_WORKER_DATABASE_URL"))
    issued = await issue_session(
        db,
        user,
        label="cli",
        session_minutes=CLI_REFRESH_MINUTES,
        access_minutes=CLI_ACCESS_MINUTES,
        with_refresh=True,
        user_agent=request.headers.get("user-agent"),
        ip_address=_client_ip(request),
    )
    return DeviceTokenResponse(
        access_token=issued.access_token,
        refresh_token=issued.refresh_token,
        expires_in=issued.expires_in,
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
    if "api_key" in fields and payload.api_key is not None:
        # LLM API keys are configured and used entirely locally now (see
        # non-code/README.md's local-AI-calls model) — the server never
        # stores one, so it can't accidentally be used for a server-side LLM
        # call. Run `sentinel config set api-key <key>` instead.
        raise HTTPException(
            status_code=400,
            detail="api_key is no longer accepted by the server. LLM API keys are stored and used locally — "
            "run `sentinel config set api-key <key>`.",
        )
    if "provider" in fields and payload.provider is not None:
        account.provider = payload.provider
    if "model" in fields and payload.model is not None:
        account.model = payload.model
    if "api_endpoint" in fields:
        account.api_endpoint = payload.api_endpoint
    if "suppression_approval_required" in fields and payload.suppression_approval_required is not None:
        account.suppression_approval_required = payload.suppression_approval_required
    if "monthly_token_budget" in fields:
        account.monthly_token_budget = payload.monthly_token_budget
    if "source_retention_days" in fields and payload.source_retention_days is not None:
        account.source_retention_days = payload.source_retention_days
    return account_config_response(account)


# NOTE: /init, /source, /source/enqueue, and /plan were removed — they took
# source code / diffs / plan content in the request body, which the
# local-AI-calls model forbids. That work now runs in the local engine
# (worker/sentinel_worker/local_cli.py, invoked by the CLI); only the graph
# delta (POST /graph/upsert) and findings (POST /findings/ingest) come back.
# The "init"/"source"/"plan" task kinds below are dead now that nothing
# enqueues them, but the claim/complete/fail/cancel machinery is still used
# by pentest tasks.


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
    finding_ids: list[str] = []
    for incoming in payload.findings:
        fingerprint = compute_fingerprint(repo.id, incoming.node_id or incoming.file or "unknown", incoming.vuln_type)
        existing = await db.scalar(select(Finding).where(Finding.fingerprint == fingerprint))
        if existing is not None:
            existing.run_id = run.id
            existing.updated_at = now()
            if not existing.suppressed:
                existing.status = "open"
            updated += 1
            finding_ids.append(existing.id)
        else:
            new_finding = Finding(
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
            db.add(new_finding)
            await db.flush()
            created += 1
            finding_ids.append(new_finding.id)

    return IngestResponse(run_id=run.id, created=created, updated=updated, total=created + updated, finding_ids=finding_ids)


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
    node = await _node_for_graph(db, finding.node_id, finding.graph_id)
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


@app.post("/findings/{finding_id}/confirm", response_model=FindingResponse)
async def confirm_pentest_result(
    finding_id: str,
    payload: PentestConfirmRequest,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(require_admin),
) -> FindingResponse:
    """DEPRECATED (AUDIT.md §3 D6): admin-only during migration.

    Confirmation is now written directly by the cloud worker inside
    `run_pentest` (oracle-gated on HTTP/sanitizer proof, AUDIT.md §1 invariant
    5). This public endpoint is retained admin-only as a manual override during
    migration and must not be called by the CLI. It never receives source,
    diffs, or secrets — only outcome + evidence text + node pointers.
    """
    finding = await _finding_for_principal(db, finding_id, principal)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")

    if payload.confirmed:
        finding.confirmed = True
        finding.status = "confirmed"
        finding.evidence = payload.evidence
        if payload.entry_node_id and payload.sink_node_id:
            # Both nodes must legitimately belong to this finding's graph —
            # _node_for_graph refuses to resolve another tenant's node here.
            entry_node = await _node_for_graph(db, payload.entry_node_id, finding.graph_id)
            sink_node = await _node_for_graph(db, payload.sink_node_id, finding.graph_id)
            if entry_node is not None and sink_node is not None:
                db.add(Edge(graph_id=finding.graph_id, src=entry_node.id, dst=sink_node.id, kind="CONFIRMED_EXPLOIT"))
    else:
        finding.status = payload.status
        finding.evidence = payload.evidence
    finding.updated_at = now()
    await db.flush()
    return await finding_response(db, finding)


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
    """Returns the finding, its graph context (pointers/metadata only), and its remediation plan.

    The remediation plan comes from `finding.remediation`, written by the local
    SAST agent when it emitted the finding — this endpoint does not call an
    LLM. A richer, agent-generated plan is available locally via `sentinel
    pull <id>`, which loads this same graph context into the local engine.
    """
    from sentinel_worker.graph_query import GraphQuery

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
    graph_query = GraphQuery(db=db, graph_id=finding.graph_id)
    graph_context = await graph_query.serialize_for_prompt(list(node_ids), max_hops=2)

    remediation_plan = [
        finding.remediation,
        "Re-run `sentinel source` after the fix to verify the finding no longer appears.",
        "If runtime confirmation exists, re-run `sentinel pentest <id>` with a patched build.",
    ]

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


async def _resolve_repo_graph(
    db: AsyncSession,
    principal: Principal,
    repo_name: str,
    graph_kind: str,
    branch_name: str | None,
) -> Graph:
    """Resolve a repo's graph for a *read*. `main` is get-or-created (idempotent
    and always expected); `branch`/`session` are looked up but never created on
    a read path — viewing a nonexistent branch is a 404, not a fresh empty graph."""
    main_graph = await get_or_create_graph(db, repo_name, account_id=_graph_account_id(principal))
    if not _skip_tenant_filter(principal) and main_graph.account_id != principal.account_id:
        raise HTTPException(status_code=403, detail="cannot read graph from another account")
    if graph_kind == "main":
        return main_graph
    stmt = select(Graph).where(Graph.repo_id == main_graph.repo_id).where(Graph.kind == graph_kind)
    if graph_kind == "branch":
        if not branch_name:
            raise HTTPException(status_code=400, detail="branch_name is required for graph_kind='branch'")
        stmt = stmt.where(Graph.branch_name == branch_name).where(Graph.status == "active")
    graph = await db.scalar(stmt)
    if graph is None:
        raise HTTPException(status_code=404, detail=f"no active {graph_kind} graph for that repo")
    return graph


@app.get("/graph", response_model=GraphResponse)
async def graph(
    repo_name: str | None = None,
    graph_kind: Literal["main", "branch", "session"] = "main",
    branch_name: str | None = None,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
    limit: int = 250,
) -> GraphResponse:
    """Return the graph for display.

    With `repo_name`, resolves that repo's graph (main by default, or a named
    branch) and materializes it through the layered session→branch→main
    resolver so the view reflects exactly one version — not a union of every
    graph. Without `repo_name`, returns an account-wide overview of *main*
    graphs only (branch/session overlays are excluded so ephemeral and isolated
    versions no longer bleed into the overview)."""
    if repo_name is not None:
        graph = await _resolve_repo_graph(db, principal, repo_name, graph_kind, branch_name)
        layered = await LayeredGraphQuery.for_graph(db, graph.id)
        nodes = await layered.materialized_nodes(limit)
        visible = {n.id for n in nodes}
        edges = [e for e in await layered.materialized_edges(limit) if e.src in visible and e.dst in visible]
        return GraphResponse(nodes=[node_response(n) for n in nodes], edges=[edge_response(e) for e in edges])

    main_ids = select(Graph.id).where(Graph.kind == "main")
    if not _skip_tenant_filter(principal):
        main_ids = main_ids.where(Graph.account_id == principal.account_id)
    node_stmt = select(Node).where(Node.graph_id.in_(main_ids)).where(Node.deleted.is_(False)).limit(limit)
    nodes = list(await db.scalars(node_stmt))
    visible = {n.id for n in nodes}
    edge_rows = list(await db.scalars(select(Edge).where(Edge.graph_id.in_(main_ids)).limit(limit)))
    edges = [e for e in edge_rows if e.src in visible and e.dst in visible]
    return GraphResponse(nodes=[node_response(node) for node in nodes], edges=[edge_response(edge) for edge in edges])


@app.get("/graphs", response_model=list[GraphMetaResponse])
async def list_graphs(
    repo_name: str,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
    limit: int = 100,
) -> list[GraphMetaResponse]:
    """List the selectable graph versions for a repo: main plus active branch
    graphs (most recent first). Powers the dashboard branch selector."""
    main_graph = await get_or_create_graph(db, repo_name, account_id=_graph_account_id(principal))
    if not _skip_tenant_filter(principal) and main_graph.account_id != principal.account_id:
        raise HTTPException(status_code=403, detail="cannot read graphs from another account")
    rows = list(
        await db.scalars(
            select(Graph)
            .where(Graph.repo_id == main_graph.repo_id)
            .where(Graph.kind.in_(("main", "branch")))
            .where(Graph.status == "active")
            .order_by(Graph.kind.desc(), Graph.created_at.desc())
            .limit(limit)
        )
    )
    return [
        GraphMetaResponse(
            id=g.id,
            kind=g.kind,
            branch_name=g.branch_name,
            status=g.status,
            created_at=g.created_at.isoformat(),
        )
        for g in rows
    ]


@app.get("/graph/subgraph", response_model=GraphSubgraphResponse)
async def graph_subgraph(
    repo_name: str,
    seeds: list[str] = Query(default_factory=list),
    edge_kinds: list[str] | None = Query(default=None),
    max_hops: int = 2,
    graph_kind: Literal["main", "branch", "session"] = "main",
    branch_name: str | None = None,
    session_id: str | None = None,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> GraphSubgraphResponse:
    """Pull a bootstrap subgraph for local context loading.

    This is the cloud side of the local-execution model: the local engine
    sends only seed node ids (extracted from the diff it is scanning locally)
    and gets back nodes/edges. Nodes carry pointers (file/line) and structural
    metadata only — never source text — so this is safe to serve regardless of
    what triggered the request.
    """
    if not seeds:
        raise HTTPException(status_code=400, detail="at least one seed node id is required")
    try:
        graph = await get_or_create_graph(
            db,
            repo_name,
            account_id=_graph_account_id(principal),
            kind=graph_kind,
            branch_name=branch_name,
            session_id=session_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not _skip_tenant_filter(principal) and graph.account_id != principal.account_id:
        raise HTTPException(status_code=403, detail="cannot read graph from another account")

    layered = await LayeredGraphQuery.for_graph(db, graph.id)
    included_nodes: dict[str, Node] = {}
    included_edges: dict[int, Edge] = {}
    for seed_id in seeds:
        seed_node = await _node_for_graph(db, seed_id, graph.id)
        if seed_node is not None:
            included_nodes[seed_node.id] = seed_node
        for neighbor in await layered.neighbors(seed_id, edge_kinds=edge_kinds, max_hops=max_hops):
            included_nodes[neighbor.node.id] = neighbor.node
            included_edges[neighbor.edge.id] = neighbor.edge

    return GraphSubgraphResponse(
        graph_id=graph.id,
        nodes=[node_response(node) for node in included_nodes.values()],
        edges=[edge_response(edge) for edge in included_edges.values()],
    )


@app.post("/graph/upsert", response_model=GraphUpsertResponse)
async def graph_upsert(
    payload: GraphUpsertRequest,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> GraphUpsertResponse:
    """Accept a graph delta (nodes/edges only — pointers and metadata, never
    source) produced by a local scan.

    A node id that already exists in a *different* graph is rejected (409)
    rather than silently adopted or overwritten — see the note on
    `sentinel_worker.scan.get_or_create_graph` and `_node_for_graph`: node ids
    are a single global primary key today (not composite with graph_id), so
    two unrelated repos can legitimately produce the same deterministic id
    (e.g. both have `fn:app.js:handler`). Without this check, an unscoped
    lookup would silently overwrite another tenant's node.
    """
    for node in payload.nodes:
        try:
            assert_no_source_markers(node.label or "", field="node.label")
            assert_no_source_markers(node.intent or "", field="node.intent")
            assert_no_source_markers(node.name, field="node.name")
        except SourcePayloadError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        graph = await get_or_create_graph(
            db,
            payload.repo_name,
            account_id=_graph_account_id(principal),
            kind=payload.graph_kind,
            branch_name=payload.branch_name,
            session_id=payload.session_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not _skip_tenant_filter(principal) and graph.account_id != principal.account_id:
        raise HTTPException(status_code=403, detail="cannot write graph for another account")

    nodes_upserted = 0
    node_fields = (
        "kind", "name", "file", "line_start", "line_end", "language", "trust_level",
        "auth_required", "privilege", "is_entry_point", "is_sink", "taint_uncertain",
        "parse_error", "label", "intent", "commit_hash", "is_new", "deleted",
    )
    for incoming in payload.nodes:
        existing = await _node_for_graph(db, incoming.id, graph.id)
        if existing is not None:
            for field_name in node_fields:
                setattr(existing, field_name, getattr(incoming, field_name))
            existing.updated_at = now()
        else:
            # Nodes now have a composite (graph_id, id) PK, so the same id can
            # legitimately exist in another graph (main vs branch vs session).
            # We scope by graph.id above, so this is a fresh node for THIS graph.
            db.add(Node(graph_id=graph.id, **incoming.model_dump()))
        nodes_upserted += 1

    edges_upserted = 0
    for incoming_edge in payload.edges:
        exists = await db.scalar(
            select(Edge)
            .where(Edge.graph_id == graph.id)
            .where(Edge.src == incoming_edge.src)
            .where(Edge.dst == incoming_edge.dst)
            .where(Edge.kind == incoming_edge.kind)
        )
        if exists is None:
            db.add(Edge(graph_id=graph.id, **incoming_edge.model_dump()))
            edges_upserted += 1

    await db.flush()
    return GraphUpsertResponse(graph_id=graph.id, nodes_upserted=nodes_upserted, edges_upserted=edges_upserted)


# NOTE: GET /source-files/... was removed. It served decrypted source snapshots
# over HTTP, which only made sense for the legacy cloud-SAST path. Under the
# target architecture the CLI reads source locally and the cloud never needs to
# hand source back. The pentest agent's read_file tool reads snapshots directly
# via sentinel_worker.source_store, not through this endpoint.


@app.post("/admin/graphs/merge")
async def merge_graph_endpoint(payload: GraphMergeRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> dict[str, object]:
    branch = await db.get(Graph, payload.branch_graph_id)
    main = await db.get(Graph, payload.main_graph_id)
    if branch is None or main is None:
        raise HTTPException(status_code=404, detail="branch or main graph not found")
    if not _skip_tenant_filter(principal) and (branch.account_id != principal.account_id or main.account_id != principal.account_id):
        raise HTTPException(status_code=403, detail="cannot merge graphs from another account")
    result = await merge_graph(db, branch_graph_id=payload.branch_graph_id, main_graph_id=payload.main_graph_id)
    return {
        "branch_graph_id": payload.branch_graph_id,
        "main_graph_id": payload.main_graph_id,
        "copied": result.copied,
        "conflicts": result.conflicts,
        "findings_repointed": result.findings_repointed,
        "had_base": result.had_base,
    }


@app.post("/graphs/merge-branch")
async def merge_branch_endpoint(
    payload: MergeBranchRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)
) -> dict[str, object]:
    """Merge a branch graph into main, resolved by repo + branch name. This is
    the CD entry point — invoked when a branch lands, so callers don't have to
    know internal graph ids."""
    main_graph = await get_or_create_graph(db, payload.repo_name, account_id=_graph_account_id(principal))
    if not _skip_tenant_filter(principal) and main_graph.account_id != principal.account_id:
        raise HTTPException(status_code=403, detail="cannot merge graphs for another account")
    branch = await db.scalar(
        select(Graph)
        .where(Graph.repo_id == main_graph.repo_id)
        .where(Graph.kind == "branch")
        .where(Graph.branch_name == payload.branch_name)
        .where(Graph.status == "active")
    )
    if branch is None:
        raise HTTPException(status_code=404, detail="no active branch graph for that repo/branch")
    result = await merge_graph(db, branch_graph_id=branch.id, main_graph_id=main_graph.id)
    return {
        "branch_graph_id": branch.id,
        "main_graph_id": main_graph.id,
        "copied": result.copied,
        "conflicts": result.conflicts,
        "findings_repointed": result.findings_repointed,
        "had_base": result.had_base,
    }


@app.post("/graphs/promote-session")
async def promote_session_endpoint(
    payload: SessionPromoteRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)
) -> dict[str, object]:
    """Promote a dev session graph into its branch graph (same diff landed in CI)."""
    main_graph = await get_or_create_graph(db, payload.repo_name, account_id=_graph_account_id(principal))
    if not _skip_tenant_filter(principal) and main_graph.account_id != principal.account_id:
        raise HTTPException(status_code=403, detail="cannot promote graphs for another account")
    branch = await db.scalar(
        select(Graph)
        .where(Graph.repo_id == main_graph.repo_id)
        .where(Graph.kind == "branch")
        .where(Graph.branch_name == payload.branch_name)
        .where(Graph.status == "active")
    )
    if branch is None:
        raise HTTPException(status_code=404, detail="no active branch graph for that repo/branch")
    session_graph = await db.scalar(
        select(Graph)
        .where(Graph.repo_id == main_graph.repo_id)
        .where(Graph.kind == "session")
        .where(Graph.session_id == payload.session_id)
    )
    if session_graph is None:
        raise HTTPException(status_code=404, detail="no session graph with that id")
    result = await promote_session_to_branch(db, session_graph_id=session_graph.id, branch_graph_id=branch.id)
    return {
        "session_graph_id": session_graph.id,
        "branch_graph_id": branch.id,
        "copied": result.copied,
        "findings_repointed": result.findings_repointed,
    }


@app.post("/admin/sessions/gc")
async def gc_sessions_endpoint(
    payload: SessionGcRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)
) -> dict[str, int]:
    """Reclaim session graphs: promoted ones, plus any older than the cutoff."""
    older_than = now() - timedelta(days=payload.older_than_days) if payload.older_than_days is not None else None
    removed = await gc_sessions(
        db,
        account_id=_graph_account_id(principal),
        older_than=older_than,
        include_promoted=payload.include_promoted,
    )
    return {"removed": removed}


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

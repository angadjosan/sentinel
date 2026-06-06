from __future__ import annotations

import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.models import Account, Edge, Finding, Graph, Node, Repo, Run, SuppressionAudit, Task, TokenSpendByComponent, User, now
from sentinel_worker.oracle import ConfirmationOracle
from sentinel_worker.scan import bootstrap_repo, review_plan, scan_diff, trace_event
from sentinel_worker.task_queue import cancel_task, claim_next_task, complete_task, enqueue_task, fail_task

from .auth import Principal, current_principal, require_admin
from .deps import get_db, init_schema
from .schemas import (
    EdgeResponse,
    EnqueueResponse,
    FindingResponse,
    GraphResponse,
    InitRequest,
    NodeResponse,
    PentestRequest,
    PlanRequest,
    RunResponse,
    SourceRequest,
    SourceResponse,
    SuppressRequest,
    TaskCompleteRequest,
    TaskFailRequest,
    TaskResponse,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_schema()
    yield


app = FastAPI(title="Sentinel API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

RUNS_TOTAL = Counter("sentinel_runs_total", "Runs by kind and status", ["kind", "status"])
FINDINGS_TOTAL = Counter("sentinel_findings_total", "Findings by type and severity", ["vuln_type", "severity"])
SCAN_DURATION = Histogram("sentinel_scan_duration_seconds", "Scan duration by kind", ["kind"])
ACTIVE_RUNS = Gauge("sentinel_active_runs", "Currently active runs")


def run_response(run: Run) -> RunResponse:
    return RunResponse(id=run.id, kind=run.kind, status=run.status, token_spend=run.token_spend, model_used=run.model_used, trace=run.trace or "")


def finding_response(finding: Finding) -> FindingResponse:
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


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
async def metrics() -> PlainTextResponse:
    return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)


@app.post("/init", response_model=RunResponse)
async def init_repo(payload: InitRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> RunResponse:
    run = await bootstrap_repo(db, payload.repo_name, payload.files, account_id=_graph_account_id(principal))
    RUNS_TOTAL.labels(kind=run.kind, status=run.status).inc()
    return run_response(run)


@app.post("/source", response_model=SourceResponse)
async def source(payload: SourceRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> SourceResponse:
    ACTIVE_RUNS.inc()
    start = datetime.now(UTC)
    try:
        run = await scan_diff(db, payload.repo_name, payload.diff, run_context=payload.run_context, account_id=_graph_account_id(principal))
        rows = await db.scalars(select(Finding).where(Finding.run_id == run.id))
        findings = list(rows)
        for finding in findings:
            FINDINGS_TOTAL.labels(vuln_type=finding.vuln_type, severity=finding.severity).inc()
        RUNS_TOTAL.labels(kind=run.kind, status=run.status).inc()
        SCAN_DURATION.labels(kind=run.kind).observe((datetime.now(UTC) - start).total_seconds())
        return SourceResponse(run=run_response(run), findings=[finding_response(finding) for finding in findings])
    finally:
        ACTIVE_RUNS.dec()


@app.post("/source/enqueue", response_model=EnqueueResponse)
async def source_enqueue(payload: SourceRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> EnqueueResponse:
    task = await enqueue_task(
        db,
        repo_name=payload.repo_name,
        kind="source",
        payload={"repo_name": payload.repo_name, "diff": payload.diff, "run_context": payload.run_context},
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    assert run is not None
    return EnqueueResponse(task_id=task.id, run=run_response(run))


@app.post("/source/stream")
async def source_stream(payload: SourceRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> StreamingResponse:
    async def events():
        yield f"data: {json.dumps({'kind': 'graph_update', 'message': 'scan started'})}\n\n"
        result = await source(payload, db)
        for finding in result.findings:
            yield f"data: {finding.model_dump_json()}\n\n"
        yield f"data: {json.dumps({'kind': 'complete', 'run_id': result.run.id, 'finding_count': len(result.findings)})}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")


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


@app.post("/plan", response_model=SourceResponse)
async def plan(payload: PlanRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> SourceResponse:
    run, findings = await review_plan(db, payload.repo_name, payload.content, with_retry=payload.with_retry, account_id=_graph_account_id(principal))
    RUNS_TOTAL.labels(kind=run.kind, status=run.status).inc()
    for finding in findings:
        FINDINGS_TOTAL.labels(vuln_type=finding.vuln_type, severity=finding.severity).inc()
    return SourceResponse(run=run_response(run), findings=[finding_response(finding) for finding in findings])


@app.get("/findings", response_model=list[FindingResponse])
async def findings(repo_name: str | None = None, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[FindingResponse]:
    stmt = select(Finding).order_by(Finding.created_at.desc())
    joined_graph = False
    if repo_name:
        stmt = (
            stmt.join(Graph, Finding.graph_id == Graph.id)
            .join(Repo, Graph.repo_id == Repo.id)
            .where(Repo.name == repo_name)
        )
        joined_graph = True
    if principal.account_id != "dev":
        if not joined_graph:
            stmt = stmt.join(Graph, Finding.graph_id == Graph.id)
        stmt = stmt.where(Graph.account_id == principal.account_id)
    rows = await db.scalars(stmt)
    return [finding_response(row) for row in rows]


@app.get("/findings/{finding_id}", response_model=FindingResponse)
async def finding_detail(finding_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> FindingResponse:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return finding_response(finding)


@app.get("/findings/{finding_id}/pull")
async def pull_finding(finding_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> dict[str, object]:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    node = await db.get(Node, finding.node_id) if finding.node_id else None
    return {
        "finding": finding_response(finding).model_dump(),
        "node": node_response(node).model_dump() if node else None,
        "remediation_plan": [
            finding.remediation,
            "Re-run `sentinel source` after the fix to verify the finding no longer appears.",
            "If runtime confirmation exists, re-run `sentinel pentest <id>` with a patched build.",
        ],
    }


@app.patch("/findings/{finding_id}/suppress", response_model=FindingResponse)
async def suppress(finding_id: str, payload: SuppressRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> FindingResponse:
    finding = await db.get(Finding, finding_id)
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
    return finding_response(finding)


@app.post("/findings/{finding_id}/unsuppress", response_model=FindingResponse)
async def unsuppress(finding_id: str, payload: SuppressRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> FindingResponse:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    actor = await _actor_from_principal(db, principal)
    finding.status = "open"
    finding.suppressed = False
    finding.suppression_reason = None
    db.add(SuppressionAudit(finding_id=finding.id, action="unsuppress", actor_id=actor.id, reason=payload.reason))
    return finding_response(finding)


@app.post("/findings/{finding_id}/suppress/approve", response_model=FindingResponse)
async def approve_suppression(finding_id: str, payload: SuppressRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> FindingResponse:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    actor = await _actor_from_principal(db, principal)
    finding.status = "suppressed"
    finding.suppressed = True
    finding.suppressed_at = now()
    db.add(SuppressionAudit(finding_id=finding.id, action="approve", actor_id=actor.id, reason=payload.reason))
    return finding_response(finding)


@app.post("/findings/{finding_id}/suppress/reject", response_model=FindingResponse)
async def reject_suppression(finding_id: str, payload: SuppressRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> FindingResponse:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    actor = await _actor_from_principal(db, principal)
    finding.status = "open"
    finding.suppressed = False
    db.add(SuppressionAudit(finding_id=finding.id, action="reject", actor_id=actor.id, reason=payload.reason))
    return finding_response(finding)


@app.post("/pentest", response_model=FindingResponse)
async def pentest(payload: PentestRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> FindingResponse:
    if not payload.finding_id:
        raise HTTPException(status_code=422, detail="finding_id is required for deterministic local pentest")
    finding = await db.get(Finding, payload.finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    oracle_result = ConfirmationOracle().evaluate(payload.sanitizer_output, payload.behavioral_proof, payload.proof_detail)
    run = Run(graph_id=finding.graph_id, kind="pentest", status="completed", completed_at=now())
    run.trace = trace_event("pentest.oracle.evaluated", confirmed=oracle_result.confirmed, kind=oracle_result.kind)
    db.add(run)
    if oracle_result.confirmed:
        finding.confirmed = True
        finding.status = "confirmed"
        finding.evidence = oracle_result.evidence
    else:
        finding.status = "not_reproducible"
    RUNS_TOTAL.labels(kind=run.kind, status=run.status).inc()
    return finding_response(finding)


@app.get("/runs", response_model=list[RunResponse])
async def runs(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[RunResponse]:
    rows = await db.scalars(select(Run).order_by(Run.created_at.desc()))
    return [run_response(row) for row in rows]


@app.get("/runs/{run_id}", response_model=RunResponse)
async def run_detail(run_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> RunResponse:
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return run_response(run)


@app.get("/runs/{run_id}/trace")
async def run_trace(run_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(require_admin)) -> PlainTextResponse:
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return PlainTextResponse(run.trace or "")


@app.post("/runs/{run_id}/cancel", response_model=RunResponse)
async def cancel_run(run_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> RunResponse:
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    if run.status == "running":
        run.status = "cancelled"
        run.completed_at = now()
        run.trace = "\n".join([run.trace or "", trace_event("run.cancelled")]).strip()
    return run_response(run)


@app.get("/graph", response_model=GraphResponse)
async def graph(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal), limit: int = 250) -> GraphResponse:
    nodes = list(await db.scalars(select(Node).limit(limit)))
    edges = list(await db.scalars(select(Edge).limit(limit)))
    return GraphResponse(nodes=[node_response(node) for node in nodes], edges=[edge_response(edge) for edge in edges])


@app.get("/analytics/token-spend")
async def token_spend(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[dict[str, int | str]]:
    rows = await db.execute(
        select(
            TokenSpendByComponent.component,
            func.sum(TokenSpendByComponent.input_tokens),
            func.sum(TokenSpendByComponent.output_tokens),
        ).group_by(TokenSpendByComponent.component)
    )
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
    total = await db.scalar(select(func.sum(Run.token_spend))) or 0
    return [{"component": "total", "input_tokens": int(total), "output_tokens": 0, "est_cost_usd": 0}]


@app.get("/analytics/finding-trends")
async def finding_trends(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[dict[str, int | str]]:
    rows = await db.execute(
        select(
            func.date(Finding.created_at),
            Finding.severity,
            func.count(Finding.id),
        )
        .group_by(func.date(Finding.created_at), Finding.severity)
        .order_by(func.date(Finding.created_at))
    )
    return [{"date": str(day), "severity": severity, "count": int(count)} for day, severity, count in rows]


@app.get("/analytics/scan-latency")
async def scan_latency(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[dict[str, float | str]]:
    rows = await db.scalars(select(Run).where(Run.completed_at.is_not(None)))
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
    total = await db.scalar(select(func.count(Finding.id))) or 0
    suppressed = await db.scalar(select(func.count(Finding.id)).where(Finding.suppressed.is_(True))) or 0
    return {"total": int(total), "suppressed": int(suppressed), "rate": (float(suppressed) / float(total)) if total else 0.0}


@app.get("/analytics/confirmation-rate")
async def confirmation_rate(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> dict[str, float | int]:
    total = await db.scalar(select(func.count(Finding.id))) or 0
    confirmed = await db.scalar(select(func.count(Finding.id)).where(Finding.confirmed.is_(True))) or 0
    return {"total": int(total), "confirmed": int(confirmed), "rate": (float(confirmed) / float(total)) if total else 0.0}


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percentile)))
    return ordered[index]


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
    account = await db.scalar(select(Account).where(Account.name == "dev"))
    if account is None:
        account = Account(name="dev")
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


def _graph_account_id(principal: Principal) -> str | None:
    return None if principal.account_id == "dev" else principal.account_id

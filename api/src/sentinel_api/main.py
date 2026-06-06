from __future__ import annotations

import json
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.models import Finding, Run, SuppressionAudit, User, now
from sentinel_worker.oracle import ConfirmationOracle
from sentinel_worker.scan import bootstrap_repo, scan_diff, trace_event

from .deps import get_db, init_schema
from .schemas import FindingResponse, InitRequest, PentestRequest, RunResponse, SourceRequest, SourceResponse, SuppressRequest

app = FastAPI(title="Sentinel API", version="0.1.0")
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


@app.on_event("startup")
async def startup() -> None:
    await init_schema()


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


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/metrics")
async def metrics() -> PlainTextResponse:
    return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)


@app.post("/init", response_model=RunResponse)
async def init_repo(payload: InitRequest, db: AsyncSession = Depends(get_db)) -> RunResponse:
    run = await bootstrap_repo(db, payload.repo_name, payload.files)
    RUNS_TOTAL.labels(kind=run.kind, status=run.status).inc()
    return run_response(run)


@app.post("/source", response_model=SourceResponse)
async def source(payload: SourceRequest, db: AsyncSession = Depends(get_db)) -> SourceResponse:
    ACTIVE_RUNS.inc()
    start = datetime.now(UTC)
    try:
        run = await scan_diff(db, payload.repo_name, payload.diff, run_context=payload.run_context)
        rows = await db.scalars(select(Finding).where(Finding.run_id == run.id))
        findings = list(rows)
        for finding in findings:
            FINDINGS_TOTAL.labels(vuln_type=finding.vuln_type, severity=finding.severity).inc()
        RUNS_TOTAL.labels(kind=run.kind, status=run.status).inc()
        SCAN_DURATION.labels(kind=run.kind).observe((datetime.now(UTC) - start).total_seconds())
        return SourceResponse(run=run_response(run), findings=[finding_response(finding) for finding in findings])
    finally:
        ACTIVE_RUNS.dec()


@app.post("/source/stream")
async def source_stream(payload: SourceRequest, db: AsyncSession = Depends(get_db)) -> StreamingResponse:
    async def events():
        yield f"data: {json.dumps({'kind': 'graph_update', 'message': 'scan started'})}\n\n"
        result = await source(payload, db)
        for finding in result.findings:
            yield f"data: {finding.model_dump_json()}\n\n"
        yield f"data: {json.dumps({'kind': 'complete', 'run_id': result.run.id, 'finding_count': len(result.findings)})}\n\n"

    return StreamingResponse(events(), media_type="text/event-stream")


@app.get("/findings", response_model=list[FindingResponse])
async def findings(db: AsyncSession = Depends(get_db)) -> list[FindingResponse]:
    rows = await db.scalars(select(Finding).order_by(Finding.created_at.desc()))
    return [finding_response(row) for row in rows]


@app.patch("/findings/{finding_id}/suppress", response_model=FindingResponse)
async def suppress(finding_id: str, payload: SuppressRequest, db: AsyncSession = Depends(get_db)) -> FindingResponse:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    actor = await _dev_actor(db)
    finding.status = "suppressed"
    finding.suppressed = True
    finding.suppressed_by = actor.id
    finding.suppressed_at = now()
    finding.suppression_reason = payload.reason
    db.add(SuppressionAudit(finding_id=finding.id, action="suppress", actor_id=actor.id, reason=payload.reason))
    return finding_response(finding)


@app.post("/findings/{finding_id}/unsuppress", response_model=FindingResponse)
async def unsuppress(finding_id: str, payload: SuppressRequest, db: AsyncSession = Depends(get_db)) -> FindingResponse:
    finding = await db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    actor = await _dev_actor(db)
    finding.status = "open"
    finding.suppressed = False
    finding.suppression_reason = None
    db.add(SuppressionAudit(finding_id=finding.id, action="unsuppress", actor_id=actor.id, reason=payload.reason))
    return finding_response(finding)


@app.post("/pentest", response_model=FindingResponse)
async def pentest(payload: PentestRequest, db: AsyncSession = Depends(get_db)) -> FindingResponse:
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
async def runs(db: AsyncSession = Depends(get_db)) -> list[RunResponse]:
    rows = await db.scalars(select(Run).order_by(Run.created_at.desc()))
    return [run_response(row) for row in rows]


@app.get("/runs/{run_id}", response_model=RunResponse)
async def run_detail(run_id: str, db: AsyncSession = Depends(get_db)) -> RunResponse:
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return run_response(run)


@app.get("/runs/{run_id}/trace")
async def run_trace(run_id: str, db: AsyncSession = Depends(get_db)) -> PlainTextResponse:
    run = await db.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="run not found")
    return PlainTextResponse(run.trace or "")


@app.get("/analytics/token-spend")
async def token_spend(db: AsyncSession = Depends(get_db)) -> list[dict[str, int | str]]:
    total = await db.scalar(select(func.sum(Run.token_spend))) or 0
    return [{"component": "total", "input_tokens": int(total), "output_tokens": 0, "est_cost_usd": 0}]


async def _dev_actor(db: AsyncSession) -> User:
    from sentinel_worker.models import Account

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

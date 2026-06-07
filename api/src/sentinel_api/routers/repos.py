from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.models import Graph, Repo, Run
from sentinel_worker.scan import bootstrap_repo, review_plan, scan_diff
from sentinel_worker.task_queue import enqueue_task

from ..auth import Principal, current_principal
from ..deps import get_db
from ..schemas import (
    EnqueueResponse,
    InitRequest,
    PlanRequest,
    PentestRequest,
    RepoCreateRequest,
    RepoResponse,
    RunResponse,
    SourceRequest,
    SourceResponse,
)

router = APIRouter(prefix="/repos", tags=["repos"])


async def _run_response_simple(db: AsyncSession, run: Run) -> RunResponse:
    """Minimal run response used inside this router — avoids circular imports."""
    from sqlalchemy import func
    from sentinel_worker.models import Finding

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


def _graph_account_id(principal: Principal) -> str | None:
    return None if principal.account_id == "dev" else principal.account_id


async def _get_repo(db: AsyncSession, repo_id: str, principal: Principal) -> Repo:
    stmt = select(Repo).where(Repo.id == repo_id)
    if principal.account_id != "dev":
        stmt = stmt.where(Repo.account_id == principal.account_id)
    repo = await db.scalar(stmt)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo not found")
    return repo


@router.post("", response_model=RepoResponse, status_code=201)
async def create_repo(
    payload: RepoCreateRequest,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> RepoResponse:
    account_id = _graph_account_id(principal) or "dev"
    repo = Repo(name=payload.name, account_id=account_id, remote_url=payload.remote_url)
    db.add(repo)
    await db.flush()
    return RepoResponse(
        id=repo.id,
        name=repo.name,
        account_id=repo.account_id,
        remote_url=repo.remote_url,
        created_at=repo.created_at.isoformat(),
    )


@router.post("/{repo_id}/init", response_model=EnqueueResponse)
async def init_repo(
    repo_id: str,
    payload: InitRequest,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> EnqueueResponse:
    repo = await _get_repo(db, repo_id, principal)
    task = await enqueue_task(
        db,
        repo_name=repo.name,
        kind="init",
        payload={"repo_name": repo.name, "files": payload.files},
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    assert run is not None
    return EnqueueResponse(task_id=task.id, run=await _run_response_simple(db, run))


@router.post("/{repo_id}/source", response_model=EnqueueResponse)
async def source_scan(
    repo_id: str,
    payload: SourceRequest,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> EnqueueResponse:
    repo = await _get_repo(db, repo_id, principal)
    task = await enqueue_task(
        db,
        repo_name=repo.name,
        kind="source",
        payload={"repo_name": repo.name, "diff": payload.diff, "run_context": payload.run_context, "base_ref": payload.base_ref, "paths": payload.paths},
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    assert run is not None
    return EnqueueResponse(task_id=task.id, run=await _run_response_simple(db, run))


@router.post("/{repo_id}/scan", response_model=EnqueueResponse)
async def scan_wrapper(
    repo_id: str,
    payload: SourceRequest,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> EnqueueResponse:
    """Wrapper endpoint: enqueues a source scan; worker will start pentest runs for each finding unless no_pentest=true."""
    repo = await _get_repo(db, repo_id, principal)
    task = await enqueue_task(
        db,
        repo_name=repo.name,
        kind="scan",
        payload={"repo_name": repo.name, "diff": payload.diff, "run_context": payload.run_context, "base_ref": payload.base_ref, "paths": payload.paths},
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    assert run is not None
    return EnqueueResponse(task_id=task.id, run=await _run_response_simple(db, run))


@router.post("/{repo_id}/pentest", response_model=EnqueueResponse)
async def pentest_scan(
    repo_id: str,
    payload: PentestRequest,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> EnqueueResponse:
    repo = await _get_repo(db, repo_id, principal)
    task = await enqueue_task(
        db,
        repo_name=repo.name,
        kind="pentest",
        payload={"repo_name": repo.name, "finding_id": payload.finding_id, "description": payload.description},
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    assert run is not None
    return EnqueueResponse(task_id=task.id, run=await _run_response_simple(db, run))


@router.post("/{repo_id}/plan", response_model=EnqueueResponse)
async def plan_review(
    repo_id: str,
    payload: PlanRequest,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> EnqueueResponse:
    repo = await _get_repo(db, repo_id, principal)
    task = await enqueue_task(
        db,
        repo_name=repo.name,
        kind="plan",
        payload={"repo_name": repo.name, "content": payload.content, "with_retry": payload.with_retry},
        account_id=_graph_account_id(principal),
    )
    run = await db.get(Run, task.run_id)
    assert run is not None
    return EnqueueResponse(task_id=task.id, run=await _run_response_simple(db, run))

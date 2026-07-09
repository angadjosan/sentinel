from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.models import Repo, Run
from sentinel_worker.task_queue import enqueue_task

from ..auth import Principal, current_principal
from ..deps import get_db
from ..schemas import (
    EnqueueResponse,
    PentestRequest,
    RepoCreateRequest,
    RepoResponse,
    RunResponse,
)

router = APIRouter(prefix="/repos", tags=["repos"])


def _is_dev_mode() -> bool:
    return os.getenv("SENTINEL_DEV_MODE", "0") == "1"


def _skip_tenant_filter(principal: Principal) -> bool:
    """Bypass tenant scoping only when in dev mode AND using the dev principal."""
    return _is_dev_mode() and principal.account_id == "dev"


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
    return None if _skip_tenant_filter(principal) else principal.account_id


async def _get_repo(db: AsyncSession, repo_id: str, principal: Principal) -> Repo:
    stmt = select(Repo).where(Repo.id == repo_id)
    if not _skip_tenant_filter(principal):
        stmt = stmt.where(Repo.account_id == principal.account_id)
    repo = await db.scalar(stmt)
    if repo is None:
        raise HTTPException(status_code=404, detail="repo not found")
    return repo


@router.get("", response_model=list[RepoResponse])
async def list_repos(
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> list[RepoResponse]:
    stmt = select(Repo).order_by(Repo.created_at.desc())
    if not _skip_tenant_filter(principal):
        stmt = stmt.where(Repo.account_id == principal.account_id)
    rows = await db.scalars(stmt)
    return [
        RepoResponse(
            id=repo.id,
            name=repo.name,
            account_id=repo.account_id,
            remote_url=repo.remote_url,
            created_at=repo.created_at.isoformat(),
        )
        for repo in rows
    ]


@router.post("", response_model=RepoResponse, status_code=201)
async def create_repo(
    payload: RepoCreateRequest,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> RepoResponse:
    from sentinel_worker.models import Account
    account_id = _graph_account_id(principal)
    if account_id is None:
        account = await db.scalar(select(Account).where(Account.name == "dev"))
        if account is None:
            account = Account(name="dev")
            db.add(account)
            await db.flush()
        account_id = account.id
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


# NOTE: /{repo_id}/init, /source, and /scan were removed — they took source
# code / diffs in the request body, which the local-AI-calls model forbids.
# See main.py's equivalent note next to /tasks/claim.


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
    if run is None:
        raise HTTPException(status_code=500, detail="run record not found after enqueue")
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
    if run is None:
        raise HTTPException(status_code=500, detail="run record not found after enqueue")
    return EnqueueResponse(task_id=task.id, run=await _run_response_simple(db, run))

from __future__ import annotations

import json
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
    RepoPentestConfigPatch,
    RepoPentestConfigResponse,
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


def _decode_egress_allowlist(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(host) for host in value] if isinstance(value, list) else []


def _pentest_config_response(repo: Repo) -> RepoPentestConfigResponse:
    return RepoPentestConfigResponse(
        repo_id=repo.id,
        pentest_mode=repo.pentest_mode or "staging",
        staging_base_url=repo.staging_base_url,
        healthcheck_path=repo.healthcheck_path,
        boot=repo.boot,
        healthcheck=repo.healthcheck,
        egress_allowlist=_decode_egress_allowlist(repo.egress_allowlist),
    )


@router.get("/{repo_id}/pentest-config", response_model=RepoPentestConfigResponse)
async def get_pentest_config(
    repo_id: str,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> RepoPentestConfigResponse:
    repo = await _get_repo(db, repo_id, principal)
    return _pentest_config_response(repo)


@router.patch("/{repo_id}/pentest-config", response_model=RepoPentestConfigResponse)
async def update_pentest_config(
    repo_id: str,
    payload: RepoPentestConfigPatch,
    db: AsyncSession = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> RepoPentestConfigResponse:
    repo = await _get_repo(db, repo_id, principal)
    if payload.pentest_mode is not None:
        repo.pentest_mode = payload.pentest_mode
    if payload.staging_base_url is not None:
        repo.staging_base_url = payload.staging_base_url or None
    if payload.healthcheck_path is not None:
        repo.healthcheck_path = payload.healthcheck_path or None
    if payload.boot is not None:
        repo.boot = payload.boot or None
    if payload.healthcheck is not None:
        repo.healthcheck = payload.healthcheck or None
    if payload.egress_allowlist is not None:
        repo.egress_allowlist = json.dumps(payload.egress_allowlist, sort_keys=True)

    # Per §3 D1, staging mode must have a base URL to probe against.
    effective_mode = repo.pentest_mode or "staging"
    if effective_mode == "staging" and not repo.staging_base_url:
        raise HTTPException(status_code=422, detail="staging_base_url is required when pentest_mode is 'staging'")
    if effective_mode == "local_worker" and not repo.boot:
        raise HTTPException(status_code=422, detail="boot is required when pentest_mode is 'local_worker'")

    await db.flush()
    return _pentest_config_response(repo)


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


# NOTE: POST /{repo_id}/plan was removed. Plan/design-doc review took the plan
# text in the request body and enqueued a cloud `kind=plan` task, which no
# longer exists — the CLI runs plan review locally via the local engine and
# only pushes back findings. (The old handler also referenced an unimported
# PlanRequest, i.e. it would have NameError'd on first call.)

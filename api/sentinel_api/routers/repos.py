from __future__ import annotations

import json
import os

from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.models import Repo

from ..auth import Principal, current_principal
from ..deps import get_db
from ..schemas import (
    RepoCreateRequest,
    RepoPentestConfigPatch,
    RepoPentestConfigResponse,
    RepoResponse,
)

router = APIRouter(prefix="/repos", tags=["repos"])


def _is_dev_mode() -> bool:
    return os.getenv("SENTINEL_DEV_MODE", "0") == "1"


def _skip_tenant_filter(principal: Principal) -> bool:
    """Bypass tenant scoping only when in dev mode AND using the dev principal."""
    return _is_dev_mode() and principal.account_id == "dev"


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


def _decode_egress_allowlist(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(host) for host in value] if isinstance(value, list) else []


def _decode_pentest_config(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return value if isinstance(value, dict) else None


def _pentest_mode(value: str | None) -> Literal["staging", "local_worker"]:
    """Narrow the free-text DB column to the response's Literal.

    The column is plain text, so anything unrecognised (or NULL) falls back to
    "staging" -- the same default the old `or "staging"` gave for NULL, now
    applied to bad values too rather than passing them through untyped.
    """
    return "local_worker" if value == "local_worker" else "staging"


def _pentest_config_response(repo: Repo) -> RepoPentestConfigResponse:
    return RepoPentestConfigResponse(
        repo_id=repo.id,
        pentest_mode=_pentest_mode(repo.pentest_mode),
        staging_base_url=repo.staging_base_url,
        healthcheck_path=repo.healthcheck_path,
        boot=repo.boot,
        healthcheck=repo.healthcheck,
        egress_allowlist=_decode_egress_allowlist(repo.egress_allowlist),
        pentest_config=_decode_pentest_config(getattr(repo, "pentest_config", None)),
    )


def _local_worker_has_target(repo: Repo) -> bool:
    """local_worker needs a bootable target: either the flat `boot` command or a
    structured target (OCI image / compose / boot) in pentest_config.sandbox."""
    if repo.boot:
        return True
    cfg = _decode_pentest_config(getattr(repo, "pentest_config", None)) or {}
    target = (cfg.get("sandbox") or {}).get("target") or {}
    return bool(target.get("image") or target.get("compose") or target.get("boot"))


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
    if payload.pentest_config is not None:
        repo.pentest_config = json.dumps(payload.pentest_config, sort_keys=True) or None

    # Per §3 D1, staging mode must have a base URL to probe against.
    effective_mode = repo.pentest_mode or "staging"
    if effective_mode == "staging" and not repo.staging_base_url:
        raise HTTPException(status_code=422, detail="staging_base_url is required when pentest_mode is 'staging'")
    if effective_mode == "local_worker" and not _local_worker_has_target(repo):
        raise HTTPException(status_code=422, detail="local_worker requires a target: set `boot` or sandbox.target (image/compose/boot) in pentest_config")

    await db.flush()
    return _pentest_config_response(repo)


# NOTE: /{repo_id}/init, /source, and /scan were removed — they took source
# code / diffs in the request body, which the local-AI-calls model forbids.
# See main.py's equivalent note next to /tasks/claim.


# NOTE: POST /{repo_id}/pentest was removed. Pentest now runs entirely on the
# developer's local machine (full gVisor sandbox stack); the local engine POSTs
# the outcome to POST /findings/{id}/confirm. The backend no longer enqueues
# pentest tasks — it is a pure results store.


# NOTE: POST /{repo_id}/plan was removed. Plan/design-doc review took the plan
# text in the request body and enqueued a cloud `kind=plan` task, which no
# longer exists — the CLI runs plan review locally via the local engine and
# only pushes back findings. (The old handler also referenced an unimported
# PlanRequest, i.e. it would have NameError'd on first call.)

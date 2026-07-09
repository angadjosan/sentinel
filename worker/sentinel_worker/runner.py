from __future__ import annotations

import json
import os

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Account, Finding, Graph, Repo, Run
from .task_queue import ClaimedTask, claim_next_task, complete_task, fail_task


async def run_one_task(db: AsyncSession, *, worker_id: str, account_id: str | None = None, _llm=None) -> str | None:
    claimed = await claim_next_task(db, worker_id=worker_id, account_id=account_id)
    if claimed is None:
        return None
    # Run the task inside a savepoint so that a mid-task DB error (e.g. FK
    # violation from a synthetic node_id) only rolls back the task's writes,
    # leaving the outer transaction valid for fail_task/complete_task.
    try:
        async with db.begin_nested():
            await execute_claimed_task(db, claimed, _llm=_llm)
    except Exception as exc:
        await fail_task(db, task_id=claimed.task.id, error=f"{type(exc).__name__}: {exc}")
        return claimed.task.id
    await complete_task(db, task_id=claimed.task.id)
    return claimed.task.id


async def execute_claimed_task(db: AsyncSession, claimed: ClaimedTask, *, _llm=None) -> None:
    task = claimed.task
    run = await db.get(Run, task.run_id)
    graph = await db.get(Graph, task.graph_id)
    repo = await db.get(Repo, task.repo_id)
    if run is None or graph is None or repo is None:
        raise ValueError("task references missing run, graph, or repo")
    # The cloud worker only runs pentest tasks now. The legacy `source` / `plan`
    # / `init` kinds ran SAST over customer diffs/source on the worker, which the
    # target architecture forbids (§1: SAST is local-only on the CLI machine).
    # Nothing enqueues those kinds anymore; a stale one is a hard error.
    if task.kind == "pentest":
        await execute_pentest_task(db, claimed, repo=repo, graph=graph, _llm=_llm)
        return
    raise ValueError(f"unsupported task kind: {task.kind}")


def _decode_egress_allowlist(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [str(host) for host in value] if isinstance(value, list) else []


async def _pentest_llm(db: AsyncSession, account: Account | None, _llm):
    """Resolve the pentest-agent LLM (AUDIT.md §3 D2).

    Precedence: an injected test LLM > `SENTINEL_PENTEST_LLM_API_KEY` env on the
    worker > optional `Account.pentest_api_key`. This is separate from the SAST
    key policy — the pentest credential lives on the server side only.
    """
    if _llm is not None:
        return _llm
    from .agent import SentinelLLMClient

    env_key = os.getenv("SENTINEL_PENTEST_LLM_API_KEY")
    provider = os.getenv("SENTINEL_PENTEST_LLM_PROVIDER") or (account.provider if account else None) or "local"
    model = os.getenv("SENTINEL_PENTEST_LLM_MODEL") or (account.model if account else None) or "ollama"
    api_key = env_key or (getattr(account, "pentest_api_key", None) if account else None)
    if provider != "local" and not api_key:
        # No usable credential for a cloud provider — fall back to template payloads.
        return None
    return SentinelLLMClient(provider=provider, model=model, api_key=api_key or "")


async def execute_pentest_task(db: AsyncSession, claimed: ClaimedTask, *, repo: Repo, graph: Graph, _llm=None) -> None:
    """Execute a cloud pentest task (AUDIT.md §6 W1 P0.2–P0.4).

    Loads the finding + repo pentest config, dispatches HTTP payloads to the
    staging URL, and lets the oracle write the finding confirmation directly.
    """
    from .pentest import PentestRequestContext, run_pentest
    from .vm import PentestSandboxConfig

    payload = claimed.payload
    finding_id = payload.get("finding_id")
    if not finding_id:
        raise ValueError("pentest task missing finding_id")
    finding = await db.get(Finding, str(finding_id))
    if finding is None:
        raise ValueError("pentest task references missing finding")

    account = await db.get(Account, graph.account_id)

    # Repo config (AUDIT.md §3 D1) is authoritative; task payload may override for
    # ad-hoc runs (e.g. a self-hosted CLI passing boot/healthcheck directly).
    staging_base_url = payload.get("staging_base_url") or repo.staging_base_url
    healthcheck_path = payload.get("healthcheck_path") or repo.healthcheck_path
    egress_allowlist = payload.get("egress_allowlist") or _decode_egress_allowlist(repo.egress_allowlist)
    boot = payload.get("boot") or repo.boot
    healthcheck = payload.get("healthcheck") or repo.healthcheck

    sandbox = PentestSandboxConfig(
        boot=boot,
        healthcheck=healthcheck,
        egress_allowlist=[str(h) for h in egress_allowlist] if isinstance(egress_allowlist, list) else [],
    )
    context = PentestRequestContext(
        sanitizer_output=str(payload.get("sanitizer_output", "")),
        behavioral_proof=payload.get("behavioral_proof"),
        proof_detail=str(payload.get("proof_detail", "")),
        sandbox=sandbox,
        executor=None,  # HTTP-only Phase 1 (AUDIT.md §3 D3); no on-worker subprocess sandbox yet.
        staging_base_url=staging_base_url,
        healthcheck_path=healthcheck_path,
    )

    llm = await _pentest_llm(db, account, _llm)
    # run_pentest creates its own Run, evaluates the oracle, and writes the
    # finding confirmation + CONFIRMED_EXPLOIT edge directly (AUDIT.md §3 D6).
    await run_pentest(db, finding, context, llm=llm)

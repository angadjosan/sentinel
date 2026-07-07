from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from .models import Graph, Repo, Run
from .scan import execute_source_scan, review_plan, trace_event
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
    if task.kind == "source":
        await execute_source_scan(
            db,
            graph=graph,
            repo=repo,
            run=run,
            diff=str(claimed.payload.get("diff", "")),
            run_context=str(claimed.payload.get("run_context", "worker")),
            base_ref=claimed.payload.get("base_ref") if isinstance(claimed.payload.get("base_ref"), str) else None,
            paths=[str(p) for p in claimed.payload.get("paths", [])] if isinstance(claimed.payload.get("paths"), list) else [],
            check_run_id=claimed.payload.get("check_run_id"),
            installation_id=claimed.payload.get("installation_id"),
            gh_repo=claimed.payload.get("repo") if isinstance(claimed.payload.get("repo"), str) else None,
            _llm=_llm,
        )
        return
    if task.kind == "plan":
        plan_run, findings = await review_plan(
            db,
            repo_name=repo.name,
            content=str(claimed.payload.get("content", "")),
            with_retry=bool(claimed.payload.get("with_retry", False)),
            account_id=graph.account_id,
            _llm=_llm,
        )
        run.status = plan_run.status
        run.completed_at = plan_run.completed_at
        run.trace = "\n".join([run.trace or "", plan_run.trace, trace_event("plan.forwarded", finding_count=len(findings))]).strip()
        return
    if task.kind == "init":
        from .scan import bootstrap_repo
        await bootstrap_repo(
            db,
            repo_name=repo.name,
            files=claimed.payload.get("files", {}),
            account_id=graph.account_id,
            _llm=_llm,
        )
        return
    raise ValueError(f"unsupported task kind: {task.kind}")

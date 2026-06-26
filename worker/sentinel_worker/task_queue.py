from __future__ import annotations

import json
from dataclasses import dataclass

from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Run, Task, now
from .notifications import notify_run_event, notify_task_available
from .scan import get_or_create_graph, trace_event
from .security import scrub_secrets
from .trace_store import offload_trace_if_large


@dataclass(frozen=True)
class ClaimedTask:
    task: Task
    payload: dict


async def enqueue_task(db: AsyncSession, *, repo_name: str, kind: str, payload: dict, account_id: str | None = None) -> Task:
    graph = await get_or_create_graph(db, repo_name, account_id=account_id)
    run = Run(graph_id=graph.id, kind=kind, status="queued", trace=trace_event("task.queued", task_kind=kind))
    db.add(run)
    await db.flush()
    task = Task(
        graph_id=graph.id,
        run_id=run.id,
        account_id=graph.account_id,
        repo_id=graph.repo_id,
        kind=kind,
        status="queued",
        payload=json.dumps(payload, sort_keys=True),
    )
    db.add(task)
    await db.flush()
    await notify_task_available(db, task.id)
    return task


async def claim_next_task(db: AsyncSession, *, worker_id: str, kinds: list[str] | None = None, account_id: str | None = None) -> ClaimedTask | None:
    task = await db.scalar(_claimable_task_stmt(kinds, account_id=account_id))
    if task is None:
        return None
    task.status = "claimed"
    task.claimed_by = worker_id
    task.claimed_at = now()
    task.attempts += 1
    run = await db.get(Run, task.run_id)
    if run is not None:
        run.status = "running"
        event = trace_event("task.claimed", task_id=task.id, worker_id=worker_id)
        run.trace = "\n".join([run.trace or "", event]).strip()
        await notify_run_event(db, run.id, event)
    return ClaimedTask(task=task, payload=json.loads(task.payload))


async def complete_task(db: AsyncSession, *, task_id: str, trace: str | None = None) -> Task:
    task = await _get_task(db, task_id)
    await db.refresh(task)
    if task.status == "cancelled":
        return task
    task.status = "completed"
    task.completed_at = now()
    run = await db.get(Run, task.run_id)
    if run is not None:
        run.status = "completed"
        run.completed_at = now()
        event = trace_event("task.completed", task_id=task.id)
        safe_trace = scrub_secrets(trace or "")
        run.trace = "\n".join(part for part in [run.trace, safe_trace, event] if part)
        await offload_trace_if_large(db, run)
        if safe_trace:
            for line in safe_trace.splitlines():
                if line.strip():
                    await notify_run_event(db, run.id, line)
        await notify_run_event(db, run.id, event)
    return task


async def fail_task(db: AsyncSession, *, task_id: str, error: str) -> Task:
    task = await _get_task(db, task_id)
    await db.refresh(task)
    if task.status == "cancelled":
        return task
    task.status = "failed"
    task.error = scrub_secrets(error)
    task.completed_at = now()
    run = await db.get(Run, task.run_id)
    if run is not None:
        run.status = "failed"
        run.completed_at = now()
        event = trace_event("task.failed", task_id=task.id, error=task.error)
        run.trace = "\n".join([run.trace or "", event]).strip()
        await offload_trace_if_large(db, run)
        await notify_run_event(db, run.id, event)
    return task


async def cancel_task(db: AsyncSession, *, task_id: str) -> Task:
    task = await _get_task(db, task_id)
    if task.status in {"completed", "failed", "cancelled"}:
        return task
    task.status = "cancelled"
    task.completed_at = now()
    run = await db.get(Run, task.run_id)
    if run is not None:
        run.status = "cancelled"
        run.completed_at = now()
        event = trace_event("task.cancelled", task_id=task.id)
        run.trace = "\n".join([run.trace or "", event]).strip()
        await offload_trace_if_large(db, run)
        await notify_run_event(db, run.id, event)
    return task


async def cancel_run_tasks(db: AsyncSession, *, run_id: str) -> Run:
    run = await db.get(Run, run_id)
    if run is None:
        raise ValueError("run not found")
    if run.status in {"completed", "failed", "cancelled"}:
        return run
    tasks = list(await db.scalars(select(Task).where(Task.run_id == run_id).where(Task.status.not_in(["completed", "failed", "cancelled"]))))
    completed_at = now()
    for task in tasks:
        task.status = "cancelled"
        task.completed_at = completed_at
    run.status = "cancelled"
    run.completed_at = completed_at
    event = trace_event("run.cancelled", cancelled_tasks=len(tasks))
    run.trace = "\n".join([run.trace or "", event]).strip()
    await offload_trace_if_large(db, run)
    await notify_run_event(db, run.id, event)
    return run


async def _get_task(db: AsyncSession, task_id: str) -> Task:
    task = await db.get(Task, task_id)
    if task is None:
        raise ValueError("task not found")
    return task


def _claimable_task_stmt(kinds: list[str] | None = None, account_id: str | None = None) -> Select[tuple[Task]]:
    stmt = select(Task).where(Task.status == "queued").order_by(Task.created_at.asc()).limit(1)
    if kinds:
        stmt = stmt.where(Task.kind.in_(kinds))
    if account_id:
        stmt = stmt.where(Task.account_id == account_id)
    return stmt.with_for_update(skip_locked=True)

from __future__ import annotations

import json
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Run, Task, now
from .scan import get_or_create_graph, trace_event


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
    return task


async def claim_next_task(db: AsyncSession, *, worker_id: str, kinds: list[str] | None = None) -> ClaimedTask | None:
    stmt = select(Task).where(Task.status == "queued").order_by(Task.created_at.asc())
    if kinds:
        stmt = stmt.where(Task.kind.in_(kinds))
    task = await db.scalar(stmt.limit(1))
    if task is None:
        return None
    task.status = "claimed"
    task.claimed_by = worker_id
    task.claimed_at = now()
    task.attempts += 1
    run = await db.get(Run, task.run_id)
    if run is not None:
        run.status = "running"
        run.trace = "\n".join([run.trace or "", trace_event("task.claimed", task_id=task.id, worker_id=worker_id)]).strip()
    return ClaimedTask(task=task, payload=json.loads(task.payload))


async def complete_task(db: AsyncSession, *, task_id: str, trace: str | None = None) -> Task:
    task = await _get_task(db, task_id)
    task.status = "completed"
    task.completed_at = now()
    run = await db.get(Run, task.run_id)
    if run is not None:
        run.status = "completed"
        run.completed_at = now()
        run.trace = "\n".join(part for part in [run.trace, trace, trace_event("task.completed", task_id=task.id)] if part)
    return task


async def fail_task(db: AsyncSession, *, task_id: str, error: str) -> Task:
    task = await _get_task(db, task_id)
    task.status = "failed"
    task.error = error
    task.completed_at = now()
    run = await db.get(Run, task.run_id)
    if run is not None:
        run.status = "failed"
        run.completed_at = now()
        run.trace = "\n".join([run.trace or "", trace_event("task.failed", task_id=task.id, error=error)]).strip()
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
        run.trace = "\n".join([run.trace or "", trace_event("task.cancelled", task_id=task.id)]).strip()
    return task


async def _get_task(db: AsyncSession, task_id: str) -> Task:
    task = await db.get(Task, task_id)
    if task is None:
        raise ValueError("task not found")
    return task

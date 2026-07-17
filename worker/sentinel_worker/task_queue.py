from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Run, Task, now
from .notifications import notify_run_event
from .scan import trace_event
from .trace_store import offload_trace_if_large


async def cancel_run_tasks(db: AsyncSession, *, run_id: str) -> Run:
    """Cancel a Run and any of its non-terminal tasks.

    The cloud task queue (enqueue/claim/complete/fail) is gone — pentest now runs
    locally and results are POSTed back. This helper survives because Runs are
    still created (e.g. by `POST /findings/ingest`) and the `DELETE /runs/{id}`
    endpoint lets a principal cancel one. With no queued tasks left it usually
    just marks the run cancelled (or no-ops on an already-terminal run).
    """
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

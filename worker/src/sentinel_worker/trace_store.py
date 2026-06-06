from __future__ import annotations

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Run, RunTraceChunk
from .security import scrub_secrets

TRACE_OFFLOAD_BYTES = 1_000_000
TRACE_CHUNK_CHARS = 64_000


async def offload_trace_if_large(db: AsyncSession, run: Run, *, threshold_bytes: int = TRACE_OFFLOAD_BYTES, chunk_chars: int = TRACE_CHUNK_CHARS) -> None:
    trace = scrub_secrets(run.trace or "")
    run.trace = trace
    if len(trace.encode("utf8")) <= threshold_bytes:
        return
    await db.execute(delete(RunTraceChunk).where(RunTraceChunk.run_id == run.id))
    for seq, start in enumerate(range(0, len(trace), chunk_chars)):
        db.add(RunTraceChunk(run_id=run.id, seq=seq, chunk=trace[start : start + chunk_chars]))
    run.trace = ""


async def read_run_trace(db: AsyncSession, run: Run) -> str:
    rows = await db.scalars(select(RunTraceChunk).where(RunTraceChunk.run_id == run.id).order_by(RunTraceChunk.seq))
    chunked = "".join(row.chunk for row in rows)
    if chunked and run.trace:
        return scrub_secrets("\n".join([chunked.rstrip("\n"), run.trace]))
    return scrub_secrets(chunked or run.trace or "")

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator, Awaitable, Callable

import asyncpg
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.models import Run
from sentinel_worker.notifications import RUN_CHANNEL_PREFIX, _safe_channel
from sentinel_worker.trace_store import read_run_trace


TERMINAL_RUN_STATUSES = {"completed", "failed", "cancelled"}
POLL_INTERVAL_SECONDS = 0.25


async def stream_run_events(
    db: AsyncSession,
    run_id: str,
    *,
    database_url: str | None = None,
    connect: Callable[[str], Awaitable[object]] | None = None,
    poll_interval: float = POLL_INTERVAL_SECONDS,
) -> AsyncIterator[str]:
    emitted = 0
    run = await db.get(Run, run_id)
    if run is None:
        yield _sse({"kind": "error", "error": "run not found"})
        return
    emitted, terminal = await _replay_trace(db, run, emitted)
    for event in terminal.events:
        yield event
    if terminal.done:
        return

    url: str = database_url or os.getenv("DATABASE_URL") or ""
    if not _is_postgres_url(url):
        async for event in _poll_run_events(db, run_id, emitted, poll_interval):
            yield event
        return

    async for event in _listen_run_events(db, run_id, emitted, url, connect or asyncpg.connect):
        yield event


async def _listen_run_events(db: AsyncSession, run_id: str, emitted: int, database_url: str, connect: Callable[[str], Awaitable[object]]) -> AsyncIterator[str]:
    queue: asyncio.Queue[str] = asyncio.Queue()
    channel = _safe_channel(f"{RUN_CHANNEL_PREFIX}{run_id}")

    def listener(_connection, _pid, _channel, payload: str) -> None:
        queue.put_nowait(payload)

    connection = await connect(database_url)
    await connection.add_listener(channel, listener)  # type: ignore[attr-defined]
    try:
        run = await db.get(Run, run_id)
        if run is not None:
            emitted, terminal = await _replay_trace(db, run, emitted)
            for event in terminal.events:
                yield event
            if terminal.done:
                return
        while True:
            payload = await queue.get()
            yield _sse_text(payload)
            run = await db.get(Run, run_id)
            if run is None:
                yield _sse({"kind": "error", "error": "run not found"})
                return
            await db.refresh(run)
            if run.status in TERMINAL_RUN_STATUSES:
                yield _sse({"kind": "complete", "run_id": run.id, "status": run.status})
                return
    finally:
        await connection.remove_listener(channel, listener)  # type: ignore[attr-defined]
        await connection.close()  # type: ignore[attr-defined]


async def _poll_run_events(db: AsyncSession, run_id: str, emitted: int, poll_interval: float) -> AsyncIterator[str]:
    while True:
        run = await db.get(Run, run_id)
        if run is None:
            yield _sse({"kind": "error", "error": "run not found"})
            return
        emitted, terminal = await _replay_trace(db, run, emitted)
        for event in terminal.events:
            yield event
        if terminal.done:
            return
        await asyncio.sleep(poll_interval)


class ReplayResult:
    def __init__(self, events: list[str], done: bool):
        self.events = events
        self.done = done


async def _replay_trace(db: AsyncSession, run: Run, emitted: int) -> tuple[int, ReplayResult]:
    lines = [line for line in (await read_run_trace(db, run)).splitlines() if line.strip()]
    events = [_sse_text(line) for line in lines[emitted:]]
    emitted = len(lines)
    done = run.status in TERMINAL_RUN_STATUSES
    if done:
        events.append(_sse({"kind": "complete", "run_id": run.id, "status": run.status}))
    return emitted, ReplayResult(events, done)


def _sse(payload: dict) -> str:
    return _sse_text(json.dumps(payload))


def _sse_text(payload: str) -> str:
    return f"data: {payload}\n\n"


def _is_postgres_url(url: str) -> bool:
    return url.startswith(("postgresql://", "postgres://", "postgresql+asyncpg://"))

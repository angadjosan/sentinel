from __future__ import annotations

import asyncio
import os
import signal

import structlog

from .db import create_engine, create_sessionmaker
from .migrations import apply_migrations
from .runner import run_one_task


log = structlog.get_logger()


async def run_worker(*, worker_id: str, poll_interval: float = 2.0, stop: asyncio.Event | None = None, account_id: str | None = None) -> None:
    engine = create_engine()
    sessionmaker = create_sessionmaker(engine)
    await apply_migrations(engine)
    stop_event = stop or asyncio.Event()
    try:
        while not stop_event.is_set():
            async with sessionmaker() as session:
                async with session.begin():
                    task_id = await run_one_task(session, worker_id=worker_id, account_id=account_id)
            if task_id:
                log.info("worker.task_processed", worker_id=worker_id, task_id=task_id)
                continue
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=poll_interval)
            except asyncio.TimeoutError:
                pass
    finally:
        await engine.dispose()


def main() -> None:
    worker_id = os.getenv("SENTINEL_WORKER_ID", f"worker-{os.getpid()}")
    poll_interval = float(os.getenv("SENTINEL_WORKER_POLL_INTERVAL", "2"))
    account_id = os.getenv("SENTINEL_ACCOUNT_ID")
    stop = asyncio.Event()

    def request_stop() -> None:
        stop.set()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, request_stop)
        except NotImplementedError:
            pass
    loop.run_until_complete(run_worker(worker_id=worker_id, poll_interval=poll_interval, stop=stop, account_id=account_id))


if __name__ == "__main__":
    main()

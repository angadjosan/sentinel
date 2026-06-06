import asyncio

import pytest

from sentinel_worker.worker_main import run_worker


@pytest.mark.asyncio
async def test_worker_loop_stops_cleanly(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'worker.db'}")
    stop = asyncio.Event()
    stop.set()
    await run_worker(worker_id="test-worker", poll_interval=0.01, stop=stop)

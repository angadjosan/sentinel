"""Test that task claiming is scoped to the requesting account."""
import pytest

from sentinel_worker.task_queue import claim_next_task, enqueue_task


@pytest.mark.asyncio
async def test_claim_scoped_to_account(db):
    await enqueue_task(db, repo_name="ra", kind="source", payload={}, account_id="A")
    await enqueue_task(db, repo_name="rb", kind="source", payload={}, account_id="B")
    claimed = await claim_next_task(db, worker_id="w", account_id="A")
    assert claimed is not None
    assert claimed.task.account_id == "A"


@pytest.mark.asyncio
async def test_claim_without_scope_claims_any(db):
    await enqueue_task(db, repo_name="rc", kind="source", payload={}, account_id="C")
    claimed = await claim_next_task(db, worker_id="w")
    assert claimed is not None

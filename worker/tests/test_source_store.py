from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.models import Account, Base, Graph, Node, Repo, SourceFileSnapshot
from sentinel_worker.scan import bootstrap_repo
from sentinel_worker.source_store import enforce_source_retention_for_account, read_source_snapshot, store_source_snapshot


@pytest.mark.asyncio
async def test_source_snapshot_encrypts_and_reads_content():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            snapshot = await store_source_snapshot(
                session,
                repo_id="repo",
                commit_hash="commit",
                file_path="app.js",
                content="const secret = 'value';",
            )
        async with session.begin():
            stored = await session.get(SourceFileSnapshot, ("repo", "commit", "app.js"))
            content = await read_source_snapshot(session, repo_id="repo", commit_hash="commit", file_path="app.js")
    assert stored is not None
    assert snapshot.content_sha == stored.content_sha
    assert "const secret" not in stored.content_enc
    assert content == "const secret = 'value';"


@pytest.mark.asyncio
async def test_bootstrap_stores_source_separately_from_nodes():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            run = await bootstrap_repo(session, "repo", {"app.js": "const password = 'secret';"})
        async with session.begin():
            graph = await session.get(Graph, run.graph_id)
            node = await session.get(Node, "file:app.js")
            assert graph is not None
            source = await read_source_snapshot(session, repo_id=graph.repo_id, commit_hash="bootstrap", file_path="app.js")
    assert node is not None
    assert node.intent is not None
    assert "password" not in node.intent
    assert source == "const password = 'secret';"


@pytest.mark.asyncio
async def test_source_retention_removes_expired_snapshots_for_account():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    current_time = datetime(2026, 6, 6, tzinfo=UTC)
    async with sessionmaker() as session:
        async with session.begin():
            account = Account(id="acct-retention", name="retention", source_retention_days=1)
            other_account = Account(id="acct-other", name="other", source_retention_days=1)
            repo = Repo(id="repo-retention", account_id=account.id, name="repo")
            other_repo = Repo(id="repo-other", account_id=other_account.id, name="repo")
            session.add_all([account, other_account, repo, other_repo])
            old = await store_source_snapshot(session, repo_id=repo.id, commit_hash="old", file_path="app.js", content="old")
            fresh = await store_source_snapshot(session, repo_id=repo.id, commit_hash="fresh", file_path="app.js", content="fresh")
            other = await store_source_snapshot(session, repo_id=other_repo.id, commit_hash="old", file_path="app.js", content="other")
            old.created_at = current_time - timedelta(days=2)
            fresh.created_at = current_time
            other.created_at = current_time - timedelta(days=2)
            await session.flush()
            removed = await enforce_source_retention_for_account(session, account.id, current_time=current_time)
        async with session.begin():
            expired = await session.get(SourceFileSnapshot, (repo.id, "old", "app.js"))
            retained = await read_source_snapshot(session, repo_id=repo.id, commit_hash="fresh", file_path="app.js")
            retained_other = await read_source_snapshot(session, repo_id=other_repo.id, commit_hash="old", file_path="app.js")

    assert removed == 1
    assert expired is None
    assert retained == "fresh"
    assert retained_other == "other"

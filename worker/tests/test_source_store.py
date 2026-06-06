import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.models import Base, Graph, Node, SourceFileSnapshot
from sentinel_worker.scan import bootstrap_repo
from sentinel_worker.source_store import read_source_snapshot, store_source_snapshot


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

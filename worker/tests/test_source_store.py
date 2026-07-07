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
async def test_store_source_snapshot_refuses_env_files():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            result = await store_source_snapshot(
                session, repo_id="repo", commit_hash="commit", file_path=".env.local", content="API_KEY=super-secret"
            )
        async with session.begin():
            stored = await session.get(SourceFileSnapshot, ("repo", "commit", ".env.local"))
    assert result is None
    assert stored is None


@pytest.mark.asyncio
async def test_read_source_snapshot_refuses_env_files_even_if_stored():
    """Defense in depth: even a pre-existing snapshot for an env-style path must not be readable."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            snapshot = SourceFileSnapshot(
                repo_id="repo",
                commit_hash="commit",
                file_path=".env",
                content_enc="irrelevant",
                content_sha="irrelevant",
                language=None,
                deleted=False,
            )
            session.add(snapshot)
        async with session.begin():
            with pytest.raises(FileNotFoundError):
                await read_source_snapshot(session, repo_id="repo", commit_hash="commit", file_path=".env")


@pytest.mark.asyncio
async def test_bootstrap_repo_skips_env_files_from_snapshots_and_llm():
    from tests.conftest import MockLLMClient

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    llm = MockLLMClient()
    async with sessionmaker() as session:
        async with session.begin():
            run = await bootstrap_repo(
                session,
                "repo",
                {"app.js": "const x = 1;", ".env.local": "DATABASE_URL=postgres://user:hunter2@host/db"},
                _llm=llm,
            )
        async with session.begin():
            graph = await session.get(Graph, run.graph_id)
            with pytest.raises(FileNotFoundError):
                await read_source_snapshot(session, repo_id=graph.repo_id, commit_hash="bootstrap", file_path=".env.local")

    assert not any("hunter2" in call.get("content_input", "") for call in llm.calls)
    assert not any("DATABASE_URL" in call.get("content_input", "") for call in llm.calls)


@pytest.mark.asyncio
async def test_bootstrap_stores_source_separately_from_nodes():
    from tests.conftest import MockLLMClient
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            run = await bootstrap_repo(session, "repo", {"app.js": "const password = 'secret';"}, _llm=MockLLMClient())
        async with session.begin():
            graph = await session.get(Graph, run.graph_id)
            node = await session.get(Node, "file:app.js")
            assert graph is not None
            source = await read_source_snapshot(session, repo_id=graph.repo_id, commit_hash="bootstrap", file_path="app.js")
    assert node is not None
    assert node.intent is not None
    assert "password" not in node.intent
    assert source == "const password = 'secret';"
    assert run.token_spend > 0
    assert "semantic_enrichment" in run.trace


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


@pytest.mark.asyncio
async def test_grep_source_tool_excludes_env_files_even_if_stored():
    """Defense in depth: even if an env-style snapshot exists, the SAST agent's
    grep_source tool must never surface it in search results."""
    from sentinel_worker.graph_query import GraphQuery
    from sentinel_worker.source_store import encrypt_source
    from sentinel_worker.tools import dispatch_tool

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            session.add_all([
                SourceFileSnapshot(
                    repo_id="repo", commit_hash="bootstrap", file_path=".env",
                    content_enc=encrypt_source("API_KEY=super-secret-value"),
                    content_sha="x", language=None, deleted=False,
                ),
                SourceFileSnapshot(
                    repo_id="repo", commit_hash="bootstrap", file_path="config.py",
                    content_enc=encrypt_source("API_KEY = load_from_env()"),
                    content_sha="y", language="python", deleted=False,
                ),
            ])
        async with session.begin():
            result = await dispatch_tool(
                tool_name="grep_source",
                tool_input={"pattern": "API_KEY"},
                graph=GraphQuery(db=session, graph_id="g1"),
                run_id="run1",
                db=session,
                repo_id="repo",
            )

    matched_files = {m["file_path"] for m in result["matches"]}
    assert ".env" not in matched_files
    assert "config.py" in matched_files

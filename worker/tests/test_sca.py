import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.construction import SourceFile, build_file_graph
from sentinel_worker.models import Base, Finding, Graph
from sentinel_worker.scan import get_or_create_graph, scan_diff
from sentinel_worker.sca import parse_dependencies, scan_dependencies


def test_parse_package_json_dependencies_from_full_or_partial_content():
    full = parse_dependencies("package.json", '{"dependencies":{"lodash":"^4.17.21"}}')
    partial = parse_dependencies("package.json", '"lodash": "^4.17.21"')
    assert full[0].name == "lodash"
    assert full[0].version == "4.17.21"
    assert partial[0].name == "lodash"
    assert partial[0].version == "4.17.21"


def test_parse_pyproject_and_gemfile_lock_dependencies():
    pyproject = parse_dependencies("pyproject.toml", 'dependencies = ["django==3.2.0"]')
    gemfile = parse_dependencies("Gemfile.lock", "GEM\n  specs:\n    rails (6.1.0)\n")
    assert pyproject[0].name == "django"
    assert pyproject[0].ecosystem == "pypi"
    assert gemfile[0].name == "rails"
    assert gemfile[0].ecosystem == "rubygems"


@pytest.mark.asyncio
async def test_sca_emits_reachable_dependency_finding():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            await build_file_graph(session, graph.id, SourceFile("app.js", "const _ = require('lodash');"))
            count = await scan_dependencies(session, graph.id, "repo", "run", "package.json", '{"dependencies":{"lodash":"4.17.21"}}')
        async with session.begin():
            finding = await session.scalar(select(Finding).where(Finding.vuln_type == "sca_reachable"))
    assert count == 1
    assert finding is not None
    assert "lodash" in finding.title


@pytest.mark.asyncio
async def test_scan_diff_runs_sca_on_package_manifest():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = await get_or_create_graph(session, "repo")
            await build_file_graph(session, graph.id, SourceFile("app.js", "const _ = require('lodash');"))
            await scan_diff(session, "repo", '+++ b/package.json\n+"lodash": "4.17.21"')
        async with session.begin():
            finding = await session.scalar(select(Finding).where(Finding.vuln_type == "sca_reachable"))
    assert finding is not None

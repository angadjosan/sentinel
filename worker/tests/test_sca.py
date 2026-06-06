import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.construction import SourceFile, build_file_graph
from sentinel_worker.models import Base, Finding, Graph
from sentinel_worker.scan import get_or_create_graph, scan_diff
from sentinel_worker.sca import Advisory, AdvisorySource, Dependency, parse_dependencies, scan_dependencies


class CountingAdvisorySource(AdvisorySource):
    def __init__(self):
        self.calls = 0

    async def lookup(self, dependency: Dependency) -> list[Advisory]:
        self.calls += 1
        return [Advisory(dependency.name, dependency.ecosystem, dependency.version, "GHSA-cache-test", "high", "cached advisory")]


def test_parse_package_json_dependencies_from_full_or_partial_content():
    full = parse_dependencies("package.json", '{"dependencies":{"lodash":"^4.17.21"}}')
    partial = parse_dependencies("package.json", '"lodash": "^4.17.21"')
    assert full[0].name == "lodash"
    assert full[0].version == "4.17.21"
    assert partial[0].name == "lodash"
    assert partial[0].version == "4.17.21"


def test_parse_package_lock_dependencies():
    deps = parse_dependencies(
        "package-lock.json",
        '{"packages":{"":{"dependencies":{"lodash":"^4.17.21"}},"node_modules/lodash":{"version":"4.17.21"}}}',
    )
    assert deps[0].name == "lodash"
    assert deps[0].version == "4.17.21"
    assert deps[0].ecosystem == "npm"


def test_parse_yarn_and_pnpm_lock_dependencies():
    yarn = parse_dependencies("yarn.lock", 'lodash@^4.17.21:\n  version "4.17.21"\n  resolved "https://registry.yarnpkg.com/lodash"\n')
    pnpm = parse_dependencies("pnpm-lock.yaml", "packages:\n  /lodash@4.17.21:\n    resolution: {}\n")
    assert yarn[0].name == "lodash"
    assert yarn[0].version == "4.17.21"
    assert pnpm[0].name == "lodash"
    assert pnpm[0].version == "4.17.21"


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


@pytest.mark.asyncio
async def test_sca_caches_advisory_lookup_by_package_version():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    source = CountingAdvisorySource()
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            await scan_dependencies(session, graph.id, "repo", "run-1", "package.json", '{"dependencies":{"lodash":"4.17.21"}}', source=source)
            await scan_dependencies(session, graph.id, "repo", "run-2", "package.json", '{"dependencies":{"lodash":"4.17.21"}}', source=source)
    await engine.dispose()
    assert source.calls == 1

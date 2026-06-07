from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.construction import SourceFile, build_file_graph
from sentinel_worker.models import Base, Edge, Finding, Graph
from sentinel_worker.scan import get_or_create_graph, scan_diff
from sentinel_worker.sca import Advisory, AdvisorySource, Dependency, parse_dependencies, parse_nvd_advisories, scan_dependencies


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


def test_parse_nvd_advisories_matches_explicit_cpe_version():
    dependency = Dependency("lodash", "4.17.20", "npm", "package-lock.json")
    advisories = parse_nvd_advisories(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2021-23337",
                        "descriptions": [{"lang": "en", "value": "lodash command injection"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
                        "configurations": [
                            {
                                "nodes": [
                                    {
                                        "cpeMatch": [
                                            {
                                                "vulnerable": True,
                                                "criteria": "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*",
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                    }
                }
            ]
        },
        dependency,
    )

    assert advisories == [Advisory("lodash", "npm", "4.17.20", "CVE-2021-23337", "high", "lodash command injection")]


def test_parse_nvd_advisories_matches_version_ranges_only_when_affected():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [{"lang": "en", "value": "affected range"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "vulnerable": True,
                                            "criteria": "cpe:2.3:a:example:django:*:*:*:*:*:python:*:*",
                                            "versionStartIncluding": "3.0.0",
                                            "versionEndExcluding": "3.2.5",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }

    affected = parse_nvd_advisories(payload, Dependency("django", "3.2.0", "pypi", "requirements.txt"))
    fixed = parse_nvd_advisories(payload, Dependency("django", "3.2.5", "pypi", "requirements.txt"))

    assert affected[0].vuln_id == "CVE-2024-0001"
    assert affected[0].severity == "critical"
    assert fixed == []


@pytest.mark.asyncio
async def test_sca_emits_reachable_dependency_finding():
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
            await build_file_graph(session, graph.id, SourceFile("app.js", "const _ = require('lodash');"))
            count = await scan_dependencies(session, graph.id, "repo", "run", "package.json", '{"dependencies":{"lodash":"4.17.21"}}', source=source)
        async with session.begin():
            finding = await session.scalar(select(Finding).where(Finding.vuln_type == "sca_reachable"))
            depends_on = await session.scalar(
                select(Edge)
                .where(Edge.kind == "DEPENDS_ON")
                .where(Edge.src == "dep:lodash")
                .where(Edge.dst == "dep:package.json:lodash@4.17.21")
            )
    assert count == 1
    assert finding is not None
    assert "lodash" in finding.title
    assert "IMPORTS edge" in finding.description
    assert depends_on is not None


@pytest.mark.asyncio
async def test_sca_marks_dependency_unreachable_without_import_edge():
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
            count = await scan_dependencies(session, graph.id, "repo", "run", "package.json", '{"dependencies":{"lodash":"4.17.21"}}', source=source)
        async with session.begin():
            finding = await session.scalar(select(Finding).where(Finding.vuln_type == "sca_unreachable"))
            depends_on = await session.scalar(select(Edge).where(Edge.kind == "DEPENDS_ON").where(Edge.dst == "dep:package.json:lodash@4.17.21"))

    assert count == 1
    assert finding is not None
    assert "not proven reachable" in finding.description
    assert depends_on is not None


@pytest.mark.asyncio
async def test_scan_diff_runs_sca_on_package_manifest():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    mock_advisory = Advisory("lodash", "npm", "4.17.21", "GHSA-scan-test", "high", "lodash scan test advisory")
    with patch("sentinel_worker.sca.OSVAdvisorySource.lookup", new=AsyncMock(return_value=[mock_advisory])):
        async with sessionmaker() as session:
            async with session.begin():
                graph = await get_or_create_graph(session, "repo")
                await build_file_graph(session, graph.id, SourceFile("app.js", "const _ = require('lodash');"))
                from tests.conftest import MockLLMClient
                await scan_diff(session, "repo", '+++ b/package.json\n+"lodash": "4.17.21"', _llm=MockLLMClient())
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


# ---------------------------------------------------------------------------
# New manifest parser tests
# ---------------------------------------------------------------------------


def test_parse_pipfile_lock():
    content = """{
        "_meta": {},
        "default": {
            "requests": {"version": "==2.28.1"},
            "flask": {"version": "==2.2.0"}
        },
        "develop": {
            "pytest": {"version": "==7.0.0"}
        }
    }"""
    deps = parse_dependencies("Pipfile.lock", content)
    result = {(d.name, d.version, d.ecosystem) for d in deps}
    assert ("requests", "2.28.1", "PyPI") in result
    assert ("flask", "2.2.0", "PyPI") in result
    assert ("pytest", "7.0.0", "PyPI") in result


def test_parse_poetry_lock():
    content = """\
[[package]]
name = "requests"
version = "2.28.1"
description = "Python HTTP for Humans."

[[package]]
name = "flask"
version = "2.2.0"
description = "A simple framework for building complex web applications."
"""
    deps = parse_dependencies("poetry.lock", content)
    result = {(d.name, d.version, d.ecosystem) for d in deps}
    assert ("requests", "2.28.1", "PyPI") in result
    assert ("flask", "2.2.0", "PyPI") in result


def test_parse_go_mod():
    content = """\
module github.com/example/myapp

go 1.21

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/stretchr/testify v1.8.4
)

require github.com/some/direct v0.5.0
"""
    deps = parse_dependencies("go.mod", content)
    result = {(d.name, d.version, d.ecosystem) for d in deps}
    assert ("github.com/gin-gonic/gin", "1.9.1", "Go") in result
    assert ("github.com/stretchr/testify", "1.8.4", "Go") in result
    assert ("github.com/some/direct", "0.5.0", "Go") in result


def test_parse_cargo_lock():
    content = """\
# This file is automatically @generated by Cargo.
# It is not intended for manual editing.
version = 3

[[package]]
name = "serde"
version = "1.0.163"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.28.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
    deps = parse_dependencies("Cargo.lock", content)
    result = {(d.name, d.version, d.ecosystem) for d in deps}
    assert ("serde", "1.0.163", "crates.io") in result
    assert ("tokio", "1.28.0", "crates.io") in result


def test_parse_pom_xml():
    content = """\
<project>
  <dependencies>
    <dependency>
      <groupId>org.springframework</groupId>
      <artifactId>spring-core</artifactId>
      <version>5.3.27</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""
    deps = parse_dependencies("pom.xml", content)
    result = {(d.name, d.version, d.ecosystem) for d in deps}
    assert ("spring-core", "5.3.27", "Maven") in result
    assert ("junit", "4.13.2", "Maven") in result


def test_builtin_advisory_source_removed():
    """BuiltinAdvisorySource (test data with hardcoded CVEs) must not exist."""
    import sentinel_worker.sca as sca_module

    assert not hasattr(sca_module, "BuiltinAdvisorySource"), (
        "BuiltinAdvisorySource is test data and must be removed from sca.py"
    )


def test_parse_cargo_toml_simple_version():
    content = """\
[package]
name = "myapp"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = { version = "1.28", features = ["full"] }

[dev-dependencies]
mockito = "^1.2"
"""
    deps = parse_dependencies("Cargo.toml", content)
    result = {(d.name, d.version, d.ecosystem) for d in deps}
    assert ("serde", "1.0", "crates.io") in result
    assert ("tokio", "1.28", "crates.io") in result
    assert ("mockito", "1.2", "crates.io") in result


def test_parse_build_gradle_implementation_strings():
    content = """\
dependencies {
    implementation 'com.google.guava:guava:32.1.2-jre'
    implementation "org.springframework.boot:spring-boot-starter:3.1.0"
    testImplementation 'junit:junit:4.13.2'
    api 'org.apache.commons:commons-lang3:3.13.0'
}
"""
    deps = parse_dependencies("build.gradle", content)
    result = {(d.name, d.version, d.ecosystem) for d in deps}
    assert ("guava", "32.1.2-jre", "Maven") in result
    assert ("spring-boot-starter", "3.1.0", "Maven") in result
    assert ("junit", "4.13.2", "Maven") in result
    assert ("commons-lang3", "3.13.0", "Maven") in result


def test_parse_build_gradle_kts():
    content = """\
dependencies {
    implementation("io.ktor:ktor-server-core:2.3.4")
    testImplementation("io.kotest:kotest-runner-junit5:5.6.2")
}
"""
    deps = parse_dependencies("build.gradle.kts", content)
    result = {(d.name, d.version, d.ecosystem) for d in deps}
    assert ("ktor-server-core", "2.3.4", "Maven") in result
    assert ("kotest-runner-junit5", "5.6.2", "Maven") in result

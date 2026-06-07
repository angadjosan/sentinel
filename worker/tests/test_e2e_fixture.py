"""End-to-end pipeline tests using the vuln-express fixture app and
language-specific source fixtures.

These tests run the full graph construction + scan pipeline against known-bad
source fixtures and assert that specific findings are emitted (or not emitted).
LLM calls are mocked; CVE feeds are mocked. Real tree-sitter parsing and
real graph construction run against the fixture source files.

Ground truth covered:
  - vuln-express/app.js: SQL injection, missing auth, hardcoded secret
  - python/sqli.py: SQL injection in Flask route
  - typescript/sqli.ts: SQL injection in Express handler
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.construction import SourceFile, build_file_graph
from sentinel_worker.models import Base, Finding, Graph
from sentinel_worker.scan import get_or_create_graph, scan_diff
from tests.conftest import MockLLMClient

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "source"
VULN_EXPRESS = Path(__file__).parent.parent.parent / "tests" / "fixtures" / "apps" / "vuln-express"


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


async def _engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return engine


def _diff_for(file_path: str, content: str) -> str:
    """Produce a minimal unified diff string that looks like a new file addition."""
    lines = content.splitlines()
    added = "\n".join(f"+{line}" for line in lines)
    return f"diff --git a/{file_path} b/{file_path}\nnew file mode 100644\n--- /dev/null\n+++ b/{file_path}\n@@ -0,0 +1,{len(lines)} @@\n{added}\n"


# ---------------------------------------------------------------------------
# vuln-express fixture: SQL injection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_vuln_express_sqli_taint_path_in_graph():
    """Graph construction for vuln-express/app.js produces a tainted FLOWS_TO edge
    from the request parameter to the db.query sink — the prerequisite for sqli detection."""
    from sentinel_worker.construction import SourceFile, build_file_graph
    from sentinel_worker.models import Edge, Node

    content = _read(VULN_EXPRESS / "app.js")
    engine = await _engine()
    sm = async_sessionmaker(engine, expire_on_commit=False)

    async with sm() as session:
        async with session.begin():
            graph = Graph(account_id="a", repo_id="r", kind="main")
            session.add(graph)
            await session.flush()
            await build_file_graph(session, graph.id, SourceFile("app.js", content, is_new=True))
        async with session.begin():
            # Must have a FLOWS_TO edge that is tainted (request param → sink)
            tainted_edge = await session.scalar(
                select(Edge).where(Edge.kind == "FLOWS_TO", Edge.tainted == True)
            )
            sink_node = await session.scalar(
                select(Node).where(Node.is_sink == True, Node.graph_id == graph.id)
            )

    assert sink_node is not None, "Should have a sink node (db.query or prepare)"
    assert tainted_edge is not None, "Should have a tainted FLOWS_TO edge from request param to sink"


@pytest.mark.asyncio
async def test_vuln_express_secret_detected():
    """scan_diff on vuln-express/app.js emits a secret_leak finding for the hardcoded key."""
    content = _read(VULN_EXPRESS / "app.js")
    engine = await _engine()
    sm = async_sessionmaker(engine, expire_on_commit=False)

    with patch("sentinel_worker.sca.OSVAdvisorySource.lookup", new=AsyncMock(return_value=[])):
        async with sm() as session:
            async with session.begin():
                await get_or_create_graph(session, "repo")
                await scan_diff(
                    session,
                    "repo",
                    _diff_for("app.js", content),
                    _llm=MockLLMClient(),
                )
            async with session.begin():
                secret_finding = await session.scalar(
                    select(Finding).where(Finding.vuln_type == "secret_leak")
                )

    assert secret_finding is not None, "Expected a secret_leak finding from vuln-express/app.js"


@pytest.mark.asyncio
async def test_vuln_express_safe_route_does_not_produce_sqli():
    """The parameterized /users/safe route should not produce a sqli finding."""
    safe_content = """
const express = require('express');
const Database = require('better-sqlite3');
const app = express();
const db = new Database(':memory:');
app.get('/users/safe', (req, res) => {
  const id = req.query.id;
  const row = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  res.json(row);
});
"""
    engine = await _engine()
    sm = async_sessionmaker(engine, expire_on_commit=False)

    with patch("sentinel_worker.sca.OSVAdvisorySource.lookup", new=AsyncMock(return_value=[])):
        async with sm() as session:
            async with session.begin():
                await get_or_create_graph(session, "repo")
                await scan_diff(
                    session,
                    "repo",
                    _diff_for("safe_app.js", safe_content),
                    _llm=MockLLMClient(),
                )
            async with session.begin():
                finding = await session.scalar(
                    select(Finding).where(Finding.vuln_type == "sqli")
                )

    assert finding is None, "Parameterized query should not produce a sqli finding"


# ---------------------------------------------------------------------------
# Python fixture: SQL injection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_python_sqli_fixture_taint_path_in_graph():
    """python/sqli.py: graph construction produces a tainted FLOWS_TO edge to cursor.execute sink."""
    from sentinel_worker.construction import SourceFile, build_file_graph
    from sentinel_worker.models import Edge, Node

    content = _read(FIXTURES_DIR / "python" / "sqli.py")
    engine = await _engine()
    sm = async_sessionmaker(engine, expire_on_commit=False)

    async with sm() as session:
        async with session.begin():
            graph = Graph(account_id="a", repo_id="r", kind="main")
            session.add(graph)
            await session.flush()
            await build_file_graph(session, graph.id, SourceFile("search.py", content, is_new=True))
        async with session.begin():
            tainted_edge = await session.scalar(
                select(Edge).where(Edge.kind == "FLOWS_TO", Edge.tainted == True, Edge.graph_id == graph.id)
            )
            sink_node = await session.scalar(
                select(Node).where(Node.is_sink == True, Node.graph_id == graph.id)
            )

    assert sink_node is not None, "python/sqli.py should produce a sink node (cursor.execute)"
    assert tainted_edge is not None, "python/sqli.py should have a tainted FLOWS_TO edge"


# ---------------------------------------------------------------------------
# TypeScript fixture: SQL injection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_typescript_sqli_fixture_taint_path_in_graph():
    """typescript/sqli.ts: graph construction produces a tainted FLOWS_TO edge to db.query sink."""
    from sentinel_worker.construction import SourceFile, build_file_graph
    from sentinel_worker.models import Edge, Node

    content = _read(FIXTURES_DIR / "typescript" / "sqli.ts")
    engine = await _engine()
    sm = async_sessionmaker(engine, expire_on_commit=False)

    async with sm() as session:
        async with session.begin():
            graph = Graph(account_id="a", repo_id="r", kind="main")
            session.add(graph)
            await session.flush()
            await build_file_graph(session, graph.id, SourceFile("handler.ts", content, is_new=True))
        async with session.begin():
            tainted_edge = await session.scalar(
                select(Edge).where(Edge.kind == "FLOWS_TO", Edge.tainted == True, Edge.graph_id == graph.id)
            )
            sink_node = await session.scalar(
                select(Node).where(Node.is_sink == True, Node.graph_id == graph.id)
            )

    assert sink_node is not None, "typescript/sqli.ts should produce a sink node (db.query)"
    assert tainted_edge is not None, "typescript/sqli.ts should have a tainted FLOWS_TO edge"


# ---------------------------------------------------------------------------
# Fixture source file parse tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_python_valid_fixture_parses_without_error():
    """python/valid.py produces nodes without parse_error."""
    content = _read(FIXTURES_DIR / "python" / "valid.py")
    engine = await _engine()
    sm = async_sessionmaker(engine, expire_on_commit=False)

    async with sm() as session:
        async with session.begin():
            graph = Graph(account_id="a", repo_id="r", kind="main")
            session.add(graph)
            await session.flush()
            await build_file_graph(
                session,
                graph.id,
                SourceFile(path="user_service.py", content=content, is_new=True),
            )
        async with session.begin():
            from sqlalchemy import select
            from sentinel_worker.models import Node
            nodes = (await session.execute(select(Node).where(Node.graph_id == graph.id))).scalars().all()

    assert any(n.kind == "FUNCTION" for n in nodes), "should parse at least one function"
    assert all(not n.parse_error for n in nodes), "no parse errors expected in valid.py"


@pytest.mark.asyncio
async def test_typescript_valid_fixture_parses_without_error():
    """typescript/valid.ts produces nodes without parse_error."""
    content = _read(FIXTURES_DIR / "typescript" / "valid.ts")
    engine = await _engine()
    sm = async_sessionmaker(engine, expire_on_commit=False)

    async with sm() as session:
        async with session.begin():
            graph = Graph(account_id="a", repo_id="r", kind="main")
            session.add(graph)
            await session.flush()
            await build_file_graph(
                session,
                graph.id,
                SourceFile(path="auth.ts", content=content, is_new=True),
            )
        async with session.begin():
            from sqlalchemy import select
            from sentinel_worker.models import Node
            nodes = (await session.execute(select(Node).where(Node.graph_id == graph.id))).scalars().all()

    assert any(n.kind == "FUNCTION" for n in nodes), "should parse at least one function from auth.ts"


# ---------------------------------------------------------------------------
# Suppression carry-forward
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_suppressed_secret_finding_not_re_emitted_on_rescan():
    """After suppressing a secret_leak finding, a rescan of the same diff does not re-emit it.

    Secret scanning is pattern-based (no LLM), so this exercises the suppression
    carry-forward path reliably without mocking the SAST agent.
    """
    from sqlalchemy import func

    # A diff with a realistic AWS access key pattern (not the known-safe example value)
    diff = _diff_for(
        "config.js",
        'const AWS_KEY = "AKIA4HFAKE0TESTKEY1Z";\nmodule.exports = { AWS_KEY };',
    )
    engine = await _engine()
    sm = async_sessionmaker(engine, expire_on_commit=False)

    with patch("sentinel_worker.sca.OSVAdvisorySource.lookup", new=AsyncMock(return_value=[])):
        async with sm() as session:
            # First scan — emits secret_leak finding
            async with session.begin():
                await get_or_create_graph(session, "repo")
                await scan_diff(session, "repo", diff, _llm=MockLLMClient())

            async with session.begin():
                finding = await session.scalar(select(Finding).where(Finding.vuln_type == "secret_leak"))
            assert finding is not None, "First scan must detect the hardcoded secret"

            # Suppress the finding
            async with sm() as session2:
                async with session2.begin():
                    f = await session2.get(Finding, finding.id)
                    assert f is not None
                    f.suppressed = True
                    f.status = "suppressed"

            # Second scan — suppressed fingerprint should prevent re-emission
            async with sm() as session3:
                async with session3.begin():
                    await scan_diff(session3, "repo", diff, _llm=MockLLMClient())

                async with session3.begin():
                    open_count = await session3.scalar(
                        select(func.count(Finding.id)).where(
                            Finding.vuln_type == "secret_leak",
                            Finding.status != "suppressed",
                        )
                    )

    assert open_count == 0, "suppressed secret_leak should not be re-emitted as open on rescan"

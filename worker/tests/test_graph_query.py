import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.graph_query import GraphQuery
from sentinel_worker.models import Base, Edge, Finding, Graph, Node
from sentinel_worker.oracle import OracleResult


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

async def _make_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    from sqlalchemy.ext.asyncio import async_sessionmaker as asm
    return asm(engine, expire_on_commit=False)


# ---------------------------------------------------------------------------
# G6: GraphQuery extra tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_neighbors_with_cycle_terminates_at_max_hops():
    """neighbors() with a cycle in graph terminates at max_hops."""
    sessionmaker = await _make_session()
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            # Create a simple cycle: A -> B -> A
            session.add_all([
                Node(id="n:A", graph_id=graph.id, kind="FUNCTION", name="A"),
                Node(id="n:B", graph_id=graph.id, kind="FUNCTION", name="B"),
            ])
            session.add_all([
                Edge(graph_id=graph.id, src="n:A", dst="n:B", kind="CALLS"),
                Edge(graph_id=graph.id, src="n:B", dst="n:A", kind="CALLS"),
            ])
            await session.flush()
            query = GraphQuery(session, graph.id)
            # max_hops=3 → should not infinite-loop
            neighbors = await query.neighbors("n:A", ["CALLS"], max_hops=3)
        # Should return some neighbors but terminate cleanly
        assert isinstance(neighbors, list)
        node_ids = [n.node.id for n in neighbors]
        # n:B must appear; A may appear once via cycle
        assert "n:B" in node_ids


@pytest.mark.asyncio
async def test_paths_returns_empty_for_disconnected_nodes():
    """paths() returns empty list for disconnected nodes."""
    sessionmaker = await _make_session()
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            session.add_all([
                Node(id="n:X", graph_id=graph.id, kind="FUNCTION", name="X"),
                Node(id="n:Y", graph_id=graph.id, kind="FUNCTION", name="Y"),
            ])
            # No edges between X and Y
            await session.flush()
            query = GraphQuery(session, graph.id)
            paths = await query.paths("n:X", "n:Y")
        assert paths == []


@pytest.mark.asyncio
async def test_serialize_for_prompt_is_deterministic():
    """serialize_for_prompt() produces deterministic output."""
    sessionmaker = await _make_session()
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            session.add_all([
                Node(id="n:A", graph_id=graph.id, kind="ROUTE", name="GET /users",
                     file="app.js", is_entry_point=True, label="Users route", intent="Returns users"),
                Node(id="n:B", graph_id=graph.id, kind="FUNCTION", name="db.query",
                     file="db.js", is_sink=True),
            ])
            session.add(Edge(graph_id=graph.id, src="n:A", dst="n:B", kind="CALLS"))
            await session.flush()
            query = GraphQuery(session, graph.id)
            first = await query.serialize_for_prompt(["n:A"], max_hops=1)
            second = await query.serialize_for_prompt(["n:A"], max_hops=1)
        assert first == second
        assert "GET /users" in first
        assert len(first) > 0


@pytest.mark.asyncio
async def test_serialize_for_prompt_correct_format():
    """serialize_for_prompt() has correct format with labels and intent."""
    sessionmaker = await _make_session()
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            session.add_all([
                Node(id="n:route", graph_id=graph.id, kind="ROUTE", name="GET /items",
                     file="app.js", is_entry_point=True,
                     label="Items endpoint", intent="Returns all items."),
            ])
            await session.flush()
            query = GraphQuery(session, graph.id)
            serialized = await query.serialize_for_prompt(["n:route"], max_hops=1)
        assert "GET /items" in serialized
        # Route with no guard should emit GUARDED_BY none
        assert "GUARDED_BY  none" in serialized


@pytest.mark.asyncio
async def test_taint_paths_returns_paths_from_untrusted_params_to_sinks():
    """taint_paths() returns paths from untrusted params to sinks."""
    sessionmaker = await _make_session()
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            session.add_all([
                Node(id="param:req.id", graph_id=graph.id, kind="PARAMETER",
                     name="req.id", trust_level="untrusted"),
                Node(id="fn:exec", graph_id=graph.id, kind="FUNCTION",
                     name="db.exec", file="db.js", is_sink=True),
            ])
            session.add(Edge(graph_id=graph.id, src="param:req.id", dst="fn:exec",
                             kind="FLOWS_TO", tainted=True))
            await session.flush()
            query = GraphQuery(session, graph.id)
            taint = await query.taint_paths()
        assert len(taint) == 1
        assert taint[0][0].id == "param:req.id"
        assert taint[0][-1].id == "fn:exec"


@pytest.mark.asyncio
async def test_taint_paths_trusted_param_not_included():
    """taint_paths() does not include paths from trusted params."""
    sessionmaker = await _make_session()
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            session.add_all([
                Node(id="param:trusted", graph_id=graph.id, kind="PARAMETER",
                     name="trusted_param", trust_level="trusted"),
                Node(id="fn:sink", graph_id=graph.id, kind="FUNCTION",
                     name="db.query", file="db.js", is_sink=True),
            ])
            session.add(Edge(graph_id=graph.id, src="param:trusted", dst="fn:sink",
                             kind="FLOWS_TO", tainted=True))
            await session.flush()
            query = GraphQuery(session, graph.id)
            taint = await query.taint_paths()
        # trusted param → no taint paths
        assert len(taint) == 0


# ---------------------------------------------------------------------------
# Original comprehensive test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_neighbors_paths_taint_and_confirmation():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            nodes = [
                Node(id="param:req.query.id", graph_id=graph.id, kind="PARAMETER", name="req.query.id", trust_level="untrusted"),
                Node(id="fn:handler", graph_id=graph.id, kind="ROUTE", name="GET /users", file="app.js", line_start=3, is_entry_point=True, label="Users endpoint", intent="Returns users."),
                Node(id="fn:query", graph_id=graph.id, kind="FUNCTION", name="db.query", file="db/users.js", line_start=9, is_sink=True),
                Node(id="fn:normalize", graph_id=graph.id, kind="FUNCTION", name="normalize", file="lib/normalize.js", line_start=1),
            ]
            session.add_all(nodes)
            session.add_all(
                [
                    Edge(graph_id=graph.id, src="fn:handler", dst="fn:query", kind="CALLS", call_uncertainty="cross_service"),
                    Edge(graph_id=graph.id, src="param:req.query.id", dst="fn:query", kind="FLOWS_TO", tainted=True, taint_uncertain=True),
                    Edge(graph_id=graph.id, src="fn:query", dst="fn:normalize", kind="CALLS"),
                ]
            )
            finding = Finding(
                graph_id=graph.id,
                node_id="fn:query",
                vuln_type="sqli",
                severity="high",
                title="SQLi",
                description="SQLi",
                remediation="parameterize",
                fingerprint="fp",
            )
            session.add(finding)
            await session.flush()
            query = GraphQuery(session, graph.id)
            neighbors = await query.neighbors("fn:handler", ["CALLS"])
            paths = await query.paths("fn:handler", "fn:query", ["CALLS"])
            taint = await query.taint_paths()
            serialized = await query.serialize_for_prompt(["fn:handler", "param:req.query.id"], max_hops=2)
            serialized_again = await query.serialize_for_prompt(["fn:handler", "param:req.query.id"], max_hops=2)
            confirmed = await query.confirm_exploit("fn:handler", "fn:query", finding.id, OracleResult(True, "behavioral", "auth_bypassed"))

        assert neighbors[0].node.id == "fn:query"
        assert [[node.id for node in path] for path in paths] == [["fn:handler", "fn:query"]]
        assert [[node.id for node in path] for path in taint] == [["param:req.query.id", "fn:query"]]
        assert "GET /users" in serialized
        assert serialized == serialized_again
        assert 'label: "Users endpoint"' in serialized
        assert "-> GUARDED_BY  none" in serialized
        assert "call_uncertainty=cross_service" in serialized
        assert "tainted=true" in serialized
        assert "taint_uncertain=true" in serialized
        assert "[MODULE] lib -- 1 function" in serialized
        assert confirmed.confirmed is True

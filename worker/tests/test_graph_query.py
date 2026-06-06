import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.graph_query import GraphQuery
from sentinel_worker.models import Base, Edge, Finding, Graph, Node
from sentinel_worker.oracle import OracleResult


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
                Node(id="fn:handler", graph_id=graph.id, kind="ROUTE", name="GET /users", is_entry_point=True),
                Node(id="fn:query", graph_id=graph.id, kind="FUNCTION", name="db.query", is_sink=True),
            ]
            session.add_all(nodes)
            session.add_all(
                [
                    Edge(graph_id=graph.id, src="fn:handler", dst="fn:query", kind="CALLS"),
                    Edge(graph_id=graph.id, src="param:req.query.id", dst="fn:query", kind="FLOWS_TO", tainted=True),
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
            serialized = await query.serialize_for_prompt(["fn:handler"])
            confirmed = await query.confirm_exploit("fn:handler", "fn:query", finding.id, OracleResult(True, "behavioral", "auth_bypassed"))

        assert neighbors[0].node.id == "fn:query"
        assert [[node.id for node in path] for path in paths] == [["fn:handler", "fn:query"]]
        assert [[node.id for node in path] for path in taint] == [["param:req.query.id", "fn:query"]]
        assert "GET /users" in serialized
        assert confirmed.confirmed is True

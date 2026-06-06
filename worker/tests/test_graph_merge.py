import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.graph_merge import merge_graph
from sentinel_worker.models import Base, Edge, Graph, Node


@pytest.mark.asyncio
async def test_merge_graph_copies_nodes_edges_and_clears_is_new():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            main = Graph(account_id="acct", repo_id="repo", kind="main")
            branch = Graph(account_id="acct", repo_id="repo", kind="branch", parent_id=main.id, branch_name="feature")
            session.add_all([main, branch])
            await session.flush()
            session.add_all(
                [
                    Node(id="route:app.js:GET /x", graph_id=branch.id, kind="ROUTE", name="GET /x", is_new=True),
                    Node(id="fn:app.js:sink", graph_id=branch.id, kind="FUNCTION", name="sink", is_sink=True, is_new=True),
                ]
            )
            await session.flush()
            session.add(Edge(graph_id=branch.id, src="route:app.js:GET /x", dst="fn:app.js:sink", kind="CONFIRMED_EXPLOIT"))
            copied = await merge_graph(session, branch_graph_id=branch.id, main_graph_id=main.id)
        async with session.begin():
            merged_route = await session.get(Node, "route:app.js:GET /x")
            exploit = await session.scalar(select(Edge).where(Edge.graph_id == main.id).where(Edge.kind == "CONFIRMED_EXPLOIT"))
            stored_branch = await session.get(Graph, branch.id)
    assert copied == 3
    assert merged_route is not None
    assert merged_route.graph_id == main.id
    assert merged_route.is_new is False
    assert exploit is not None
    assert stored_branch is not None
    assert stored_branch.status == "merged"

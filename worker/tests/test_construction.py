import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.construction import SourceFile, build_file_graph
from sentinel_worker.models import Base, Edge, Graph, Node


@pytest.mark.asyncio
async def test_build_file_graph_extracts_route_sink_and_taint_edge():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            await build_file_graph(
                session,
                graph.id,
                SourceFile(
                    path="app.js",
                    content="app.get('/u', auth, (req, res) => db.query(`select * from users where id=${req.query.id}`));",
                    is_new=True,
                ),
            )
        async with session.begin():
            route = await session.get(Node, "route:app.js:GET /u")
            param = await session.get(Node, "param:app.js:request")
            sink = await session.get(Node, "fn:app.js:db.query")
            flow = await session.scalar(select(Edge).where(Edge.kind == "FLOWS_TO"))

    assert route is not None
    assert route.auth_required is True
    assert param is not None
    assert param.trust_level == "untrusted"
    assert sink is not None
    assert sink.is_sink is True
    assert flow is not None
    assert flow.tainted is True

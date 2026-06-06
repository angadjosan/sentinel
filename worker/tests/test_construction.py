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


@pytest.mark.asyncio
async def test_express_adapter_emits_ordered_guard_edges():
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
                    content="app.get('/admin', auth, authorizeAdmin, (req, res) => res.json({ ok: true }));",
                    is_new=True,
                ),
            )
        async with session.begin():
            route = await session.get(Node, "route:app.js:GET /admin")
            guards = (
                await session.execute(
                    select(Edge).where(Edge.kind == "GUARDED_BY").where(Edge.src == "route:app.js:GET /admin").order_by(Edge.order_index)
                )
            ).scalars().all()
            guard_nodes = [await session.get(Node, edge.dst) for edge in guards]

    assert route is not None
    assert route.auth_required is True
    assert [edge.order_index for edge in guards] == [1, 2]
    assert [node.name for node in guard_nodes if node is not None] == ["auth", "authorizeAdmin"]


@pytest.mark.asyncio
async def test_build_file_graph_marks_parse_error_and_skips_children():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            nodes = await build_file_graph(session, graph.id, SourceFile(path="broken.js", content="function broken( {", is_new=True))
        async with session.begin():
            file_node = await session.get(Node, "file:broken.js")
            functions = list(await session.scalars(select(Node).where(Node.file == "broken.js").where(Node.kind == "FUNCTION")))
    assert [node.kind for node in nodes] == ["FILE"]
    assert file_node is not None
    assert file_node.parse_error is True
    assert functions == []


@pytest.mark.asyncio
async def test_build_file_graph_emits_import_edges_and_dynamic_dispatch_uncertainty():
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
                SourceFile(path="dispatch.js", content="import lodash from 'lodash';\nhandlers[method](req);", is_new=True),
            )
        async with session.begin():
            dep = await session.get(Node, "dep:lodash")
            import_edge = await session.scalar(select(Edge).where(Edge.kind == "IMPORTS").where(Edge.dst == "dep:lodash"))
            dynamic = await session.get(Node, "fn:dispatch.js:handlers[method]")
            dynamic_edge = await session.scalar(select(Edge).where(Edge.kind == "CALLS").where(Edge.dst == "fn:dispatch.js:handlers[method]"))

    assert dep is not None
    assert dep.kind == "DEPENDENCY"
    assert import_edge is not None
    assert dynamic is not None
    assert dynamic_edge is not None
    assert dynamic_edge.call_uncertainty == "dynamic_dispatch"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "content", "route_id", "auth_required"),
    [
        ("src/app/api/users/route.ts", "export async function GET() { return Response.json({}); }", "route:src/app/api/users/route.ts:GET /api/users", False),
        ("urls.py", "urlpatterns = [path('admin/users', login_required(view))]", "route:urls.py:ANY /admin/users", True),
        ("config/routes.rb", "get '/admin/users', to: 'users#index'\nbefore_action :authenticate_user!", "route:config/routes.rb:GET /admin/users", True),
        ("UserController.java", "@PreAuthorize(\"hasRole('ADMIN')\")\n@GetMapping(\"/admin/users\")\nList<User> users() { return List.of(); }", "route:UserController.java:GET /admin/users", True),
    ],
)
async def test_framework_adapters_extract_routes(path: str, content: str, route_id: str, auth_required: bool):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            await build_file_graph(session, graph.id, SourceFile(path=path, content=content, is_new=True))
        async with session.begin():
            route = await session.get(Node, route_id)
    assert route is not None
    assert route.is_entry_point is True
    assert route.auth_required is auth_required

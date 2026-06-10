from fastapi.testclient import TestClient
from uuid import uuid4

import sentinel_api.deps as deps
from sentinel_api.main import app
from sentinel_worker.models import Edge, Graph, Node


def test_admin_graph_merge_endpoint():
    import asyncio
    suffix = uuid4().hex
    route_id = f"route:merge-api-{suffix}:GET /x"
    sink_id = f"fn:merge-api-{suffix}:sink"

    async def seed():
        # Use deps.SessionLocal at call time so the _isolated_db monkeypatch applies.
        async with deps.SessionLocal() as session:
            async with session.begin():
                main = Graph(account_id="dev", repo_id="repo-admin-merge", kind="main")
                branch = Graph(account_id="dev", repo_id="repo-admin-merge", kind="branch", branch_name="feature")
                session.add_all([main, branch])
                await session.flush()
                session.add_all(
                    [
                        Node(id=route_id, graph_id=branch.id, kind="ROUTE", name="GET /x", is_new=True),
                        Node(id=sink_id, graph_id=branch.id, kind="FUNCTION", name="sink", is_sink=True, is_new=True),
                    ]
                )
                await session.flush()
                session.add(Edge(graph_id=branch.id, src=route_id, dst=sink_id, kind="CALLS"))
                return branch.id, main.id

    loop = asyncio.new_event_loop()
    branch_id, main_id = loop.run_until_complete(seed())
    loop.close()

    with TestClient(app) as client:
        response = client.post("/admin/graphs/merge", json={"branch_graph_id": branch_id, "main_graph_id": main_id})
    assert response.status_code == 200
    assert response.json()["copied"] == 3

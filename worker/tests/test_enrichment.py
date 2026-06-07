import json

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.agent import LLMCallResult, SentinelLLMClient
from sentinel_worker.construction import SourceFile, build_file_graph
from sentinel_worker.enrichment import enrich_graph_nodes
from sentinel_worker.models import Base, Graph, Node, Run, TokenSpendByComponent


class RecordingProvider:
    provider = "fixture"

    def __init__(self):
        self.system = ""
        self.data = ""

    async def complete(self, *, system: str, data: str, model: str) -> LLMCallResult:
        self.system = system
        self.data = data
        payload = json.loads(data)
        annotations = [
            {
                "node_id": node["id"],
                "label": f"annotated {node['kind'].lower()}",
                "intent": f"{node['name']} was annotated from graph and source context.",
                "trust_level": "trusted" if node["auth_required"] else "untrusted",
            }
            for node in payload["nodes"]
        ]
        return LLMCallResult(content=json.dumps({"annotations": annotations}), input_tokens=17, output_tokens=11, model=model, provider=self.provider)


@pytest.mark.asyncio
async def test_enrichment_updates_new_nodes_and_records_tokens():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    provider = RecordingProvider()
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            run = Run(graph_id=graph.id, kind="init")
            session.add(run)
            await session.flush()
            await build_file_graph(session, graph.id, SourceFile(path="app.js", content="app.get('/u', auth, (req, res) => res.json({ ok: true }));", is_new=True))
            count = await enrich_graph_nodes(
                session,
                graph_id=graph.id,
                run_id=run.id,
                llm=SentinelLLMClient(provider=provider, model="fixture-model"),
                source_by_file={"app.js": "app.get('/u', auth, (req, res) => res.json({ ok: true }));"},
            )
        async with session.begin():
            route = await session.get(Node, "route:app.js:GET /u")
            aggregate = await session.get(TokenSpendByComponent, (run.id, "semantic_enrichment", "fixture-model"))
            stored = await session.get(Run, run.id)

    assert count > 0
    assert route is not None
    assert route.label == "annotated route"
    assert route.intent == "GET /u was annotated from graph and source context."
    assert route.trust_level == "trusted"
    assert aggregate is not None
    assert aggregate.input_tokens == 17
    assert stored is not None
    assert stored.token_spend == 28
    assert "app.get('/u'" in provider.data
    assert "app.get('/u'" not in provider.system


@pytest.mark.asyncio
async def test_validation_loop_reenriches_auth_nodes_without_guarded_by():
    """Nodes labeled 'auth middleware' but with no GUARDED_BY edge must be re-enriched."""
    from sentinel_worker.enrichment import validate_enrichment_labels
    from sentinel_worker.models import Edge

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    calls: list[str] = []

    class CapturingProvider:
        provider = "fixture"

        async def complete(self, *, system: str, data: str, model: str) -> LLMCallResult:
            calls.append(system)
            payload = json.loads(data)
            annotations = [{"node_id": n["id"], "label": "corrected auth guard", "intent": "Fixed label.", "trust_level": "trusted"} for n in payload["nodes"]]
            return LLMCallResult(content=json.dumps({"annotations": annotations}), input_tokens=5, output_tokens=5, model=model, provider=self.provider)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            run = Run(graph_id=graph.id, kind="init")
            session.add(run)
            await session.flush()
            # Create a node labeled 'auth' but with no GUARDED_BY edge
            node = Node(
                id="fn:app.js:checkAuth",
                graph_id=graph.id,
                kind="FUNCTION",
                name="checkAuth",
                file="app.js",
                label="auth middleware",
                intent="Validates authentication token.",
                is_new=True,
            )
            session.add(node)

        provider = CapturingProvider()
        async with session.begin():
            count = await validate_enrichment_labels(
                session,
                graph_id=graph.id,
                run_id=run.id,
                llm=SentinelLLMClient(provider=provider, model="fixture-model"),
            )
            reloaded = await session.get(Node, "fn:app.js:checkAuth")

    assert count == 1
    assert len(calls) == 1
    assert "CRITICAL" in calls[0]  # clarifying prompt injected
    assert reloaded is not None
    assert reloaded.label == "corrected auth guard"


@pytest.mark.asyncio
async def test_validation_loop_skips_nodes_with_guarded_by_edge():
    """Nodes labeled 'auth' that DO have a GUARDED_BY edge must not be re-enriched."""
    from sentinel_worker.enrichment import validate_enrichment_labels
    from sentinel_worker.models import Edge

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    calls: list[str] = []

    class CapturingProvider:
        provider = "fixture"

        async def complete(self, *, system: str, data: str, model: str) -> LLMCallResult:
            calls.append(system)
            return LLMCallResult(content=json.dumps({"annotations": []}), input_tokens=1, output_tokens=1, model=model, provider=self.provider)

    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            graph = Graph(account_id="acct", repo_id="repo", kind="main")
            session.add(graph)
            await session.flush()
            run = Run(graph_id=graph.id, kind="init")
            session.add(run)
            await session.flush()
            route = Node(id="route:app.js:GET /u", graph_id=graph.id, kind="ROUTE", name="GET /u", file="app.js", label="auth route")
            guard = Node(id="fn:app.js:checkAuth", graph_id=graph.id, kind="FUNCTION", name="checkAuth", file="app.js", label="auth middleware")
            session.add_all([route, guard])
            await session.flush()
            # GUARDED_BY edge present — should not trigger re-enrichment
            session.add(Edge(graph_id=graph.id, src="route:app.js:GET /u", dst="fn:app.js:checkAuth", kind="GUARDED_BY"))

        provider = CapturingProvider()
        async with session.begin():
            count = await validate_enrichment_labels(
                session,
                graph_id=graph.id,
                run_id=run.id,
                llm=SentinelLLMClient(provider=provider, model="fixture-model"),
            )

    assert count == 0
    assert len(calls) == 0

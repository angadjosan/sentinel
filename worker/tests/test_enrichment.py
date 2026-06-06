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

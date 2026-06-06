import json

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.agent import ChannelViolationError, SentinelLLMClient
from sentinel_worker.models import Base, Run, TokenSpendByComponent


@pytest.mark.asyncio
async def test_llm_client_rejects_repo_content_in_system_prompt():
    client = SentinelLLMClient()
    with pytest.raises(ChannelViolationError):
        await client.call(system="Scan this db.query(req.query.id)", data="", component="sast")


@pytest.mark.asyncio
async def test_llm_client_records_token_event_on_run():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
        async with session.begin():
            run = Run(graph_id="graph", kind="source")
            session.add(run)
            await session.flush()
            result = await SentinelLLMClient().call(
                system="You are a security reviewer.",
                data="repo code lives in data channel",
                component="sast",
                db=session,
                run_id=run.id,
                iteration=3,
            )
        async with session.begin():
            stored = await session.get(Run, run.id)
            aggregate = await session.get(TokenSpendByComponent, (run.id, "sast", "ollama"))
    assert stored is not None
    assert aggregate is not None
    assert stored.token_spend == result.input_tokens + result.output_tokens
    assert aggregate.input_tokens == result.input_tokens
    assert aggregate.output_tokens == result.output_tokens
    event = json.loads(stored.trace.splitlines()[-1])
    assert event["kind"] == "token_event"
    assert event["component"] == "sast"
    assert event["iteration"] == 3

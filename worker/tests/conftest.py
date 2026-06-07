import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from sentinel_worker.models import Base


@pytest_asyncio.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as session:
        async with session.begin():
            yield session
    await engine.dispose()


class MockLLMClient:
    """Test mock — accepts both calling conventions used in the codebase.

    Enrichment calls: call(system=..., data=..., component=..., db=..., run_id=...)
    SAST/other calls: call(system=..., user=...) or call_with_tools(...)

    Returns an LLMCallResult-compatible object so callers can do result.content.
    """

    def __init__(self, tool_responses: list | None = None):
        self.tool_responses = tool_responses or []
        self._call_count = 0
        self.calls = []

    async def call(self, *, system: str, user: str | None = None, data: str | None = None, **kwargs):
        from sentinel_worker.agent import LLMCallResult
        content_input = user or data or ""
        self.calls.append({"system": system, "content_input": content_input})
        # Return an empty but valid annotations payload for enrichment calls
        if data is not None:
            import json as _json
            try:
                payload = _json.loads(data)
                nodes = payload.get("nodes", [])
                annotations = [{"node_id": n["id"], "label": n.get("name", ""), "intent": ""} for n in nodes]
                content = _json.dumps({"annotations": annotations})
            except Exception:
                content = '{"annotations": []}'
        else:
            content = ""
        return LLMCallResult(content=content, input_tokens=0, output_tokens=0, model="mock", provider="mock")

    async def call_with_tools(self, *, system, user, tools, tool_dispatcher, max_iterations=50, **kwargs):
        self.calls.append({"system": system, "user": user})
        for resp in self.tool_responses:
            yield resp
        # Empty by default (no findings from mock)


@pytest.fixture
def mock_llm():
    return MockLLMClient()

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
    """Test mock - replays fixture responses, raises on unknown calls."""

    def __init__(self, tool_responses: list | None = None):
        self.tool_responses = tool_responses or []
        self._call_count = 0
        self.calls = []

    async def call(self, *, system: str, user: str, **kwargs) -> str:
        self.calls.append({"system": system, "user": user})
        return ""

    async def call_with_tools(self, *, system, user, tools, tool_dispatcher, max_iterations=50, **kwargs):
        self.calls.append({"system": system, "user": user})
        for resp in self.tool_responses:
            yield resp
        # Empty by default (no findings from mock)


@pytest.fixture
def mock_llm():
    return MockLLMClient()

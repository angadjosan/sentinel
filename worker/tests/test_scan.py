import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from sqlalchemy import select

from sentinel_worker.models import Base, Edge, Finding, Node
from sentinel_worker.scan import parse_unified_diff, scan_diff


@pytest.mark.asyncio
async def test_scan_diff_emits_sql_injection_finding():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
      async with session.begin():
        run = await scan_diff(session, "repo", "+++ b/app.js\n+app.get('/u', (req,res)=> db.query(`select * from users where id=${req.query.id}`))")
      async with session.begin():
        finding = await session.get(Finding, (await session.execute(Finding.__table__.select())).first()[0])
    assert run.status == "completed"
    assert finding.vuln_type == "sqli"


@pytest.mark.asyncio
async def test_scan_diff_populates_context_graph():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
      async with session.begin():
        await scan_diff(session, "repo", "+++ b/app.js\n+app.get('/u', (req,res)=> db.query(`select * from users where id=${req.query.id}`))")
      async with session.begin():
        route = await session.get(Node, "route:app.js:GET /u")
        flow = await session.scalar(select(Edge).where(Edge.kind == "FLOWS_TO"))
    assert route is not None
    assert route.is_entry_point is True
    assert flow is not None


def test_parse_unified_diff_collects_added_lines():
    files = parse_unified_diff("diff --git a/a b/a\n+++ b/a.py\n+print('x')\n unchanged")
    assert files[0].path == "a.py"
    assert "print" in files[0].content

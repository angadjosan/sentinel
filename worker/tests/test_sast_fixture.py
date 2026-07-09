"""SAST ground-truth fixture test (AUDIT.md §6 W4 P3.3 / Gate 3).

Restores a real SQLi source fixture on disk and drives a local scan through the
*tool boundary*: the LLM stub reads the file via the `read_file` tool and only
emits a finding after it has seen the vulnerable line the tool returned. It
never regex-matches the diff.

Why this shape matters (the "no fake-green" invariant):

  - The stub returns *without* emitting for the SAFE fixture (parameterized
    query) — so a scanner that blindly flags every file would fail this test.
  - The stub emits for the VULNERABLE fixture only because `read_file` handed
    back the interpolated `cursor.execute(f"...{q}...")` line. If `read_file`
    or `emit_finding` were deleted / broken, the finding would not appear and
    the test would fail. That is the property Gate 3 requires: the test
    measures the real tool path, not a regex on the diff text.

Contrast with `_PatternLLM` in api/tests/conftest.py, which pattern-matches the
diff — that mock is only appropriate for webhook smoke tests, not for proving
the SAST engine actually reads source.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from sentinel_worker.agent import ToolCallEvent
from sentinel_worker.local_engine import run_local_source_scan

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "source"


@pytest.fixture(autouse=True)
def _isolated_trace_home(tmp_path_factory, monkeypatch):
    """`run_local_source_scan` persists a trace to Path.home()/.sentinel/runs —
    isolate that from the developer's real home directory for the test run."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setattr(Path, "home", lambda: home)


def _diff_for(file_path: str, content: str) -> str:
    lines = content.splitlines()
    added = "\n".join(f"+{line}" for line in lines)
    return (
        f"diff --git a/{file_path} b/{file_path}\n"
        f"new file mode 100644\n--- /dev/null\n+++ b/{file_path}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n{added}\n"
    )


class _ReadFileThenEmitLLM:
    """SAST stub that emits a sqli finding ONLY after reading the vulnerable
    line back through the `read_file` tool.

    This is the tool-boundary contract: no regex on the diff. It reads the two
    routes and confirms the tainted, string-interpolated `cursor.execute(...)`
    is present (vulnerable route) while the parameterized `execute(..., (...))`
    is the safe route. It emits exactly one high-severity sqli finding.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.read_content: str | None = None
        self.emitted = False

    async def call_with_tools(self, *, system, user, tools, tool_dispatcher, max_iterations=50, **kwargs):
        read_result = await tool_dispatcher("read_file", {"file_path": self.file_path})
        self.read_content = read_result.get("content")
        content = self.read_content or ""
        # The vulnerable route interpolates the request param straight into SQL.
        vulnerable = 'cursor.execute(f"SELECT' in content or "cursor.execute(f'SELECT" in content
        if not vulnerable:
            return  # nothing to report — do NOT flag on the file's mere existence
        result = await tool_dispatcher(
            "emit_finding",
            {
                "vuln_type": "sqli",
                "severity": "high",
                "title": "SQL Injection in /search",
                "description": "request.args['q'] flows unsanitized into cursor.execute() (read via read_file).",
                "remediation": "Use a parameterized query with bound parameters.",
                "node_id": f"file:{self.file_path}",
                "taint_path": [f"param:{self.file_path}:q", f"file:{self.file_path}"],
            },
        )
        self.emitted = True
        yield ToolCallEvent(type="tool_call", tool_name="emit_finding", tool_input={}, result=result)


@pytest.mark.asyncio
async def test_sqli_fixture_flagged_via_read_file_and_emit_finding(tmp_path):
    """Ground-truth: python/sqli.py yields exactly one high-severity sqli finding,
    and the finding exists only because the LLM read the file through read_file."""
    src = FIXTURES_DIR / "python" / "sqli.py"
    assert src.exists(), "SQLi fixture must exist on disk (P3.3)"

    (tmp_path / "app").mkdir()
    dest_rel = "app/search.py"
    shutil.copy(src, tmp_path / dest_rel)
    content = (tmp_path / dest_rel).read_text()

    llm = _ReadFileThenEmitLLM(dest_rel)
    result = await run_local_source_scan(
        repo_name="acme/vuln-app",
        repo_dir=str(tmp_path),
        diff=_diff_for(dest_rel, content),
        llm=llm,
    )

    # Proves the SAST tool boundary was actually exercised.
    assert llm.read_content is not None, "read_file must have been dispatched"
    assert "cursor.execute(f" in llm.read_content, "read_file must return the real on-disk source"
    assert llm.emitted, "finding must be emitted through the emit_finding tool, not synthesized"

    sqli = [f for f in result.scan.findings if f.vuln_type == "sqli"]
    assert len(sqli) == 1, f"expected exactly one sqli finding, got {result.scan.findings!r}"
    assert sqli[0].severity == "high"


@pytest.mark.asyncio
async def test_safe_parameterized_query_not_flagged(tmp_path):
    """A file whose only DB call is parameterized must NOT be flagged — guards
    against a scanner that hill-climbs by flagging every file it sees."""
    safe_source = (
        "from flask import Flask, request\n"
        "import sqlite3\n"
        "app = Flask(__name__)\n\n"
        "@app.route('/search/safe')\n"
        "def search_safe():\n"
        "    q = request.args.get('q', '')\n"
        "    cur = sqlite3.connect(':memory:').cursor()\n"
        "    cur.execute('SELECT * FROM products WHERE name LIKE ?', (f'%{q}%',))\n"
        "    return 'ok'\n"
    )
    (tmp_path / "app").mkdir()
    dest_rel = "app/safe.py"
    (tmp_path / dest_rel).write_text(safe_source)

    llm = _ReadFileThenEmitLLM(dest_rel)
    result = await run_local_source_scan(
        repo_name="acme/safe-app",
        repo_dir=str(tmp_path),
        diff=_diff_for(dest_rel, safe_source),
        llm=llm,
    )

    assert llm.read_content is not None, "read_file must have been dispatched"
    assert not llm.emitted, "parameterized query must not be flagged"
    assert not [f for f in result.scan.findings if f.vuln_type == "sqli"], "no sqli finding expected for the safe variant"

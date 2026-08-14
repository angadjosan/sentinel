"""Adapter-coverage plumbing (AUDIT.md §6 W4 P5.4).

The local scan surfaces the changed files that no framework adapter matched, so
the CLI can warn the user (route coverage / pentest targeting is weaker there).
These tests cover the extraction from the run trace and the end-to-end
population on `LocalScanResult`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel_worker.local_engine import (
    _unmatched_adapter_files_from_trace,
    run_local_source_scan,
)


def test_extract_unmatched_files_from_trace():
    trace = "\n".join(
        [
            json.dumps({"kind": "scan.started", "base_ref": "HEAD"}),
            json.dumps({"kind": "adapter.coverage", "matched_files": ["app/routes.py"], "unmatched_files": ["lib/weird.rb", "x.md"]}),
            json.dumps({"kind": "scan.completed"}),
        ]
    )
    assert _unmatched_adapter_files_from_trace(trace) == ["lib/weird.rb", "x.md"]


def test_extract_handles_missing_or_malformed_trace():
    assert _unmatched_adapter_files_from_trace(None) == []
    assert _unmatched_adapter_files_from_trace("") == []
    assert _unmatched_adapter_files_from_trace("not json\n{broken") == []
    # No adapter.coverage line -> empty.
    assert _unmatched_adapter_files_from_trace(json.dumps({"kind": "scan.started"})) == []


class _NoopLLM:
    async def call_with_tools(self, *, tool_dispatcher=None, **kwargs):
        return
        yield  # async generator

    async def call(self, **kwargs):
        from sentinel_worker.agent import LLMCallResult
        return LLMCallResult(content='{"annotations": []}', input_tokens=0, output_tokens=0, model="mock", provider="mock")


@pytest.fixture(autouse=True)
def _isolated_trace_home(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setattr(Path, "home", lambda: home)


@pytest.mark.asyncio
async def test_local_scan_populates_adapter_unmatched_files(tmp_path):
    """A changed source file that no adapter recognizes shows up in
    `adapter_unmatched_files` on the scan result (the field the CLI prints)."""
    # A plain module with no framework routes — no adapter should match it.
    (tmp_path / "lib").mkdir()
    src = "def helper(x):\n    return x + 1\n"
    (tmp_path / "lib" / "helper.py").write_text(src)

    added = "\n".join(f"+{line}" for line in src.splitlines())
    diff = (
        "diff --git a/lib/helper.py b/lib/helper.py\n"
        "new file mode 100644\n--- /dev/null\n+++ b/lib/helper.py\n"
        f"@@ -0,0 +1,{len(src.splitlines())} @@\n{added}\n"
    )

    result = await run_local_source_scan(
        repo_name="acme/lib",
        repo_dir=str(tmp_path),
        diff=diff,
        llm=_NoopLLM(),
    )

    # The field exists and is a list; the touched non-framework file is unmatched.
    assert isinstance(result.adapter_unmatched_files, list)
    assert "lib/helper.py" in result.adapter_unmatched_files

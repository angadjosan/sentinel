"""Integration test for the `sentinel-local` console script (local_cli.py).

This is the process the Node CLI shells out to and parses stdout from as JSON
— so the load-bearing contract is: stdout is *exactly* one JSON line, no log
noise, regardless of how much the pipeline logs internally. That contract
broke once already (structlog's default PrintLoggerFactory targets stdout);
this test pins it down at the process level so it can't silently regress.
"""
import json
import os
import subprocess
import sys

_SECRET_DIFF = """diff --git a/config.py b/config.py
--- a/config.py
+++ b/config.py
@@ -1,1 +1,2 @@
 import os
+AWS_ACCESS_KEY_ID = "AKIA1234567890ABCDEF"
"""


def _run_local_cli(args: list[str], tmp_path) -> subprocess.CompletedProcess:
    diff_file = tmp_path / "diff.patch"
    diff_file.write_text(_SECRET_DIFF)
    # HOME is overridden so _save_local_trace writes into this test's tmp_path
    # instead of the real developer's ~/.sentinel/runs.
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", "sentinel_worker.local_cli", "source",
         "--repo-name", "smoke/repo", "--repo-dir", str(tmp_path),
         "--diff-file", str(diff_file), "--provider", "mock", *args],
        capture_output=True, text=True, timeout=30,
        env={**os.environ, "HOME": str(home)},
    )


def test_stdout_is_exactly_one_json_line(tmp_path):
    proc = _run_local_cli([], tmp_path)
    lines = proc.stdout.splitlines()
    assert len(lines) == 1, f"expected exactly one stdout line, got: {proc.stdout!r}"
    body = json.loads(lines[0])
    assert body["finding_count"] == 1
    assert body["findings"][0]["vuln_type"] == "secret_leak"


def test_progress_logs_go_to_stderr_not_stdout(tmp_path):
    proc = _run_local_cli([], tmp_path)
    assert "scan.started" in proc.stderr
    assert "scan.started" not in proc.stdout


def test_exit_code_1_when_findings_at_or_above_fail_on(tmp_path):
    proc = _run_local_cli([], tmp_path)
    assert proc.returncode == 1


def test_exit_code_0_with_fail_on_none(tmp_path):
    proc = _run_local_cli(["--fail-on", "none"], tmp_path)
    assert proc.returncode == 0

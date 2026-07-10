"""Tests for the local-filesystem mode of read_file/grep_source.

When `repo_dir` is passed to dispatch_tool, source reads must come from the
local working tree, not the cloud-encrypted source_files snapshots — this is
the mechanism that keeps source code local during a local scan.
"""
import pytest

from sentinel_worker.graph_query import GraphQuery
from sentinel_worker.tools import dispatch_tool


@pytest.mark.asyncio
async def test_read_file_local_mode_reads_from_disk(db, tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "routes.py").write_text("def handle_login():\n    return db.query(user_id)\n")

    graph = GraphQuery(db=db, graph_id="g1")
    result = await dispatch_tool(
        "read_file",
        {"file_path": "app/routes.py"},
        graph=graph,
        run_id=None,
        db=db,
        repo_id="repo1",
        repo_dir=str(tmp_path),
    )
    assert "error" not in result
    assert "db.query(user_id)" in result["content"]


@pytest.mark.asyncio
async def test_read_file_local_mode_rejects_path_escape(db, tmp_path):
    graph = GraphQuery(db=db, graph_id="g1")
    result = await dispatch_tool(
        "read_file",
        {"file_path": "../../etc/passwd"},
        graph=graph,
        run_id=None,
        db=db,
        repo_id="repo1",
        repo_dir=str(tmp_path),
    )
    assert "error" in result


@pytest.mark.asyncio
async def test_read_file_local_mode_missing_file(db, tmp_path):
    graph = GraphQuery(db=db, graph_id="g1")
    result = await dispatch_tool(
        "read_file",
        {"file_path": "nope.py"},
        graph=graph,
        run_id=None,
        db=db,
        repo_id="repo1",
        repo_dir=str(tmp_path),
    )
    assert "error" in result


@pytest.mark.asyncio
async def test_grep_source_local_mode_finds_matches_and_skips_env_files(db, tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text("def q():\n    return db.query(x)\n")
    (tmp_path / ".env").write_text("SECRET=db.query(leak)\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "vendor.js").write_text("db.query(ignored)\n")

    graph = GraphQuery(db=db, graph_id="g1")
    result = await dispatch_tool(
        "grep_source",
        {"pattern": r"db\.query"},
        graph=graph,
        run_id=None,
        db=db,
        repo_id="repo1",
        repo_dir=str(tmp_path),
    )
    assert "error" not in result
    files_matched = {m["file_path"] for m in result["matches"]}
    assert files_matched == {"app/db.py"}


@pytest.mark.asyncio
async def test_read_file_without_repo_dir_falls_back_to_cloud_snapshot_path(db):
    """Backward-compat: omitting repo_dir must behave exactly as before (cloud path)."""
    graph = GraphQuery(db=db, graph_id="g1")
    result = await dispatch_tool(
        "read_file",
        {"file_path": "app/routes.py"},
        graph=graph,
        run_id=None,
        db=db,
        repo_id="repo1",
    )
    # No snapshot exists in this empty test DB -> not-found, but critically it
    # must not have tried (or been able) to read the real local filesystem.
    assert result == {"error": "File not found: app/routes.py"}

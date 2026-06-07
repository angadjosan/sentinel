"""Tests for SAST tool definitions (G3)."""
from __future__ import annotations

import pytest

from sentinel_worker.tools import TOOLS


def test_tools_list_has_seven_entries():
    tool_names = {t["name"] for t in TOOLS}
    expected = {"graph_neighbors", "graph_paths", "graph_taint_paths", "read_file", "grep_source", "emit_finding", "graph_annotate"}
    assert expected == tool_names, f"Missing tools: {expected - tool_names}"


def test_emit_finding_requires_taint_path():
    emit_tool = next(t for t in TOOLS if t["name"] == "emit_finding")
    required = emit_tool["input_schema"]["required"]
    assert "taint_path" in required
    assert "node_id" in required
    assert "vuln_type" in required


def test_read_file_requires_file_path():
    rt = next(t for t in TOOLS if t["name"] == "read_file")
    assert "file_path" in rt["input_schema"]["required"]


def test_all_tools_have_descriptions():
    for tool in TOOLS:
        assert len(tool.get("description", "")) > 10, f"Tool {tool['name']} needs a description"


def test_emit_finding_severity_is_enum():
    emit_tool = next(t for t in TOOLS if t["name"] == "emit_finding")
    severity_prop = emit_tool["input_schema"]["properties"]["severity"]
    assert "enum" in severity_prop
    assert "critical" in severity_prop["enum"]
    assert "high" in severity_prop["enum"]


def test_graph_neighbors_has_max_hops_property():
    tool = next(t for t in TOOLS if t["name"] == "graph_neighbors")
    props = tool["input_schema"]["properties"]
    assert "max_hops" in props
    assert props["max_hops"]["type"] == "integer"


def test_graph_taint_paths_not_required():
    """graph_taint_paths has no required fields - it works with defaults."""
    tool = next(t for t in TOOLS if t["name"] == "graph_taint_paths")
    required = tool["input_schema"].get("required", [])
    assert len(required) == 0


def test_emit_finding_taint_path_is_array():
    emit_tool = next(t for t in TOOLS if t["name"] == "emit_finding")
    taint_prop = emit_tool["input_schema"]["properties"]["taint_path"]
    assert taint_prop["type"] == "array"
    assert taint_prop["items"]["type"] == "string"


def test_graph_annotate_node_id_required():
    tool = next(t for t in TOOLS if t["name"] == "graph_annotate")
    assert "node_id" in tool["input_schema"]["required"]


def test_graph_annotate_trust_level_enum():
    tool = next(t for t in TOOLS if t["name"] == "graph_annotate")
    trust_prop = tool["input_schema"]["properties"]["trust_level"]
    assert set(trust_prop["enum"]) == {"untrusted", "validated", "trusted", "internal"}

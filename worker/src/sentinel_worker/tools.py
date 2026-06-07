from __future__ import annotations

import re

import structlog

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import graph_query as gq
from . import source_store
from .models import Node, SourceFileSnapshot

log = structlog.get_logger(__name__)


TOOLS: list[dict] = [
    {
        "name": "graph_neighbors",
        "description": "Traverse from a node following specified edge kinds. Use to explore call graphs, data flows, and guard chains.",
        "input_schema": {
            "type": "object",
            "properties": {
                "node_id": {"type": "string"},
                "edge_kinds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "e.g. ['CALLS','FLOWS_TO']. Omit for all edge kinds.",
                },
                "max_hops": {
                    "type": "integer",
                    "default": 50,
                    "description": "Cycle-protection cap. Do not lower below 20.",
                },
            },
            "required": ["node_id"],
        },
    },
    {
        "name": "graph_paths",
        "description": "Find all paths between two nodes. Use to confirm a taint path from source to sink.",
        "input_schema": {
            "type": "object",
            "properties": {
                "src_id": {"type": "string"},
                "dst_id": {"type": "string"},
                "edge_kinds": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["src_id", "dst_id"],
        },
    },
    {
        "name": "graph_taint_paths",
        "description": "Find all taint paths from untrusted sources to sinks. The primary tool for SAST analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "source_kinds": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["PARAMETER"],
                },
                "source_filter": {
                    "type": "object",
                    "description": 'e.g. {"trust_level": "untrusted"}',
                },
                "sink_filter": {
                    "type": "object",
                    "description": 'e.g. {"is_sink": true}',
                },
                "include_uncertain": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include taint_uncertain paths. Always true for SAST.",
                },
            },
        },
    },
    {
        "name": "read_file",
        "description": "Read source file content from the encrypted cloud source snapshot. Always use this to read actual code before forming a finding.",
        "input_schema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Repo-relative path."},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["file_path"],
        },
    },
    {
        "name": "grep_source",
        "description": "Search encrypted source snapshots for a pattern. Use when the graph points to a symbol but you need to find all usages.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "file_pattern": {
                    "type": "string",
                    "description": "Glob. e.g. '**/*.ts'",
                },
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "emit_finding",
        "description": "Emit a security finding. Do not call this unless you have read the source and confirmed the taint path.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_type": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "title": {"type": "string"},
                "description": {
                    "type": "string",
                    "description": "Must include: the specific taint path from source to sink. Must cite file and line numbers.",
                },
                "remediation": {"type": "string"},
                "node_id": {"type": "string", "description": "The sink node id."},
                "taint_path": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of node IDs from source to sink.",
                },
            },
            "required": [
                "vuln_type",
                "severity",
                "title",
                "description",
                "remediation",
                "node_id",
                "taint_path",
            ],
        },
    },
    {
        "name": "graph_annotate",
        "description": "Write semantic labels onto a node. Used by the enrichment pass; also available to the SAST agent to correct a misclassified node during analysis.",
        "input_schema": {
            "type": "object",
            "properties": {
                "node_id": {"type": "string"},
                "label": {
                    "type": "string",
                    "description": "Short noun phrase (<=10 words). e.g. 'JWT auth middleware'",
                },
                "intent": {
                    "type": "string",
                    "description": "1-2 sentences describing what the node does and its security role.",
                },
                "trust_level": {
                    "type": "string",
                    "enum": ["untrusted", "validated", "trusted", "internal"],
                    "description": "Override structural trust_level when source evidence justifies it.",
                },
            },
            "required": ["node_id"],
        },
    },
]


def _serialize_node(node: Node) -> dict:
    return {
        "id": node.id,
        "kind": node.kind,
        "name": node.name,
        "file": node.file,
        "label": node.label,
        "intent": node.intent,
        "trust_level": node.trust_level,
        "is_sink": node.is_sink,
        "is_entry_point": node.is_entry_point,
        "auth_required": node.auth_required,
        "tainted": node.tainted,
        "taint_uncertain": node.taint_uncertain,
        "line_start": node.line_start,
        "line_end": node.line_end,
    }


def _file_pattern_to_regex(file_pattern: str | None) -> re.Pattern | None:
    if not file_pattern:
        return None
    # Convert simple glob to regex
    pattern = re.escape(file_pattern)
    pattern = pattern.replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", ".")
    return re.compile(pattern + "$")


async def dispatch_tool(
    tool_name: str,
    tool_input: dict,
    graph: gq.GraphQuery,
    run_id: str | None,
    db: AsyncSession,
    repo_id: str,
) -> dict:
    log.debug("tool.dispatch", tool=tool_name, run_id=run_id)

    if tool_name == "graph_neighbors":
        node_id = tool_input["node_id"]
        edge_kinds = tool_input.get("edge_kinds") or None
        max_hops = tool_input.get("max_hops", 50)
        neighbors = await graph.neighbors(node_id, edge_kinds=edge_kinds, max_hops=max_hops)
        return {
            "neighbors": [
                {
                    "node": _serialize_node(n.node),
                    "edge_kind": n.edge.kind,
                    "depth": n.depth,
                }
                for n in neighbors
            ]
        }

    elif tool_name == "graph_paths":
        src_id = tool_input["src_id"]
        dst_id = tool_input["dst_id"]
        edge_kinds = tool_input.get("edge_kinds") or None
        paths = await graph.paths(src_id, dst_id, edge_kinds=edge_kinds)
        return {
            "paths": [
                [_serialize_node(node) for node in path]
                for path in paths
            ]
        }

    elif tool_name == "graph_taint_paths":
        include_uncertain = tool_input.get("include_uncertain", True)
        paths = await graph.taint_paths(include_uncertain=include_uncertain)
        return {
            "taint_paths": [
                [_serialize_node(node) for node in path]
                for path in paths
            ]
        }

    elif tool_name == "read_file":
        file_path = tool_input["file_path"]
        start_line = tool_input.get("start_line")
        end_line = tool_input.get("end_line")
        try:
            content = await source_store.read_source_snapshot(
                db,
                repo_id=repo_id,
                commit_hash="bootstrap",
                file_path=file_path,
            )
            if start_line is not None or end_line is not None:
                lines = content.splitlines()
                s = (start_line - 1) if start_line and start_line > 0 else 0
                e = end_line if end_line else len(lines)
                content = "\n".join(lines[s:e])
            return {"file_path": file_path, "content": content}
        except FileNotFoundError:
            return {"error": f"File not found: {file_path}"}

    elif tool_name == "grep_source":
        pattern = tool_input["pattern"]
        file_pattern = tool_input.get("file_pattern")
        file_re = _file_pattern_to_regex(file_pattern)
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return {"error": f"Invalid regex pattern: {exc}"}

        # Query all source snapshots for this repo at bootstrap commit
        stmt = select(SourceFileSnapshot).where(
            SourceFileSnapshot.repo_id == repo_id,
            SourceFileSnapshot.commit_hash == "bootstrap",
            SourceFileSnapshot.deleted.is_(False),
        )
        snapshots = list(await db.scalars(stmt))
        matches: list[dict] = []
        for snap in snapshots:
            if file_re and not file_re.search(snap.file_path):
                continue
            try:
                content = source_store.decrypt_source(snap.content_enc)
            except Exception:
                continue
            for lineno, line in enumerate(content.splitlines(), start=1):
                if regex.search(line):
                    matches.append({
                        "file_path": snap.file_path,
                        "line": lineno,
                        "content": line,
                    })
        return {"matches": matches}

    elif tool_name == "emit_finding":
        return {"type": "finding", "data": tool_input}

    elif tool_name == "graph_annotate":
        node_id = tool_input["node_id"]
        node = await db.get(Node, node_id)
        if node is None:
            return {"error": f"Node not found: {node_id}"}
        if "label" in tool_input and tool_input["label"]:
            node.label = tool_input["label"][:255]
        if "intent" in tool_input and tool_input["intent"]:
            node.intent = tool_input["intent"]
        if "trust_level" in tool_input and tool_input["trust_level"]:
            node.trust_level = tool_input["trust_level"]
        return {"annotated": node_id, "label": node.label, "intent": node.intent, "trust_level": node.trust_level}

    else:
        return {"error": f"Unknown tool: {tool_name}"}

from __future__ import annotations

import os
import re
from pathlib import Path

import structlog

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import graph_query as gq
from . import source_store
from .models import Node, SourceFileSnapshot
from .security import is_env_var_file

log = structlog.get_logger(__name__)

# Directories never walked when grepping a local working tree — build output,
# dependencies, and VCS internals are noise (and node_modules/.git can be huge).
_LOCAL_GREP_IGNORE_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".next"}


def _resolve_local_path(repo_dir: str, file_path: str) -> Path:
    """Resolve a repo-relative path against repo_dir, rejecting escapes (../, absolute paths)."""
    normalized = os.path.normpath(file_path)
    if normalized.startswith("..") or os.path.isabs(normalized):
        raise FileNotFoundError(file_path)
    return Path(repo_dir) / normalized


def _read_local_file(repo_dir: str, file_path: str) -> str:
    try:
        return _resolve_local_path(repo_dir, file_path).read_text(errors="strict")
    except (FileNotFoundError, IsADirectoryError, UnicodeDecodeError) as exc:
        raise FileNotFoundError(file_path) from exc


def _iter_local_files(repo_dir: str):
    root = Path(repo_dir)
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _LOCAL_GREP_IGNORE_DIRS for part in path.parts):
            continue
        yield path


_PENTEST_RESULT_TOOL: dict = {
    "name": "emit_pentest_result",
    "description": (
        "Report pentest results. Call once when analysis is complete. "
        "Include every payload attempted. Set confirmed=true only when behavioral proof was observed."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "payloads": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Exact payloads targeted at this finding's sink.",
            },
            "confirmed": {
                "type": "boolean",
                "description": "True only when behavioral proof was observed.",
            },
            "outcome": {
                "type": "string",
                "enum": ["data_exfiltrated", "auth_bypassed", "command_executed", "privilege_escalated", "no_evidence"],
            },
            "proof_artifact": {
                "type": "string",
                "description": "The specific data constituting proof (response excerpt, command output, etc.).",
            },
            "reasoning": {
                "type": "string",
                "description": "Brief explanation of why each payload was chosen and what was observed.",
            },
        },
        "required": ["payloads", "confirmed", "outcome"],
    },
}

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
        "description": "Emit a security vulnerability finding. Call this for every vulnerability you identify in the diff.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_type": {
                    "type": "string",
                    "description": "Vulnerability type: sqli, cmdi, xss, ssrf, path_traversal, auth_bypass, secret_leak, insecure_deserialization, open_redirect, idor, or other.",
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "title": {"type": "string", "description": "Short title, e.g. 'SQL Injection in user query'"},
                "description": {
                    "type": "string",
                    "description": "Describe the vulnerability: what untrusted input reaches what dangerous sink, and why it is exploitable.",
                },
                "remediation": {"type": "string", "description": "How to fix the vulnerability."},
                "node_id": {
                    "type": "string",
                    "description": "Graph node ID of the vulnerable sink, or 'file:<path>' if no graph node exists.",
                },
                "taint_path": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Node IDs from source to sink. Use 'param:<file>:<name>' for inputs and 'file:<path>' for files if graph nodes don't exist.",
                },
            },
            "required": [
                "vuln_type",
                "severity",
                "title",
                "description",
                "remediation",
                "node_id",
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
        "tainted": node.tainted,  # type: ignore[attr-defined]
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
    *,
    repo_dir: str | None = None,
) -> dict:
    """Dispatch a tool call from the LLM.

    `repo_dir`, when set, makes `read_file`/`grep_source` read the local
    working tree directly instead of decrypting a cloud source snapshot — this
    is what keeps source code on the local machine during a local scan.
    Omitting it preserves the original cloud-worker behavior unchanged.
    """
    log.debug("tool.dispatch", tool=tool_name, run_id=run_id)
    try:
        return await _dispatch_tool_inner(tool_name, tool_input, graph, run_id, db, repo_id, repo_dir=repo_dir)
    except (KeyError, TypeError, ValueError) as exc:
        return {"error": f"Invalid arguments for tool {tool_name}: {exc}"}


async def _dispatch_tool_inner(
    tool_name: str,
    tool_input: dict,
    graph: gq.GraphQuery,
    run_id: str | None,
    db: AsyncSession,
    repo_id: str,
    *,
    repo_dir: str | None = None,
) -> dict:

    if tool_name == "graph_neighbors":
        node_id = tool_input.get("node_id") or tool_input.get("id") or tool_input.get("node")
        if not node_id:
            return {"error": "node_id is required"}
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
        src_id = tool_input.get("src_id") or tool_input.get("source") or tool_input.get("from")
        dst_id = tool_input.get("dst_id") or tool_input.get("destination") or tool_input.get("to")
        if not src_id or not dst_id:
            return {"error": "src_id and dst_id are required"}
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
        file_path = tool_input.get("file_path") or tool_input.get("path") or tool_input.get("file")
        if not file_path:
            return {"error": "file_path is required"}
        start_line = tool_input.get("start_line") or tool_input.get("line_start")
        end_line = tool_input.get("end_line") or tool_input.get("line_end")
        try:
            if repo_dir is not None:
                content = _read_local_file(repo_dir, file_path)
            else:
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

        matches: list[dict] = []
        if repo_dir is not None:
            for path in _iter_local_files(repo_dir):
                rel_path = path.relative_to(repo_dir).as_posix()
                if is_env_var_file(rel_path):
                    continue
                if file_re and not file_re.search(rel_path):
                    continue
                try:
                    content = path.read_text(errors="strict")
                except (UnicodeDecodeError, OSError):
                    continue
                for lineno, line in enumerate(content.splitlines(), start=1):
                    if regex.search(line):
                        matches.append({"file_path": rel_path, "line": lineno, "content": line})
            return {"matches": matches}

        # Cloud-worker path: query all source snapshots for this repo at bootstrap commit.
        stmt = select(SourceFileSnapshot).where(
            SourceFileSnapshot.repo_id == repo_id,
            SourceFileSnapshot.commit_hash == "bootstrap",
            SourceFileSnapshot.deleted.is_(False),
        )
        snapshots = list(await db.scalars(stmt))
        for snap in snapshots:
            if is_env_var_file(snap.file_path):
                continue
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

    elif tool_name == "emit_pentest_result":
        # Captured by the pentest agent loop's dispatcher closure; echo back for tracing.
        return {"type": "pentest_result", "data": tool_input}

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


# Pentest agent has access to graph + source reads but not SAST-specific emit_finding/graph_annotate.
PENTEST_TOOLS: list[dict] = [
    tool for tool in TOOLS if tool["name"] not in {"emit_finding", "graph_annotate"}
] + [_PENTEST_RESULT_TOOL]

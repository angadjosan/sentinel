from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .languages import language_for
from .models import Edge, Node


JS_FUNCTION_RE = re.compile(r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>")
PY_FUNCTION_RE = re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)
CALL_RE = re.compile(r"(?<!function\s)\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(")
IMPORT_REF_RE = re.compile(r"(?:from\s+['\"]([^'\"]+)['\"]|import\s+[^'\n]+from\s+['\"]([^'\"]+)['\"]|require\(\s*['\"]([^'\"]+)['\"]\s*\))")
EXPRESS_ROUTE_RE = re.compile(r"(app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)")
FASTAPI_ROUTE_RE = re.compile(r"@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)")
DJANGO_ROUTE_RE = re.compile(r"\bpath\(\s*['\"]([^'\"]*)['\"]")
RAILS_ROUTE_RE = re.compile(r"\b(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]")
SPRING_ROUTE_RE = re.compile(r"@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*(?:\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"])?")
PY_PARAM_RE = re.compile(r"\b(request\.(?:GET|POST|query_params|path_params)|params|query)\b")
JS_PARAM_RE = re.compile(r"\b(req\.(?:body|query|params)|request\.(?:body|query|params))\b")
SINK_RE = re.compile(r"\b(db\.query|query|execute|exec|spawn|system|popen|readFile|open|send_file|FileResponse)\s*\(", re.IGNORECASE)
SANITIZER_RE = re.compile(r"\b(sanitize|escape|validate|parameterize|quote)\w*\s*\(", re.IGNORECASE)
AUTH_RE = re.compile(r"\b(auth\w*|authenticate\w*|authorize\w*|login_required|Depends\(get_current_user|PreAuthorize)\b", re.IGNORECASE)


@dataclass(frozen=True)
class SourceFile:
    path: str
    content: str
    is_new: bool = False


async def build_file_graph(db: AsyncSession, graph_id: str, source: SourceFile) -> list[Node]:
    await db.execute(delete(Edge).where(Edge.graph_id == graph_id).where(Edge.src.like(f"%:{source.path}:%")))
    language = language_for(source.path)
    imports = sorted({group.split("/")[0] if not group.startswith("@") else "/".join(group.split("/")[:2]) for match in IMPORT_REF_RE.finditer(source.content) for group in match.groups() if group and not group.startswith(".")})
    import_intent = f" Imports packages: {', '.join(imports)}." if imports else ""
    file_node = Node(
        id=f"file:{source.path}",
        graph_id=graph_id,
        kind="FILE",
        name=source.path,
        file=source.path,
        line_start=1,
        line_end=max(1, len(source.content.splitlines())),
        language=language,
        is_new=source.is_new,
        label=f"{source.path} source file" if not source.is_new else f"Changed {source.path}",
        intent=f"Repository source file indexed into the graph.{import_intent}",
    )
    await db.merge(file_node)
    created = [file_node]
    function_nodes = await _emit_functions(db, graph_id, source, language)
    route_nodes = await _emit_routes(db, graph_id, source, language)
    await _emit_calls(db, graph_id, source, function_nodes)
    await _emit_taint(db, graph_id, source, route_nodes, function_nodes)
    return [*created, *function_nodes, *route_nodes]


async def _emit_functions(db: AsyncSession, graph_id: str, source: SourceFile, language: str | None) -> list[Node]:
    pattern = PY_FUNCTION_RE if language == "python" else JS_FUNCTION_RE
    nodes: list[Node] = []
    for match in pattern.finditer(source.content):
        name = next(group for group in match.groups() if group)
        line = source.content[: match.start()].count("\n") + 1
        node = Node(
            id=f"fn:{source.path}:{name}",
            graph_id=graph_id,
            kind="FUNCTION",
            name=name,
            file=source.path,
            line_start=line,
            line_end=line,
            language=language,
            is_sink=bool(SINK_RE.search(_line_at(source.content, line))),
            is_new=source.is_new,
            label=f"{name} function",
            intent=_intent_for_name(name),
        )
        await db.merge(node)
        nodes.append(node)
    return nodes


async def _emit_routes(db: AsyncSession, graph_id: str, source: SourceFile, language: str | None) -> list[Node]:
    nodes: list[Node] = []
    if _is_next_route(source.path):
        method = _next_method(source.content)
        route_path = _next_route_path(source.path)
        node = _route_node(graph_id, source, language, method, route_path, 1, _nearby_auth(source.content, 0))
        await db.merge(node)
        nodes.append(node)
    if language == "python":
        for match in FASTAPI_ROUTE_RE.finditer(source.content):
            method = match.group(1).upper()
            path = match.group(2)
            line = source.content[: match.start()].count("\n") + 1
            node = _route_node(graph_id, source, language, method, path, line, _nearby_auth(source.content, match.start()))
            await db.merge(node)
            nodes.append(node)
        for match in DJANGO_ROUTE_RE.finditer(source.content):
            path = "/" + match.group(1).strip("/")
            line = source.content[: match.start()].count("\n") + 1
            node = _route_node(graph_id, source, language, "ANY", path if path != "/" else "/", line, _nearby_auth(source.content, match.start()))
            await db.merge(node)
            nodes.append(node)
    elif language == "ruby":
        for match in RAILS_ROUTE_RE.finditer(source.content):
            method = match.group(1).upper()
            path = match.group(2)
            line = source.content[: match.start()].count("\n") + 1
            node = _route_node(graph_id, source, language, method, path, line, _nearby_auth(source.content, match.start()))
            await db.merge(node)
            nodes.append(node)
    elif language == "java":
        for match in SPRING_ROUTE_RE.finditer(source.content):
            method = _spring_method(match.group(1))
            path = match.group(2) or "/"
            line = source.content[: match.start()].count("\n") + 1
            node = _route_node(graph_id, source, language, method, path, line, _nearby_auth(source.content, match.start()))
            await db.merge(node)
            nodes.append(node)
    else:
        for match in EXPRESS_ROUTE_RE.finditer(source.content):
            method = match.group(2).upper()
            path = match.group(3)
            line = source.content[: match.start()].count("\n") + 1
            node = _route_node(graph_id, source, language, method, path, line, _nearby_auth(source.content, match.start()))
            await db.merge(node)
            nodes.append(node)
    return nodes


async def _emit_calls(db: AsyncSession, graph_id: str, source: SourceFile, functions: list[Node]) -> None:
    by_name = {node.name: node for node in functions}
    file_node_id = f"file:{source.path}"
    for match in CALL_RE.finditer(source.content):
        callee_name = match.group(1).split(".")[-1]
        dst = by_name.get(callee_name)
        if dst is not None:
            await _add_edge(db, graph_id, file_node_id, dst.id, "CALLS")
        elif "." in match.group(1) or callee_name in {"eval", "exec", "spawn", "system", "popen", "query", "execute"}:
            sink_id = f"fn:{source.path}:{match.group(1)}"
            line = source.content[: match.start()].count("\n") + 1
            await db.merge(
                Node(
                    id=sink_id,
                    graph_id=graph_id,
                    kind="FUNCTION",
                    name=match.group(1),
                    file=source.path,
                    line_start=line,
                    line_end=line,
                    language=language_for(source.path),
                    is_sink=bool(SINK_RE.search(match.group(0))),
                    is_new=source.is_new,
                    label=f"{match.group(1)} call target",
                    intent="External or unresolved call target.",
                )
            )
            await _add_edge(db, graph_id, file_node_id, sink_id, "CALLS", call_uncertainty="unresolved_import")


async def _emit_taint(db: AsyncSession, graph_id: str, source: SourceFile, routes: list[Node], functions: list[Node]) -> None:
    param_pattern = PY_PARAM_RE if language_for(source.path) == "python" else JS_PARAM_RE
    params = list(param_pattern.finditer(source.content))
    sinks = list(SINK_RE.finditer(source.content))
    if not params or not sinks:
        return
    source_node = Node(
        id=f"param:{source.path}:request",
        graph_id=graph_id,
        kind="PARAMETER",
        name="request input",
        file=source.path,
        line_start=source.content[: params[0].start()].count("\n") + 1,
        line_end=source.content[: params[0].start()].count("\n") + 1,
        language=language_for(source.path),
        trust_level="untrusted",
        is_new=source.is_new,
        label="HTTP request input",
        intent="Untrusted input supplied by an external caller.",
    )
    await db.merge(source_node)
    for sink in sinks:
        sink_id = f"fn:{source.path}:{sink.group(1)}"
        line = source.content[: sink.start()].count("\n") + 1
        sink_node = Node(
            id=sink_id,
            graph_id=graph_id,
            kind="FUNCTION",
            name=sink.group(1),
            file=source.path,
            line_start=line,
            line_end=line,
            language=language_for(source.path),
            is_sink=True,
            is_new=source.is_new,
            label=f"{sink.group(1)} sink",
            intent="Security-sensitive sink reached by code in this file.",
        )
        await db.merge(sink_node)
        sanitized = bool(SANITIZER_RE.search(source.content[: sink.start()]))
        await _add_edge(db, graph_id, source_node.id, sink_node.id, "FLOWS_TO", tainted=not sanitized, sanitized=sanitized)
        for route in routes:
            await _add_edge(db, graph_id, route.id, sink_node.id, "CALLS")


def _route_node(graph_id: str, source: SourceFile, language: str | None, method: str, path: str, line: int, auth_required: bool) -> Node:
    return Node(
        id=f"route:{source.path}:{method} {path}",
        graph_id=graph_id,
        kind="ROUTE",
        name=f"{method} {path}",
        file=source.path,
        line_start=line,
        line_end=line,
        language=language,
        is_entry_point=True,
        auth_required=auth_required,
        privilege="user" if auth_required else "anonymous",
        is_new=source.is_new,
        label=f"{method} {path} route",
        intent="HTTP entry point discovered by framework adapter.",
    )


async def _add_edge(db: AsyncSession, graph_id: str, src: str, dst: str, kind: str, **kwargs: object) -> None:
    existing = await db.scalar(select(Edge).where(Edge.graph_id == graph_id).where(Edge.src == src).where(Edge.dst == dst).where(Edge.kind == kind))
    if existing is None:
        db.add(Edge(graph_id=graph_id, src=src, dst=dst, kind=kind, **kwargs))


def _nearby_auth(content: str, offset: int) -> bool:
    return bool(AUTH_RE.search(content[max(0, offset - 300) : offset + 300]))


def _line_at(content: str, line_number: int) -> str:
    lines = content.splitlines()
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return ""


def _intent_for_name(name: str) -> str:
    lowered = name.lower()
    if "auth" in lowered or "login" in lowered:
        return "Authentication or authorization related function."
    if "query" in lowered or "db" in lowered:
        return "Database access function."
    if "handler" in lowered or "route" in lowered:
        return "Request handler function."
    return "Application function discovered during graph construction."


def _is_next_route(path: str) -> bool:
    return ("/app/api/" in f"/{path}" or "/pages/api/" in f"/{path}") and path.endswith((".ts", ".tsx", ".js", ".jsx"))


def _next_route_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    marker = "/app/api/" if "/app/api/" in f"/{normalized}" else "/pages/api/"
    tail = f"/{normalized}".split(marker, 1)[1]
    for suffix in ("/route.ts", "/route.tsx", "/route.js", "/route.jsx", ".ts", ".tsx", ".js", ".jsx"):
        if tail.endswith(suffix):
            tail = tail[: -len(suffix)]
            break
    return "/api/" + tail.strip("/")


def _next_method(content: str) -> str:
    match = re.search(r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b", content)
    return match.group(1) if match else "ANY"


def _spring_method(annotation: str) -> str:
    return {
        "GetMapping": "GET",
        "PostMapping": "POST",
        "PutMapping": "PUT",
        "PatchMapping": "PATCH",
        "DeleteMapping": "DELETE",
        "RequestMapping": "ANY",
    }[annotation]

from __future__ import annotations

import ast
import importlib
import re
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .adapters.django import DjangoAdapter
from .adapters.express import ExpressAdapter
from .adapters.fastapi import FastAPIAdapter
from .adapters.nextjs import NextJSAdapter
from .adapters.rails import RailsAdapter
from .adapters.spring import SpringAdapter
from .languages import language_for
from .models import Edge, Node

log = structlog.get_logger(__name__)

ADAPTERS = [
    ExpressAdapter(),
    FastAPIAdapter(),
    NextJSAdapter(),
    DjangoAdapter(),
    RailsAdapter(),
    SpringAdapter(),
]


def _run_adapters(file_path: str, content: str, ast_node_ids: dict) -> tuple[list, list]:
    t0 = time.monotonic()
    matched_nodes: list = []
    matched_edges: list = []
    adapters_matched: list[str] = []
    for adapter in ADAPTERS:
        if adapter.detect(file_path, content):
            adapter_name = type(adapter).__name__
            nodes, edges = adapter.extract(file_path, content, ast_node_ids)
            matched_nodes.extend(nodes)
            matched_edges.extend(edges)
            adapters_matched.append(adapter_name)
    duration_ms = int((time.monotonic() - t0) * 1000)
    routes_found = sum(1 for n in matched_nodes if getattr(n, "kind", None) == "ROUTE")
    log.info(
        "pass.adapters.completed",
        file=file_path,
        routes_found=routes_found,
        adapters_matched=adapters_matched,
        duration_ms=duration_ms,
    )
    return matched_nodes, matched_edges


JS_FUNCTION_RE = re.compile(r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>")
PY_FUNCTION_RE = re.compile(r"^\s*def\s+([A-Za-z_]\w*)\s*\(", re.MULTILINE)
CALL_RE = re.compile(r"(?<!function\s)\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(")
IMPORT_REF_RE = re.compile(r"(?:from\s+['\"]([^'\"]+)['\"]|import\s+[^'\n]+from\s+['\"]([^'\"]+)['\"]|require\(\s*['\"]([^'\"]+)['\"]\s*\))")
DYNAMIC_CALL_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\[\s*([A-Za-z_$][\w$]*)\s*\]\s*\(")
MONKEY_PATCH_RE = re.compile(r"^\s*([A-Za-z_]\w*)\.([A-Za-z_]\w*)\s*=", re.MULTILINE)
HTTP_CALL_RE = re.compile(r"\b(fetch|axios\.(?:get|post|put|patch|delete)|requests\.(?:get|post|put|patch|delete)|httpx\.(?:get|post|put|patch|delete))\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
HTTP_METHOD_RE = re.compile(r"\bmethod\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]", re.IGNORECASE)
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
IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?$")


@dataclass(frozen=True)
class SourceFile:
    path: str
    content: str
    is_new: bool = False


@dataclass(frozen=True)
class ParsedFunction:
    name: str
    line_start: int
    line_end: int


@dataclass(frozen=True)
class ParsedSource:
    parse_error: bool
    functions: list[ParsedFunction] = field(default_factory=list)


@dataclass(frozen=True)
class LocalImport:
    imported_name: str
    module_ref: str
    file_path: str


class IncrementalSyntaxIndex:
    def __init__(self) -> None:
        self._trees: dict[str, Any] = {}
        self._parser_by_language: dict[str, Any] = {}

    def parse(self, source: SourceFile, language: str | None) -> ParsedSource:
        if language == "python":
            ts_parser = self._parser_for("python")
            if ts_parser is not None:
                source_bytes = source.content.encode()
                previous_tree = self._trees.get(source.path)
                tree = ts_parser.parse(source_bytes, previous_tree)
                self._trees[source.path] = tree
                root = tree.root_node
                return ParsedSource(parse_error=bool(root.has_error), functions=_tree_sitter_functions(source.content, root, language))
            return _parse_python_ast(source.content)
        parser = self._parser_for(language)
        if parser is None:
            return ParsedSource(parse_error=_has_obvious_parse_error(source.content), functions=[])
        source_bytes = source.content.encode()
        previous_tree = self._trees.get(source.path)
        tree = parser.parse(source_bytes, previous_tree)
        self._trees[source.path] = tree
        root = tree.root_node
        return ParsedSource(parse_error=bool(root.has_error), functions=_tree_sitter_functions(source.content, root, language))

    _GRAMMAR_MODULE_MAP: dict[str, tuple[str, str]] = {
        "typescript": ("tree_sitter_typescript", "language_typescript"),
        "python": ("tree_sitter_python", "language"),
        "javascript": ("tree_sitter_javascript", "language"),
        "go": ("tree_sitter_go", "language"),
        "rust": ("tree_sitter_rust", "language"),
        "java": ("tree_sitter_java", "language"),
        "c": ("tree_sitter_c", "language"),
        "cpp": ("tree_sitter_cpp", "language"),
        "ruby": ("tree_sitter_ruby", "language"),
    }

    def _parser_for(self, language: str | None) -> Any | None:
        if language not in self._GRAMMAR_MODULE_MAP:
            return None
        if language in self._parser_by_language:
            return self._parser_by_language[language]
        module_name, factory_attr = self._GRAMMAR_MODULE_MAP[language]
        try:
            tree_sitter = importlib.import_module("tree_sitter")
            grammar_module = importlib.import_module(module_name)
        except ModuleNotFoundError:
            self._parser_by_language[language] = None
            return None
        language_factory = getattr(grammar_module, factory_attr, None)
        if language_factory is None:
            self._parser_by_language[language] = None
            return None
        try:
            ts_language = tree_sitter.Language(language_factory())
            parser = tree_sitter.Parser()
            if hasattr(parser, "set_language"):
                parser.set_language(ts_language)
            else:
                parser.language = ts_language
        except Exception:
            self._parser_by_language[language] = None
            return None
        self._parser_by_language[language] = parser
        return parser


_SYNTAX_INDEX = IncrementalSyntaxIndex()


async def build_file_graph(db: AsyncSession, graph_id: str, source: SourceFile) -> list[Node]:
    return await _build_file_graph(db, graph_id, source, _SYNTAX_INDEX)


async def build_source_graph(db: AsyncSession, graph_id: str, sources: list[SourceFile]) -> list[Node]:
    created: list[Node] = []
    syntax_index = IncrementalSyntaxIndex()
    for source in sources:
        created.extend(await _build_file_graph(db, graph_id, source, syntax_index))
    await resolve_cross_file_references(db, graph_id, sources)
    return created


async def _build_file_graph(db: AsyncSession, graph_id: str, source: SourceFile, syntax_index: IncrementalSyntaxIndex) -> list[Node]:
    await db.execute(delete(Edge).where(Edge.graph_id == graph_id).where(Edge.src.like(f"%:{source.path}:%")))
    language = language_for(source.path)
    parsed = syntax_index.parse(source, language)
    imports = _imports(source.content)
    import_intent = f" Imports packages: {', '.join(imports)}." if imports else ""
    parse_error = parsed.parse_error
    file_node = Node(
        id=f"file:{source.path}",
        graph_id=graph_id,
        kind="FILE",
        name=source.path,
        file=source.path,
        line_start=1,
        line_end=max(1, len(source.content.splitlines())),
        language=language,
        parse_error=parse_error,
        is_new=source.is_new,
        label=f"{source.path} source file" if not source.is_new else f"Changed {source.path}",
        intent=f"Repository source file indexed into the graph.{import_intent}" if not parse_error else "Parse error detected; graph construction skipped for this file.",
    )
    await db.merge(file_node)
    created = [file_node]
    if parse_error:
        return created
    await _emit_imports(db, graph_id, source, imports)
    function_nodes = await _emit_functions(db, graph_id, source, language, parsed)
    route_nodes = await _emit_routes(db, graph_id, source, language)
    await _emit_calls(db, graph_id, source, function_nodes)
    await _emit_taint(db, graph_id, source, route_nodes, function_nodes)
    await _emit_cross_service_calls(db, graph_id, source)
    return [*created, *function_nodes, *route_nodes]


async def _emit_functions(db: AsyncSession, graph_id: str, source: SourceFile, language: str | None, parsed: ParsedSource) -> list[Node]:
    nodes: list[Node] = []
    parsed_functions = parsed.functions or _regex_functions(source.content, language)
    for function in parsed_functions:
        node = Node(
            id=f"fn:{source.path}:{function.name}",
            graph_id=graph_id,
            kind="FUNCTION",
            name=function.name,
            file=source.path,
            line_start=function.line_start,
            line_end=function.line_end,
            language=language,
            is_sink=bool(SINK_RE.search(_lines_between(source.content, function.line_start, function.line_end))),
            is_new=source.is_new,
            label=f"{function.name} function",
            intent=_intent_for_name(function.name),
        )
        await db.merge(node)
        nodes.append(node)
    return nodes


async def resolve_cross_file_references(db: AsyncSession, graph_id: str, sources: list[SourceFile]) -> None:
    paths = {source.path for source in sources}
    function_nodes = list(await db.scalars(select(Node).where(Node.graph_id == graph_id).where(Node.kind == "FUNCTION")))
    functions_by_file_name = {(node.file or "", node.name): node for node in function_nodes}
    for source in sources:
        for local_import in _local_imports(source):
            target_path = _resolve_module_path(source.path, local_import.module_ref, paths)
            if target_path is None:
                continue
            target = functions_by_file_name.get((target_path, local_import.imported_name))
            if target is None:
                continue
            if _calls_name(source.content, local_import.imported_name):
                await _add_edge(db, graph_id, f"file:{source.path}", target.id, "CALLS", call_uncertainty="resolved_import")


def _parse_python_ast(content: str) -> ParsedSource:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return ParsedSource(parse_error=True)
    functions = [
        ParsedFunction(node.name, node.lineno, getattr(node, "end_lineno", node.lineno) or node.lineno)
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    functions.sort(key=lambda function: (function.line_start, function.name))
    return ParsedSource(parse_error=False, functions=functions)


_FUNCTION_NODE_TYPES: dict[str | None, set[str]] = {
    "javascript": {"function_declaration", "method_definition", "generator_function_declaration", "arrow_function"},
    "typescript": {"function_declaration", "method_definition", "generator_function_declaration", "arrow_function", "method_signature"},
    "python": {"function_definition", "async_function_definition"},
    "go": {"function_declaration", "method_declaration"},
    "rust": {"function_item"},
    "java": {"method_declaration", "constructor_declaration"},
    "c": {"function_definition"},
    "cpp": {"function_definition"},
    "ruby": {"method", "singleton_method"},
}
_DEFAULT_FUNCTION_NODE_TYPES = {"function_declaration", "method_definition", "function_definition"}


def _tree_sitter_functions(content: str, root: Any, language: str | None) -> list[ParsedFunction]:
    valid_types = _FUNCTION_NODE_TYPES.get(language, _DEFAULT_FUNCTION_NODE_TYPES)
    functions: list[ParsedFunction] = []
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(reversed(getattr(node, "children", [])))
        node_type = getattr(node, "type", "")
        if node_type not in valid_types:
            continue
        name = _tree_sitter_function_name(content, node, language)
        if name:
            functions.append(ParsedFunction(name=name, line_start=node.start_point[0] + 1, line_end=node.end_point[0] + 1))
    functions.sort(key=lambda function: (function.line_start, function.name))
    return functions


def _tree_sitter_function_name(content: str, node: Any, language: str | None = None) -> str | None:
    get = (lambda field: node.child_by_field_name(field)) if hasattr(node, "child_by_field_name") else (lambda _: None)

    # C/C++: function_definition → declarator → direct_declarator → name
    if language in {"c", "cpp"}:
        declarator = get("declarator")
        while declarator is not None:
            inner = (declarator.child_by_field_name("declarator") if hasattr(declarator, "child_by_field_name") else None)
            if getattr(declarator, "type", "") in {"pointer_declarator", "reference_declarator"} and inner is not None:
                declarator = inner
                continue
            name_node = (declarator.child_by_field_name("name") if hasattr(declarator, "child_by_field_name") else None)
            if name_node is not None:
                return content[name_node.start_byte : name_node.end_byte]
            # direct_declarator: first child is the identifier
            for child in getattr(declarator, "children", []):
                if getattr(child, "type", "") in {"identifier", "field_identifier"}:
                    return content[child.start_byte : child.end_byte]
            break

    name_node = get("name")
    if name_node is not None:
        return content[name_node.start_byte : name_node.end_byte]

    # JS/TS arrow functions assigned to const
    parent = getattr(node, "parent", None)
    if parent is None:
        return None
    if getattr(parent, "type", "") == "variable_declarator":
        declarator_name = parent.child_by_field_name("name") if hasattr(parent, "child_by_field_name") else None
        if declarator_name is not None:
            return content[declarator_name.start_byte : declarator_name.end_byte]
    return None


def _regex_functions(content: str, language: str | None) -> list[ParsedFunction]:
    pattern = PY_FUNCTION_RE if language == "python" else JS_FUNCTION_RE
    functions: list[ParsedFunction] = []
    for match in pattern.finditer(content):
        name = next(group for group in match.groups() if group)
        line = content[: match.start()].count("\n") + 1
        functions.append(ParsedFunction(name=name, line_start=line, line_end=line))
    return functions


def _local_imports(source: SourceFile) -> list[LocalImport]:
    language = language_for(source.path)
    if language == "python":
        return _python_local_imports(source)
    if language in {"javascript", "typescript"}:
        return _js_local_imports(source)
    return []


def _python_local_imports(source: SourceFile) -> list[LocalImport]:
    imports: list[LocalImport] = []
    for match in re.finditer(r"^\s*from\s+([.\w]+)\s+import\s+([^\n#]+)", source.content, re.MULTILINE):
        module_ref = match.group(1)
        if not module_ref.startswith(".") and "." not in module_ref:
            module_ref = f".{module_ref}"
        for raw_name in match.group(2).split(","):
            imported_name = raw_name.strip().split(" as ")[0].strip()
            if imported_name and imported_name != "*":
                imports.append(LocalImport(imported_name=imported_name, module_ref=module_ref, file_path=source.path))
    return imports


def _js_local_imports(source: SourceFile) -> list[LocalImport]:
    imports: list[LocalImport] = []
    for match in re.finditer(r"import\s+\{([^}]+)\}\s+from\s+['\"]([^'\"]+)['\"]", source.content):
        module_ref = match.group(2)
        if not module_ref.startswith("."):
            continue
        for raw_name in match.group(1).split(","):
            imported_name = raw_name.strip().split(" as ")[0].strip()
            if imported_name:
                imports.append(LocalImport(imported_name=imported_name, module_ref=module_ref, file_path=source.path))
    for match in re.finditer(r"const\s+\{([^}]+)\}\s*=\s*require\(\s*['\"]([^'\"]+)['\"]\s*\)", source.content):
        module_ref = match.group(2)
        if not module_ref.startswith("."):
            continue
        for raw_name in match.group(1).split(","):
            imported_name = raw_name.strip().split(":")[0].strip()
            if imported_name:
                imports.append(LocalImport(imported_name=imported_name, module_ref=module_ref, file_path=source.path))
    return imports


def _resolve_module_path(source_path: str, module_ref: str, known_paths: set[str]) -> str | None:
    base = PurePosixPath(source_path).parent
    if module_ref.startswith("."):
        target = (base / module_ref).as_posix()
    else:
        target = module_ref
    target = _collapse_posix_path(target)
    candidates = [
        target,
        f"{target}.py",
        f"{target}.js",
        f"{target}.ts",
        f"{target}.tsx",
        f"{target}/__init__.py",
        f"{target}/index.js",
        f"{target}/index.ts",
    ]
    for candidate in candidates:
        if candidate in known_paths:
            return candidate
    return None


def _collapse_posix_path(path: str) -> str:
    parts: list[str] = []
    for part in path.split("/"):
        if not part or part == ".":
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def _calls_name(content: str, name: str) -> bool:
    return bool(re.search(rf"(?<![\w$]){re.escape(name)}\s*\(", content))


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
            await _emit_express_guards(db, graph_id, source, node, match.end())
            nodes.append(node)
    return nodes


async def _emit_calls(db: AsyncSession, graph_id: str, source: SourceFile, functions: list[Node]) -> None:
    by_name = {node.name: node for node in functions}
    file_node_id = f"file:{source.path}"
    monkey_patched = {f"{match.group(1)}.{match.group(2)}" for match in MONKEY_PATCH_RE.finditer(source.content)}
    for match in DYNAMIC_CALL_RE.finditer(source.content):
        target = f"{match.group(1)}[{match.group(2)}]"
        dynamic_id = f"fn:{source.path}:{target}"
        line = source.content[: match.start()].count("\n") + 1
        await db.merge(
            Node(
                id=dynamic_id,
                graph_id=graph_id,
                kind="FUNCTION",
                name=target,
                file=source.path,
                line_start=line,
                line_end=line,
                language=language_for(source.path),
                is_new=source.is_new,
                label=f"{target} dynamic call target",
                intent="Dynamic dispatch call target; exact callee requires runtime resolution.",
            )
        )
        await _add_edge(db, graph_id, file_node_id, dynamic_id, "CALLS", call_uncertainty="dynamic_dispatch")
    for match in CALL_RE.finditer(source.content):
        callee_name = match.group(1).split(".")[-1]
        dst = by_name.get(callee_name)
        uncertainty = "monkey_patched" if match.group(1) in monkey_patched else None
        if dst is not None and uncertainty is None:
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
            await _add_edge(db, graph_id, file_node_id, sink_id, "CALLS", call_uncertainty=uncertainty or "unresolved_import")


async def _emit_imports(db: AsyncSession, graph_id: str, source: SourceFile, imports: list[str]) -> None:
    file_node_id = f"file:{source.path}"
    for package in imports:
        dep_id = f"dep:{package}"
        await db.merge(
            Node(
                id=dep_id,
                graph_id=graph_id,
                kind="DEPENDENCY",
                name=package,
                file=None,
                language=None,
                is_new=source.is_new,
                label=f"{package} dependency",
                intent="Imported package or module referenced by repository source.",
            )
        )
        await _add_edge(db, graph_id, file_node_id, dep_id, "IMPORTS", call_uncertainty="unresolved_import")


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


async def _emit_cross_service_calls(db: AsyncSession, graph_id: str, source: SourceFile) -> None:
    file_node_id = f"file:{source.path}"
    for match in HTTP_CALL_RE.finditer(source.content):
        path = _http_path(match.group(2))
        if path is None:
            continue
        method = _http_method(match.group(1), source.content[match.start() : match.start() + 300])
        route = await _matching_route(db, graph_id, method, path)
        if route is not None and route.file != source.path:
            await _add_edge(db, graph_id, file_node_id, route.id, "CALLS", call_uncertainty="cross_service")


async def _emit_express_guards(db: AsyncSession, graph_id: str, source: SourceFile, route: Node, args_offset: int) -> None:
    call_end = source.content.find(");", args_offset)
    if call_end < 0:
        return
    args = source.content[args_offset:call_end]
    for index, guard_name in enumerate(_middleware_names(args), start=1):
        guard = Node(
            id=f"middleware:{source.path}:{guard_name}",
            graph_id=graph_id,
            kind="MIDDLEWARE",
            name=guard_name,
            file=source.path,
            line_start=route.line_start,
            line_end=route.line_start,
            language=language_for(source.path),
            auth_required=True,
            privilege="user",
            is_new=source.is_new,
            label=f"{guard_name} middleware",
            intent="Route guard or middleware discovered by framework adapter.",
        )
        await db.merge(guard)
        await _add_edge(db, graph_id, route.id, guard.id, "GUARDED_BY", order_index=index)


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


def _imports(content: str) -> list[str]:
    return sorted(
        {
            group.split("/")[0] if not group.startswith("@") else "/".join(group.split("/")[:2])
            for match in IMPORT_REF_RE.finditer(content)
            for group in match.groups()
            if group and not group.startswith(".")
        }
    )


def _has_obvious_parse_error(content: str) -> bool:
    pairs = {"(": ")", "{": "}", "[": "]"}
    stack: list[str] = []
    for char in content:
        if char in pairs:
            stack.append(pairs[char])
        elif char in pairs.values():
            if not stack or stack.pop() != char:
                return True
    return bool(stack)


def _middleware_names(args: str) -> list[str]:
    names: list[str] = []
    for raw in args.split(","):
        candidate = raw.strip()
        if not candidate or "=>" in candidate or candidate.startswith(("function", "async function", "(", "{")):
            continue
        if IDENTIFIER_RE.match(candidate) and AUTH_RE.search(candidate):
            names.append(candidate)
    return names


def _line_at(content: str, line_number: int) -> str:
    lines = content.splitlines()
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1]
    return ""


def _lines_between(content: str, start: int, end: int) -> str:
    lines = content.splitlines()
    return "\n".join(lines[max(0, start - 1) : max(start, end)])


async def _matching_route(db: AsyncSession, graph_id: str, method: str, path: str) -> Node | None:
    routes = await db.scalars(select(Node).where(Node.graph_id == graph_id).where(Node.kind == "ROUTE"))
    normalized_path = _normalize_route_path(path)
    for route in routes:
        route_method, _, route_path = route.name.partition(" ")
        if _normalize_route_path(route_path) != normalized_path:
            continue
        if route_method in {method, "ANY"} or method == "ANY":
            return route
    return None


def _http_path(url: str) -> str | None:
    if url.startswith("/"):
        return urlparse(url).path
    parsed = urlparse(url)
    return parsed.path if parsed.scheme and parsed.netloc and parsed.path else None


def _http_method(callee: str, call_fragment: str) -> str:
    lowered = callee.lower()
    if "." in lowered:
        return lowered.rsplit(".", 1)[1].upper()
    match = HTTP_METHOD_RE.search(call_fragment)
    return match.group(1).upper() if match else "GET"


def _normalize_route_path(path: str) -> str:
    normalized = "/" + path.strip("/")
    return normalized if normalized != "/" else "/"


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

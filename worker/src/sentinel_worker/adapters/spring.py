from __future__ import annotations

import re

from .base import EdgeRecord, FrameworkAdapter, NodeRecord

SPRING_MAPPING_RE = re.compile(
    r"@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*(?:\(\s*(?:value\s*=\s*)?['\"]([^'\"]+)['\"])?"
)
SPRING_AUTH_RE = re.compile(
    r"@(PreAuthorize|Secured|RolesAllowed)\s*\(|authorizeRequests\s*\(\s*\)"
)
SPRING_IMPORT_RE = re.compile(
    r"import\s+org\.springframework\.(web|security)"
)

_METHOD_MAP = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "PatchMapping": "PATCH",
    "DeleteMapping": "DELETE",
    "RequestMapping": "ANY",
}


class SpringAdapter(FrameworkAdapter):
    def detect(self, file_path: str, content: str) -> bool:
        return bool(SPRING_MAPPING_RE.search(content)) or bool(SPRING_IMPORT_RE.search(content))

    def extract(
        self, file_path: str, content: str, ast_node_ids: dict
    ) -> tuple[list[NodeRecord], list[EdgeRecord]]:
        nodes: list[NodeRecord] = []
        edges: list[EdgeRecord] = []

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            m = SPRING_MAPPING_RE.search(line)
            if not m:
                continue
            annotation = m.group(1)
            method = _METHOD_MAP.get(annotation, "ANY")
            path = m.group(2) or "/"
            route_id = f"route:{file_path}:{method} {path}"

            # Check surrounding lines (±5) for auth annotations
            window_start = max(0, i - 5)
            window_end = min(len(lines), i + 5)
            context_window = "\n".join(lines[window_start:window_end])
            auth_required = bool(SPRING_AUTH_RE.search(context_window))

            route_node = NodeRecord(
                id=route_id,
                kind="ROUTE",
                name=f"{method} {path}",
                file=file_path,
                line_start=i,
                line_end=i,
                language="java",
                auth_required=auth_required,
                is_entry_point=True,
                privilege="user" if auth_required else "anonymous",
                label=f"{method} {path} route",
                intent="HTTP entry point discovered by framework adapter.",
            )
            nodes.append(route_node)

        return nodes, edges

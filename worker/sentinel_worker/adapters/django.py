from __future__ import annotations

import re

from .base import EdgeRecord, FrameworkAdapter, NodeRecord

DJANGO_PATH_RE = re.compile(
    r"\b(?:re_)?path\s*\(\s*r?['\"]([^'\"]*)['\"](?:\s*,\s*(\w+))?"
)
DJANGO_IMPORT_RE = re.compile(r"from\s+django|import\s+django")
LOGIN_REQUIRED_RE = re.compile(r"@login_required|permission_classes\s*=")


class DjangoAdapter(FrameworkAdapter):
    def detect(self, file_path: str, content: str) -> bool:
        filename = file_path.split("/")[-1]
        return (
            filename == "urls.py"
            or bool(DJANGO_PATH_RE.search(content))
            or bool(DJANGO_IMPORT_RE.search(content))
        )

    def extract(
        self, file_path: str, content: str, ast_node_ids: dict
    ) -> tuple[list[NodeRecord], list[EdgeRecord]]:
        nodes: list[NodeRecord] = []
        edges: list[EdgeRecord] = []

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            m = DJANGO_PATH_RE.search(line)
            if not m:
                continue
            raw_path = m.group(1)
            path = "/" + raw_path.strip("/")
            if path == "/":
                path = "/"
            view_name = m.group(2) if m.group(2) else "view"
            route_id = f"route:{file_path}:ANY {path}"

            # Look at surrounding lines for auth decorators
            window_start = max(0, i - 5)
            window_end = min(len(lines), i + 5)
            context_window = "\n".join(lines[window_start:window_end])
            auth_required = bool(LOGIN_REQUIRED_RE.search(context_window))

            route_node = NodeRecord(
                id=route_id,
                kind="ROUTE",
                name=f"ANY {path}",
                file=file_path,
                line_start=i,
                line_end=i,
                language="python",
                auth_required=auth_required,
                is_entry_point=True,
                privilege="user" if auth_required else "anonymous",
                label=f"ANY {path} route",
                intent="HTTP entry point discovered by framework adapter.",
            )
            nodes.append(route_node)

        return nodes, edges

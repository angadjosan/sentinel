from __future__ import annotations

import re

from .base import EdgeRecord, FrameworkAdapter, NodeRecord

FASTAPI_ROUTE_RE = re.compile(
    r"@(?:app|router)\.(get|post|put|patch|delete)\s*\(\s*['\"]([^'\"]+)['\"]"
)
DEPENDS_AUTH_RE = re.compile(
    r"Depends\s*\(\s*(get_current_user|get_current_active_user|oauth2_scheme|authenticate|verify_token|require_auth)",
    re.IGNORECASE,
)
APIROUTER_DEPS_RE = re.compile(
    r"APIRouter\s*\([^)]*dependencies\s*=\s*\[",
    re.IGNORECASE,
)


class FastAPIAdapter(FrameworkAdapter):
    def detect(self, file_path: str, content: str) -> bool:
        return bool(
            re.search(r"@(?:app|router)\.(get|post|put|patch|delete)\s*\(", content)
        )

    def extract(
        self, file_path: str, content: str, ast_node_ids: dict
    ) -> tuple[list[NodeRecord], list[EdgeRecord]]:
        nodes: list[NodeRecord] = []
        edges: list[EdgeRecord] = []

        # Check if APIRouter is declared with global auth dependencies
        router_has_auth = bool(APIROUTER_DEPS_RE.search(content))

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            route_match = FASTAPI_ROUTE_RE.search(line)
            if route_match:
                method = route_match.group(1).upper()
                path = route_match.group(2)
                route_id = f"route:{file_path}:{method} {path}"

                # Look ahead for handler signature (up to 10 lines)
                handler_window = "\n".join(lines[i : i + 10])
                auth_required = (
                    router_has_auth
                    or bool(DEPENDS_AUTH_RE.search(handler_window))
                )

                route_node = NodeRecord(
                    id=route_id,
                    kind="ROUTE",
                    name=f"{method} {path}",
                    file=file_path,
                    line_start=i,
                    line_end=i,
                    language="python",
                    auth_required=auth_required,
                    is_entry_point=True,
                    privilege="user" if auth_required else "anonymous",
                    label=f"{method} {path} route",
                    intent="HTTP entry point discovered by framework adapter.",
                )
                nodes.append(route_node)

        return nodes, edges

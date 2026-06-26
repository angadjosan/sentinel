from __future__ import annotations

import re

from .base import EdgeRecord, FrameworkAdapter, NodeRecord

RAILS_ROUTE_RE = re.compile(
    r"\b(get|post|put|patch|delete)\s+['\"]([^'\"]+)['\"]"
)
RAILS_BEFORE_ACTION_AUTH_RE = re.compile(
    r"before_action\s+:authenticate_user!|before_action\s+:require_login|before_action\s+:authenticate"
)
RAILS_CONTROLLER_RE = re.compile(r"class\s+\w+Controller\s*<")
RAILS_ROUTES_FILE_RE = re.compile(r"Rails\.application\.routes\.draw")


class RailsAdapter(FrameworkAdapter):
    def detect(self, file_path: str, content: str) -> bool:
        filename = file_path.split("/")[-1]
        return (
            filename == "routes.rb"
            or bool(RAILS_ROUTES_FILE_RE.search(content))
            or bool(RAILS_CONTROLLER_RE.search(content))
            or bool(RAILS_ROUTE_RE.search(content))
        )

    def extract(
        self, file_path: str, content: str, ast_node_ids: dict
    ) -> tuple[list[NodeRecord], list[EdgeRecord]]:
        nodes: list[NodeRecord] = []
        edges: list[EdgeRecord] = []

        auth_required_global = bool(RAILS_BEFORE_ACTION_AUTH_RE.search(content))

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            m = RAILS_ROUTE_RE.search(line)
            if not m:
                continue
            method = m.group(1).upper()
            path = m.group(2)
            route_id = f"route:{file_path}:{method} {path}"

            route_node = NodeRecord(
                id=route_id,
                kind="ROUTE",
                name=f"{method} {path}",
                file=file_path,
                line_start=i,
                line_end=i,
                language="ruby",
                auth_required=auth_required_global,
                is_entry_point=True,
                privilege="user" if auth_required_global else "anonymous",
                label=f"{method} {path} route",
                intent="HTTP entry point discovered by framework adapter.",
            )
            nodes.append(route_node)

        return nodes, edges

from __future__ import annotations

import re

from .base import EdgeRecord, FrameworkAdapter, NodeRecord

EXPRESS_ROUTE_PATTERN = re.compile(
    r'(?:app|router)\.(get|post|put|delete|patch|all)\s*\(\s*["\']([^"\']+)["\']'
)
EXPRESS_USE_PATTERN = re.compile(
    r'(?:app|router)\.use\s*\(\s*(?:["\'][^"\']*["\'],\s*)?(\w+)'
)


class ExpressAdapter(FrameworkAdapter):
    def detect(self, file_path: str, content: str) -> bool:
        return (
            "express" in content.lower()
            and (
                "app.get" in content
                or "app.post" in content
                or "router.get" in content
                or "Router()" in content
            )
        )

    def extract(
        self, file_path: str, content: str, ast_node_ids: dict
    ) -> tuple[list[NodeRecord], list[EdgeRecord]]:
        nodes: list[NodeRecord] = []
        edges: list[EdgeRecord] = []

        middleware_order = 0
        # list of (mw_name, order_index)
        active_middleware: list[tuple[str, int]] = []

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            use_match = EXPRESS_USE_PATTERN.search(line)
            if use_match:
                mw_name = use_match.group(1)
                mw_id = f"middleware:{file_path}:{mw_name}"
                mw_node = NodeRecord(
                    id=mw_id,
                    kind="MIDDLEWARE",
                    name=mw_name,
                    file=file_path,
                    line_start=i,
                    line_end=i,
                    auth_required=self._is_auth_middleware(mw_name),
                    label=f"{mw_name} middleware",
                    intent="Route guard or middleware discovered by framework adapter.",
                )
                nodes.append(mw_node)
                active_middleware.append((mw_name, middleware_order))
                middleware_order += 1

            route_match = EXPRESS_ROUTE_PATTERN.search(line)
            if route_match:
                method = route_match.group(1).upper()
                path = route_match.group(2)
                route_id = f"route:{file_path}:{method} {path}"

                auth_required = any(
                    self._is_auth_middleware(mw_name) for mw_name, _ in active_middleware
                )

                route_node = NodeRecord(
                    id=route_id,
                    kind="ROUTE",
                    name=f"{method} {path}",
                    file=file_path,
                    line_start=i,
                    line_end=i,
                    auth_required=auth_required,
                    is_entry_point=True,
                    privilege="user" if auth_required else "anonymous",
                    label=f"{method} {path} route",
                    intent="HTTP entry point discovered by framework adapter.",
                )
                nodes.append(route_node)

                for mw_name, order in active_middleware:
                    mw_id = f"middleware:{file_path}:{mw_name}"
                    edges.append(
                        EdgeRecord(
                            src=route_id,
                            dst=mw_id,
                            kind="GUARDED_BY",
                            order_index=order,
                        )
                    )

        return nodes, edges

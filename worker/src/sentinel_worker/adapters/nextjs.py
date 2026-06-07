from __future__ import annotations

import re

from .base import EdgeRecord, FrameworkAdapter, NodeRecord

NEXT_AUTH_RE = re.compile(
    r"\b(getServerSession|withAuth|auth\(\)|NextAuth|getToken|useSession)\b",
    re.IGNORECASE,
)
NEXT_HTTP_METHOD_RE = re.compile(
    r"export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b"
)


def _is_next_route_file(file_path: str) -> bool:
    normalized = "/" + file_path.replace("\\", "/")
    return (
        "/app/" in normalized or "/pages/" in normalized or file_path.endswith("middleware.ts") or file_path.endswith("middleware.js")
    ) and file_path.endswith((".ts", ".tsx", ".js", ".jsx"))


def _route_path_from_file(file_path: str) -> str:
    normalized = file_path.replace("\\", "/")
    for marker in ("/app/api/", "/pages/api/", "/app/", "/pages/"):
        if marker in f"/{normalized}":
            tail = f"/{normalized}".split(marker, 1)[1]
            for suffix in ("/route.ts", "/route.tsx", "/route.js", "/route.jsx", ".ts", ".tsx", ".js", ".jsx"):
                if tail.endswith(suffix):
                    tail = tail[: -len(suffix)]
                    break
            prefix = "/api" if "api" in marker else ""
            return f"{prefix}/{tail.strip('/')}"
    return "/" + normalized.split("/")[-1].rsplit(".", 1)[0]


class NextJSAdapter(FrameworkAdapter):
    def detect(self, file_path: str, content: str) -> bool:
        return _is_next_route_file(file_path) or (
            "next" in content.lower()
            and (
                "export default" in content
                or "export async function" in content
                or re.search(r"export\s+(const|function)\s+(GET|POST|PUT|DELETE|PATCH)", content)
            )
            and (
                "/app/" in f"/{file_path}" or "/pages/" in f"/{file_path}"
            )
        )

    def extract(
        self, file_path: str, content: str, ast_node_ids: dict
    ) -> tuple[list[NodeRecord], list[EdgeRecord]]:
        nodes: list[NodeRecord] = []
        edges: list[EdgeRecord] = []

        # middleware.ts applies globally
        is_middleware = file_path.endswith(("middleware.ts", "middleware.js"))
        if is_middleware:
            auth_required = bool(NEXT_AUTH_RE.search(content))
            mw_id = f"middleware:{file_path}:global"
            mw_node = NodeRecord(
                id=mw_id,
                kind="MIDDLEWARE",
                name="global_middleware",
                file=file_path,
                line_start=1,
                auth_required=auth_required,
                label="Next.js global middleware",
                intent="Next.js middleware applied to all matched routes.",
            )
            nodes.append(mw_node)
            return nodes, edges

        route_path = _route_path_from_file(file_path)
        auth_required = bool(NEXT_AUTH_RE.search(content))

        # Detect exported HTTP methods
        methods = NEXT_HTTP_METHOD_RE.findall(content)
        if not methods:
            # Check for default export handler
            if "export default" in content:
                methods = ["ANY"]

        for method in methods:
            route_id = f"route:{file_path}:{method} {route_path}"
            line = 1
            for i, m in enumerate(content.split("\n"), 1):
                if re.search(rf"export\s+(?:async\s+)?function\s+{method}\b", m):
                    line = i
                    break
            route_node = NodeRecord(
                id=route_id,
                kind="ROUTE",
                name=f"{method} {route_path}",
                file=file_path,
                line_start=line,
                line_end=line,
                language="typescript",
                auth_required=auth_required,
                is_entry_point=True,
                privilege="user" if auth_required else "anonymous",
                label=f"{method} {route_path} route",
                intent="HTTP entry point discovered by framework adapter.",
            )
            nodes.append(route_node)

        return nodes, edges

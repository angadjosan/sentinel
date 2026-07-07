from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Edge, Finding, Node, now
from .oracle import OracleResult


@dataclass(frozen=True)
class Neighbor:
    node: Node
    edge: Edge
    depth: int


class GraphQuery:
    def __init__(self, db: AsyncSession, graph_id: str):
        self.db = db
        self.graph_id = graph_id

    async def _get_node(self, node_id: str) -> Node | None:
        """Fetch a node scoped to this graph.

        `nodes.id` is a single global primary key (not composite with
        graph_id) — `db.get(Node, node_id)` would return whichever graph
        happens to own that id first, which leaks or corrupts another
        tenant's node whenever two unrelated graphs produce the same
        deterministic id (e.g. two repos both have `fn:app.js:handler`).
        Every node lookup in this class must go through this method, not
        `db.get`, until nodes get a composite (graph_id, id) key.
        """
        return await self.db.scalar(select(Node).where(Node.id == node_id).where(Node.graph_id == self.graph_id))

    async def neighbors(self, node_id: str, edge_kinds: list[str] | None = None, max_hops: int | None = None) -> list[Neighbor]:
        cap = max_hops if max_hops is not None else 50
        seen = {node_id}
        queue: deque[tuple[str, int]] = deque([(node_id, 0)])
        result: list[Neighbor] = []
        while queue:
            current, depth = queue.popleft()
            if depth >= cap:
                continue
            stmt = select(Edge).where(Edge.graph_id == self.graph_id).where(Edge.src == current)
            if edge_kinds:
                stmt = stmt.where(Edge.kind.in_(edge_kinds))
            edges = list(await self.db.scalars(stmt.order_by(Edge.kind.asc(), Edge.dst.asc(), Edge.id.asc())))
            for edge in edges:
                node = await self._get_node(edge.dst)
                if node is None:
                    continue
                result.append(Neighbor(node=node, edge=edge, depth=depth + 1))
                if edge.dst not in seen:
                    seen.add(edge.dst)
                    queue.append((edge.dst, depth + 1))
        return result

    async def paths(self, src_id: str, dst_id: str, edge_kinds: list[str] | None = None, max_hops: int | None = None) -> list[list[Node]]:
        cap = max_hops if max_hops is not None else 20
        queue: deque[tuple[str, list[str]]] = deque([(src_id, [src_id])])
        paths: list[list[Node]] = []
        while queue:
            current, path = queue.popleft()
            if len(path) > cap + 1:
                continue
            if current == dst_id:
                nodes = [node for node_id in path if (node := await self._get_node(node_id)) is not None]
                paths.append(nodes)
                continue
            stmt = select(Edge).where(Edge.graph_id == self.graph_id).where(Edge.src == current)
            if edge_kinds:
                stmt = stmt.where(Edge.kind.in_(edge_kinds))
            for edge in list(await self.db.scalars(stmt.order_by(Edge.kind.asc(), Edge.dst.asc(), Edge.id.asc()))):
                if edge.dst not in path:
                    queue.append((edge.dst, [*path, edge.dst]))
        return paths

    async def taint_paths(self, include_uncertain: bool = True) -> list[list[Node]]:
        sources = list(
            await self.db.scalars(
                select(Node)
                .where(Node.graph_id == self.graph_id)
                .where(Node.kind == "PARAMETER")
                .where(Node.trust_level == "untrusted")
            )
        )
        sinks = list(
            await self.db.scalars(select(Node).where(Node.graph_id == self.graph_id).where(Node.is_sink.is_(True)))
        )
        all_paths: list[list[Node]] = []
        for source in sources:
            for sink in sinks:
                paths = await self.paths(source.id, sink.id, edge_kinds=["FLOWS_TO"], max_hops=20)
                for path in paths:
                    if include_uncertain or not await self._path_has_uncertainty(path):
                        all_paths.append(path)
        return all_paths

    async def serialize_for_prompt(self, node_ids: list[str], max_hops: int = 1) -> str:
        lines: list[str] = []
        included_nodes: set[str] = set()
        included_edges: set[int] = set()
        for node_id in node_ids:
            node = await self._get_node(node_id)
            if node is None or node.id in included_nodes:
                continue
            lines.extend(self._format_node_block(node))
            included_nodes.add(node.id)
            route_has_guard = False
            module_summaries: dict[str, Counter[str]] = defaultdict(Counter)
            for neighbor in await self.neighbors(node.id, edge_kinds=["CALLS", "FLOWS_TO", "GUARDED_BY", "CONFIRMED_EXPLOIT"], max_hops=max_hops):
                if neighbor.depth >= 2:
                    module_summaries[_module_for(neighbor.node)][neighbor.node.kind] += 1
                    continue
                if neighbor.edge.id in included_edges:
                    continue
                included_edges.add(neighbor.edge.id)
                if neighbor.edge.kind == "GUARDED_BY":
                    route_has_guard = True
                lines.append(f"  -> {neighbor.edge.kind}{self._format_edge_attrs(neighbor.edge)}  {self._format_node_inline(neighbor.node)}")
                if neighbor.node.label:
                    lines.append(f'    label: "{neighbor.node.label}"')
                if neighbor.node.intent:
                    lines.append(f'    intent: "{neighbor.node.intent}"')
                included_nodes.add(neighbor.node.id)
            if node.kind == "ROUTE" and not route_has_guard:
                lines.append("  -> GUARDED_BY  none")
            for module, counts in sorted(module_summaries.items()):
                summary = ", ".join(f"{count} {kind.lower()}" for kind, count in sorted(counts.items()))
                lines.append(f"  -> [MODULE] {module} -- {summary}")
            lines.append("")
        return "\n".join(lines).strip()

    async def confirm_exploit(self, entry_node_id: str, sink_node_id: str, finding_id: str, oracle_result: OracleResult) -> Finding:
        if not oracle_result.confirmed:
            raise ValueError("cannot confirm exploit without oracle confirmation")
        finding = await self.db.get(Finding, finding_id)
        if finding is None:
            raise ValueError("finding not found")
        finding.confirmed = True
        finding.status = "confirmed"
        finding.evidence = oracle_result.evidence
        finding.updated_at = now()
        self.db.add(
            Edge(
                graph_id=self.graph_id,
                src=entry_node_id,
                dst=sink_node_id,
                kind="CONFIRMED_EXPLOIT",
            )
        )
        return finding

    async def _path_has_uncertainty(self, path: list[Node]) -> bool:
        for left, right in zip(path, path[1:]):
            edge = await self.db.scalar(
                select(Edge)
                .where(Edge.graph_id == self.graph_id)
                .where(Edge.src == left.id)
                .where(Edge.dst == right.id)
                .where(Edge.kind == "FLOWS_TO")
            )
            if edge and edge.taint_uncertain:
                return True
        return False

    def _format_node_block(self, node: Node) -> list[str]:
        lines = [self._format_node_inline(node)]
        if node.label:
            lines.append(f'  label: "{node.label}"')
        if node.intent:
            lines.append(f'  intent: "{node.intent}"')
        if node.is_new:
            lines.append("  ! NEW (this diff)")
        return lines

    def _format_node_inline(self, node: Node) -> str:
        flags = []
        if node.is_entry_point:
            flags.append("entry_point=true")
        if node.auth_required:
            flags.append("auth_required=true")
        if node.is_sink:
            flags.append("sink=true")
        if node.trust_level:
            flags.append(f"trust_level={node.trust_level}")
        if node.is_new:
            flags.append("is_new=true")
        details = "  ".join(flags)
        pointer = f" {node.file}:{node.line_start}" if node.file else ""
        return f"[{node.kind}] {node.name}{pointer}  {details}".strip()

    def _format_edge_attrs(self, edge: Edge) -> str:
        attrs = []
        if edge.order_index is not None:
            attrs.append(f"order={edge.order_index}")
        if edge.tainted:
            attrs.append("tainted=true")
        if edge.sanitized:
            attrs.append("sanitized=true")
        if edge.taint_uncertain:
            attrs.append("taint_uncertain=true")
        if edge.call_uncertainty:
            attrs.append(f"call_uncertainty={edge.call_uncertainty}")
        return f"  {'  '.join(attrs)}" if attrs else ""


def _module_for(node: Node) -> str:
    if not node.file:
        return "external"
    parts = node.file.replace("\\", "/").split("/")
    return "/".join(parts[:-1]) or "."


class LayeredGraphQuery:
    """Query resolver implementing session → branch → main priority resolution.

    Nodes and edges from higher-priority graphs shadow those in lower-priority graphs.
    This matches the spec's UNION ALL DISTINCT ON (id) ORDER BY graph_priority semantics.
    """

    def __init__(self, db: AsyncSession, graph_ids: list[str]):
        self.db = db
        self.graph_ids = graph_ids  # ordered by priority: [session, branch, main]
        self._queries = [GraphQuery(db=db, graph_id=gid) for gid in graph_ids]

    async def neighbors(self, node_id: str, edge_kinds: list[str] | None = None, max_hops: int | None = None) -> list[Neighbor]:
        seen_nodes: set[str] = set()
        merged: list[Neighbor] = []
        for q in self._queries:
            for neighbor in await q.neighbors(node_id, edge_kinds=edge_kinds, max_hops=max_hops):
                if neighbor.node.id not in seen_nodes:
                    seen_nodes.add(neighbor.node.id)
                    merged.append(neighbor)
        return merged

    async def taint_paths(self, include_uncertain: bool = True) -> list[list[Node]]:
        seen_path_keys: set[tuple[str, ...]] = set()
        merged: list[list[Node]] = []
        for q in self._queries:
            for path in await q.taint_paths(include_uncertain=include_uncertain):
                key = tuple(n.id for n in path)
                if key not in seen_path_keys:
                    seen_path_keys.add(key)
                    merged.append(path)
        return merged

    async def serialize_for_prompt(self, node_ids: list[str], max_hops: int = 1) -> str:
        if self._queries:
            return await self._queries[0].serialize_for_prompt(node_ids, max_hops=max_hops)
        return ""

    @classmethod
    async def for_graph(cls, db: AsyncSession, graph_id: str) -> "LayeredGraphQuery":
        """Build a layered query for a graph by walking its parent chain."""
        from .models import Graph

        chain: list[str] = []
        current_id: str | None = graph_id
        visited: set[str] = set()
        while current_id and current_id not in visited:
            visited.add(current_id)
            chain.append(current_id)
            graph = await db.get(Graph, current_id)
            current_id = graph.parent_id if graph else None
        return cls(db=db, graph_ids=chain)

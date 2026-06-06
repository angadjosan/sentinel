from __future__ import annotations

from collections import deque
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
            edges = list(await self.db.scalars(stmt))
            for edge in edges:
                node = await self.db.get(Node, edge.dst)
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
                nodes = [node for node_id in path if (node := await self.db.get(Node, node_id)) is not None]
                paths.append(nodes)
                continue
            stmt = select(Edge).where(Edge.graph_id == self.graph_id).where(Edge.src == current)
            if edge_kinds:
                stmt = stmt.where(Edge.kind.in_(edge_kinds))
            for edge in list(await self.db.scalars(stmt)):
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
        included: set[str] = set()
        for node_id in node_ids:
            node = await self.db.get(Node, node_id)
            if node is None:
                continue
            lines.append(self._format_node(node, 0))
            included.add(node.id)
            for neighbor in await self.neighbors(node.id, edge_kinds=["CALLS", "FLOWS_TO", "GUARDED_BY", "CONFIRMED_EXPLOIT"], max_hops=max_hops):
                if neighbor.node.id in included:
                    continue
                lines.append(f"  -> {neighbor.edge.kind} {self._format_node(neighbor.node, neighbor.depth)}")
                included.add(neighbor.node.id)
        return "\n".join(lines)

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

    def _format_node(self, node: Node, depth: int) -> str:
        flags = []
        if node.is_entry_point:
            flags.append("entry_point=true")
        if node.auth_required:
            flags.append("auth_required=true")
        if node.is_sink:
            flags.append("sink=true")
        if node.is_new:
            flags.append("NEW")
        details = " ".join(flags)
        label = f" label={node.label}" if node.label else ""
        pointer = f" {node.file}:{node.line_start}" if node.file else ""
        return f"[{node.kind}] {node.name}{pointer}{label} {details}".strip()

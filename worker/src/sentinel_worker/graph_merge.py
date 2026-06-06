from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Edge, Graph, Node, now


async def merge_graph(db: AsyncSession, *, branch_graph_id: str, main_graph_id: str) -> int:
    branch = await db.get(Graph, branch_graph_id)
    main = await db.get(Graph, main_graph_id)
    if branch is None or main is None:
        raise ValueError("branch or main graph not found")
    copied = 0
    branch_nodes = list(await db.scalars(select(Node).where(Node.graph_id == branch_graph_id)))
    for node in branch_nodes:
        merged = Node(
            id=node.id,
            graph_id=main_graph_id,
            kind=node.kind,
            name=node.name,
            file=node.file,
            line_start=node.line_start,
            line_end=node.line_end,
            language=node.language,
            trust_level=node.trust_level,
            auth_required=node.auth_required,
            privilege=node.privilege,
            is_entry_point=node.is_entry_point,
            is_sink=node.is_sink,
            taint_uncertain=node.taint_uncertain,
            parse_error=node.parse_error,
            label=node.label,
            intent=node.intent,
            commit_hash=node.commit_hash,
            is_new=False,
        )
        await db.merge(merged)
        copied += 1
    branch_edges = list(await db.scalars(select(Edge).where(Edge.graph_id == branch_graph_id)))
    for edge in branch_edges:
        existing = await db.scalar(
            select(Edge)
            .where(Edge.graph_id == main_graph_id)
            .where(Edge.src == edge.src)
            .where(Edge.dst == edge.dst)
            .where(Edge.kind == edge.kind)
            .where(Edge.call_uncertainty == edge.call_uncertainty)
        )
        if existing is None:
            db.add(
                Edge(
                    graph_id=main_graph_id,
                    src=edge.src,
                    dst=edge.dst,
                    kind=edge.kind,
                    tainted=edge.tainted,
                    sanitized=edge.sanitized,
                    taint_uncertain=edge.taint_uncertain,
                    call_uncertainty=edge.call_uncertainty,
                    order_index=edge.order_index,
                )
            )
            copied += 1
    branch.status = "merged"
    branch.merged_at = now()
    return copied

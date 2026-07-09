from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Edge, Finding, Graph, Node, now


async def merge_graph(db: AsyncSession, *, branch_graph_id: str, main_graph_id: str) -> int:
    """Merge a branch graph into main.

    Semantics (see non-code/README.md, "Branch graph merge semantics"):
    - Nodes: last-write-wins upsert of the branch's nodes onto main. The branch
      only holds the nodes it added or changed, so untouched main nodes are left
      alone. Tombstones ride along — a branch node with `deleted=True` upserts
      main's copy as deleted, so removals actually land instead of leaving stale
      nodes in main forever.
    - Edges: append-only. Edges present on the branch but not on main are added;
      nothing is deleted, so `CONFIRMED_EXPLOIT` edges from either side survive.
    - Findings: re-pointed from the branch graph onto main, so a finding
      confirmed on the branch follows the code into main instead of dangling on
      a dead branch graph.
    """
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
            deleted=node.deleted,
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
    # Re-point findings recorded against the branch graph onto main so confirmed
    # exploits follow the merged code instead of dangling on the dead branch.
    await db.execute(
        update(Finding).where(Finding.graph_id == branch_graph_id).values(graph_id=main_graph_id)
    )
    branch.status = "merged"
    branch.merged_at = now()
    return copied

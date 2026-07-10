from __future__ import annotations

from datetime import datetime
from dataclasses import dataclass, field

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Edge, Finding, Graph, Node, now

# Node fields that carry semantic meaning for conflict detection. Bookkeeping
# columns (is_new, commit_hash, timestamps) are deliberately excluded so a
# re-scan that only bumps commit_hash is not treated as a real change.
_SEMANTIC_FIELDS = (
    "kind", "name", "file", "line_start", "line_end", "language", "trust_level",
    "auth_required", "privilege", "is_entry_point", "is_sink", "taint_uncertain",
    "parse_error", "label", "intent", "deleted",
)


@dataclass
class MergeResult:
    copied: int = 0
    conflicts: list[str] = field(default_factory=list)
    findings_repointed: int = 0
    had_base: bool = False


def _fingerprint(node: Node | None) -> tuple | None:
    """Semantic identity of a node, or None if the node is absent."""
    if node is None:
        return None
    return tuple(getattr(node, f) for f in _SEMANTIC_FIELDS)


def _copy_node(node: Node, dst_graph_id: str) -> Node:
    return Node(
        id=node.id,
        graph_id=dst_graph_id,
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


async def _append_missing_edges(db: AsyncSession, *, src_graph_id: str, dst_graph_id: str) -> int:
    """Append edges from src that dst does not already have. Append-only: no
    edge is ever deleted, so CONFIRMED_EXPLOIT edges from either side survive."""
    added = 0
    for edge in list(await db.scalars(select(Edge).where(Edge.graph_id == src_graph_id))):
        existing = await db.scalar(
            select(Edge)
            .where(Edge.graph_id == dst_graph_id)
            .where(Edge.src == edge.src)
            .where(Edge.dst == edge.dst)
            .where(Edge.kind == edge.kind)
            .where(Edge.call_uncertainty == edge.call_uncertainty)
        )
        if existing is None:
            db.add(
                Edge(
                    graph_id=dst_graph_id,
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
            added += 1
    return added


async def _repoint_findings(db: AsyncSession, *, from_graph_id: str, to_graph_id: str) -> int:
    findings = list(await db.scalars(select(Finding).where(Finding.graph_id == from_graph_id)))
    if findings:
        await db.execute(
            update(Finding).where(Finding.graph_id == from_graph_id).values(graph_id=to_graph_id)
        )
    return len(findings)


async def merge_graph(db: AsyncSession, *, branch_graph_id: str, main_graph_id: str) -> MergeResult:
    """3-way merge a branch graph into main.

    Semantics (non-code/README.md, "Branch graph merge semantics"):
    - The merge base is the immutable snapshot of main taken at branch creation
      (Graph.base_graph_id). Legacy branches with no base fall back to a plain
      2-way upsert (no conflict detection).
    - Nodes: a branch only holds the nodes it touched, so every branch node
      takes the branch version onto main ("touched -> branch"); untouched nodes
      are not in the branch and keep their current-main version. When main also
      changed a touched node since the base, that is a conflict: we still defer
      to the branch (the newer semantics, per spec) but record the node id so
      the caller can surface it. Tombstones ride along, so deletions land.
    - Edges: append-only. Branch edges missing from main are added; nothing is
      deleted, so CONFIRMED_EXPLOIT edges from both sides are preserved. (Edge
      *removal* would require an edge tombstone the sparse branch overlay does
      not record; node removals are handled via the node tombstone.)
    - Findings recorded against the branch graph are re-pointed onto main so a
      finding confirmed on the branch follows the merged code.
    """
    branch = await db.get(Graph, branch_graph_id)
    main = await db.get(Graph, main_graph_id)
    if branch is None or main is None:
        raise ValueError("branch or main graph not found")

    result = MergeResult(had_base=branch.base_graph_id is not None)

    base_nodes: dict[str, Node] = {}
    if branch.base_graph_id is not None:
        base_nodes = {
            n.id: n for n in await db.scalars(select(Node).where(Node.graph_id == branch.base_graph_id))
        }
    main_nodes = {n.id: n for n in await db.scalars(select(Node).where(Node.graph_id == main_graph_id))}

    for node in list(await db.scalars(select(Node).where(Node.graph_id == branch_graph_id))):
        if result.had_base:
            base_fp = _fingerprint(base_nodes.get(node.id))
            main_fp = _fingerprint(main_nodes.get(node.id))
            main_changed_since_base = main_fp != base_fp
            # Conflict only when main moved AND the branch's version differs from
            # current main (otherwise there is nothing to reconcile).
            if main_changed_since_base and _fingerprint(node) != main_fp:
                result.conflicts.append(node.id)
        await db.merge(_copy_node(node, main_graph_id))
        result.copied += 1

    result.copied += await _append_missing_edges(db, src_graph_id=branch_graph_id, dst_graph_id=main_graph_id)
    result.findings_repointed = await _repoint_findings(db, from_graph_id=branch_graph_id, to_graph_id=main_graph_id)

    branch.status = "merged"
    branch.merged_at = now()
    return result


async def promote_session_to_branch(db: AsyncSession, *, session_graph_id: str, branch_graph_id: str) -> MergeResult:
    """Fold a dev session graph into its branch graph.

    A session graph is a per-developer overlay on the branch, scoped to the
    working diff. When the same diff lands in CI, its nodes/edges/findings are
    promoted onto the branch graph (session wins — it is the newer state) and
    the session is marked promoted so it can be GC'd. This is a 2-way overlay
    apply, not a 3-way merge: the branch is the session's own parent, so there
    is no independent third version to reconcile.
    """
    session_g = await db.get(Graph, session_graph_id)
    branch_g = await db.get(Graph, branch_graph_id)
    if session_g is None or branch_g is None:
        raise ValueError("session or branch graph not found")
    result = MergeResult()
    for node in list(await db.scalars(select(Node).where(Node.graph_id == session_graph_id))):
        await db.merge(_copy_node(node, branch_graph_id))
        result.copied += 1
    result.copied += await _append_missing_edges(db, src_graph_id=session_graph_id, dst_graph_id=branch_graph_id)
    result.findings_repointed = await _repoint_findings(db, from_graph_id=session_graph_id, to_graph_id=branch_graph_id)
    session_g.status = "promoted"
    session_g.promoted_at = now()
    return result


async def gc_sessions(
    db: AsyncSession,
    *,
    account_id: str | None = None,
    older_than: datetime | None = None,
    include_promoted: bool = True,
) -> int:
    """Delete session graphs (and their nodes/edges/findings) that are already
    promoted or older than a cutoff. Session graphs are ephemeral by design;
    nothing reclaimed them before, so they accumulated forever.

    Returns the number of session graphs removed.
    """
    stmt = select(Graph).where(Graph.kind == "session")
    if account_id is not None:
        stmt = stmt.where(Graph.account_id == account_id)
    removed = 0
    for g in list(await db.scalars(stmt)):
        stale = older_than is not None and g.created_at < older_than
        promoted = include_promoted and g.status == "promoted"
        if not (stale or promoted):
            continue
        await db.execute(delete(Finding).where(Finding.graph_id == g.id))
        await db.execute(delete(Edge).where(Edge.graph_id == g.id))
        await db.execute(delete(Node).where(Node.graph_id == g.id))
        await db.delete(g)
        removed += 1
    return removed

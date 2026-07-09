"""Tests for the branch/session graph resolution added to get_or_create_graph.

Existing "main"-kind behavior must be untouched (every pre-existing call site
passes no kind at all). Branch/session graphs are new overlays parented off
main, per the versioning model in non-code/README.md.
"""
import pytest

from sentinel_worker.models import Graph
from sentinel_worker.scan import get_or_create_graph


@pytest.mark.asyncio
async def test_default_kind_is_main_and_idempotent(db):
    first = await get_or_create_graph(db, "acme/repo")
    second = await get_or_create_graph(db, "acme/repo")
    assert first.id == second.id
    assert first.kind == "main"


@pytest.mark.asyncio
async def test_branch_graph_created_parented_off_main(db):
    main = await get_or_create_graph(db, "acme/repo")
    branch = await get_or_create_graph(db, "acme/repo", kind="branch", branch_name="feature/x")
    assert branch.id != main.id
    assert branch.kind == "branch"
    assert branch.branch_name == "feature/x"
    assert branch.parent_id == main.id


@pytest.mark.asyncio
async def test_branch_graph_resolution_is_idempotent(db):
    first = await get_or_create_graph(db, "acme/repo", kind="branch", branch_name="feature/x")
    second = await get_or_create_graph(db, "acme/repo", kind="branch", branch_name="feature/x")
    assert first.id == second.id


@pytest.mark.asyncio
async def test_distinct_branches_get_distinct_graphs(db):
    a = await get_or_create_graph(db, "acme/repo", kind="branch", branch_name="feature/a")
    b = await get_or_create_graph(db, "acme/repo", kind="branch", branch_name="feature/b")
    assert a.id != b.id


@pytest.mark.asyncio
async def test_branch_requires_branch_name(db):
    with pytest.raises(ValueError):
        await get_or_create_graph(db, "acme/repo", kind="branch")


@pytest.mark.asyncio
async def test_session_graph_parents_off_main_by_default(db):
    main = await get_or_create_graph(db, "acme/repo")
    session = await get_or_create_graph(db, "acme/repo", kind="session", session_id="dev-1")
    assert session.kind == "session"
    assert session.parent_id == main.id


@pytest.mark.asyncio
async def test_session_graph_parents_off_branch_when_given(db):
    branch = await get_or_create_graph(db, "acme/repo", kind="branch", branch_name="feature/x")
    session = await get_or_create_graph(
        db, "acme/repo", kind="session", session_id="dev-1", branch_name="feature/x"
    )
    assert session.parent_id == branch.id


@pytest.mark.asyncio
async def test_session_requires_session_id(db):
    with pytest.raises(ValueError):
        await get_or_create_graph(db, "acme/repo", kind="session")


@pytest.mark.asyncio
async def test_unknown_kind_rejected(db):
    with pytest.raises(ValueError):
        await get_or_create_graph(db, "acme/repo", kind="bogus")


@pytest.mark.asyncio
async def test_materialized_nodes_shadows_tombstone(db):
    """A tombstone in a higher layer hides the live copy below it, but the lower
    layer viewed on its own still shows the node."""
    from sentinel_worker.graph_query import LayeredGraphQuery
    from sentinel_worker.models import Node

    main = await get_or_create_graph(db, "acme/repo")
    branch = await get_or_create_graph(db, "acme/repo", kind="branch", branch_name="feature/x")
    db.add(Node(id="n:x", graph_id=main.id, kind="FUNCTION", name="x"))
    db.add(Node(id="n:x", graph_id=branch.id, kind="FUNCTION", name="x", deleted=True))
    await db.flush()

    branch_layered = await LayeredGraphQuery.for_graph(db, branch.id)
    assert "n:x" not in {n.id for n in await branch_layered.materialized_nodes()}

    main_layered = await LayeredGraphQuery.for_graph(db, main.id)
    assert "n:x" in {n.id for n in await main_layered.materialized_nodes()}

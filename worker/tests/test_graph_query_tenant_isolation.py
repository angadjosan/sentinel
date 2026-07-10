"""nodes.id is a single global primary key (not composite with graph_id), so
two unrelated graphs can legitimately produce the same deterministic id (e.g.
two repos both have `fn:app.js:handler`). GraphQuery must never resolve a node
by that global id alone — it has to stay scoped to self.graph_id, or one
graph's traversal can return another graph's (possibly another tenant's) node
data. This was a real bug: `db.get(Node, id)` ignores graph_id entirely.
"""
import pytest

from sentinel_worker.graph_query import GraphQuery
from sentinel_worker.models import Edge, Node


@pytest.mark.asyncio
async def test_neighbors_does_not_leak_node_from_another_graph(db):
    # Graph "other" owns a node with the colliding id and a very different label.
    other_node = Node(id="fn:app.js:handler", graph_id="other-graph", kind="FUNCTION", name="handler", label="OTHER TENANT SECRET LABEL")
    db.add(other_node)

    # Graph "mine" has an edge pointing at that same id, but never created its own copy.
    route = Node(id="route:mine", graph_id="my-graph", kind="ROUTE", name="mine")
    db.add(route)
    db.add(Edge(graph_id="my-graph", src="route:mine", dst="fn:app.js:handler", kind="CALLS"))
    await db.flush()

    query = GraphQuery(db=db, graph_id="my-graph")
    neighbors = await query.neighbors("route:mine", edge_kinds=["CALLS"])

    # The dangling edge resolves to nothing — NOT to the other tenant's node.
    assert neighbors == []


@pytest.mark.asyncio
async def test_serialize_for_prompt_does_not_leak_node_from_another_graph(db):
    db.add(Node(id="fn:app.js:handler", graph_id="other-graph", kind="FUNCTION", name="handler", label="OTHER TENANT SECRET LABEL"))
    await db.flush()

    query = GraphQuery(db=db, graph_id="my-graph")
    serialized = await query.serialize_for_prompt(["fn:app.js:handler"])

    assert "OTHER TENANT SECRET LABEL" not in serialized


@pytest.mark.asyncio
async def test_neighbors_still_resolves_a_node_that_legitimately_belongs_to_the_graph(db):
    route = Node(id="route:mine", graph_id="my-graph", kind="ROUTE", name="mine")
    sink = Node(id="fn:app.js:handler", graph_id="my-graph", kind="FUNCTION", name="handler", label="legit label")
    db.add_all([route, sink])
    db.add(Edge(graph_id="my-graph", src="route:mine", dst="fn:app.js:handler", kind="CALLS"))
    await db.flush()

    query = GraphQuery(db=db, graph_id="my-graph")
    neighbors = await query.neighbors("route:mine", edge_kinds=["CALLS"])

    assert len(neighbors) == 1
    assert neighbors[0].node.label == "legit label"

"""Tests for GET /graph/subgraph and POST /graph/upsert.

These two endpoints are the cloud side of the local-execution model: the local
engine pulls a bootstrap subgraph for context (nodes/edges only, never source),
runs analysis locally, then pushes back the graph delta it produced.
"""
from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel_api.auth import create_token
from sentinel_api.main import app

_NODE_A = {
    "id": "fn:app/routes.py:handle_login",
    "kind": "ROUTE",
    "name": "handle_login",
    "file": "app/routes.py",
    "line_start": 10,
    "line_end": 20,
    "language": "python",
    "is_entry_point": True,
    "label": "login route",
    "intent": "authenticates a user and issues a session",
}
_NODE_B = {
    "id": "fn:app/db.py:query_user",
    "kind": "FUNCTION",
    "name": "query_user",
    "file": "app/db.py",
    "line_start": 5,
    "line_end": 8,
    "is_sink": True,
    "label": "db query",
}
_EDGE = {"src": _NODE_A["id"], "dst": _NODE_B["id"], "kind": "CALLS"}


def _headers():
    token = create_token("sync-user", f"sync-account-{uuid4().hex}", "admin")
    return {"Authorization": f"Bearer {token}"}


def test_upsert_creates_main_graph_nodes_and_edges(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    with TestClient(app) as client:
        resp = client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "main", "nodes": [_NODE_A, _NODE_B], "edges": [_EDGE]},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["nodes_upserted"] == 2
        assert body["edges_upserted"] == 1
        assert body["graph_id"]


def test_upsert_is_idempotent_for_nodes_and_edges(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    payload = {"repo_name": repo, "graph_kind": "main", "nodes": [_NODE_A, _NODE_B], "edges": [_EDGE]}
    with TestClient(app) as client:
        first = client.post("/graph/upsert", headers=headers, json=payload)
        assert first.status_code == 200, first.text

        updated_node_a = {**_NODE_A, "label": "login route (updated)"}
        second = client.post(
            "/graph/upsert",
            headers=headers,
            json={**payload, "nodes": [updated_node_a, _NODE_B]},
        )
        assert second.status_code == 200, second.text
        body = second.json()
        assert body["nodes_upserted"] == 2
        assert body["edges_upserted"] == 0  # same edge, not re-created

        sub = client.get(
            "/graph/subgraph",
            headers=headers,
            params={"repo_name": repo, "seeds": [_NODE_A["id"]], "max_hops": 2},
        )
        assert sub.status_code == 200, sub.text
        nodes_by_id = {n["id"]: n for n in sub.json()["nodes"]}
        assert nodes_by_id[_NODE_A["id"]]["label"] == "login route (updated)"


def test_subgraph_pulls_neighbors_from_seed(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    with TestClient(app) as client:
        client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "main", "nodes": [_NODE_A, _NODE_B], "edges": [_EDGE]},
        )
        resp = client.get(
            "/graph/subgraph",
            headers=headers,
            params={"repo_name": repo, "seeds": [_NODE_A["id"]], "edge_kinds": ["CALLS"], "max_hops": 1},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        node_ids = {n["id"] for n in body["nodes"]}
        assert node_ids == {_NODE_A["id"], _NODE_B["id"]}
        assert len(body["edges"]) == 1
        assert body["edges"][0]["kind"] == "CALLS"

        # No source-bearing fields anywhere in the response shape.
        for node in body["nodes"]:
            assert set(node.keys()) == {
                "id", "kind", "name", "file", "line_start", "line_end", "language",
                "auth_required", "is_entry_point", "is_sink", "label", "intent",
            }


def test_subgraph_requires_at_least_one_seed(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    with TestClient(app) as client:
        resp = client.get("/graph/subgraph", headers=headers, params={"repo_name": "no-seeds-repo"})
        assert resp.status_code == 400


def test_upsert_rejects_diff_marker_smuggled_in_label(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    poisoned_node = {**_NODE_A, "label": "+++ b/app/routes.py\nfull file contents here"}
    with TestClient(app) as client:
        resp = client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "main", "nodes": [poisoned_node], "edges": []},
        )
        assert resp.status_code == 422


def test_upsert_rejects_oversized_intent_field(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    poisoned_node = {**_NODE_A, "intent": "x" * 2001}
    with TestClient(app) as client:
        resp = client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "main", "nodes": [poisoned_node], "edges": []},
        )
        assert resp.status_code == 422


def test_branch_graph_holds_own_copy_of_main_node_id(monkeypatch):
    """With the composite (graph_id, id) node key, a branch graph carries its
    own copy of a node id that main already has, and the layered read overlays
    the branch version on top of main — main itself is unchanged.
    """
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    with TestClient(app) as client:
        main_resp = client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "main", "nodes": [_NODE_A], "edges": []},
        )
        assert main_resp.status_code == 200, main_resp.text

        branch_node = {**_NODE_A, "label": "login route (branch override)", "is_new": True}
        branch_resp = client.post(
            "/graph/upsert",
            headers=headers,
            json={
                "repo_name": repo,
                "graph_kind": "branch",
                "branch_name": "feature/x",
                "nodes": [branch_node],
                "edges": [],
            },
        )
        assert branch_resp.status_code == 200, branch_resp.text
        assert branch_resp.json()["graph_id"] != main_resp.json()["graph_id"]

        # Branch view overlays the branch's version of the node.
        branch_view = client.get(
            "/graph",
            headers=headers,
            params={"repo_name": repo, "graph_kind": "branch", "branch_name": "feature/x"},
        )
        assert branch_view.status_code == 200, branch_view.text
        branch_nodes = {n["id"]: n for n in branch_view.json()["nodes"]}
        assert branch_nodes[_NODE_A["id"]]["label"] == "login route (branch override)"

        # Main view is unaffected — still the original label.
        main_view = client.get("/graph", headers=headers, params={"repo_name": repo})
        assert main_view.status_code == 200, main_view.text
        main_nodes = {n["id"]: n for n in main_view.json()["nodes"]}
        assert main_nodes[_NODE_A["id"]]["label"] == "login route"


def test_graph_view_defaults_to_selected_repo_main(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    with TestClient(app) as client:
        client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "main", "nodes": [_NODE_A, _NODE_B], "edges": [_EDGE]},
        )
        resp = client.get("/graph", headers=headers, params={"repo_name": repo})
        assert resp.status_code == 200, resp.text
        node_ids = {n["id"] for n in resp.json()["nodes"]}
        assert node_ids == {_NODE_A["id"], _NODE_B["id"]}


def test_graphs_list_returns_main_and_active_branches(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    with TestClient(app) as client:
        client.post("/graph/upsert", headers=headers, json={"repo_name": repo, "graph_kind": "main", "nodes": [_NODE_A], "edges": []})
        client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "branch", "branch_name": "feature/x", "nodes": [{**_NODE_A, "is_new": True}], "edges": []},
        )
        resp = client.get("/graphs", headers=headers, params={"repo_name": repo})
        assert resp.status_code == 200, resp.text
        kinds = {(g["kind"], g["branch_name"]) for g in resp.json()}
        assert ("main", None) in kinds
        assert ("branch", "feature/x") in kinds


def test_graph_view_branch_missing_is_404(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    with TestClient(app) as client:
        client.post("/graph/upsert", headers=headers, json={"repo_name": repo, "graph_kind": "main", "nodes": [_NODE_A], "edges": []})
        resp = client.get("/graph", headers=headers, params={"repo_name": repo, "graph_kind": "branch", "branch_name": "nope"})
        assert resp.status_code == 404


def test_merge_branch_by_name_merges_into_main(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    with TestClient(app) as client:
        client.post("/graph/upsert", headers=headers, json={"repo_name": repo, "graph_kind": "main", "nodes": [_NODE_A], "edges": []})
        client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "branch", "branch_name": "feature/x", "nodes": [_NODE_B], "edges": []},
        )
        resp = client.post("/graphs/merge-branch", headers=headers, json={"repo_name": repo, "branch_name": "feature/x"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["had_base"] is True
        # After merge, main carries the branch's node too.
        main_view = client.get("/graph", headers=headers, params={"repo_name": repo})
        assert _NODE_B["id"] in {n["id"] for n in main_view.json()["nodes"]}


def test_merge_branch_missing_is_404(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    with TestClient(app) as client:
        client.post("/graph/upsert", headers=headers, json={"repo_name": repo, "graph_kind": "main", "nodes": [_NODE_A], "edges": []})
        resp = client.post("/graphs/merge-branch", headers=headers, json={"repo_name": repo, "branch_name": "nope"})
        assert resp.status_code == 404


def test_promote_session_into_branch(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    with TestClient(app) as client:
        client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "branch", "branch_name": "feature/x", "nodes": [_NODE_A], "edges": []},
        )
        client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "session", "session_id": "dev-1", "branch_name": "feature/x", "nodes": [_NODE_B], "edges": []},
        )
        resp = client.post(
            "/graphs/promote-session",
            headers=headers,
            json={"repo_name": repo, "branch_name": "feature/x", "session_id": "dev-1"},
        )
        assert resp.status_code == 200, resp.text
        branch_view = client.get(
            "/graph", headers=headers, params={"repo_name": repo, "graph_kind": "branch", "branch_name": "feature/x"}
        )
        assert _NODE_B["id"] in {n["id"] for n in branch_view.json()["nodes"]}


def test_session_gc_requires_admin_and_reclaims(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    headers = _headers()
    repo = f"sync-repo-{uuid4().hex}"
    with TestClient(app) as client:
        client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "branch", "branch_name": "feature/x", "nodes": [_NODE_A], "edges": []},
        )
        client.post(
            "/graph/upsert",
            headers=headers,
            json={"repo_name": repo, "graph_kind": "session", "session_id": "dev-1", "branch_name": "feature/x", "nodes": [_NODE_B], "edges": []},
        )
        client.post("/graphs/promote-session", headers=headers, json={"repo_name": repo, "branch_name": "feature/x", "session_id": "dev-1"})
        resp = client.post("/admin/sessions/gc", headers=headers, json={"include_promoted": True})
        assert resp.status_code == 200, resp.text
        assert resp.json()["removed"] >= 1


def test_upsert_requires_auth(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    with TestClient(app) as client:
        resp = client.post(
            "/graph/upsert",
            json={"repo_name": "no-auth-repo", "nodes": [_NODE_A], "edges": []},
        )
    assert resp.status_code == 401

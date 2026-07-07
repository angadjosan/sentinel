from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel_api.auth import create_token
from sentinel_api.main import app
from .conftest import seed_finding


def test_auth_required_rejects_missing_token(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    with TestClient(app) as client:
        response = client.get("/findings")
    assert response.status_code == 401


def test_auth_required_accepts_valid_token(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    token = create_token("user-1", "account-1", "member")
    with TestClient(app) as client:
        response = client.get("/findings", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_trace_requires_admin_when_auth_enabled(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    member = create_token("user-1", "account-1", "member")
    with TestClient(app) as client:
        response = client.get("/runs/missing/trace", headers={"Authorization": f"Bearer {member}"})
    assert response.status_code == 403


def test_authenticated_accounts_have_isolated_findings(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    token_a = create_token("user-a", "account-a", "admin")
    token_b = create_token("user-b", "account-b", "admin")
    with TestClient(app) as client:
        # Distinct node ids: two accounts scanning a repo of the same *name*
        # are still different repos/graphs — giving them the same node id
        # would be a genuine cross-tenant id collision (see graph_upsert),
        # not what this test is about.
        seed_finding(client, repo_name="shared-repo", vuln_type="sqli", node_id="fn:a/app.js:sink", headers={"Authorization": f"Bearer {token_a}"})
        seed_finding(client, repo_name="shared-repo", vuln_type="cmdi", node_id="fn:b/app.js:sink", headers={"Authorization": f"Bearer {token_b}"})

        findings_a = client.get("/findings?repo_name=shared-repo", headers={"Authorization": f"Bearer {token_a}"})
        findings_b = client.get("/findings?repo_name=shared-repo", headers={"Authorization": f"Bearer {token_b}"})
    assert findings_a.status_code == 200
    assert findings_b.status_code == 200
    assert {finding["vuln_type"] for finding in findings_a.json()} == {"sqli"}
    assert {finding["vuln_type"] for finding in findings_b.json()} == {"cmdi"}


def test_authenticated_ingest_run_is_scoped(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    account_id = f"stream-account-{uuid4().hex}"
    token = create_token("stream-user", account_id, "admin")
    with TestClient(app) as client:
        ingested = seed_finding(client, repo_name="stream-repo", vuln_type="sqli", headers={"Authorization": f"Bearer {token}"})
        run_id = ingested["run_id"]

        run = client.get(f"/runs/{run_id}", headers={"Authorization": f"Bearer {token}"})
        assert run.status_code == 200
        findings = client.get("/findings?repo_name=stream-repo", headers={"Authorization": f"Bearer {token}"})
        assert findings.status_code == 200
        assert any(f["vuln_type"] == "sqli" for f in findings.json())


def test_authenticated_accounts_cannot_access_other_account_details(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    token_a = create_token("owner-a", "detail-account-a", "admin")
    token_b = create_token("owner-b", "detail-account-b", "admin")
    with TestClient(app) as client:
        ingested = seed_finding(client, repo_name="detail-repo", vuln_type="sqli", headers={"Authorization": f"Bearer {token_a}"})
        run_id = ingested["run_id"]

        findings_resp = client.get("/findings?repo_name=detail-repo", headers={"Authorization": f"Bearer {token_a}"})
        assert findings_resp.status_code == 200
        finding_id = findings_resp.json()[0]["id"]

        own_finding = client.get(f"/findings/{finding_id}", headers={"Authorization": f"Bearer {token_a}"})
        other_finding = client.get(f"/findings/{finding_id}", headers={"Authorization": f"Bearer {token_b}"})
        other_pull = client.get(f"/findings/{finding_id}/pull", headers={"Authorization": f"Bearer {token_b}"})
        other_suppress = client.patch(f"/findings/{finding_id}/suppress", headers={"Authorization": f"Bearer {token_b}"}, json={"reason": "nope"})
        own_run = client.get(f"/runs/{run_id}", headers={"Authorization": f"Bearer {token_a}"})
        other_run = client.get(f"/runs/{run_id}", headers={"Authorization": f"Bearer {token_b}"})
        other_trace = client.get(f"/runs/{run_id}/trace", headers={"Authorization": f"Bearer {token_b}"})
        other_cancel = client.post(f"/runs/{run_id}/cancel", headers={"Authorization": f"Bearer {token_b}"})

    assert own_finding.status_code == 200
    assert own_run.status_code == 200
    assert other_finding.status_code == 404
    assert other_pull.status_code == 404
    assert other_suppress.status_code == 404
    assert other_run.status_code == 404
    assert other_trace.status_code == 404
    assert other_cancel.status_code == 404


def test_authenticated_graph_runs_and_analytics_are_account_scoped(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    suffix = uuid4().hex
    account_a = f"scope-account-a-{suffix}"
    account_b = f"scope-account-b-{suffix}"
    token_a = create_token("scope-a", account_a, "admin")
    token_b = create_token("scope-b", account_b, "admin")
    with TestClient(app) as client:
        ingested_a = seed_finding(
            client, repo_name=f"scope-repo-a-{suffix}", vuln_type="sqli", severity="high",
            file="services/a/app.js", headers={"Authorization": f"Bearer {token_a}"},
        )
        seed_finding(
            client, repo_name=f"scope-repo-b-{suffix}", vuln_type="cmdi",
            file="services/b/app.js", headers={"Authorization": f"Bearer {token_b}"},
        )
        run_a_id = ingested_a["run_id"]

        runs_a = client.get("/runs", headers={"Authorization": f"Bearer {token_a}"})
        graph_a = client.get("/graph", headers={"Authorization": f"Bearer {token_a}"})
        trends_a = client.get("/analytics/finding-trends", headers={"Authorization": f"Bearer {token_a}"})
        fp_a = client.get("/analytics/false-positive-rate", headers={"Authorization": f"Bearer {token_a}"})

    assert {run["id"] for run in runs_a.json()} == {run_a_id}
    assert any((node.get("file") or "") == "services/a/app.js" for node in graph_a.json()["nodes"])
    assert all((node.get("file") or "") != "services/b/app.js" for node in graph_a.json()["nodes"])
    assert {row["severity"] for row in trends_a.json()} == {"high"}
    assert fp_a.json()["total"] == 1


def test_authenticated_graph_subgraph_and_upsert_are_account_scoped(monkeypatch):
    """Closes the coverage gap left by removing /source-files (which used to
    prove tenant isolation on reading stored source): the graph sync endpoints
    that replaced it must be isolated the same way."""
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    suffix = uuid4().hex
    token_a = create_token("graph-a", f"graph-account-a-{suffix}", "admin")
    token_b = create_token("graph-b", f"graph-account-b-{suffix}", "admin")
    repo = f"graph-scope-{suffix}"
    node_id = "fn:app.js:sink"
    with TestClient(app) as client:
        pushed = client.post(
            "/graph/upsert",
            headers={"Authorization": f"Bearer {token_a}"},
            json={"repo_name": repo, "graph_kind": "main", "nodes": [{"id": node_id, "kind": "FUNCTION", "name": "sink", "file": "app.js"}], "edges": []},
        )
        assert pushed.status_code == 200

        allowed = client.get(
            "/graph/subgraph", headers={"Authorization": f"Bearer {token_a}"},
            params={"repo_name": repo, "seeds": [node_id]},
        )
        # A different account has no such repo yet, so get_or_create_graph makes
        # a fresh (empty) one for it — it must not see account A's node.
        denied = client.get(
            "/graph/subgraph", headers={"Authorization": f"Bearer {token_b}"},
            params={"repo_name": repo, "seeds": [node_id]},
        )
    assert allowed.status_code == 200
    assert any(n["id"] == node_id for n in allowed.json()["nodes"])
    assert denied.status_code == 200
    assert all(n["id"] != node_id for n in denied.json()["nodes"])


def test_device_auth_flow_issues_token_after_admin_approval(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    monkeypatch.delenv("SENTINEL_DEV_MODE", raising=False)
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "test-secret-for-auth-flow")
    admin = create_token("device-admin", "device-account", "admin")
    with TestClient(app) as client:
        started = client.post("/auth/device")
        assert started.status_code == 200
        body = started.json()
        assert body["device_code"]
        assert body["user_code"]

        pending = client.get(f"/auth/device/token?device_code={body['device_code']}")
        assert pending.status_code == 202

        approved = client.post(
            "/auth/device/approve",
            headers={"Authorization": f"Bearer {admin}"},
            json={"user_code": body["user_code"]},
        )
        assert approved.status_code == 200

        token = client.get(f"/auth/device/token?device_code={body['device_code']}")
        assert token.status_code == 200
        token_body = token.json()
        assert token_body["account_id"] == "device-account"
        assert token_body["user_id"] == "device-admin"
        assert token_body["access_token"]


def test_device_auth_approval_requires_admin(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    member = create_token("device-member", "device-member-account", "member")
    with TestClient(app) as client:
        started = client.post("/auth/device")
        response = client.post(
            "/auth/device/approve",
            headers={"Authorization": f"Bearer {member}"},
            json={"user_code": started.json()["user_code"]},
        )
    assert response.status_code == 403


def test_device_auth_token_auto_approves_in_dev_mode(monkeypatch):
    """With SENTINEL_DEV_MODE=1, polling /auth/device/token immediately returns a token."""
    monkeypatch.setenv("SENTINEL_DEV_MODE", "1")
    with TestClient(app) as client:
        started = client.post("/auth/device")
        assert started.status_code == 200
        token = client.get(f"/auth/device/token?device_code={started.json()['device_code']}")
    assert token.status_code == 200
    body = token.json()
    assert body["access_token"]
    assert body["account_id"]
    assert body["user_id"]


def test_device_auth_token_stays_pending_without_dev_mode(monkeypatch):
    """Without SENTINEL_DEV_MODE, polling before approval returns 202."""
    monkeypatch.delenv("SENTINEL_DEV_MODE", raising=False)
    with TestClient(app) as client:
        started = client.post("/auth/device")
        pending = client.get(f"/auth/device/token?device_code={started.json()['device_code']}")
    assert pending.status_code == 202

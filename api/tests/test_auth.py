from fastapi.testclient import TestClient

from sentinel_api.auth import create_token
from sentinel_api.main import app


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
        scan_a = client.post(
            "/plan",
            headers={"Authorization": f"Bearer {token_a}"},
            json={"repo_name": "shared-repo", "content": "db.query(`select ${req.query.id}`)", "with_retry": False},
        )
        scan_b = client.post(
            "/plan",
            headers={"Authorization": f"Bearer {token_b}"},
            json={"repo_name": "shared-repo", "content": "exec(`run ${req.query.id}`)", "with_retry": False},
        )
        assert scan_a.status_code == 200
        assert scan_b.status_code == 200
        findings_a = client.get("/findings?repo_name=shared-repo", headers={"Authorization": f"Bearer {token_a}"})
        findings_b = client.get("/findings?repo_name=shared-repo", headers={"Authorization": f"Bearer {token_b}"})
    assert findings_a.status_code == 200
    assert findings_b.status_code == 200
    assert {finding["vuln_type"] for finding in findings_a.json()} == {"sqli"}
    assert {finding["vuln_type"] for finding in findings_b.json()} == {"cmdi"}


def test_monthly_token_budget_blocks_new_runs(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    token = create_token("budget-admin", "budget-account", "admin")
    with TestClient(app) as client:
        budget = client.put(
            "/admin/accounts/budget-account/token-budget",
            headers={"Authorization": f"Bearer {token}"},
            json={"monthly_token_budget": 0},
        )
        assert budget.status_code == 200
        response = client.post(
            "/plan",
            headers={"Authorization": f"Bearer {token}"},
            json={"repo_name": "budget-repo", "content": "db.query(`select ${req.query.id}`)", "with_retry": False},
        )
    assert response.status_code == 429
    assert response.json()["detail"]["error"] == "monthly_token_budget_exceeded"


def test_source_file_reads_are_account_scoped(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    token_a = create_token("source-a", "source-account-a", "admin")
    token_b = create_token("source-b", "source-account-b", "admin")
    with TestClient(app) as client:
        created = client.post(
            "/init",
            headers={"Authorization": f"Bearer {token_a}"},
            json={"repo_name": "shared-source", "files": {"app.js": "const tenant = 'a';"}},
        )
        assert created.status_code == 200
        allowed = client.get("/source-files/shared-source/bootstrap/app.js", headers={"Authorization": f"Bearer {token_a}"})
        denied = client.get("/source-files/shared-source/bootstrap/app.js", headers={"Authorization": f"Bearer {token_b}"})
    assert allowed.status_code == 200
    assert denied.status_code == 404


def test_device_auth_flow_issues_token_after_admin_approval(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
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

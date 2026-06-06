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

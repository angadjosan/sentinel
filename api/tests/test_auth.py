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

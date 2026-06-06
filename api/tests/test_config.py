from fastapi.testclient import TestClient
from uuid import uuid4

from sentinel_api.auth import create_token
from sentinel_api.main import app


def test_account_config_get_and_patch(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    suffix = uuid4().hex
    token = create_token(f"config-admin-{suffix}", f"config-account-{suffix}", "admin")
    with TestClient(app) as client:
        initial = client.get("/config", headers={"Authorization": f"Bearer {token}"})
        assert initial.status_code == 200
        assert initial.json()["provider"] == "local"

        updated = client.patch(
            "/config",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "provider": "openai",
                "model": "gpt-5-mini",
                "api_endpoint": "https://api.openai.example",
                "suppression_approval_required": False,
                "monthly_token_budget": 120000,
                "source_retention_days": 90,
            },
        )
        assert updated.status_code == 200
        body = updated.json()
        assert body["provider"] == "openai"
        assert body["model"] == "gpt-5-mini"
        assert body["api_endpoint"] == "https://api.openai.example"
        assert body["suppression_approval_required"] is False
        assert body["monthly_token_budget"] == 120000
        assert body["source_retention_days"] == 90

        cleared = client.patch(
            "/config",
            headers={"Authorization": f"Bearer {token}"},
            json={"api_endpoint": None, "monthly_token_budget": None},
        )
        assert cleared.status_code == 200
        assert cleared.json()["api_endpoint"] is None
        assert cleared.json()["monthly_token_budget"] is None


def test_account_config_patch_requires_admin(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    token = create_token("config-member", "config-member-account", "member")
    with TestClient(app) as client:
        response = client.patch("/config", headers={"Authorization": f"Bearer {token}"}, json={"provider": "openai"})
    assert response.status_code == 403

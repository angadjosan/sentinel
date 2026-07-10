import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from sentinel_api.main import app


def _sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_github_webhook_rejects_bad_signature(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "test-secret")
    with TestClient(app) as client:
        response = client.post(
            "/webhook/github",
            content=b"{}",
            headers={"x-hub-signature-256": "sha256=deadbeef", "x-github-event": "pull_request"},
        )
    assert response.status_code == 401


def test_github_webhook_requires_configured_secret(monkeypatch):
    monkeypatch.delenv("GITHUB_APP_WEBHOOK_SECRET", raising=False)
    with TestClient(app) as client:
        response = client.post(
            "/webhook/github",
            content=b"{}",
            headers={"x-hub-signature-256": "sha256=whatever", "x-github-event": "pull_request"},
        )
    assert response.status_code == 503


def test_github_webhook_does_not_fetch_diff_or_enqueue_scan(monkeypatch):
    """AUDIT.md §3 D5 / Gate 2: the webhook no longer runs SAST in the cloud.

    A valid pull_request delivery must be acknowledged WITHOUT pulling the PR
    diff or enqueuing a `kind=source` task (which would store the customer's diff
    in tasks.payload — a SAST-privacy violation). PR SAST runs in CI via
    action.yml / standalone.py instead.
    """
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "test-secret")

    called = {"fetch_pr_diff": False, "get_installation_token": False, "create_check_run": False}

    async def fake_fetch_pr_diff(*args, **kwargs):
        called["fetch_pr_diff"] = True
        return ""

    async def fake_get_installation_token(*args, **kwargs):
        called["get_installation_token"] = True
        return "fake-token"

    async def fake_create_check_run(*args, **kwargs):
        called["create_check_run"] = True
        return 999

    monkeypatch.setattr("sentinel_worker.github_app.fetch_pr_diff", fake_fetch_pr_diff)
    monkeypatch.setattr("sentinel_worker.github_app.get_installation_token", fake_get_installation_token)
    monkeypatch.setattr("sentinel_worker.github_app.create_check_run", fake_create_check_run)

    payload = {
        "action": "opened",
        "installation": {"id": 12345},
        "repository": {"full_name": "acme/widgets"},
        "pull_request": {"number": 7, "head": {"sha": "abc123"}, "base": {"sha": "def456"}},
    }
    body = json.dumps(payload).encode()
    signature = _sign("test-secret", body)

    with TestClient(app) as client:
        response = client.post(
            "/webhook/github",
            content=body,
            headers={
                "x-hub-signature-256": signature,
                "x-github-event": "pull_request",
                "content-type": "application/json",
            },
        )
        assert response.status_code == 200
        assert response.json() == {"ok": True}

    # The legacy cloud-scan path must be fully severed.
    assert called["fetch_pr_diff"] is False
    assert called["get_installation_token"] is False
    assert called["create_check_run"] is False


def test_github_webhook_ignores_other_actions(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "test-secret")
    payload = {"action": "closed", "installation": {"id": 1}, "repository": {"full_name": "acme/widgets"}}
    body = json.dumps(payload).encode()
    signature = _sign("test-secret", body)
    with TestClient(app) as client:
        response = client.post(
            "/webhook/github",
            content=body,
            headers={"x-hub-signature-256": signature, "x-github-event": "pull_request"},
        )
    assert response.status_code == 200
    assert response.json() == {"ok": True}

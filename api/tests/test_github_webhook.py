import hashlib
import hmac
import json

from fastapi.testclient import TestClient

from sentinel_api.main import app

from .conftest import process_tasks


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


def test_github_webhook_enqueues_scan_and_completes_check_run(monkeypatch):
    monkeypatch.setenv("GITHUB_APP_WEBHOOK_SECRET", "test-secret")

    calls = {}
    completed = {}

    async def fake_get_installation_token(installation_id):
        calls["installation_id"] = installation_id
        return "fake-token"

    async def fake_create_check_run(token, repo, sha):
        calls["check_run_repo"] = repo
        calls["check_run_sha"] = sha
        return 999

    async def fake_fetch_pr_diff(token, repo, pr_number):
        calls["pr_number"] = pr_number
        return (
            "+++ b/app.js\n"
            "+app.get('/u', (req,res)=> db.query(`select * from users where id=${req.query.id}`))"
        )

    async def fake_complete_check_run(token, repo, check_run_id, findings):
        completed["repo"] = repo
        completed["check_run_id"] = check_run_id
        completed["findings"] = findings

    monkeypatch.setattr("sentinel_worker.github_app.get_installation_token", fake_get_installation_token)
    monkeypatch.setattr("sentinel_worker.github_app.create_check_run", fake_create_check_run)
    monkeypatch.setattr("sentinel_worker.github_app.fetch_pr_diff", fake_fetch_pr_diff)
    monkeypatch.setattr("sentinel_worker.github_app.complete_check_run", fake_complete_check_run)

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
        assert calls["installation_id"] == 12345
        assert calls["check_run_repo"] == "acme/widgets"
        assert calls["check_run_sha"] == "abc123"
        assert calls["pr_number"] == 7

        process_tasks(1)

    assert completed["repo"] == "acme/widgets"
    assert completed["check_run_id"] == 999
    assert completed["findings"]
    assert completed["findings"][0]["vuln_type"] == "sqli"


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

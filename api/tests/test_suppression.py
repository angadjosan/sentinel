from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel_api.auth import create_token
from sentinel_api.main import app


def _create_finding(client: TestClient, token: str, marker: str) -> str:
    unique = f"{marker}-{uuid4().hex}"
    response = client.post(
        "/plan",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "repo_name": f"repo-{unique}",
            "content": f"Add route that calls exec(`convert ${{req.query.file}}`) // {unique}",
            "with_retry": False,
        },
    )
    assert response.status_code == 200
    return response.json()["findings"][0]["id"]


def test_member_suppression_requires_admin_approval(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    member = create_token("member-suppress", "acct-suppress", "member")
    admin = create_token("admin-suppress", "acct-suppress", "admin")
    with TestClient(app) as client:
        finding_id = _create_finding(client, member, "pending")
        pending = client.patch(
            f"/findings/{finding_id}/suppress",
            headers={"Authorization": f"Bearer {member}"},
            json={"reason": "false positive in generated test"},
        )
        assert pending.status_code == 200
        assert pending.json()["status"] == "suppression_pending"
        assert pending.json()["confirmed"] is False

        approved = client.post(
            f"/findings/{finding_id}/suppress/approve",
            headers={"Authorization": f"Bearer {admin}"},
            json={"reason": "reviewed"},
        )
        assert approved.status_code == 200
        assert approved.json()["status"] == "suppressed"


def test_readonly_cannot_suppress(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    admin = create_token("admin-readonly-test", "acct-readonly-test", "admin")
    readonly = create_token("readonly-test", "acct-readonly-test", "readonly")
    with TestClient(app) as client:
        finding_id = _create_finding(client, admin, "readonly")
        response = client.patch(
            f"/findings/{finding_id}/suppress",
            headers={"Authorization": f"Bearer {readonly}"},
            json={"reason": "try suppress"},
        )
    assert response.status_code == 403

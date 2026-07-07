from uuid import uuid4

from fastapi.testclient import TestClient

from sentinel_api.main import app


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_signup_creates_account_and_returns_token(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "test-secret")
    email = f"ada-{uuid4().hex}@example.com"
    with TestClient(app) as client:
        resp = client.post("/auth/signup", json={"name": "Ada", "email": email, "password": "hunter22hunter22"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["access_token"]
        assert body["user"]["email"] == email
        assert body["user"]["role"] == "admin"

        me = client.get("/auth/me", headers=_auth(body["access_token"]))
        assert me.status_code == 200
        assert me.json()["email"] == email


def test_signup_rejects_duplicate_email(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "test-secret")
    email = f"dup-{uuid4().hex}@example.com"
    with TestClient(app) as client:
        first = client.post("/auth/signup", json={"name": "Ada", "email": email, "password": "hunter22hunter22"})
        assert first.status_code == 200
        second = client.post("/auth/signup", json={"name": "Ada 2", "email": email, "password": "hunter22hunter22"})
        assert second.status_code == 409


def test_login_rejects_wrong_password_and_accepts_correct(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "test-secret")
    email = f"login-{uuid4().hex}@example.com"
    with TestClient(app) as client:
        client.post("/auth/signup", json={"name": "Ada", "email": email, "password": "correct-horse-battery"})

        bad = client.post("/auth/login", json={"email": email, "password": "wrong"})
        assert bad.status_code == 401

        good = client.post("/auth/login", json={"email": email, "password": "correct-horse-battery"})
        assert good.status_code == 200
        assert good.json()["access_token"]


def test_logout_revokes_session_immediately(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "test-secret")
    email = f"logout-{uuid4().hex}@example.com"
    with TestClient(app) as client:
        signup = client.post("/auth/signup", json={"name": "Ada", "email": email, "password": "hunter22hunter22"})
        token = signup.json()["access_token"]

        before = client.get("/auth/me", headers=_auth(token))
        assert before.status_code == 200

        logout = client.post("/auth/logout", headers=_auth(token))
        assert logout.status_code == 200

        after = client.get("/auth/me", headers=_auth(token))
        assert after.status_code == 401


def test_session_list_and_manual_revoke(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "test-secret")
    email = f"sessions-{uuid4().hex}@example.com"
    with TestClient(app) as client:
        signup = client.post("/auth/signup", json={"name": "Ada", "email": email, "password": "hunter22hunter22"})
        token = signup.json()["access_token"]

        sessions = client.get("/auth/sessions", headers=_auth(token))
        assert sessions.status_code == 200
        rows = sessions.json()
        assert len(rows) == 1
        assert rows[0]["current"] is True

        revoke = client.delete(f"/auth/sessions/{rows[0]['id']}", headers=_auth(token))
        assert revoke.status_code == 200

        after = client.get("/auth/me", headers=_auth(token))
        assert after.status_code == 401


def test_device_verification_url_points_at_configured_dashboard(monkeypatch):
    monkeypatch.setenv("SENTINEL_DASHBOARD_URL", "https://dash.example.com")
    with TestClient(app) as client:
        started = client.post("/auth/device")
        assert started.status_code == 200
        body = started.json()
        assert body["verification_url"] == f"https://dash.example.com/device?user_code={body['user_code']}"


def test_device_approval_issues_long_lived_revocable_session(monkeypatch):
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    monkeypatch.delenv("SENTINEL_DEV_MODE", raising=False)
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "test-secret")
    with TestClient(app) as client:
        signup = client.post(
            "/auth/signup",
            json={"name": "Admin", "email": f"cli-{uuid4().hex}@example.com", "password": "hunter22hunter22"},
        )
        admin_token = signup.json()["access_token"]

        started = client.post("/auth/device")
        user_code = started.json()["user_code"]
        device_code = started.json()["device_code"]

        pending = client.get(f"/auth/device/token?device_code={device_code}")
        assert pending.status_code == 202

        approved = client.post("/auth/device/approve", headers=_auth(admin_token), json={"user_code": user_code})
        assert approved.status_code == 200

        issued = client.get(f"/auth/device/token?device_code={device_code}")
        assert issued.status_code == 200
        cli_token = issued.json()["access_token"]

        sessions = client.get("/auth/sessions", headers=_auth(admin_token))
        labels = {row["label"] for row in sessions.json()}
        assert "cli" in labels

        cli_me = client.get("/auth/me", headers=_auth(cli_token))
        assert cli_me.status_code == 200

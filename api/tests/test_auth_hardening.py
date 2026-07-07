from uuid import uuid4

import httpx
import pyotp
import respx
from fastapi.testclient import TestClient

from sentinel_api.main import app
from sentinel_api.routers import auth as auth_router
from sentinel_api.routers.auth import GITHUB_TOKEN_URL, GITHUB_USER_URL


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _capture_generated_token(monkeypatch) -> dict[str, str]:
    """Spy on security.generate_token so tests can read the raw value behind a hash."""
    captured: dict[str, str] = {}
    original = auth_router.generate_token

    def spy():
        token = original()
        captured["value"] = token
        return token

    monkeypatch.setattr(auth_router, "generate_token", spy)
    return captured


def _base_env(monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_REQUIRE_AUTH", "1")
    monkeypatch.setenv("SENTINEL_JWT_SECRET", "test-secret")


def test_login_lockout_after_max_failed_attempts(monkeypatch):
    _base_env(monkeypatch)
    email = f"lockout-{uuid4().hex}@example.com"
    with TestClient(app) as client:
        client.post("/auth/signup", json={"name": "Ada", "email": email, "password": "hunter22hunter22"})

        for _ in range(auth_router.MAX_FAILED_LOGINS - 1):
            resp = client.post("/auth/login", json={"email": email, "password": "wrong"})
            assert resp.status_code == 401

        last_bad = client.post("/auth/login", json={"email": email, "password": "wrong"})
        assert last_bad.status_code == 401  # this one crosses the threshold and locks the account

        locked = client.post("/auth/login", json={"email": email, "password": "hunter22hunter22"})
        assert locked.status_code == 423


def test_ip_rate_limit_blocks_after_threshold(monkeypatch):
    _base_env(monkeypatch)
    with TestClient(app) as client:
        statuses = [client.post("/auth/login", json={"email": "nobody@example.com", "password": "x"}).status_code for _ in range(auth_router.IP_MAX_ATTEMPTS + 1)]
    assert statuses[:-1] == [401] * auth_router.IP_MAX_ATTEMPTS
    assert statuses[-1] == 429


def test_email_verification_flow(monkeypatch):
    _base_env(monkeypatch)
    captured = _capture_generated_token(monkeypatch)
    email = f"verify-{uuid4().hex}@example.com"
    with TestClient(app) as client:
        signup = client.post("/auth/signup", json={"name": "Ada", "email": email, "password": "hunter22hunter22"})
        token = signup.json()["access_token"]
        assert signup.json()["user"]["email_verified"] is False

        bad = client.post("/auth/verify-email", params={"token": "garbage"})
        assert bad.status_code == 400

        good = client.post("/auth/verify-email", params={"token": captured["value"]})
        assert good.status_code == 200

        me = client.get("/auth/me", headers=_auth(token))
        assert me.json()["email_verified"] is True

        already = client.post("/auth/verify-email/resend", headers=_auth(token))
        assert already.json()["status"] == "already_verified"


def test_password_reset_flow_revokes_existing_sessions(monkeypatch):
    _base_env(monkeypatch)
    captured = _capture_generated_token(monkeypatch)
    email = f"reset-{uuid4().hex}@example.com"
    with TestClient(app) as client:
        signup = client.post("/auth/signup", json={"name": "Ada", "email": email, "password": "hunter22hunter22"})
        old_token = signup.json()["access_token"]

        forgot = client.post("/auth/forgot-password", json={"email": email})
        assert forgot.status_code == 200
        reset_token = captured["value"]

        reset = client.post("/auth/reset-password", json={"token": reset_token, "password": "brand-new-pass1"})
        assert reset.status_code == 200

        assert client.get("/auth/me", headers=_auth(old_token)).status_code == 401
        assert client.post("/auth/login", json={"email": email, "password": "hunter22hunter22"}).status_code == 401
        assert client.post("/auth/login", json={"email": email, "password": "brand-new-pass1"}).status_code == 200

        replay = client.post("/auth/reset-password", json={"token": reset_token, "password": "another-pass1"})
        assert replay.status_code == 400  # single-use


def test_forgot_password_does_not_leak_account_existence(monkeypatch):
    _base_env(monkeypatch)
    with TestClient(app) as client:
        known = client.post("/auth/forgot-password", json={"email": f"real-{uuid4().hex}@example.com"})
        unknown = client.post("/auth/forgot-password", json={"email": "definitely-not-registered@example.com"})
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json() == {"status": "ok"}


def test_mfa_full_lifecycle(monkeypatch):
    _base_env(monkeypatch)
    email = f"mfa-{uuid4().hex}@example.com"
    with TestClient(app) as client:
        signup = client.post("/auth/signup", json={"name": "Ada", "email": email, "password": "hunter22hunter22"})
        token = signup.json()["access_token"]

        # Not yet enabled — normal login works without a challenge.
        assert client.post("/auth/login", json={"email": email, "password": "hunter22hunter22"}).json()["mfa_required"] is False

        enroll = client.post("/auth/mfa/enroll", headers=_auth(token))
        assert enroll.status_code == 200
        secret = enroll.json()["secret"]

        # Enrolling alone doesn't flip mfa_enabled — must confirm with a valid code.
        assert client.get("/auth/me", headers=_auth(token)).json()["mfa_enabled"] is False

        bad_confirm = client.post("/auth/mfa/confirm", headers=_auth(token), json={"code": "000000"})
        assert bad_confirm.status_code == 401

        confirm = client.post("/auth/mfa/confirm", headers=_auth(token), json={"code": pyotp.TOTP(secret).now()})
        assert confirm.status_code == 200
        assert client.get("/auth/me", headers=_auth(token)).json()["mfa_enabled"] is True

        login = client.post("/auth/login", json={"email": email, "password": "hunter22hunter22"})
        assert login.json()["mfa_required"] is True
        assert login.json()["access_token"] is None
        challenge = login.json()["challenge_token"]

        bad_code = client.post("/auth/login/mfa", json={"challenge_token": challenge, "code": "000000"})
        assert bad_code.status_code == 401

        good_code = client.post("/auth/login/mfa", json={"challenge_token": challenge, "code": pyotp.TOTP(secret).now()})
        assert good_code.status_code == 200
        mfa_session_token = good_code.json()["access_token"]

        wrong_password_disable = client.post("/auth/mfa/disable", headers=_auth(mfa_session_token), json={"password": "wrong"})
        assert wrong_password_disable.status_code == 401

        disable = client.post("/auth/mfa/disable", headers=_auth(mfa_session_token), json={"password": "hunter22hunter22"})
        assert disable.status_code == 200
        assert client.get("/auth/me", headers=_auth(mfa_session_token)).json()["mfa_enabled"] is False


def test_mfa_challenge_token_cannot_be_reused_as_a_bearer_token(monkeypatch):
    _base_env(monkeypatch)
    email = f"mfa-guard-{uuid4().hex}@example.com"
    with TestClient(app) as client:
        signup = client.post("/auth/signup", json={"name": "Ada", "email": email, "password": "hunter22hunter22"})
        token = signup.json()["access_token"]
        secret = client.post("/auth/mfa/enroll", headers=_auth(token)).json()["secret"]
        client.post("/auth/mfa/confirm", headers=_auth(token), json={"code": pyotp.TOTP(secret).now()})

        challenge = client.post("/auth/login", json={"email": email, "password": "hunter22hunter22"}).json()["challenge_token"]

        # The challenge token has no `sid` and isn't a real session token — it must not authenticate API calls.
        me = client.get("/auth/me", headers=_auth(challenge))
        assert me.status_code == 401


def test_refresh_token_rotation_and_reuse_detection(monkeypatch):
    _base_env(monkeypatch)
    monkeypatch.delenv("SENTINEL_DEV_MODE", raising=False)
    from sentinel_api.auth import create_token

    with TestClient(app) as client:
        admin_token = create_token("owner-1", "owner-account", "admin")
        started = client.post("/auth/device")
        client.post("/auth/device/approve", headers=_auth(admin_token), json={"user_code": started.json()["user_code"]})
        issued = client.get(f"/auth/device/token?device_code={started.json()['device_code']}")
        assert issued.status_code == 200
        first_refresh = issued.json()["refresh_token"]
        assert issued.json()["expires_in"] == 60 * 60  # 1h CLI access token

        rotated = client.post("/auth/refresh", json={"refresh_token": first_refresh})
        assert rotated.status_code == 200
        second_refresh = rotated.json()["refresh_token"]
        assert second_refresh != first_refresh

        reuse = client.post("/auth/refresh", json={"refresh_token": first_refresh})
        assert reuse.status_code == 401

        again = client.post("/auth/refresh", json={"refresh_token": second_refresh})
        assert again.status_code == 200


def test_oauth_github_not_configured_returns_501(monkeypatch):
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("GITHUB_OAUTH_CLIENT_SECRET", raising=False)
    with TestClient(app) as client:
        resp = client.post("/auth/oauth/github", json={"code": "x", "redirect_uri": "http://localhost/callback"})
    assert resp.status_code == 501


def test_oauth_github_creates_account_then_reuses_it_on_repeat_login(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "test-secret")
    profile = {"id": 999111, "login": "adalovelace", "name": "Ada Lovelace", "email": f"ada-{uuid4().hex}@github.example.com"}

    with respx.mock:
        respx.post(GITHUB_TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "gh-token"}))
        respx.get(GITHUB_USER_URL).mock(return_value=httpx.Response(200, json=profile))
        with TestClient(app) as client:
            first = client.post("/auth/oauth/github", json={"code": "code-1", "redirect_uri": "http://localhost/callback"})
    assert first.status_code == 200
    assert first.json()["user"]["email_verified"] is True
    first_user_id = first.json()["user"]["id"]

    with respx.mock:
        respx.post(GITHUB_TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "gh-token-2"}))
        respx.get(GITHUB_USER_URL).mock(return_value=httpx.Response(200, json=profile))
        with TestClient(app) as client:
            second = client.post("/auth/oauth/github", json={"code": "code-2", "redirect_uri": "http://localhost/callback"})
    assert second.status_code == 200
    assert second.json()["user"]["id"] == first_user_id


def test_oauth_github_falls_back_to_primary_email_when_profile_email_hidden(monkeypatch):
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("GITHUB_OAUTH_CLIENT_SECRET", "test-secret")
    email = f"private-{uuid4().hex}@github.example.com"

    with respx.mock:
        respx.post(GITHUB_TOKEN_URL).mock(return_value=httpx.Response(200, json={"access_token": "gh-token"}))
        respx.get(GITHUB_USER_URL).mock(return_value=httpx.Response(200, json={"id": 42, "login": "hidden", "name": "Hidden Email", "email": None}))
        respx.get("https://api.github.com/user/emails").mock(
            return_value=httpx.Response(200, json=[{"email": "secondary@example.com", "primary": False}, {"email": email, "primary": True}])
        )
        with TestClient(app) as client:
            resp = client.post("/auth/oauth/github", json={"code": "code", "redirect_uri": "http://localhost/callback"})
    assert resp.status_code == 200
    assert resp.json()["user"]["email"] == email

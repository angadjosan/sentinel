"""GitHub App installation access token exchange.

Flow:
  1. Sign a JWT with the App's RSA private key (RS256, 10-min TTL)
  2. POST /app/installations/{id}/access_tokens → short-lived token (~1 hr)
  3. Cache tokens in-process; refresh when < 5 min remain
"""
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import math
import os
import time
from typing import Optional

import httpx

# ── JWT (RS256) built without PyJWT to avoid an extra dependency ──────────────

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _rs256_sign(payload: dict, private_key_pem: str) -> str:
    """Produce a compact RS256 JWT.  Uses only stdlib + cryptography if present,
    otherwise falls back to the `PyJWT` package."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding

        key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
        header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        body = _b64url(json.dumps(payload).encode())
        signing_input = f"{header}.{body}".encode()
        sig = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{header}.{body}.{_b64url(sig)}"

    except ImportError:
        pass  # fall through to PyJWT

    try:
        import jwt as _jwt  # PyJWT
        return _jwt.encode(payload, private_key_pem, algorithm="RS256")
    except ImportError:
        raise RuntimeError(
            "GitHub App auth requires either 'cryptography' or 'PyJWT'. "
            "Run: pip install cryptography"
        )


def _make_app_jwt(app_id: str, private_key_pem: str) -> str:
    """Create a 10-minute GitHub App JWT."""
    now = int(time.time())
    return _rs256_sign(
        {"iat": now - 60, "exp": now + 540, "iss": str(app_id)},
        private_key_pem,
    )


# ── Token cache ───────────────────────────────────────────────────────────────

# {installation_id: {"token": str, "expires_at": float (unix)}}
_token_cache: dict[int, dict] = {}
_REFRESH_BEFORE = 300  # refresh 5 min before expiry


async def get_installation_token(
    installation_id: int,
    app_id: Optional[str] = None,
    private_key_pem: Optional[str] = None,
) -> str:
    """Return a valid installation access token, refreshing from cache if needed.

    Reads GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY from env when not supplied.
    GITHUB_APP_PRIVATE_KEY may be a raw PEM string or a base64-encoded PEM.
    """
    app_id = app_id or os.environ.get("GITHUB_APP_ID", "")
    pem = private_key_pem or os.environ.get("GITHUB_APP_PRIVATE_KEY", "")

    if not app_id or not pem:
        raise RuntimeError(
            "Set GITHUB_APP_ID and GITHUB_APP_PRIVATE_KEY env vars to use "
            "GitHub App token exchange."
        )

    # Decode base64-wrapped PEM (common in CI env vars)
    if not pem.strip().startswith("-----"):
        try:
            pem = base64.b64decode(pem).decode()
        except Exception:
            pass

    cached = _token_cache.get(installation_id)
    if cached and cached["expires_at"] - time.time() > _REFRESH_BEFORE:
        return cached["token"]

    token = await _exchange_token(installation_id, app_id, pem)
    # GitHub tokens expire in 1 hour; we store that minus the refresh buffer
    _token_cache[installation_id] = {
        "token": token,
        "expires_at": time.time() + 3600,
    }
    return token


async def _exchange_token(installation_id: int, app_id: str, pem: str) -> str:
    """Call /app/installations/{id}/access_tokens and return the token string."""
    jwt_token = _make_app_jwt(app_id, pem)
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            url,
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        resp.raise_for_status()
        return resp.json()["token"]

from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.fernet import Fernet, InvalidToken

from .auth import jwt_secret


def _fernet_key() -> bytes:
    """Derive a stable Fernet key from SENTINEL_JWT_SECRET — no separate secret to manage."""
    digest = hashlib.sha256(jwt_secret().encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(value: str) -> str:
    return Fernet(_fernet_key()).encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str | None:
    try:
        return Fernet(_fernet_key()).decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return None


def hash_token(token: str) -> str:
    """One-way hash for single-use/refresh tokens stored at rest.

    These are high-entropy random tokens, not user-chosen passwords — a fast
    hash is fine here (bcrypt's cost factor exists to slow down guessing
    low-entropy secrets, which doesn't apply to a 32-byte random token).
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def client_ip(request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

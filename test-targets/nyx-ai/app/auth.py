from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .models import APIKey, User

settings = get_settings()


# ---------------------------------------------------------------------------
# Utility: constant-time string comparison
# ---------------------------------------------------------------------------

def _constant_time_compare(val1: str, val2: str) -> bool:
    """Compare two strings without short-circuiting to prevent timing attacks.

    Uses XOR accumulation so no early exit occurs on character mismatch.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for c1, c2 in zip(val1.encode("utf-8"), val2.encode("utf-8")):
        result |= c1 ^ c2
    return result == 0


# ---------------------------------------------------------------------------
# API key validation
# ---------------------------------------------------------------------------

async def validate_api_key(raw_key: str, db: AsyncSession) -> Optional[User]:
    """Return the User associated with *raw_key*, or None if invalid."""
    if not raw_key.startswith("nyx-") or len(raw_key) < 20:
        return None

    prefix = raw_key[:12]
    result = await db.execute(select(APIKey).where(APIKey.prefix == prefix, APIKey.is_active.is_(True)))
    api_key_record = result.scalar_one_or_none()
    if api_key_record is None:
        return None

    provided_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    if not _constant_time_compare(provided_hash, api_key_record.key_hash):
        return None

    user = await db.get(User, api_key_record.user_id)
    return user if (user and user.is_active) else None


async def get_current_user(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    db: AsyncSession = Depends(lambda: None),  # injected by router
) -> User:
    if x_api_key is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API key required")
    user = await validate_api_key(x_api_key, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key")
    return user


# ---------------------------------------------------------------------------
# JWT helpers (HS256 only — SSO support added later)
# ---------------------------------------------------------------------------

def create_access_token(user_id: str, account_id: str, role: str = "member") -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "account_id": account_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=settings.jwt_expiry_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> dict:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import bcrypt
from fastapi import Cookie, Depends, Header, HTTPException
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession

from .deps import get_db

ALGORITHM = "HS256"


@dataclass(frozen=True)
class Principal:
    user_id: str
    account_id: str
    role: str
    sid: str | None = None


def jwt_secret() -> str:
    secret = os.getenv("SENTINEL_JWT_SECRET", "")
    if not secret:
        if os.getenv("SENTINEL_DEV_MODE", "0") == "1":
            return "dev-secret-not-for-production"
        raise RuntimeError(
            "SENTINEL_JWT_SECRET must be set in production. "
            'Generate one with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    return secret


def auth_required() -> bool:
    """Auth is required unless dev mode is active.

    SENTINEL_REQUIRE_AUTH=1 forces auth on even in dev mode (used by tests).
    In production (SENTINEL_DEV_MODE not set) auth is always required.
    """
    if os.getenv("SENTINEL_REQUIRE_AUTH", "0") == "1":
        return True
    return os.getenv("SENTINEL_DEV_MODE", "0") != "1"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_token(user_id: str, account_id: str, role: str = "admin", expires_minutes: int = 60, sid: str | None = None) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": user_id,
        "account_id": account_id,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    if sid:
        payload["sid"] = sid
    return jwt.encode(payload, jwt_secret(), algorithm=ALGORITHM)


# Must match SESSION_COOKIE in dashboard/src/lib/session.ts.
SESSION_COOKIE_NAME = "sentinel_session"


async def _principal_from_token(token: str, db: AsyncSession) -> Principal:
    """Validate a session JWT and resolve it to a Principal.

    Shared by the Bearer path and the SSE cookie path so the two can never
    drift apart on revocation or purpose-token handling.
    """
    try:
        payload = jwt.decode(token, jwt_secret(), algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="invalid bearer token") from exc

    if payload.get("purpose"):
        # Single-purpose ephemeral tokens (e.g. the MFA login challenge) are
        # signed with the same secret but must never work as a general bearer
        # token — they prove one narrow fact ("this request just presented a
        # correct password"), not a full authenticated session.
        raise HTTPException(status_code=401, detail="invalid bearer token")

    sid = payload.get("sid")
    if sid:
        # Tokens minted through login/signup/device-approval carry a session id
        # that can be revoked (logout, "sign out this device") before the JWT
        # naturally expires. Tokens without a sid (e.g. tests calling
        # create_token directly) are stateless, as before.
        from sentinel_worker.models import Session as SessionRow  # local import avoids a cycle

        session = await db.get(SessionRow, sid)
        if session is None or session.revoked_at is not None or _as_utc(session.expires_at) < datetime.now(UTC):
            raise HTTPException(status_code=401, detail="session revoked or expired")

    return Principal(
        user_id=str(payload.get("sub")),
        account_id=str(payload.get("account_id")),
        role=str(payload.get("role", "readonly")),
        sid=str(sid) if sid else None,
    )


async def current_principal(
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Principal:
    if not auth_required():
        return Principal(user_id="dev", account_id="dev", role="admin")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    return await _principal_from_token(authorization.removeprefix("Bearer ").strip(), db)


async def current_principal_sse(
    authorization: str | None = Header(default=None),
    session_cookie: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: AsyncSession = Depends(get_db),
) -> Principal:
    """Auth for EventSource streams, which cannot send an Authorization header.

    The browser's EventSource API has no way to set headers, so a dashboard
    page streaming a run can only present the session cookie the dashboard
    already set (same-origin via the /api proxy). Accepting it is scoped
    deliberately to this read-only GET: the cookie is SameSite=lax, so it does
    not ride along on cross-site requests, and no state-changing endpoint
    accepts cookie auth. A Bearer header still wins when both are present, so
    the CLI is unaffected.
    """
    if not auth_required():
        return Principal(user_id="dev", account_id="dev", role="admin")
    if authorization and authorization.startswith("Bearer "):
        return await _principal_from_token(authorization.removeprefix("Bearer ").strip(), db)
    if session_cookie:
        return await _principal_from_token(session_cookie, db)
    raise HTTPException(status_code=401, detail="missing bearer token")


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


async def require_admin(principal: Principal = Depends(current_principal)) -> Principal:
    if principal.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return principal

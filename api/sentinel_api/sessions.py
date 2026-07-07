from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.models import Session as SessionRow, User, now

from .auth import create_token
from .security import generate_token, hash_token

# Dashboard password/OAuth logins get one JWT that lives in the browser cookie —
# no separate refresh flow, re-login after expiry is cheap for a human.
DASHBOARD_SESSION_MINUTES = 60 * 24 * 14  # 14 days

# The CLI is a long-running credential a script might use unattended, so it gets
# a short-lived access token plus a rotating refresh token, mirroring standard
# OAuth practice — a leaked access token is only useful for an hour.
CLI_ACCESS_MINUTES = 60  # 1 hour
CLI_REFRESH_MINUTES = 60 * 24 * 90  # 90 days, slides forward on each refresh


def now_plus(minutes: int):
    return now() + timedelta(minutes=minutes)


@dataclass(frozen=True)
class IssuedSession:
    access_token: str
    refresh_token: str | None
    session_id: str
    expires_in: int


async def issue_session(
    db: AsyncSession,
    user: User,
    *,
    label: str,
    session_minutes: int,
    access_minutes: int,
    with_refresh: bool,
    user_agent: str | None = None,
    ip_address: str | None = None,
) -> IssuedSession:
    """Create a Session row and mint its access token (+ optional refresh token).

    `session_minutes` bounds the row's lifetime (and, for refreshable sessions,
    how long the refresh token is valid); `access_minutes` bounds the JWT itself.
    For non-refreshable sessions (dashboard) these are typically the same value.
    """
    refresh_token = generate_token() if with_refresh else None
    session = SessionRow(
        user_id=user.id,
        account_id=user.account_id,
        label=label,
        expires_at=now_plus(session_minutes),
        user_agent=user_agent,
        ip_address=ip_address,
        refresh_token_hash=hash_token(refresh_token) if refresh_token else None,
    )
    db.add(session)
    await db.flush()
    access_token = create_token(user.id, user.account_id, user.role, expires_minutes=access_minutes, sid=session.id)
    return IssuedSession(access_token=access_token, refresh_token=refresh_token, session_id=session.id, expires_in=access_minutes * 60)

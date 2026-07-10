from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import httpx
import pyotp
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from jose import JWTError, jwt
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel_worker.models import Account, AuthToken, LoginAttempt, Session as SessionRow, User, now

from ..auth import ALGORITHM, Principal, create_token, current_principal, hash_password, jwt_secret, verify_password
from .. import deps
from ..deps import get_db
from ..email import send_password_reset_email, send_verification_email
from ..schemas import (
    AuthResponse,
    AuthUserResponse,
    ForgotPasswordRequest,
    GithubOAuthRequest,
    LoginRequest,
    LoginResponse,
    MfaConfirmRequest,
    MfaDisableRequest,
    MfaEnrollResponse,
    MfaLoginRequest,
    RefreshRequest,
    RefreshResponse,
    ResetPasswordRequest,
    SessionResponse,
    SignupRequest,
)
from ..security import client_ip, decrypt_secret, encrypt_secret, generate_token, hash_token
from ..sessions import CLI_ACCESS_MINUTES, CLI_REFRESH_MINUTES, DASHBOARD_SESSION_MINUTES, issue_session, now_plus

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# ── Rate limiting / lockout policy ─────────────────────────────────────────────
MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15
IP_WINDOW_MINUTES = 5
IP_MAX_ATTEMPTS = 20  # coarse per-IP cap; per-account lockout above is the real defense

EMAIL_VERIFY_TTL_MINUTES = 60 * 24  # 24h
PASSWORD_RESET_TTL_MINUTES = 60  # 1h
MFA_CHALLENGE_TTL_MINUTES = 5

GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_URL = "https://api.github.com/user"
GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _is_dev_mode() -> bool:
    return os.getenv("SENTINEL_DEV_MODE", "0") == "1"


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _expired(expires_at: datetime) -> bool:
    return _as_utc(expires_at) < datetime.now(UTC)


def _dashboard_url(path: str) -> str:
    base = os.getenv("SENTINEL_DASHBOARD_URL", "").rstrip("/")
    return f"{base}{path}" if base else path


def _encode_purpose_token(user_id: str, purpose: str, minutes: int) -> str:
    payload = {"sub": user_id, "purpose": purpose, "exp": int((datetime.now(UTC) + timedelta(minutes=minutes)).timestamp())}
    return jwt.encode(payload, jwt_secret(), algorithm=ALGORITHM)


def _decode_purpose_token(token: str, purpose: str) -> str | None:
    try:
        payload = jwt.decode(token, jwt_secret(), algorithms=[ALGORITHM])
    except JWTError:
        return None
    return payload.get("sub") if payload.get("purpose") == purpose else None


async def _run_committed(fn) -> None:
    """Run `fn(session)` in its own short-lived transaction that commits immediately.

    Needed for bookkeeping (rate-limit counters, lockout state) that must persist
    even when the endpoint goes on to raise an HTTPException — get_db()'s
    `session.begin()` rolls back the *entire* request transaction on any
    exception, which would otherwise silently erase the very record a failed
    attempt is supposed to leave behind.
    """
    # Look up deps.SessionLocal dynamically (not via a module-level `from ..deps
    # import SessionLocal`) so tests that monkeypatch deps.SessionLocal to an
    # isolated test DB are actually honored here too.
    async with deps.SessionLocal() as session:
        async with session.begin():
            await fn(session)


async def _check_ip_rate_limit(db: AsyncSession, request: Request, endpoint: str) -> None:
    ip = client_ip(request)
    window_start = now() - timedelta(minutes=IP_WINDOW_MINUTES)
    count = await db.scalar(
        select(func.count(LoginAttempt.id))
        .where(LoginAttempt.ip_address == ip)
        .where(LoginAttempt.endpoint == endpoint)
        .where(LoginAttempt.created_at >= window_start)
    )

    async def _record(session: AsyncSession) -> None:
        session.add(LoginAttempt(ip_address=ip, endpoint=endpoint))

    await _run_committed(_record)

    if count and count >= IP_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="too many attempts from this address — try again later")


async def _record_failed_login(user_id: str) -> None:
    async def _record(session: AsyncSession) -> None:
        user = await session.get(User, user_id)
        if user is None:
            return
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED_LOGINS:
            user.locked_until = now_plus(LOCKOUT_MINUTES)
            log.warning("auth.account_locked", user_id=user.id)

    await _run_committed(_record)


async def _resolve_actor(db: AsyncSession, principal: Principal) -> User:
    """Resolve the real DB user behind this principal.

    In dev mode current_principal returns a fixed "dev"/"dev" pseudo-principal
    that has no matching DB row — resolve it to the single local dev user
    (created lazily), mirroring main.py's dev-mode handling for the rest of
    the API so /auth/me, /auth/sessions, etc. work under `docker compose up`.
    """
    if _is_dev_mode() and principal.user_id == "dev":
        user = await db.scalar(select(User).order_by(User.created_at).limit(1))
        if user is not None:
            return user
        account = await db.scalar(select(Account).where(Account.name == "dev"))
        if account is None:
            account = Account(name="dev")
            db.add(account)
            await db.flush()
        user = User(account_id=account.id, email="dev@sentinel.local", name="Dev", role="admin")
        db.add(user)
        await db.flush()
        return user
    user = await db.get(User, principal.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    return user


async def _user_response(db: AsyncSession, user: User) -> AuthUserResponse:
    account = await db.get(Account, user.account_id)
    return AuthUserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        account_id=user.account_id,
        account_name=account.name if account else user.account_id,
        email_verified=user.email_verified_at is not None,
        mfa_enabled=user.totp_confirmed,
    )


async def _create_auth_token(db: AsyncSession, user: User, purpose: str, minutes: int) -> str:
    raw = generate_token()
    db.add(AuthToken(user_id=user.id, purpose=purpose, token_hash=hash_token(raw), expires_at=now_plus(minutes)))
    await db.flush()
    return raw


async def _send_verification_email(db: AsyncSession, user: User) -> None:
    raw = await _create_auth_token(db, user, "email_verify", EMAIL_VERIFY_TTL_MINUTES)
    await send_verification_email(user.email, _dashboard_url(f"/verify-email?token={raw}"))


async def _dashboard_session(db: AsyncSession, user: User, request: Request):
    return await issue_session(
        db,
        user,
        label="dashboard",
        session_minutes=DASHBOARD_SESSION_MINUTES,
        access_minutes=DASHBOARD_SESSION_MINUTES,
        with_refresh=False,
        user_agent=request.headers.get("user-agent"),
        ip_address=client_ip(request),
    )


# ── Signup / login / logout ────────────────────────────────────────────────────


@router.post("/signup", response_model=AuthResponse)
async def signup(payload: SignupRequest, request: Request, db: AsyncSession = Depends(get_db)) -> AuthResponse:
    await _check_ip_rate_limit(db, request, "signup")
    email = _normalize_email(payload.email)
    existing = await db.scalar(select(User).where(User.email == email))
    if existing is not None:
        raise HTTPException(status_code=409, detail="an account with this email already exists")

    account = Account(name=payload.account_name or f"{payload.name}'s team")
    db.add(account)
    await db.flush()

    user = User(
        account_id=account.id,
        email=email,
        name=payload.name,
        password_hash=hash_password(payload.password),
        role="admin",
    )
    db.add(user)
    await db.flush()

    await _send_verification_email(db, user)

    issued = await _dashboard_session(db, user, request)
    return AuthResponse(access_token=issued.access_token, user=await _user_response(db, user))


@router.post("/login", response_model=LoginResponse)
async def login(payload: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)) -> LoginResponse:
    await _check_ip_rate_limit(db, request, "login")
    email = _normalize_email(payload.email)
    user = await db.scalar(select(User).where(User.email == email))

    if user is not None and user.locked_until is not None and _as_utc(user.locked_until) > datetime.now(UTC):
        raise HTTPException(status_code=423, detail="account temporarily locked from repeated failed logins — try again later")

    if user is None or not user.password_hash or not verify_password(payload.password, user.password_hash):
        if user is not None:
            await _record_failed_login(user.id)
        raise HTTPException(status_code=401, detail="invalid email or password")

    user.failed_login_count = 0
    user.locked_until = None

    if user.totp_confirmed:
        challenge = _encode_purpose_token(user.id, "mfa_challenge", MFA_CHALLENGE_TTL_MINUTES)
        return LoginResponse(mfa_required=True, challenge_token=challenge)

    issued = await _dashboard_session(db, user, request)
    return LoginResponse(access_token=issued.access_token, user=await _user_response(db, user))


@router.post("/login/mfa", response_model=AuthResponse)
async def login_mfa(payload: MfaLoginRequest, request: Request, db: AsyncSession = Depends(get_db)) -> AuthResponse:
    user_id = _decode_purpose_token(payload.challenge_token, "mfa_challenge")
    if user_id is None:
        raise HTTPException(status_code=401, detail="challenge expired or invalid — log in again")
    user = await db.get(User, user_id)
    if user is None or not user.totp_confirmed or not user.totp_secret_enc:
        raise HTTPException(status_code=401, detail="MFA is not enabled for this account")
    secret = decrypt_secret(user.totp_secret_enc)
    if not secret or not pyotp.TOTP(secret).verify(payload.code, valid_window=1):
        raise HTTPException(status_code=401, detail="invalid code")

    issued = await _dashboard_session(db, user, request)
    return AuthResponse(access_token=issued.access_token, user=await _user_response(db, user))


@router.post("/logout")
async def logout(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> dict[str, str]:
    if principal.sid:
        session = await db.get(SessionRow, principal.sid)
        if session is not None:
            session.revoked_at = now()
    return {"status": "ok"}


@router.get("/me", response_model=AuthUserResponse)
async def me(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> AuthUserResponse:
    actor = await _resolve_actor(db, principal)
    return await _user_response(db, actor)


@router.get("/members", response_model=list[AuthUserResponse])
async def list_members(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[AuthUserResponse]:
    """List the users in the caller's account (team roster)."""
    actor = await _resolve_actor(db, principal)
    rows = await db.scalars(
        select(User).where(User.account_id == actor.account_id).order_by(User.created_at.asc())
    )
    return [await _user_response(db, user) for user in rows]


# ── Sessions ────────────────────────────────────────────────────────────────────


@router.get("/sessions", response_model=list[SessionResponse])
async def list_sessions(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> list[SessionResponse]:
    actor = await _resolve_actor(db, principal)
    rows = await db.scalars(
        select(SessionRow)
        .where(SessionRow.user_id == actor.id)
        .where(SessionRow.revoked_at.is_(None))
        .order_by(SessionRow.created_at.desc())
    )
    return [
        SessionResponse(
            id=row.id,
            label=row.label,
            created_at=row.created_at.isoformat(),
            expires_at=row.expires_at.isoformat(),
            last_seen_at=row.last_seen_at.isoformat(),
            user_agent=row.user_agent,
            ip_address=row.ip_address,
            current=row.id == principal.sid,
        )
        for row in rows
    ]


@router.delete("/sessions/{session_id}")
async def revoke_session(session_id: str, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> dict[str, str]:
    actor = await _resolve_actor(db, principal)
    session = await db.get(SessionRow, session_id)
    if session is None or session.user_id != actor.id:
        raise HTTPException(status_code=404, detail="session not found")
    session.revoked_at = now()
    return {"status": "revoked"}


@router.post("/refresh", response_model=RefreshResponse)
async def refresh(payload: RefreshRequest, db: AsyncSession = Depends(get_db)) -> RefreshResponse:
    session = await db.scalar(select(SessionRow).where(SessionRow.refresh_token_hash == hash_token(payload.refresh_token)))
    if session is None or session.revoked_at is not None or _expired(session.expires_at):
        raise HTTPException(status_code=401, detail="refresh token invalid or expired")
    user = await db.get(User, session.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="user not found")

    new_refresh = generate_token()
    session.refresh_token_hash = hash_token(new_refresh)
    session.expires_at = now_plus(CLI_REFRESH_MINUTES)  # sliding window — stays alive as long as it's used
    session.last_seen_at = now()
    access_token = create_token(user.id, user.account_id, user.role, expires_minutes=CLI_ACCESS_MINUTES, sid=session.id)
    return RefreshResponse(access_token=access_token, refresh_token=new_refresh, expires_in=CLI_ACCESS_MINUTES * 60)


# ── Email verification ───────────────────────────────────────────────────────────


@router.post("/verify-email/resend")
async def resend_verification(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> dict[str, str]:
    actor = await _resolve_actor(db, principal)
    if actor.email_verified_at is not None:
        return {"status": "already_verified"}
    await _send_verification_email(db, actor)
    return {"status": "sent"}


@router.post("/verify-email")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    row = await db.scalar(select(AuthToken).where(AuthToken.token_hash == hash_token(token)).where(AuthToken.purpose == "email_verify"))
    if row is None or row.used_at is not None or _expired(row.expires_at):
        raise HTTPException(status_code=400, detail="invalid or expired verification link")
    user = await db.get(User, row.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    user.email_verified_at = now()
    row.used_at = now()
    return {"status": "verified"}


# ── Password reset ──────────────────────────────────────────────────────────────


@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest, request: Request, db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    await _check_ip_rate_limit(db, request, "forgot-password")
    user = await db.scalar(select(User).where(User.email == _normalize_email(payload.email)))
    if user is not None and user.password_hash is not None:
        raw = await _create_auth_token(db, user, "password_reset", PASSWORD_RESET_TTL_MINUTES)
        await send_password_reset_email(user.email, _dashboard_url(f"/reset-password/{raw}"))
    # Always the same response — don't reveal whether the email is registered.
    return {"status": "ok"}


@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest, db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    row = await db.scalar(select(AuthToken).where(AuthToken.token_hash == hash_token(payload.token)).where(AuthToken.purpose == "password_reset"))
    if row is None or row.used_at is not None or _expired(row.expires_at):
        raise HTTPException(status_code=400, detail="invalid or expired reset link")
    user = await db.get(User, row.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")

    user.password_hash = hash_password(payload.password)
    user.failed_login_count = 0
    user.locked_until = None
    row.used_at = now()

    # A password reset is a strong signal the account may have been compromised —
    # sign every other device out rather than leaving old sessions valid.
    active = await db.scalars(select(SessionRow).where(SessionRow.user_id == user.id).where(SessionRow.revoked_at.is_(None)))
    for session in active:
        session.revoked_at = now()

    return {"status": "reset"}


# ── TOTP-based MFA ────────────────────────────────────────────────────────────────


@router.post("/mfa/enroll", response_model=MfaEnrollResponse)
async def mfa_enroll(db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> MfaEnrollResponse:
    actor = await _resolve_actor(db, principal)
    secret = pyotp.random_base32()
    actor.totp_secret_enc = encrypt_secret(secret)
    actor.totp_confirmed = False
    otpauth_url = pyotp.TOTP(secret).provisioning_uri(name=actor.email, issuer_name="Sentinel")
    return MfaEnrollResponse(secret=secret, otpauth_url=otpauth_url)


@router.post("/mfa/confirm")
async def mfa_confirm(payload: MfaConfirmRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> dict[str, str]:
    actor = await _resolve_actor(db, principal)
    if not actor.totp_secret_enc:
        raise HTTPException(status_code=400, detail="call /mfa/enroll first")
    secret = decrypt_secret(actor.totp_secret_enc)
    if not secret or not pyotp.TOTP(secret).verify(payload.code, valid_window=1):
        raise HTTPException(status_code=401, detail="invalid code")
    actor.totp_confirmed = True
    return {"status": "enabled"}


@router.post("/mfa/disable")
async def mfa_disable(payload: MfaDisableRequest, db: AsyncSession = Depends(get_db), principal: Principal = Depends(current_principal)) -> dict[str, str]:
    actor = await _resolve_actor(db, principal)
    if not actor.password_hash or not verify_password(payload.password, actor.password_hash):
        raise HTTPException(status_code=401, detail="invalid password")
    actor.totp_secret_enc = None
    actor.totp_confirmed = False
    return {"status": "disabled"}


# ── GitHub OAuth ──────────────────────────────────────────────────────────────────


@router.post("/oauth/github", response_model=AuthResponse)
async def oauth_github(payload: GithubOAuthRequest, request: Request, db: AsyncSession = Depends(get_db)) -> AuthResponse:
    client_id = os.getenv("GITHUB_OAUTH_CLIENT_ID")
    client_secret = os.getenv("GITHUB_OAUTH_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise HTTPException(status_code=501, detail="GitHub sign-in is not configured on this server")

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_resp = await client.post(
            GITHUB_TOKEN_URL,
            headers={"Accept": "application/json"},
            data={"client_id": client_id, "client_secret": client_secret, "code": payload.code, "redirect_uri": payload.redirect_uri},
        )
        github_token = (token_resp.json() or {}).get("access_token") if token_resp.status_code == 200 else None
        if not github_token:
            raise HTTPException(status_code=401, detail="GitHub authorization failed")

        auth_header = {"Authorization": f"Bearer {github_token}", "Accept": "application/json"}
        profile_resp = await client.get(GITHUB_USER_URL, headers=auth_header)
        if profile_resp.status_code != 200:
            raise HTTPException(status_code=401, detail="could not read GitHub profile")
        profile = profile_resp.json()
        github_id = str(profile.get("id"))
        name = profile.get("name") or profile.get("login") or "GitHub user"
        email = profile.get("email")

        if not email:
            emails_resp = await client.get(GITHUB_EMAILS_URL, headers=auth_header)
            if emails_resp.status_code == 200:
                for entry in emails_resp.json():
                    if entry.get("primary"):
                        email = entry.get("email")
                        break

    if not email:
        raise HTTPException(status_code=400, detail="GitHub account has no email available to sign in with — add a public email on GitHub and try again")
    email = _normalize_email(email)

    user = await db.scalar(select(User).where(User.github_id == github_id))
    if user is None:
        user = await db.scalar(select(User).where(User.email == email))
        if user is not None:
            user.github_id = github_id  # link GitHub to an existing password account
        else:
            account = Account(name=f"{name}'s team")
            db.add(account)
            await db.flush()
            user = User(account_id=account.id, email=email, name=name, github_id=github_id, role="admin", email_verified_at=now())
            db.add(user)
            await db.flush()

    issued = await _dashboard_session(db, user, request)
    return AuthResponse(access_token=issued.access_token, user=await _user_response(db, user))

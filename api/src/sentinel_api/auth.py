from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, Header, HTTPException
from jose import JWTError, jwt


ALGORITHM = "HS256"


@dataclass(frozen=True)
class Principal:
    user_id: str
    account_id: str
    role: str


def jwt_secret() -> str:
    return os.getenv("SENTINEL_JWT_SECRET", "dev-secret")


def auth_required() -> bool:
    return os.getenv("SENTINEL_REQUIRE_AUTH", "0") == "1"


def create_token(user_id: str, account_id: str, role: str = "admin", expires_minutes: int = 60) -> str:
    now = datetime.now(UTC)
    return jwt.encode(
        {
            "sub": user_id,
            "account_id": account_id,
            "role": role,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
        },
        jwt_secret(),
        algorithm=ALGORITHM,
    )


async def current_principal(authorization: str | None = Header(default=None)) -> Principal:
    if not auth_required():
        return Principal(user_id="dev", account_id="dev", role="admin")
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, jwt_secret(), algorithms=[ALGORITHM])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="invalid bearer token") from exc
    return Principal(
        user_id=str(payload.get("sub")),
        account_id=str(payload.get("account_id")),
        role=str(payload.get("role", "readonly")),
    )


async def require_admin(principal: Principal = Depends(current_principal)) -> Principal:
    if principal.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    return principal

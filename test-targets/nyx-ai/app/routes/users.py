from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import get_current_user
from ..models import APIKey, TokenUsage, User

router = APIRouter(prefix="/users", tags=["users"])


class UserResponse(BaseModel):
    id: str
    email: str
    role: str
    account_id: str


class APIKeyResponse(BaseModel):
    id: str
    prefix: str
    label: str
    is_active: bool
    created_at: str


class UsageResponse(BaseModel):
    user_id: str
    prompt_tokens: int
    completion_tokens: int


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        role=current_user.role,
        account_id=current_user.account_id,
    )


@router.get("/{user_id}/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(lambda: None),
) -> list[APIKeyResponse]:
    if current_user.role != "admin" and current_user.id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    result = await db.execute(select(APIKey).where(APIKey.user_id == user_id))
    return [
        APIKeyResponse(
            id=k.id,
            prefix=k.prefix,
            label=k.label,
            is_active=k.is_active,
            created_at=k.created_at.isoformat(),
        )
        for k in result.scalars()
    ]


@router.get("/{user_id}/usage", response_model=UsageResponse)
async def get_usage(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(lambda: None),
) -> UsageResponse:
    """Return cumulative token usage for a user."""
    result = await db.execute(
        select(
            func.sum(TokenUsage.prompt_tokens),
            func.sum(TokenUsage.completion_tokens),
        ).where(TokenUsage.user_id == user_id)
    )
    row = result.one()
    return UsageResponse(
        user_id=user_id,
        prompt_tokens=int(row[0] or 0),
        completion_tokens=int(row[1] or 0),
    )

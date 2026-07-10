from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, relationship


def _now() -> datetime:
    return datetime.now(UTC)


def _uuid() -> str:
    return str(uuid4())


class Base(DeclarativeBase):
    pass


class Account(Base):
    __tablename__ = "accounts"

    id: str = Column(String, primary_key=True, default=_uuid)
    name: str = Column(String, nullable=False)
    created_at: datetime = Column(DateTime(timezone=True), default=_now)

    users = relationship("User", back_populates="account")
    api_keys = relationship("APIKey", back_populates="account")


class User(Base):
    __tablename__ = "users"

    id: str = Column(String, primary_key=True, default=_uuid)
    account_id: str = Column(String, ForeignKey("accounts.id"), nullable=False)
    email: str = Column(String, unique=True, nullable=False)
    role: str = Column(String, default="member")
    is_active: bool = Column(Boolean, default=True)
    created_at: datetime = Column(DateTime(timezone=True), default=_now)

    account = relationship("Account", back_populates="users")
    api_keys = relationship("APIKey", back_populates="user")


class APIKey(Base):
    __tablename__ = "api_keys"

    id: str = Column(String, primary_key=True, default=_uuid)
    user_id: str = Column(String, ForeignKey("users.id"), nullable=False)
    account_id: str = Column(String, ForeignKey("accounts.id"), nullable=False)
    prefix: str = Column(String(12), nullable=False, index=True)
    key_hash: str = Column(String(64), nullable=False)
    label: str = Column(String, default="")
    is_active: bool = Column(Boolean, default=True)
    created_at: datetime = Column(DateTime(timezone=True), default=_now)

    user = relationship("User", back_populates="api_keys")
    account = relationship("Account", back_populates="api_keys")


class TokenUsage(Base):
    __tablename__ = "token_usage"

    id: str = Column(String, primary_key=True, default=_uuid)
    user_id: str = Column(String, ForeignKey("users.id"), nullable=False)
    account_id: str = Column(String, ForeignKey("accounts.id"), nullable=False)
    model: str = Column(String, nullable=False)
    prompt_tokens: int = Column(Integer, default=0)
    completion_tokens: int = Column(Integer, default=0)
    created_at: datetime = Column(DateTime(timezone=True), default=_now)

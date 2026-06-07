"""Valid Python fixture: known structure for parse and resolution pass tests.

Expected parse output:
  - FILE node: file:worker/tests/fixtures/source/python/valid.py
  - FUNCTION nodes: authenticate_user, get_user_by_id, hash_password, _validate_token
  - CLASS node: UserService
  - PARAMETER nodes on each function
"""
from __future__ import annotations

import hashlib


class UserService:
    def __init__(self, db):
        self.db = db

    def authenticate_user(self, username: str, password: str) -> dict | None:
        hashed = hash_password(password)
        return self.db.execute(
            "SELECT * FROM users WHERE username = ? AND password_hash = ?",
            (username, hashed),
        ).fetchone()

    def get_user_by_id(self, user_id: int) -> dict | None:
        return self.db.execute(
            "SELECT id, username, email FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def _validate_token(token: str) -> bool:
    return isinstance(token, str) and len(token) == 64

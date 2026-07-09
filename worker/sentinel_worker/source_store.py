"""Encrypted source-snapshot storage.

Scope note (AUDIT.md §1 invariant 1, P2.3): source snapshots are NOT written to
the cloud on the CLI scan path. The CLI's local engine runs SAST against an
ephemeral local SQLite DB and only pushes graph deltas + findings to the cloud;
`store_source_snapshot` in that path writes to the throwaway local DB, not the
hosted one. The legacy cloud-SAST callers (GitHub webhook `kind=source` /
`init` runner tasks) that persisted snapshots server-side have been removed. The
remaining server-side reader is the pentest agent's `read_file`/`grep_source`
tools (see tools.py), gated by mode=local_worker with a mounted repo (§3 D3).
"""
from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime, timedelta

from cryptography.fernet import Fernet
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .languages import language_for
from .models import Account, Repo, SourceFileSnapshot
from .security import is_secret_file


DEV_SOURCE_KEY = "sentinel-dev-source-key"


def source_key() -> bytes:
    raw = os.getenv("SENTINEL_SOURCE_KEY", DEV_SOURCE_KEY).encode()
    digest = hashlib.sha256(raw).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_source(content: str) -> str:
    return Fernet(source_key()).encrypt(content.encode()).decode()


def decrypt_source(content_enc: str) -> str:
    return Fernet(source_key()).decrypt(content_enc.encode()).decode()


async def store_source_snapshot(
    db: AsyncSession,
    *,
    repo_id: str,
    commit_hash: str,
    file_path: str,
    content: str,
    deleted: bool = False,
) -> SourceFileSnapshot | None:
    if is_secret_file(file_path):
        # .env-style files are never persisted, so the SAST agent's read_file/grep_source
        # tools have no snapshot to retrieve them from.
        return None
    snapshot = SourceFileSnapshot(
        repo_id=repo_id,
        commit_hash=commit_hash,
        file_path=file_path,
        content_enc=encrypt_source(content),
        content_sha=hashlib.sha256(content.encode()).hexdigest(),
        language=language_for(file_path),
        deleted=deleted,
    )
    stored = await db.merge(snapshot)
    return stored


async def read_source_snapshot(db: AsyncSession, *, repo_id: str, commit_hash: str, file_path: str) -> str:
    if is_secret_file(file_path):
        raise FileNotFoundError(file_path)
    snapshot = await db.get(SourceFileSnapshot, (repo_id, commit_hash, file_path))
    if snapshot is None or snapshot.deleted:
        raise FileNotFoundError(file_path)
    return decrypt_source(snapshot.content_enc)


async def enforce_source_retention_for_account(db: AsyncSession, account_id: str, *, current_time: datetime | None = None) -> int:
    account = await db.get(Account, account_id)
    if account is None:
        return 0
    cutoff = (current_time or datetime.now(UTC)) - timedelta(days=account.source_retention_days)
    result = await db.execute(
        delete(SourceFileSnapshot).where(
            SourceFileSnapshot.repo_id.in_(select(Repo.id).where(Repo.account_id == account_id)),
            SourceFileSnapshot.created_at < cutoff,
        )
    )
    return int(result.rowcount or 0)  # type: ignore[attr-defined]

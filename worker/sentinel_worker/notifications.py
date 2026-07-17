from __future__ import annotations

import re

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


RUN_CHANNEL_PREFIX = "run_"
CHANNEL_RE = re.compile(r"[^A-Za-z0-9_]")


async def notify_run_event(db: AsyncSession, run_id: str, payload: str) -> None:
    await notify(db, f"{RUN_CHANNEL_PREFIX}{run_id}", payload)


async def notify(db: AsyncSession, channel: str, payload: str) -> None:
    bind = db.get_bind()
    if bind.dialect.name != "postgresql":
        return
    await db.execute(text("SELECT pg_notify(:channel, :payload)"), {"channel": _safe_channel(channel), "payload": payload})


def _safe_channel(channel: str) -> str:
    return CHANNEL_RE.sub("_", channel)[:63]

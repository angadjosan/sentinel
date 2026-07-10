#!/usr/bin/env python3
"""
Approve a pending sentinel auth login.

Usage:
    python scripts/approve_login.py

Watches for pending device auth sessions and approves them automatically.
Run this in one terminal, then `sentinel auth login` in another.
Press Ctrl+C when done.

Requires:
    DATABASE_URL env var (or edit the DEFAULT_DB below)
"""
import asyncio
import os
import sys

if not os.environ.get("DATABASE_URL"):
    sys.exit("Set DATABASE_URL env var to your Neon connection string and re-run.")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "worker"))

from datetime import UTC, datetime
from sentinel_worker.db import create_engine, create_sessionmaker
from sentinel_worker.models import Account, DeviceAuthSession, User
from sqlalchemy import select


ACCOUNT_ID = "092a0951-d98c-4dc9-a20f-c08828978383"
USER_ID    = "791a9839-c77d-4a39-a5eb-912d2e94f831"


async def main() -> None:
    engine = create_engine()
    sm = create_sessionmaker(engine)
    print("Watching for login attempts — run `sentinel auth login` now...")
    try:
        while True:
            async with sm() as db:
                async with db.begin():
                    now = datetime.now(UTC)
                    pending = list(await db.scalars(
                        select(DeviceAuthSession)
                        .where(DeviceAuthSession.status == "pending")
                        .where(DeviceAuthSession.expires_at > now)
                    ))
                    for s in pending:
                        s.status = "approved"
                        s.account_id = ACCOUNT_ID
                        s.user_id = USER_ID
                        s.role = "admin"
                        s.approved_at = now
                        print(f"  ✓ Approved: {s.user_code}")
            await asyncio.sleep(2)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        await engine.dispose()


asyncio.run(main())

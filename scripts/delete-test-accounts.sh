#!/usr/bin/env bash
# Delete throwaway accounts (e.g. ones created while smoke-testing signup) from
# the hosted database. There is no delete-account endpoint, so this is the
# supported way to clean them up.
#
# Usage:
#   bash scripts/delete-test-accounts.sh 'deploy-probe-%@trysentinel.dev'   # dry run
#   bash scripts/delete-test-accounts.sh 'deploy-probe-%@trysentinel.dev' --confirm
#
# The argument is a SQL LIKE pattern matched against users.email ('%' = wildcard).
# Dry run is the default: nothing is deleted unless --confirm is passed.
#
# SAFETY: an account is skipped if it owns any repos, graphs or runs. This is
# for disposable test accounts only; it must never be the thing that quietly
# deletes a real customer's data because a pattern was too broad.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PATTERN="${1:-}"
CONFIRM=0
for arg in "${@:2}"; do
  case "$arg" in
    --confirm) CONFIRM=1 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ -z "$PATTERN" ]; then
  sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 2
fi

if [ -t 1 ] && command -v tput >/dev/null 2>&1 && tput colors >/dev/null 2>&1; then
  RED="$(tput bold)$(tput setaf 1)"; GREEN="$(tput bold)$(tput setaf 2)"
  YELLOW="$(tput bold)$(tput setaf 3)"; DIM="$(tput dim)"; NC="$(tput sgr0)"
else
  RED=""; GREEN=""; YELLOW=""; DIM=""; NC=""
fi
die() { echo "${RED}error:${NC} $*" >&2; exit 1; }

command -v vercel >/dev/null 2>&1 || die "vercel CLI not found — npm i -g vercel"

ENV_FILE="$(mktemp -t sentinel-prod-env)"
trap 'rm -f "$ENV_FILE"' EXIT INT TERM

echo "==> Pulling production environment from Vercel"
( cd "$REPO_DIR" && vercel env pull "$ENV_FILE" --environment=production --yes >/dev/null ) \
  || die "vercel env pull failed"

DB_URL="$(ENV_FILE="$ENV_FILE" python3 <<'PY'
import os, pathlib, re, sys
env = {}
for line in pathlib.Path(os.environ["ENV_FILE"]).read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        k, v = line.split("=", 1)
        env[k] = v.strip().strip('"')
url = env.get("POSTGRES_URL_NON_POOLING") or env.get("DATABASE_URL_UNPOOLED") or ""
if not url:
    sys.exit("no unpooled Postgres URL in the pulled environment")
url = re.sub(r"^postgres(ql)?://", "postgresql+asyncpg://", url)
url = re.sub(r"[?&](sslmode|channel_binding)=[^&]*", "", url)
print(url + ("&" if "?" in url else "?") + "ssl=require")
PY
)" || die "could not build the database URL"

echo "    pattern: ${DIM}${PATTERN}${NC}"
[ "$CONFIRM" -eq 1 ] && echo "    mode: ${YELLOW}DELETE${NC}" || echo "    mode: ${GREEN}dry run${NC} (pass --confirm to delete)"
echo

DB_URL="$DB_URL" PATTERN="$PATTERN" CONFIRM="$CONFIRM" python3 <<'PY'
import asyncio, os, sys

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

PATTERN = os.environ["PATTERN"]
CONFIRM = os.environ["CONFIRM"] == "1"


async def main() -> int:
    engine = create_async_engine(os.environ["DB_URL"])
    deleted = skipped = matched = 0
    async with engine.begin() as conn:
        rows = (await conn.execute(
            text("SELECT id, account_id, email FROM users WHERE email LIKE :p ORDER BY email"),
            {"p": PATTERN},
        )).fetchall()

        if not rows:
            print("No users matched. Nothing to do.")
            return 0

        for user_id, account_id, email in rows:
            # Refuse anything that looks like real usage rather than a probe.
            owned = {}
            for table in ("repos", "graphs", "runs"):
                if table == "runs":
                    q = text("SELECT count(*) FROM runs r JOIN graphs g ON r.graph_id = g.id "
                             "WHERE g.account_id = :a")
                else:
                    q = text(f"SELECT count(*) FROM {table} WHERE account_id = :a")
                owned[table] = (await conn.execute(q, {"a": account_id})).scalar() or 0

            if any(owned.values()):
                detail = ", ".join(f"{k}={v}" for k, v in owned.items() if v)
                print(f"  SKIP   {email}  (account owns data: {detail})")
                skipped += 1
                continue

            matched += 1
            print(f"  {'DELETE' if CONFIRM else 'would delete'}  {email}")
            if not CONFIRM:
                continue

            # FK order: no ON DELETE CASCADE is declared on these tables.
            await conn.execute(text("DELETE FROM auth_tokens WHERE user_id = :u"), {"u": user_id})
            await conn.execute(text("DELETE FROM sessions WHERE user_id = :u"), {"u": user_id})
            await conn.execute(
                text("DELETE FROM device_auth_sessions WHERE user_id = :u OR account_id = :a"),
                {"u": user_id, "a": account_id},
            )
            await conn.execute(text("DELETE FROM users WHERE id = :u"), {"u": user_id})
            remaining = (await conn.execute(
                text("SELECT count(*) FROM users WHERE account_id = :a"), {"a": account_id}
            )).scalar() or 0
            if remaining == 0:
                await conn.execute(text("DELETE FROM accounts WHERE id = :a"), {"a": account_id})
            deleted += 1

    await engine.dispose()
    print()
    if CONFIRM:
        print(f"Deleted {deleted} account(s); skipped {skipped}.")
    else:
        print(f"Dry run: {matched} would be deleted, {skipped} skipped. "
              f"Re-run with --confirm to apply.")
    return 0


sys.exit(asyncio.run(main()))
PY

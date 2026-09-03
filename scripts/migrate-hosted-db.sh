#!/usr/bin/env bash
# Migrate the hosted (Neon) database to the current Alembic head.
#
# Usage: bash scripts/migrate-hosted-db.sh [--yes] [--status]
#
#   --status   show the current revision and pending migrations, change nothing
#   --yes      skip the confirmation prompt (for CI / deploy pipelines)
#
# Runnable from anywhere in the repo — it resolves its own paths.
#
# Why this script exists rather than a documented `alembic upgrade head`:
#
#   * The URL must be the UNPOOLED Neon endpoint (the host WITHOUT `-pooler`).
#     DDL over PgBouncer is what silently failed for months.
#   * asyncpg wants `ssl=require`; Neon hands out `sslmode=require`, which
#     asyncpg rejects as an unknown keyword.
#   * ALEMBIC_DB_URL must be EXPORTED. Setting it as a plain shell variable
#     leaves env.py falling back to alembic.ini's localhost default, so the
#     migration quietly targets the wrong database instead of failing.
#
# The hosted API does not migrate on boot (see sentinel_worker.migrations):
# a serverless cold start is the wrong place to run DDL. This script is the
# supported path for the hosted backend. Self-hosted Docker migrates itself.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ASSUME_YES=0
STATUS_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --yes|-y)    ASSUME_YES=1 ;;
    --status)    STATUS_ONLY=1 ;;
    -h|--help)   sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)           echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ -t 1 ] && command -v tput >/dev/null 2>&1 && tput colors >/dev/null 2>&1; then
  RED="$(tput bold)$(tput setaf 1)"; GREEN="$(tput bold)$(tput setaf 2)"
  YELLOW="$(tput bold)$(tput setaf 3)"; DIM="$(tput dim)"; NC="$(tput sgr0)"
else
  RED=""; GREEN=""; YELLOW=""; DIM=""; NC=""
fi

die() { echo "${RED}error:${NC} $*" >&2; exit 1; }

command -v vercel  >/dev/null 2>&1 || die "vercel CLI not found — npm i -g vercel"
command -v alembic >/dev/null 2>&1 || die "alembic not found — pip install -e \"$REPO_DIR/worker\""

# Pull production env into a temp file that is removed on any exit path: it
# holds live database credentials and must not linger in the working tree.
ENV_FILE="$(mktemp -t sentinel-prod-env)"
cleanup() { rm -f "$ENV_FILE"; }
trap cleanup EXIT INT TERM

echo "==> Pulling production environment from Vercel"
( cd "$REPO_DIR" && vercel env pull "$ENV_FILE" --environment=production --yes >/dev/null ) \
  || die "vercel env pull failed — are you logged in and linked to the API project?"

# Build the connection URL. Kept in Python so the parsing matches what the
# application itself does, rather than re-implementing it in sed.
DB_URL="$(ENV_FILE="$ENV_FILE" python3 <<'PY'
import os, pathlib, re, sys

env = {}
for line in pathlib.Path(os.environ["ENV_FILE"]).read_text().splitlines():
    if "=" in line and not line.startswith("#"):
        key, value = line.split("=", 1)
        env[key] = value.strip().strip('"')

url = env.get("POSTGRES_URL_NON_POOLING") or env.get("DATABASE_URL_UNPOOLED") or ""
if not url:
    sys.exit("no unpooled Postgres URL in the pulled environment "
             "(expected POSTGRES_URL_NON_POOLING or DATABASE_URL_UNPOOLED)")
if "-pooler." in url:
    sys.exit(f"refusing to migrate through the connection pooler: {url.split('@')[-1].split('/')[0]}")

url = re.sub(r"^postgres(ql)?://", "postgresql+asyncpg://", url)
url = re.sub(r"[?&](sslmode|channel_binding)=[^&]*", "", url)
print(url + ("&" if "?" in url else "?") + "ssl=require")
PY
)" || die "could not build the database URL"

[ -n "$DB_URL" ] || die "database URL came back empty"

# EXPORTED, not merely assigned — env.py reads it from the environment.
export ALEMBIC_DB_URL="$DB_URL"

SAFE_TARGET="$(printf '%s' "$DB_URL" | sed -E 's#//[^@]*@#//<redacted>@#')"
echo "    target: ${DIM}${SAFE_TARGET%%\?*}${NC}"

cd "$REPO_DIR/worker"   # alembic.ini lives here; script_location is relative to it

echo
echo "==> Current state"
alembic current || die "could not reach the database"
echo
echo "==> Pending"
alembic history --indicate-current 2>/dev/null | sed -n '1,15p' || true

if [ "$STATUS_ONLY" -eq 1 ]; then
  echo
  echo "${YELLOW}--status given: nothing was changed.${NC}"
  exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  echo
  printf "Apply migrations to this PRODUCTION database? [y/N] "
  read -r reply
  case "$reply" in
    [yY]|[yY][eE][sS]) ;;
    *) echo "aborted."; exit 1 ;;
  esac
fi

echo
echo "==> Upgrading to head"
alembic upgrade head

echo
echo "==> Now at"
alembic current

echo
echo "${GREEN}Done.${NC} Verify the API can reach the schema:"
echo "  curl -s -o /dev/null -w '%{http_code}\\n' -X POST \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"email\":\"probe@example.com\",\"password\":\"x\"}' \\"
echo "    https://www.trysentinel.dev/api/auth/login"
echo "  ${DIM}401 = working (credentials rejected by a live database). 500 = still broken.${NC}"

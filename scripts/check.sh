#!/usr/bin/env bash
# Sentinel health check — diagnose any setup issue at a glance.
# Usage: bash scripts/check.sh [/path/to/your-repo]
#
# Examples:
#   bash scripts/check.sh                  # checks from current directory
#   bash scripts/check.sh ~/code/my-app    # checks a specific repo

SENTINEL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_DIR="${1:-$PWD}"

# ── Colours ───────────────────────────────────────────────────────────────────
if [ -t 1 ] && command -v tput &>/dev/null && tput colors &>/dev/null; then
  RED="$(tput bold)$(tput setaf 1)"
  GREEN="$(tput bold)$(tput setaf 2)"
  YELLOW="$(tput bold)$(tput setaf 3)"
  CYAN="$(tput setaf 6)"
  BOLD="$(tput bold)"
  DIM="$(tput dim)"
  NC="$(tput sgr0)"
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; DIM=''; NC=''
fi

PASS=0; FAIL=0; WARN=0

ok()   {
  echo "  ${GREEN}✓${NC}  $1"
  PASS=$((PASS+1))
}

fail() {
  local msg="$1"; local fix="$2"
  echo ""
  echo "  ${RED}✗  $msg${NC}"
  echo "     ${DIM}Fix:${NC} ${CYAN}${fix}${NC}"
  FAIL=$((FAIL+1))
}

warn() {
  echo "  ${YELLOW}⚠${NC}  $1"
  WARN=$((WARN+1))
}

sep() {
  echo ""
  echo "  ${BOLD}$1${NC}"
  echo "  ${DIM}$(python3 -c "print('─'*55)" 2>/dev/null || printf '%55s' | tr ' ' '─')${NC}"
}

# ── Docker Compose command ────────────────────────────────────────────────────
if docker compose version &>/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose &>/dev/null; then
  DC="docker-compose"
else
  DC=""
fi

# ── OS ────────────────────────────────────────────────────────────────────────
OS="unknown"
case "$(uname -s)" in Darwin) OS="macos";; Linux) OS="linux";; esac

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo "  ${BOLD}Sentinel Health Check${NC}"
echo "  ${DIM}$(date)${NC}"

# ═════════════════════════════════════════════════════════════════════════════
sep "Infrastructure"
# ═════════════════════════════════════════════════════════════════════════════

# Docker daemon
if ! command -v docker &>/dev/null; then
  fail "Docker is not installed" \
    "https://docs.docker.com/get-docker/"
elif ! docker info &>/dev/null 2>&1; then
  if [ "$OS" = "macos" ]; then
    fail "Docker Desktop is not running" \
      "open -a Docker  (then wait for the menu bar icon)"
  else
    fail "Docker daemon is not running" \
      "sudo systemctl start docker"
  fi
else
  ok "Docker $(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)"
fi

if [ -z "$DC" ]; then
  fail "Docker Compose not found" \
    "https://docs.docker.com/compose/install/"
else
  ok "Docker Compose (${DC})"
fi

# Containers — use `docker compose ps` from sentinel dir so we don't rely on
# container name format (which varies by directory name and compose version)
if [ -n "$DC" ] && docker info &>/dev/null 2>&1; then
  cd "$SENTINEL_DIR"
  for svc in postgres api worker dashboard; do
    # Get the container name for this service from compose
    CNAME=$($DC ps -q "$svc" 2>/dev/null | head -1)
    if [ -n "$CNAME" ]; then
      STATE=$(docker inspect --format='{{.State.Status}}' "$CNAME" 2>/dev/null || echo "unknown")
      HEALTH=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$CNAME" 2>/dev/null || echo "")
      LABEL="${svc}"
      [ -n "$HEALTH" ] && LABEL="${svc}  ${DIM}(${HEALTH})${NC}"
      if [ "$STATE" = "running" ]; then
        ok "$LABEL"
      else
        fail "sentinel-${svc} is ${STATE}" \
          "cd ${SENTINEL_DIR} && ${DC} up -d"
      fi
    else
      fail "sentinel-${svc} is not running" \
        "cd ${SENTINEL_DIR} && ${DC} up -d"
    fi
  done
  cd - >/dev/null
fi

# ═════════════════════════════════════════════════════════════════════════════
sep "API  (http://localhost:8000)"
# ═════════════════════════════════════════════════════════════════════════════

if ! curl -sf http://localhost:8000/health &>/dev/null; then
  fail "API is not reachable at http://localhost:8000" \
    "cd ${SENTINEL_DIR} && ${DC:-docker compose} up -d"
else
  ok "API is reachable"

  CONFIG=$(curl -s http://localhost:8000/config 2>/dev/null || echo "")

  if [ -z "$CONFIG" ]; then
    fail "GET /config returned nothing — API may still be starting" \
      "Wait 10 seconds and re-run this script"
  else
    # Parse with python3 (required by sentinel anyway)
    PROVIDER=$(echo "$CONFIG" | python3 -c "import sys,json; print(json.load(sys.stdin).get('provider',''))" 2>/dev/null || echo "")
    MODEL=$(echo "$CONFIG" | python3 -c "import sys,json; print(json.load(sys.stdin).get('model',''))" 2>/dev/null || echo "")
    ENDPOINT=$(echo "$CONFIG" | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_endpoint') or '')" 2>/dev/null || echo "")

    # Provider
    if [ -n "$PROVIDER" ]; then
      ok "Provider: ${PROVIDER}"
    else
      fail "provider is not set" \
        "sentinel config set provider local"
    fi

    # Model — "ollama" is not a real model name
    if [ -z "$MODEL" ]; then
      fail "model is not set" \
        "sentinel config set model llama3.2"
    elif [ "$MODEL" = "ollama" ]; then
      fail "model is set to 'ollama' which is not a real model name" \
        "sentinel config set model llama3.2  (or whatever is in: ollama list)"
    else
      ok "Model: ${MODEL}"
    fi

    # Ollama endpoint (only matters for local provider)
    if [ "$PROVIDER" = "local" ]; then
      if [ -z "$ENDPOINT" ]; then
        fail "api_endpoint is not set — the API container can't reach localhost:11434 on your machine" \
          "sentinel config set api_endpoint http://host.docker.internal:11434"
      else
        ok "Ollama endpoint: ${ENDPOINT}"
      fi
    fi
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
sep "Ollama  (http://localhost:11434)"
# ═════════════════════════════════════════════════════════════════════════════

if ! command -v ollama &>/dev/null; then
  if [ "$OS" = "macos" ]; then
    fail "Ollama is not installed" \
      "brew install ollama  OR  https://ollama.com"
  else
    fail "Ollama is not installed" \
      "curl -fsSL https://ollama.com/install.sh | sh"
  fi
elif ! curl -sf http://localhost:11434/api/tags &>/dev/null; then
  if [ "$OS" = "macos" ]; then
    fail "Ollama is installed but not running" \
      "open -a Ollama  OR  ollama serve"
  else
    fail "Ollama is installed but not running" \
      "ollama serve  (run in a separate terminal and leave it open)"
  fi
else
  ok "Ollama is running at http://localhost:11434"

  # Models
  MODELS_JSON=$(curl -s http://localhost:11434/api/tags 2>/dev/null)
  MODELS=$(echo "$MODELS_JSON" | python3 -c \
    "import sys,json; d=json.load(sys.stdin); print(', '.join(m['name'] for m in d['models']))" 2>/dev/null || echo "")

  if [ -z "$MODELS" ]; then
    fail "No models are downloaded" \
      "ollama pull llama3.2"
  else
    ok "Models available: ${MODELS}"

    # Check the configured model is actually pulled
    SERVER_MODEL=$(curl -s http://localhost:8000/config 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('model',''))" 2>/dev/null || echo "")
    if [ -n "$SERVER_MODEL" ] && [ "$SERVER_MODEL" != "ollama" ]; then
      # Strip :latest tag for comparison
      BASE_MODEL="${SERVER_MODEL%%:*}"
      if ! echo "$MODELS" | grep -q "$BASE_MODEL"; then
        fail "Configured model '${SERVER_MODEL}' is not downloaded" \
          "ollama pull ${SERVER_MODEL}"
      fi
    fi
  fi

  # Connectivity from inside the API container
  if docker info &>/dev/null 2>&1; then
    cd "$SENTINEL_DIR"
    API_CONTAINER=$($DC ps -q api 2>/dev/null | head -1)
    cd - >/dev/null
    if [ -n "$API_CONTAINER" ]; then
      REACH=$(docker exec "$API_CONTAINER" python3 -c \
        "import urllib.request; urllib.request.urlopen('http://host.docker.internal:11434/api/tags', timeout=5); print('ok')" \
        2>/dev/null || echo "fail")
      if [ "$REACH" = "ok" ]; then
        ok "API container can reach Ollama via host.docker.internal"
      else
        if [ "$OS" = "linux" ]; then
          fail "API container cannot reach Ollama at host.docker.internal:11434" \
            "Add 'extra_hosts: - host.docker.internal:host-gateway' to api and worker in docker-compose.yml, then: ${DC:-docker compose} up -d"
        else
          fail "API container cannot reach Ollama at host.docker.internal:11434" \
            "Ensure Docker Desktop is running (not just Docker Engine)"
        fi
      fi
    fi
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
sep "CLI"
# ═════════════════════════════════════════════════════════════════════════════

CLI="${SENTINEL_DIR}/cli/dist/index.js"

if [ ! -f "${SENTINEL_DIR}/cli/package.json" ]; then
  fail "CLI source not found at ${SENTINEL_DIR}/cli" \
    "Ensure you are running this from the sentinel repo"
elif [ ! -d "${SENTINEL_DIR}/cli/node_modules" ]; then
  fail "CLI dependencies not installed" \
    "cd ${SENTINEL_DIR}/cli && npm install"
elif [ ! -f "$CLI" ]; then
  fail "CLI has not been built" \
    "cd ${SENTINEL_DIR}/cli && npm run build"
else
  ok "CLI is built at ${CLI}"
fi

if command -v sentinel &>/dev/null; then
  LINKED_PATH=$(command -v sentinel)
  ok "sentinel is linked globally  (${LINKED_PATH})"
else
  warn "sentinel is not linked globally — must use: node ${CLI} <command>"
  warn "To link: cd ${SENTINEL_DIR}/cli && npm link"
fi

# ═════════════════════════════════════════════════════════════════════════════
sep "Repo  (${REPO_DIR})"
# ═════════════════════════════════════════════════════════════════════════════

CFG="${REPO_DIR}/sentinel.config.json"

if [ ! -f "$CFG" ]; then
  fail "sentinel.config.json not found in ${REPO_DIR}" \
    "node ${CLI} init --api-url http://localhost:8000"
else
  ok "sentinel.config.json found"

  REPO_API_URL=$(python3 -c "import json; print(json.load(open('${CFG}')).get('apiUrl',''))" 2>/dev/null || echo "")
  REPO_NAME=$(python3 -c "import json; print(json.load(open('${CFG}')).get('repoName',''))" 2>/dev/null || echo "")
  REPO_MODEL=$(python3 -c "import json; print(json.load(open('${CFG}')).get('model',''))" 2>/dev/null || echo "")

  [ -n "$REPO_API_URL" ] && ok "apiUrl: ${REPO_API_URL}"
  [ -n "$REPO_NAME"    ] && ok "repoName: ${REPO_NAME}"

  if [ -n "$REPO_MODEL" ] && [ "$REPO_MODEL" = "ollama" ]; then
    warn "model in sentinel.config.json is 'ollama' — this is overridden by the server config"
  fi

  # Check the repo has at least one git commit so scans work
  if command -v git &>/dev/null && git -C "$REPO_DIR" rev-parse HEAD &>/dev/null 2>&1; then
    COMMIT_COUNT=$(git -C "$REPO_DIR" rev-list --count HEAD 2>/dev/null || echo 0)
    if [ "${COMMIT_COUNT:-0}" -lt 1 ]; then
      warn "This repo has no commits yet — sentinel scan diffs git history, so there must be at least one commit"
    else
      ok "Git repo with ${COMMIT_COUNT} commit(s)"
    fi
  else
    warn "${REPO_DIR} is not a git repository — sentinel scan requires git"
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
sep "Python"
# ═════════════════════════════════════════════════════════════════════════════

PYTHON=""
for candidate in python3.12 python3 python; do
  if command -v "$candidate" &>/dev/null; then
    PY_VER=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
    PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if [ "${PY_MAJOR:-0}" -ge 3 ] && [ "${PY_MINOR:-0}" -ge 12 ]; then
      PYTHON="$candidate"
      break
    fi
  fi
done

if [ -z "$PYTHON" ]; then
  fail "Python 3.12+ not found" \
    "brew install pyenv && pyenv install 3.12 && pyenv global 3.12"
else
  ok "Python $($PYTHON --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"

  if "$PYTHON" -c "import sentinel_api" &>/dev/null 2>&1; then
    ok "sentinel-api package installed"
  else
    warn "sentinel-api not installed (only needed to run the worker outside Docker)"
    warn "Install: pip install -e ${SENTINEL_DIR}/api -e ${SENTINEL_DIR}/worker"
  fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# Summary
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "  ${DIM}$(python3 -c "print('─'*55)" 2>/dev/null || printf '%55s' | tr ' ' '─')${NC}"

if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
  echo "  ${GREEN}${BOLD}All checks passed.${NC}  Ready to scan."
  echo ""
  echo "  ${CYAN}node ${CLI} scan${NC}"
elif [ "$FAIL" -eq 0 ]; then
  echo "  ${YELLOW}${BOLD}${WARN} warning(s).${NC}  ${PASS} checks passed."
  echo ""
  echo "  ${CYAN}node ${CLI} scan${NC}"
else
  echo "  ${RED}${BOLD}${FAIL} check(s) failed.${NC}  ${PASS} passed, ${WARN} warnings."
  echo ""
  echo "  Fix the items marked ${RED}✗${NC} above, then re-run:"
  echo "  ${CYAN}bash ${SENTINEL_DIR}/scripts/check.sh${NC}"
fi
echo ""

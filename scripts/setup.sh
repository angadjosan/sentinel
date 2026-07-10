#!/usr/bin/env bash
# Sentinel one-shot setup script.
# Usage: bash scripts/setup.sh
#
# Override the Ollama model:
#   SENTINEL_MODEL=qwen3 bash scripts/setup.sh

set -euo pipefail
IFS=$'\n\t'

SENTINEL_DIR="$(cd "$(dirname "$0")/.." && pwd)"
MODEL="${SENTINEL_MODEL:-llama3.2}"
SCRIPT="bash ${SENTINEL_DIR}/scripts/setup.sh"

# ── Colour helpers ────────────────────────────────────────────────────────────
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

HR="${DIM}$(printf '%0.s─' {1..60})${NC}"

step()  { echo ""; echo "${BOLD}==> $1${NC}"; }
ok()    { echo "  ${GREEN}✓${NC}  $1"; }
warn()  { echo "  ${YELLOW}⚠${NC}  $1"; }
info()  { echo "  ${CYAN}→${NC}  $1"; }

# Vivid error block — like Homebrew
die() {
  local title="$1"; shift
  echo ""
  echo "${HR}"
  echo "  ${RED}Error: ${title}${NC}"
  echo "${HR}"
  echo ""
  # Print remaining args as body lines
  for line in "$@"; do
    echo "  $line"
  done
  echo ""
  echo "  ${DIM}Fix the issue above, then re-run:${NC}"
  echo "  ${CYAN}${SCRIPT}${NC}"
  echo ""
  exit 1
}

# ── OS detection ──────────────────────────────────────────────────────────────
OS="unknown"
case "$(uname -s)" in
  Darwin) OS="macos" ;;
  Linux)  OS="linux" ;;
  MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
esac

if [ "$OS" = "windows" ]; then
  die "Windows is not supported by this script." \
    "Please use WSL2 (Windows Subsystem for Linux) and re-run from there." \
    "" \
    "Install WSL2:  https://learn.microsoft.com/en-us/windows/wsl/install" \
    "Then inside WSL2, clone the repo and run:  bash scripts/setup.sh"
fi

# ── Docker Compose command (v1 = docker-compose, v2 = docker compose) ─────────
if docker compose version &>/dev/null 2>&1; then
  DC="docker compose"
elif command -v docker-compose &>/dev/null; then
  DC="docker-compose"
else
  DC=""
fi

# ── Banner ────────────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo ""
echo "  ${BOLD}Sentinel Setup${NC}"
echo "  ${DIM}Setting up all services and dependencies${NC}"
echo ""

# ═════════════════════════════════════════════════════════════════════════════
step "Checking prerequisites"
# ═════════════════════════════════════════════════════════════════════════════

# ── Docker ────────────────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
  if [ "$OS" = "macos" ]; then
    die "Docker is not installed." \
      "Install Docker Desktop for Mac:" \
      "" \
      "  ${CYAN}https://docs.docker.com/desktop/install/mac-install/${NC}" \
      "" \
      "Or with Homebrew:" \
      "  ${CYAN}brew install --cask docker${NC}"
  else
    die "Docker is not installed." \
      "Install Docker Engine for Linux:" \
      "" \
      "  ${CYAN}https://docs.docker.com/engine/install/${NC}" \
      "" \
      "Or with the convenience script:" \
      "  ${CYAN}curl -fsSL https://get.docker.com | sh${NC}" \
      "  ${CYAN}sudo usermod -aG docker \$USER${NC}  (then log out and back in)"
  fi
fi

if ! docker info &>/dev/null 2>&1; then
  if [ "$OS" = "macos" ]; then
    die "Docker Desktop is installed but not running." \
      "Start it from your Applications folder, or run:" \
      "" \
      "  ${CYAN}open -a Docker${NC}" \
      "" \
      "Wait for the whale icon to appear in your menu bar, then re-run this script."
  else
    die "Docker daemon is not running." \
      "Start it with:" \
      "" \
      "  ${CYAN}sudo systemctl start docker${NC}" \
      "" \
      "To start Docker automatically on boot:" \
      "  ${CYAN}sudo systemctl enable docker${NC}"
  fi
fi

if [ -z "$DC" ]; then
  die "Docker Compose is not available." \
    "Docker Compose v2 ships with Docker Desktop." \
    "" \
    "If you are on Linux without Docker Desktop, install the plugin:" \
    "  ${CYAN}sudo apt-get install docker-compose-plugin${NC}  (Debian/Ubuntu)" \
    "  ${CYAN}sudo yum install docker-compose-plugin${NC}       (RHEL/Fedora)"
fi

DOCKER_VER=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
ok "Docker ${DOCKER_VER}"
ok "Docker Compose ($(${DC} version --short 2>/dev/null || echo 'v2'))"

# ── Node.js ───────────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null; then
  if [ "$OS" = "macos" ]; then
    die "Node.js is not installed." \
      "Install Node.js v20 or later:" \
      "" \
      "  ${CYAN}brew install node${NC}" \
      "" \
      "Or download from:  ${CYAN}https://nodejs.org${NC}"
  else
    die "Node.js is not installed." \
      "Install Node.js v20 or later:" \
      "" \
      "  ${CYAN}curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -${NC}" \
      "  ${CYAN}sudo apt-get install -y nodejs${NC}  (Debian/Ubuntu)" \
      "" \
      "Or download from:  ${CYAN}https://nodejs.org${NC}"
  fi
fi

NODE_MAJOR=$(node --version | grep -oE '^v([0-9]+)' | tr -d 'v')
if [ "${NODE_MAJOR:-0}" -lt 20 ]; then
  die "Node.js $(node --version) is too old. Sentinel requires v20 or later." \
    "Current version:  $(node --version)" \
    "Required version: v20+" \
    "" \
    "Update with:" \
    "  ${CYAN}brew upgrade node${NC}  (macOS with Homebrew)" \
    "  ${CYAN}https://nodejs.org/en/download${NC}  (download installer)"
fi
ok "Node.js $(node --version)"

# ── Python 3.12+ ──────────────────────────────────────────────────────────────
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
  CURRENT_VER=$(python3 --version 2>/dev/null || python --version 2>/dev/null || echo "not found")
  if [ "$OS" = "macos" ]; then
    die "Python 3.12 or later is required. Found: ${CURRENT_VER}" \
      "Install Python 3.12 via pyenv (recommended — doesn't affect system Python):" \
      "" \
      "  ${CYAN}brew install pyenv${NC}" \
      "  ${CYAN}pyenv install 3.12${NC}" \
      "  ${CYAN}pyenv global 3.12${NC}" \
      "" \
      "Then open a new terminal and re-run this script." \
      "" \
      "Alternatively, install directly:" \
      "  ${CYAN}brew install python@3.12${NC}"
  else
    die "Python 3.12 or later is required. Found: ${CURRENT_VER}" \
      "Install Python 3.12:" \
      "" \
      "  ${CYAN}sudo apt-get install python3.12 python3.12-venv${NC}  (Debian/Ubuntu)" \
      "  ${CYAN}sudo dnf install python3.12${NC}                       (Fedora/RHEL)" \
      "" \
      "Or via pyenv:" \
      "  ${CYAN}curl https://pyenv.run | bash${NC}" \
      "  ${CYAN}pyenv install 3.12 && pyenv global 3.12${NC}" \
      "" \
      "Then open a new terminal and re-run this script."
  fi
fi
ok "Python $("$PYTHON" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"

# ── Ollama ────────────────────────────────────────────────────────────────────
if ! command -v ollama &>/dev/null; then
  if [ "$OS" = "macos" ]; then
    die "Ollama is not installed." \
      "Ollama runs AI models locally. Install it:" \
      "" \
      "  ${CYAN}brew install ollama${NC}" \
      "" \
      "Or download from:  ${CYAN}https://ollama.com${NC}"
  else
    die "Ollama is not installed." \
      "Install Ollama:" \
      "" \
      "  ${CYAN}curl -fsSL https://ollama.com/install.sh | sh${NC}" \
      "" \
      "Or download from:  ${CYAN}https://ollama.com${NC}"
  fi
fi
ok "Ollama $(ollama --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo 'installed')"

# ═════════════════════════════════════════════════════════════════════════════
step "Ollama"
# ═════════════════════════════════════════════════════════════════════════════

if ! curl -sf http://localhost:11434/api/tags &>/dev/null; then
  info "Ollama is not running. Attempting to start it..."
  if [ "$OS" = "macos" ] && [ -d "/Applications/Ollama.app" ]; then
    open -a Ollama 2>/dev/null || true
  else
    # On Linux, try to start ollama as a background process
    ollama serve &>/dev/null &
    disown 2>/dev/null || true
  fi

  STARTED=0
  for i in $(seq 1 20); do
    sleep 2
    if curl -sf http://localhost:11434/api/tags &>/dev/null; then
      STARTED=1
      break
    fi
  done

  if [ "$STARTED" -eq 0 ]; then
    if [ "$OS" = "macos" ]; then
      die "Ollama did not start within 40 seconds." \
        "Try starting it manually:" \
        "" \
        "  ${CYAN}ollama serve${NC}  (run this in a separate terminal, leave it open)" \
        "" \
        "Or open the Ollama app from your Applications folder." \
        "Wait until you see the Ollama icon in the menu bar, then re-run this script."
    else
      die "Ollama did not start within 40 seconds." \
        "Start Ollama in a separate terminal:" \
        "" \
        "  ${CYAN}ollama serve${NC}" \
        "" \
        "Leave that terminal open, then re-run this script."
    fi
  fi
fi
ok "Ollama is running at http://localhost:11434"

# Pull model if not present
if ! ollama list 2>/dev/null | grep -q "^${MODEL}[: ]"; then
  info "Pulling model '${MODEL}' — this downloads ~2 GB and may take several minutes..."
  info "Progress is shown below. Do not close this terminal."
  echo ""
  if ! ollama pull "$MODEL"; then
    die "Failed to pull Ollama model '${MODEL}'." \
      "Possible causes:" \
      "  • No internet connection" \
      "  • The model name '${MODEL}' does not exist" \
      "" \
      "Check available models:" \
      "  ${CYAN}ollama list${NC}            (models already downloaded)" \
      "  ${CYAN}https://ollama.com/search${NC}  (browse all models)" \
      "" \
      "To use a different model:" \
      "  ${CYAN}SENTINEL_MODEL=qwen3 bash ${SENTINEL_DIR}/scripts/setup.sh${NC}"
  fi
  echo ""
fi
ok "Model '${MODEL}' is available"

# ── Linux host.docker.internal warning ───────────────────────────────────────
if [ "$OS" = "linux" ]; then
  warn "Linux detected. Adding host.docker.internal to docker-compose.yml..."
  # Patch docker-compose if extra_hosts not already present
  if ! grep -q "host.docker.internal:host-gateway" "$SENTINEL_DIR/docker-compose.yml"; then
    python3 - <<'PYEOF'
import sys, re
path = sys.argv[1]
with open(path) as f:
    content = f.read()
# Insert extra_hosts under api and worker services
patch = '    extra_hosts:\n      - "host.docker.internal:host-gateway"\n'
for svc in ['  api:', '  worker:']:
    content = content.replace(svc + '\n', svc + '\n' + patch, 1)
with open(path, 'w') as f:
    f.write(content)
print("Patched docker-compose.yml")
PYEOF
    python3 - "$SENTINEL_DIR/docker-compose.yml" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()
patch = '    extra_hosts:\n      - "host.docker.internal:host-gateway"\n'
for svc in ['  api:\n', '  worker:\n']:
    content = content.replace(svc, svc + patch, 1)
with open(path, 'w') as f:
    f.write(content)
PYEOF
  fi
  ok "extra_hosts configured for Linux Docker Engine"
fi

# ═════════════════════════════════════════════════════════════════════════════
step "Starting Docker services"
# ═════════════════════════════════════════════════════════════════════════════

cd "$SENTINEL_DIR"
if ! $DC up -d 2>&1; then
  die "docker compose up failed." \
    "Check the logs for more detail:" \
    "" \
    "  ${CYAN}cd ${SENTINEL_DIR} && ${DC} logs${NC}" \
    "" \
    "Common fixes:" \
    "  • Port 8000 in use:  lsof -ti :8000 | xargs kill" \
    "  • Port 5433 in use:  lsof -ti :5433 | xargs kill" \
    "  • Rebuild images:    ${DC} down && ${DC} up -d --build"
fi

info "Waiting for API to become healthy..."
for i in $(seq 1 40); do
  if curl -sf http://localhost:8000/health &>/dev/null; then break; fi
  if [ "$i" -eq 40 ]; then
    die "API did not become healthy after 80 seconds." \
      "Check what went wrong:" \
      "" \
      "  ${CYAN}cd ${SENTINEL_DIR} && ${DC} logs api --tail 50${NC}" \
      "" \
      "Try a clean restart:" \
      "  ${CYAN}${DC} down && ${DC} up -d${NC}"
  fi
  sleep 2
done

ok "API is healthy        → http://localhost:8000"
ok "Dashboard is running  → http://localhost:3000"

# ═════════════════════════════════════════════════════════════════════════════
step "Building CLI"
# ═════════════════════════════════════════════════════════════════════════════

cd "$SENTINEL_DIR/cli"

if ! npm install 2>&1; then
  die "npm install failed." \
    "This usually means a network issue or a corrupted node_modules." \
    "" \
    "Try:" \
    "  ${CYAN}cd ${SENTINEL_DIR}/cli${NC}" \
    "  ${CYAN}rm -rf node_modules package-lock.json${NC}" \
    "  ${CYAN}npm install${NC}"
fi

if ! npm run build 2>&1; then
  die "TypeScript build failed." \
    "Check the TypeScript errors printed above." \
    "" \
    "To try manually:" \
    "  ${CYAN}cd ${SENTINEL_DIR}/cli && npm run build${NC}"
fi
ok "CLI built → ${SENTINEL_DIR}/cli/dist/index.js"

# ═════════════════════════════════════════════════════════════════════════════
step "Installing Python packages"
# ═════════════════════════════════════════════════════════════════════════════

cd "$SENTINEL_DIR"
if ! "$PYTHON" -m pip install -e ./api -e ./worker --quiet 2>&1; then
  die "pip install failed." \
    "Python version detected: $("$PYTHON" --version 2>&1)" \
    "" \
    "Try with verbose output to see the error:" \
    "  ${CYAN}$PYTHON -m pip install -e ./api -e ./worker${NC}" \
    "" \
    "If the error is about Python version, re-check:" \
    "  ${CYAN}$PYTHON --version${NC}  (must be 3.12+)"
fi
ok "sentinel-api and sentinel-worker installed"

# ═════════════════════════════════════════════════════════════════════════════
step "Configuring server"
# ═════════════════════════════════════════════════════════════════════════════

CLI="node ${SENTINEL_DIR}/cli/dist/index.js"

# Create a temporary repo directory with a minimal sentinel.config.json
# so the CLI can talk to the API without needing to be inside a real repo.
TMPDIR_CFG="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_CFG"' EXIT

cat > "$TMPDIR_CFG/sentinel.config.json" <<EOF
{
  "apiUrl": "http://localhost:8000",
  "repoName": "_setup_"
}
EOF

cd "$TMPDIR_CFG"

# Auth (dev mode auto-approves immediately)
$CLI auth login &>/dev/null || warn "auth login skipped (may already be logged in)"

# Set model
if ! $CLI config set model "$MODEL" &>/dev/null; then
  warn "Could not set model automatically. Run manually:"
  warn "  sentinel config set model $MODEL"
fi

# Set Ollama endpoint so the Docker container can reach the host
if ! $CLI config set api_endpoint "http://host.docker.internal:11434" &>/dev/null; then
  warn "Could not set api_endpoint automatically. Run manually:"
  warn "  sentinel config set api_endpoint http://host.docker.internal:11434"
fi

cd "$SENTINEL_DIR"

# Verify it took
FINAL_MODEL=$(curl -s http://localhost:8000/config 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('model',''))" 2>/dev/null || echo "")
FINAL_ENDPOINT=$(curl -s http://localhost:8000/config 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('api_endpoint') or '')" 2>/dev/null || echo "")

ok "Model set to '${FINAL_MODEL:-$MODEL}'"
ok "Ollama endpoint: ${FINAL_ENDPOINT:-http://host.docker.internal:11434}"

# ═════════════════════════════════════════════════════════════════════════════
step "Done"
# ═════════════════════════════════════════════════════════════════════════════

echo ""
echo "  ${GREEN}${BOLD}Sentinel is ready.${NC}"
echo ""
echo "  Now go to the repo you want to scan and run:"
echo ""
echo "  ${CYAN}node ${SENTINEL_DIR}/cli/dist/index.js init --api-url http://localhost:8000${NC}"
echo "  ${CYAN}node ${SENTINEL_DIR}/cli/dist/index.js auth login${NC}"
echo "  ${CYAN}node ${SENTINEL_DIR}/cli/dist/index.js scan${NC}"
echo ""
echo "  To use 'sentinel' as a global command instead of 'node dist/index.js':"
echo ""
echo "  ${CYAN}cd ${SENTINEL_DIR}/cli && npm link${NC}"
echo "  ${CYAN}sentinel scan${NC}"
echo ""
echo "  Dashboard:    ${CYAN}http://localhost:3000${NC}"
echo "  Health check: ${CYAN}bash ${SENTINEL_DIR}/scripts/check.sh${NC}"
echo ""

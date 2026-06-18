# Sentinel

Sentinel is an open source application security agent harness. It integrates with any model provider to find real vulnerabilities in your codebase — not just pattern matches.

The entire incumbent AppSec stack (SAST, SCA, dependency bots) answers one question: *does this code match a known-bad pattern?* That means it can only find vulns it's already catalogued. It misses business-logic flaws, auth gaps unique to your architecture, and anything that doesn't look like an existing CVE. It also floods you with false positives — "47 vulnerabilities," 3 of which matter.

Sentinel's fix is contextual reasoning over exploitability. Pattern matching is a cheap prior that tells you *where to look* — it's an input, not the product. The product is the layer that reasons about whether a finding is actually reachable and exploitable in *this* codebase, on *this* diff. That kills the false positives signatures over-flag and surfaces novel vulns no signature describes.

A raw LLM can't do this either — no persistent architectural context, stale CVE data, no way to verify its own hunches. Sentinel is the harness that supplies all three: a persistent code graph updated on every diff, live CVE feeds at scan time, and a pentest tier that confirms findings with runtime oracle evidence.

---

## Table of contents

- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Automated setup](#automated-setup)
- [Manual setup](#manual-setup)
- [Running a scan](#running-a-scan)
- [Using a cloud LLM instead of Ollama](#using-a-cloud-llm-instead-of-ollama)
- [CI integration](#ci-integration)
- [Troubleshooting](#troubleshooting)
- [sentinel.config.json reference](#sentinelconfigjson-reference)
- [CLI reference](#cli-reference)
- [Architecture overview](#architecture-overview)

---

## How it works

**Setup (once per repo):**
- **`sentinel init`** — parse the full codebase into a code graph: call edges, data-flow edges, route/middleware chains, semantic intent per node.
- **`sentinel auth login`** — authenticate the CLI.

**Scanning:**
- **`sentinel source`** — on every diff, update the graph incrementally and run SAST, SCA, and secret scanning in parallel. Exits `1` if findings are returned, making it a drop-in CI gate.
- **`sentinel scan`** — run `source` + `pentest` in one shot.
- **`sentinel pentest`** — attempt to actually exploit a finding in a replica of your app. Confirmation requires runtime oracle evidence — sanitizer output or behavioral proof, not just agent judgment.
- **`sentinel plan`** — review a design doc or plan text for security issues before any code is written.

**Managing findings:**
- **`sentinel list`** — list findings, filterable by status and severity.
- **`sentinel pull <id>`** — fetch full remediation context for a finding.
- **`sentinel suppress <id>`** — suppress a finding with a required reason.

---

## Prerequisites

| Requirement | Version | Install |
|---|---|---|
| Docker Desktop | Latest | [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) |
| Node.js | v20+ | [nodejs.org](https://nodejs.org) |
| Python | 3.12+ | `brew install pyenv && pyenv install 3.12 && pyenv global 3.12` |
| Ollama | Latest | [ollama.com](https://ollama.com) or `brew install ollama` |

### Verify prerequisites

```bash
docker --version          # Docker version 24+
node --version            # v20+
python3 --version         # 3.12+
ollama --version          # any
```

### Python 3.12

If `python3 --version` shows 3.11 or older:

```bash
brew install pyenv
pyenv install 3.12
pyenv global 3.12

# Open a new terminal and verify:
python3 --version   # Python 3.12.x
```

---

## Automated setup

The fastest way to get everything running:

```bash
git clone <repo-url>
cd sentinel
bash scripts/setup.sh
```

`setup.sh` will:
1. Verify all prerequisites are installed
2. Start Ollama and pull `llama3.2` if needed
3. Start all Docker services
4. Build the CLI
5. Install Python packages
6. Configure the server with the correct model and Ollama endpoint

Then from your target repo:

```bash
node /path/to/sentinel/cli/dist/index.js init --api-url http://localhost:8000
node /path/to/sentinel/cli/dist/index.js auth login
node /path/to/sentinel/cli/dist/index.js scan
```

To use a different Ollama model:

```bash
SENTINEL_MODEL=qwen3 bash scripts/setup.sh
```

---

## Manual setup

Follow these steps if you prefer to set up each component yourself, or if `setup.sh` fails at a specific step.

### Step 1 — Pull an Ollama model

Ollama must be running before you start a scan. On macOS, opening the Ollama app starts it as a background service.

```bash
# Verify Ollama is running
curl http://localhost:11434/api/tags

# Pull a model (if not already done)
ollama pull llama3.2
```

If you see `address already in use` when running `ollama serve`, Ollama is already running — that's fine, skip `ollama serve`.

Supported models: any model available in `ollama list`. `llama3.2` is recommended for a good balance of speed and quality. `qwen3` is also available.

### Step 2 — Start Docker services

```bash
cd sentinel
docker compose up -d
```

Wait for the API to be healthy (~10–20 seconds):

```bash
curl http://localhost:8000/health
# → {"status":"ok"}
```

| Service | Port | Description |
|---|---|---|
| `postgres` | 5433 | Findings and graph database (data persists across restarts) |
| `api` | 8000 | REST API + auth + synchronous scan execution |
| `worker` | — | Background pentest job processor |
| `dashboard` | 3000 | Web UI |

### Step 3 — Build the CLI

```bash
cd sentinel/cli
npm install
npm run build
```

The built CLI is at `cli/dist/index.js`. To use it as `sentinel` instead of `node dist/index.js`:

```bash
# From sentinel/cli:
npm link

# Verify:
sentinel --help
```

> If `npm link` gives a permissions error: `sudo npm link`

### Step 4 — Install Python packages (optional — only if running worker locally)

The worker runs inside Docker by default. If you want to run it outside Docker (e.g. to avoid the Ollama networking issue described in [Troubleshooting](#troubleshooting)):

```bash
cd sentinel
pip install -e ./api -e ./worker
```

Requires Python 3.12+. If this fails, see [Python 3.12](#python-312) above.

### Step 5 — Initialize your repo

From the root of **the repo you want to scan** (not the sentinel repo):

```bash
node /path/to/sentinel/cli/dist/index.js init --api-url http://localhost:8000
```

This does two things:
1. Writes `sentinel.config.json` to your repo root (if it doesn't exist).
2. Uploads your codebase to the API, which builds the initial code graph.

> The first `init` can take 30–120 seconds depending on repo size and model speed.

### Step 6 — Authenticate

```bash
node /path/to/sentinel/cli/dist/index.js auth login
```

In dev mode (`SENTINEL_DEV_MODE=1`, set in docker-compose by default) this auto-approves immediately with no browser step.

### Step 7 — Configure the model and Ollama endpoint

**This step is required.** Without it, the API cannot reach Ollama.

```bash
# Set the actual model name (must match a name in `ollama list`)
node /path/to/sentinel/cli/dist/index.js config set model llama3.2

# Tell the API container where Ollama lives on the host machine
node /path/to/sentinel/cli/dist/index.js config set api_endpoint http://host.docker.internal:11434
```

**Why `host.docker.internal`?** The API runs inside a Docker container. Inside that container, `localhost` refers to the container itself — not your Mac. `host.docker.internal` is a special DNS name that Docker Desktop provides to let containers reach services on the host machine. It is only available on Docker Desktop (macOS and Windows) — see [Linux workaround](#linux-docker-engine) in Troubleshooting.

Verify the config was saved:

```bash
curl http://localhost:8000/config
# Should show: "model": "llama3.2", "api_endpoint": "http://host.docker.internal:11434"
```

---

## Running a scan

```bash
cd /path/to/your-repo
node /path/to/sentinel/cli/dist/index.js scan
```

Example output:

```
  Scanning HEAD~1..HEAD  ·  3 files changed

  ⠋  Analyzing...
  ✓  Scan complete  ·  18.4s  ·  2 issues found

  1.  CRITICAL  SQL Injection                           src/db/queries.py:42
                sql_injection  ·  a1b2c3d4
                User input reaches database query without parameterization.
                → Use parameterized queries or an ORM.

  2.  MEDIUM    Hardcoded Secret                        config/settings.py:15
                hardcoded_secret  ·  e5f6a7b8
                API key present in source-controlled file.
                → Move to environment variables and rotate the key.

  2 issues  ·  1 critical  ·  1 medium
```

### What gets scanned

The scan diffs your git history, not the full codebase. By default:

- If you have **uncommitted changes** (staged or unstaged), those are scanned.
- If the **working tree is clean**, the most recent commit (`HEAD~1..HEAD`) is scanned automatically.

```bash
sentinel scan                        # auto-detect
sentinel scan --staged               # staged changes only
sentinel scan --base origin/main     # everything not in main
sentinel scan --base HEAD~5          # last 5 commits
sentinel scan src/auth/              # scope to a directory
sentinel scan --no-pentest           # SAST + SCA + secrets only, skip pentest
```

### Getting remediation detail

```bash
sentinel list                        # list all open findings
sentinel pull <id>                   # full description + step-by-step fix
```

---

## Using a cloud LLM instead of Ollama

If you'd prefer not to run a local model, Sentinel supports Anthropic and OpenAI:

```bash
# Anthropic
sentinel config set provider anthropic
sentinel config set model claude-sonnet-4-6
sentinel config set api-key sk-ant-...

# OpenAI
sentinel config set provider openai
sentinel config set model gpt-4o
sentinel config set api-key sk-...
```

When using a cloud provider, you do **not** need to set `api_endpoint`.

`api-key` is stored encrypted on the server — it is never written to `sentinel.config.json` or to disk locally.

---

## CI integration

Add to your pipeline after checkout:

```yaml
# GitHub Actions example
- name: Sentinel scan
  run: sentinel source --base ${{ github.event.pull_request.base.sha }}
  env:
    CI: "true"
```

`sentinel source` exits `1` if any findings are returned, `0` if clean — drop-in as a blocking gate.

To scan without blocking CI (fire and forget):

```bash
sentinel source --queue
```

---

## Troubleshooting

Run the health check script first — it diagnoses all common issues at once:

```bash
bash scripts/check.sh
```

---

### "Cannot connect to Ollama at http://localhost:11434"

The API container is running but can't reach Ollama. Two causes:

**1. `api_endpoint` was never set:**
```bash
sentinel config set api_endpoint http://host.docker.internal:11434
```

**2. Model name is wrong (`model` is set to `"ollama"` instead of an actual model):**
```bash
sentinel config set model llama3.2
```

Verify both:
```bash
curl http://localhost:8000/config
# "model" should be "llama3.2" (or whatever you have in `ollama list`)
# "api_endpoint" should be "http://host.docker.internal:11434"
```

---

### "Cannot connect to the Sentinel API"

Docker is not running or the API container is down.

```bash
# Check containers
docker ps | grep sentinel

# Start everything
cd sentinel
docker compose up -d

# Verify
curl http://localhost:8000/health
```

If the API keeps crashing, check its logs:
```bash
docker compose logs api --tail 50
```

---

### "Not authenticated"

Run auth login. You must do this after every time the database is reset (e.g. after `docker compose down -v`):

```bash
sentinel auth login
```

---

### "Repository not initialized"

You're running `sentinel scan` in a repo that hasn't been initialized, or the database was wiped.

```bash
sentinel init --api-url http://localhost:8000
sentinel auth login
```

---

### "422 Unprocessable Entity: LLM authentication failed"

Your API key is invalid or missing.

```bash
sentinel config set api-key <your-key>
```

---

### "error: unknown option '--api-url'" on `auth login`

`auth login` reads the API URL from `sentinel.config.json`. Run `init` first:

```bash
sentinel init --api-url http://localhost:8000
sentinel auth login
```

---

### "MODULE_NOT_FOUND" when running the CLI

You're running `node dist/index.js` from the wrong directory, or the CLI hasn't been built.

```bash
# Build:
cd /path/to/sentinel/cli
npm install && npm run build

# Run with full path:
node /path/to/sentinel/cli/dist/index.js scan
```

---

### `pip install` fails: "requires Python >=3.12"

Your system Python is too old.

```bash
brew install pyenv
pyenv install 3.12
pyenv global 3.12

# Open a new terminal, then verify:
python3 --version   # 3.12.x

pip install -e /path/to/sentinel/api -e /path/to/sentinel/worker
```

---

### `ollama serve` fails: "address already in use"

Ollama is already running as a background service. This is not an error — just skip `ollama serve`.

```bash
# Verify it's up:
curl http://localhost:11434/api/tags
```

---

### Linux Docker Engine (no `host.docker.internal`)

`host.docker.internal` is only available on Docker Desktop. On Linux with Docker Engine, add the host IP manually to docker-compose:

```yaml
# docker-compose.yml
services:
  api:
    extra_hosts:
      - "host.docker.internal:host-gateway"
  worker:
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

Then `docker compose up -d` and set the endpoint as normal:

```bash
sentinel config set api_endpoint http://host.docker.internal:11434
```

---

### Dashboard shows no data

The dashboard shows data from the database. If you recently reset the database:

1. Re-run `sentinel init` and `sentinel auth login`
2. Run a scan to populate findings
3. Hard-refresh the browser (`Cmd+Shift+R`)

---

### Scan returns 0 findings immediately

Likely causes:

1. **Empty diff** — if the working tree is clean and `HEAD~1..HEAD` is also empty (e.g. a brand-new repo with one commit), there's nothing to scan. Make some changes and re-run.
2. **Model is too small or slow** — small models (< 7B parameters) may not produce reliable security findings. Try `llama3.2` (3B) at minimum; `qwen3` or a larger model for better results.
3. **Ollama connectivity** — run `bash scripts/check.sh` to verify the API can reach Ollama.

---

### Database resets after `docker compose down`

The database now uses a named volume (`pgdata`) and persists across `docker compose down / up`. It is only wiped if you run:

```bash
docker compose down -v   # -v removes volumes — use with caution
```

---

## sentinel.config.json reference

This file lives in your target repo root and is written by `sentinel init`. Most values can also be set with `sentinel config set <key> <value>`.

| Field | Type | Default | Description |
|---|---|---|---|
| `apiUrl` | string | `http://localhost:8000` | Sentinel API URL |
| `repoName` | string | directory name | Display name for this repo |
| `provider` | string | `local` | LLM provider: `local` (Ollama), `anthropic`, `openai` |
| `model` | string | — | Model name — must match a name in `ollama list` or a provider model ID |
| `boot` | string | — | Command to start your app for pentesting |
| `healthcheck` | string | — | Command that exits 0 when app is ready |
| `env.from` | string | — | Path to env file loaded into the pentest environment |
| `egress_allowlist` | string[] | `[]` | Hosts the pentest runner may contact |
| `variants` | object | — | Named build variants (e.g. `asan`, `ubsan`) |
| `firecracker.enabled` | boolean | `false` | Run pentest sandbox in Firecracker microVM |

Example:

```json
{
  "apiUrl": "http://localhost:8000",
  "repoName": "my-app",
  "provider": "local",
  "model": "llama3.2",
  "boot": "docker compose up -d",
  "healthcheck": "curl -sf http://localhost:3000/health",
  "egress_allowlist": ["localhost"],
  "env": { "from": ".env.sentinel" },
  "variants": {
    "asan": { "build": "cmake -DCMAKE_BUILD_TYPE=Asan .", "requires": "clang" }
  }
}
```

---

## CLI reference

### `sentinel init`

Initialize Sentinel for this repository. Run once per repo from the repo root.

```
sentinel init [options]

Options:
  --api-url <url>      Sentinel API URL  (default: http://localhost:8000)
  --repo-name <name>   Repository name   (default: current directory name)
```

Does two things:
1. Writes `sentinel.config.json` if it doesn't exist.
2. Uploads your full codebase and builds the initial code graph (parse → symbols → routes → taint → enrichment).

---

### `sentinel auth login`

Authorize the CLI. Requires `sentinel.config.json` to exist — run `init` first.

```
sentinel auth login [options]

Options:
  --poll-interval <seconds>   Polling interval while waiting for approval  (default: 2)
```

Prints a verification URL and code. With `SENTINEL_DEV_MODE=1` (default in docker-compose) it auto-approves with no browser step.

The access token is stored in the **system keychain** (macOS Keychain / libsecret on Linux). It is never written to disk.

---

### `sentinel source [paths...]`

Scan the current git diff. Runs SAST, SCA, and secret scanning in parallel. Exits `1` if findings are returned.

```
sentinel source [paths...] [options]

Options:
  --staged          Scan staged changes only
  --base <ref>      Diff against this git ref
  --queue           Queue for async worker execution instead of blocking
```

Diff behaviour:
- Default: `git diff HEAD` (staged + unstaged uncommitted changes)
- If working tree is clean: falls back to `git diff HEAD~1..HEAD` automatically
- `--staged`: `git diff --staged`
- `--base <ref>`: `git diff <ref>..HEAD`

```bash
sentinel source                          # auto-detect
sentinel source --staged                 # staged only
sentinel source src/api/routes.ts        # scope to a file
sentinel source --base origin/main       # everything not in main
sentinel source --queue                  # fire and forget
```

---

### `sentinel scan [paths...]`

Full scan: source scan followed by automated pentesting of each finding.

```
sentinel scan [paths...] [options]

Options:
  --staged                     Scan staged changes only
  --base <ref>                 Diff against this git ref
  --no-pentest                 Skip pentest phase (SAST + SCA + secrets only)
  --pentest-concurrency <n>    Max concurrent pentest jobs  (default: 4)
```

---

### `sentinel pentest [target...]`

Attempt to confirm a finding with runtime oracle evidence. The pentest agent generates payloads, runs them against your app, and checks for sanitizer output or behavioral proof.

```
sentinel pentest [target...] [options]

Arguments:
  target   Finding UUID, natural-language description, or empty to auto-select

Options:
  --sanitizer-output <text>    Sanitizer output (ASan, TSan, UBSan) to attach as evidence
  --behavioral-proof <kind>    Proof kind: command_executed | auth_bypassed | data_exfiltrated | privilege_escalated
  --proof-detail <text>        Additional detail for the proof
```

```bash
sentinel pentest                                         # auto-select
sentinel pentest abc123ef-...                            # by finding ID
sentinel pentest "SQL injection in user login handler"   # by description
```

Requires `boot` and `healthcheck` to be set in `sentinel.config.json`.

---

### `sentinel list`

List findings for this repo.

```
sentinel list [options]

Options:
  --status <status>      Filter: open | suppressed | confirmed
  --severity <severity>  Filter: critical | high | medium | low | info
```

---

### `sentinel pull <id>`

Fetch full remediation context: description, step-by-step fix plan, and the code graph node the finding is anchored to.

```
sentinel pull <id>

Arguments:
  id   Finding UUID (first 8 characters are enough)
```

---

### `sentinel plan [input...]`

Review a design doc, plan file, or inline text for security issues before implementation. Exits `1` if issues are found.

```
sentinel plan [input...] [options]

Options:
  --with-retry   Run additional review passes to catch more issues
```

```bash
sentinel plan DESIGN.md
sentinel plan "users reset passwords via a magic link sent to their email"
cat plan.txt | sentinel plan
```

---

### `sentinel suppress`

```
sentinel suppress <id> --reason <reason>           # suppress a finding
sentinel suppress remove <id> --reason <reason>    # unsuppress
sentinel suppress approve <id> --reason <reason>   # approve a pending suppression
sentinel suppress reject <id> --reason <reason>    # reject a pending suppression
```

Suppressions are keyed on `file + vuln_type` fingerprint (not line number) so they survive refactors that shift line numbers.

---

### `sentinel runs`

```
sentinel runs list              # list all runs with status and token spend
sentinel runs show <id>         # full trace + per-component token breakdown
sentinel runs watch <id>        # stream live events from a running scan
sentinel runs cancel <id>       # cancel an in-progress run
```

---

### `sentinel config`

```
sentinel config show               # display current config
sentinel config set <key> <value>  # update a value
```

Keys synced to the server immediately: `provider`, `model`, `api_endpoint`
Keys stored in system keychain: `api-key`
Local-only keys: `apiUrl`, `repoName`, `boot`, `healthcheck`, `repo_id`, `firecracker.*`

```bash
sentinel config set model llama3.2
sentinel config set api_endpoint http://host.docker.internal:11434
sentinel config set provider anthropic
sentinel config set model claude-sonnet-4-6
sentinel config set api-key sk-ant-...
sentinel config set boot "docker compose up -d"
sentinel config set healthcheck "curl -sf http://localhost:3000/health"
sentinel config set firecracker.enabled true
sentinel config set firecracker.mem_size_mib 1024
```

---

## Findings lifecycle

```
open
 ├─► confirmed    (pentest passed — runtime oracle evidence)
 └─► suppressed   (manually dismissed with --reason)
      ├─► approval pending   (if suppression_approval_required = true)
      │    ├─► approved
      │    └─► rejected → open
      └─► (immediate if approval not required)
```

Approved suppressions are not re-surfaced on subsequent scans unless the file+vuln_type fingerprint changes.

---

## Architecture overview

```
┌─────────────┐     REST      ┌──────────────────┐     SQL      ┌──────────────┐
│  CLI        │ ────────────► │  API (FastAPI)    │ ──────────► │  Postgres    │
│  (Node.js)  │               │  :8000           │              │  :5433       │
└─────────────┘               └──────────────────┘              └──────────────┘
                                       │                                ▲
                               scan_diff() runs                         │
                               synchronously in API                     │
                               process (no queue)                       │
                                       │                                │
                                       ▼                                │
                              ┌──────────────────┐                      │
                              │  Worker          │ ─────────────────────┘
                              │  (Python)        │  pentest tasks via queue
                              └──────────────────┘
                                       │
                                       ▼
                              ┌──────────────────┐
                              │  Ollama / LLM    │
                              │  :11434          │
                              └──────────────────┘

┌──────────────────┐   SSR fetches   ┌──────────────────┐
│  Dashboard       │ ──────────────► │  API (internal)  │
│  (Next.js) :3000 │                 │  http://api:8000  │
└──────────────────┘                 └──────────────────┘
```

**Key design decisions:**

- `sentinel source` and `sentinel scan` run **synchronously in the API process** — no worker queue needed for basic scans. The worker queue is used for pentest jobs and `sentinel source --queue`.
- The dashboard makes **server-side requests** to `http://api:8000` (internal Docker network) for SSR — it does not proxy through the browser.
- The code graph is stored in **Postgres** and updated incrementally on every diff. `sentinel init` builds the full graph once; subsequent scans only re-parse changed files.
- Findings are **fingerprinted** on `file + vuln_type` so suppressions survive line-number shifts and minor refactors.
- Source snapshots are **encrypted at rest** and automatically deleted after `source_retention_days` (default: 365).

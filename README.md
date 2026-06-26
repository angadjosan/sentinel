# Sentinel

LLM-powered application security agent. Finds real vulnerabilities in your codebase — not just pattern matches.

The entire incumbent AppSec stack (SAST, SCA, dependency bots) answers one question: *does this code match a known-bad pattern?* That means it can only find vulns it's already catalogued, and it floods you with false positives — "47 vulnerabilities," 3 of which matter.

Sentinel's answer is contextual reasoning over exploitability. Pattern matching is a cheap prior that tells you *where to look* — it's an input, not the product. The product is the layer that reasons about whether a finding is actually reachable and exploitable *in this specific codebase, on this specific diff*. That kills the false positives signatures over-flag and surfaces novel vulns no signature describes.

---

## Table of contents

- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [Install the CLI](#install-the-cli)
- [Self-host the backend](#self-host-the-backend)
- [Running a scan](#running-a-scan)
- [CI integration](#ci-integration)
- [Using a cloud LLM](#using-a-cloud-llm)
- [sentinel.config.json reference](#sentinelconfigjson-reference)
- [CLI reference](#cli-reference)
- [Troubleshooting](#troubleshooting)
- [Architecture overview](#architecture-overview)

---

## Quickstart

```bash
# 1. Install the CLI
npm install -g @sentinel/cli

# 2. Start the backend (Docker required)
git clone https://github.com/your-org/sentinel
cd sentinel
cp .env.example .env   # edit POSTGRES_PASSWORD and SENTINEL_JWT_SECRET
docker compose up -d

# 3. Initialize your repo and run your first scan
cd /path/to/your-repo
sentinel init
sentinel auth login
sentinel scan
```

## Install

```bash
npm install -g sentinel-sec
```

Then:

```bash
sentinel auth login     # browser device-code login
cd your-repo && sentinel init
sentinel source         # scan your diff
```

Scans and pentests run locally (Docker required); findings sync to the hosted backend and dashboard. Bring your own model key:

```bash
sentinel config set api-key sk-ant-...
```

**Pin in your project** (recommended for CI):

```bash
npm install --save-dev sentinel-sec
```

```yaml
# .github/workflows/pr.yml
- run: npx sentinel source
```

**Alternative — curl install** (for non-Node projects):

```bash
curl -fsSL https://raw.githubusercontent.com/sentineldev/sentinel/main/install.sh | bash
```

---

## How it works

**Setup (once per repo):**
- **`sentinel init`** — parse the full codebase into a persistent code graph: call edges, data-flow edges, route/middleware chains, semantic intent per node.
- **`sentinel auth login`** — authenticate the CLI.

**On every diff:**
- **`sentinel source`** — update the graph incrementally and run SAST, SCA, and secret scanning in parallel. Exits `1` if findings are returned, making it a drop-in CI gate.
- **`sentinel scan`** — run `source` + automated pentesting of each finding.

**Deep investigation:**
- **`sentinel pentest`** — attempt to confirm a finding with runtime oracle evidence — sanitizer output or behavioral proof, not just agent judgment.
- **`sentinel plan`** — review a design doc for security issues before any code is written.

**Managing findings:**
- **`sentinel list`** — list findings, filterable by status and severity.
- **`sentinel pull <id>`** — fetch full remediation context for a finding.
- **`sentinel suppress <id>`** — suppress a finding with a required reason.

---

## Install the CLI

```bash
npm install -g @sentinel/cli
```

Requires Node.js v20 or later. Verify with `node --version`.

To install from source instead:

```bash
git clone https://github.com/your-org/sentinel
cd sentinel/cli
npm install && npm run build && npm link
```

---

## Self-host the backend

Sentinel's backend (API, worker, database, dashboard) runs in Docker. You self-host it — your source code never leaves your network.

### Prerequisites

| Requirement | Version | Install |
|---|---|---|
| Docker Desktop | Latest | [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) |
| Ollama (local LLM) | Latest | [ollama.com](https://ollama.com) |

### Start the backend

```bash
git clone https://github.com/your-org/sentinel
cd sentinel

# Create your env file and set the two required secrets
cp .env.example .env
# Edit POSTGRES_PASSWORD and SENTINEL_JWT_SECRET (see .env.example for instructions)

docker compose up -d
```

Wait for the API to be ready (~10–20 seconds):

```bash
curl http://localhost:8000/health
# → {"status":"ok"}
```

| Service | URL | Description |
|---|---|---|
| API | `http://localhost:8000` | REST API — the CLI talks to this |
| Dashboard | `http://localhost:3000` | Web UI for findings and run history |
| Postgres | `localhost:5433` | Database (persists across restarts) |

> **Linux:** `docker compose` requires the compose plugin. If you get `command not found`, install it: `apt-get install docker-compose-plugin`

### Pull an Ollama model

```bash
ollama pull llama3.2
```

Then tell the API where Ollama lives:

```bash
sentinel config set model llama3.2
sentinel config set api_endpoint http://host.docker.internal:11434
```

> **Linux:** `host.docker.internal` is not set by default. See [Linux Docker Engine](#linux-docker-engine) in Troubleshooting.

### Production deployment

For a hardened production deployment (strong DB credentials, restart policies, no dev mode):

```bash
cp .env.example .env   # fill in all values
docker compose -f docker-compose.prod.yml --env-file .env up -d
```

For TLS, put nginx or Caddy in front of the API:

```nginx
server {
    listen 443 ssl;
    server_name api.your-domain.com;

    ssl_certificate     /etc/letsencrypt/live/api.your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.your-domain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## Running a scan

```bash
cd /path/to/your-repo
sentinel scan
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

The scan diffs your git history — not the full codebase. By default:

- If you have **uncommitted changes** (staged or unstaged), those are scanned.
- If the **working tree is clean**, the most recent commit (`HEAD~1..HEAD`) is scanned.

```bash
sentinel scan                        # auto-detect
sentinel scan --staged               # staged changes only
sentinel scan --base origin/main     # everything not in main
sentinel scan --base HEAD~5          # last 5 commits
sentinel scan src/auth/              # scope to a directory
sentinel scan --no-pentest           # SAST + SCA + secrets only, skip pentest
sentinel scan --dry-run              # preview what files would be scanned
```

### Getting remediation detail

```bash
sentinel list                        # list all open findings
sentinel pull <id>                   # full description + step-by-step fix
```

---

## CI integration

Drop this into your GitHub Actions workflow:

```yaml
- name: Install Sentinel
  run: npm install -g @sentinel/cli

- name: Scan PR diff
  run: sentinel source --base ${{ github.event.pull_request.base.sha }}
  env:
    SENTINEL_TOKEN: ${{ secrets.SENTINEL_TOKEN }}
```

`sentinel source` exits `1` if findings are returned — use it as a blocking gate. See [`examples/github-actions.yml`](examples/github-actions.yml) for a full workflow, or [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml) for GitLab.

To scan without blocking CI (fire and forget):

```bash
sentinel source --queue
```

---

## Using a cloud LLM

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

When using a cloud provider, you do **not** need to set `api_endpoint`. The API key is stored encrypted on the server and never written to disk locally.

---

## sentinel.config.json reference

Written by `sentinel init` into your repo root. Commit this file — it contains no secrets.

| Field | Type | Default | Description |
|---|---|---|---|
| `apiUrl` | string | `http://localhost:8000` | Sentinel API URL |
| `repoName` | string | directory name | Display name for this repo |
| `provider` | string | `local` | LLM provider: `local` (Ollama), `anthropic`, `openai` |
| `model` | string | — | Model name |
| `boot` | string | — | Command to start your app for pentesting |
| `healthcheck` | string | — | Command that exits 0 when app is ready |
| `env.from` | string | — | Path to env file loaded into the pentest environment |
| `egress_allowlist` | string[] | `[]` | Hosts the pentest runner may contact |
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
  "env": { "from": ".env.sentinel" }
}
```

---

## CLI reference

### `sentinel doctor`

Check that everything is set up correctly. Run this first if something isn't working.

```bash
sentinel doctor
```

Checks: git repo present · config file · API reachable · authenticated · LLM configured · Node.js version.

---

### `sentinel init`

Initialize Sentinel for this repository. Run once from your repo root.

```bash
sentinel init [--api-url <url>] [--repo-name <name>]
```

Writes `sentinel.config.json` and uploads your codebase to build the initial code graph. The first init can take 30–120 seconds depending on repo size and model speed.

---

### `sentinel auth login`

Authenticate the CLI. Run after `init`. Re-run after resetting the database.

```bash
sentinel auth login
```

Prints a verification URL. With `SENTINEL_DEV_MODE=1` (default in `docker-compose.yml`) it auto-approves with no browser step. The token is stored in the system keychain and never written to disk.

---

### `sentinel source [paths...]`

Scan the current git diff. Runs SAST, SCA, and secret scanning in parallel. Exits `1` if findings are found.

```bash
sentinel source [--staged] [--base <ref>] [--queue] [--dry-run] [paths...]
```

---

### `sentinel scan [paths...]`

Full scan: `source` + automated pentesting of each finding.

```bash
sentinel scan [--staged] [--base <ref>] [--no-pentest] [--pentest-concurrency <n>] [--dry-run] [paths...]
```

---

### `sentinel pentest [target...]`

Confirm a finding with runtime oracle evidence. The pentest agent generates payloads, runs them against your app, and checks for sanitizer output or behavioral proof.

```bash
sentinel pentest                                         # auto-select
sentinel pentest abc123ef-...                            # by finding ID
sentinel pentest "SQL injection in user login handler"   # by description
```

Requires `boot` and `healthcheck` to be set in `sentinel.config.json`.

---

### `sentinel plan [input...]`

Review a design doc or inline text for security issues before implementation. Exits `1` if issues are found.

```bash
sentinel plan DESIGN.md
sentinel plan "users reset passwords via a magic link sent to their email"
cat plan.txt | sentinel plan
```

---

### `sentinel list`

List findings for this repo.

```bash
sentinel list [--status open|suppressed|confirmed] [--severity critical|high|medium|low|info]
```

---

### `sentinel pull <id>`

Fetch full remediation context: description, step-by-step fix, and the code graph node the finding is anchored to.

```bash
sentinel pull <id>   # first 8 characters of the ID are enough
```

---

### `sentinel suppress`

```bash
sentinel suppress <id> --reason <reason>           # suppress
sentinel suppress remove <id> --reason <reason>    # unsuppress
sentinel suppress approve <id> --reason <reason>   # approve pending suppression
sentinel suppress reject <id> --reason <reason>    # reject pending suppression
```

Suppressions are keyed on `file + vuln_type` fingerprint — they survive refactors that shift line numbers.

---

### `sentinel runs`

```bash
sentinel runs list              # list all runs
sentinel runs show <id>         # full trace + token breakdown
sentinel runs watch <id>        # stream live events from a running scan
sentinel runs cancel <id>       # cancel an in-progress run
```

---

### `sentinel config`

```bash
sentinel config show               # display current config
sentinel config set <key> <value>  # update a value
```

Keys synced to the server: `provider`, `model`, `api_endpoint`
Keys stored in system keychain: `api-key`
Local-only keys: `apiUrl`, `repoName`, `boot`, `healthcheck`

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

Approved suppressions are not re-surfaced on subsequent scans unless the `file + vuln_type` fingerprint changes.

---

## Troubleshooting

Run this first — it diagnoses all common issues:

```bash
sentinel doctor
```

---

### "Cannot connect to the Sentinel API"

Docker is not running or the API container is down.

```bash
docker compose up -d
curl http://localhost:8000/health
```

If the API keeps crashing:

```bash
docker compose logs api --tail 50
```

---

### "Not authenticated"

```bash
sentinel auth login
```

You must re-run this after resetting the database (`docker compose down -v`).

---

### "Repository not initialized"

```bash
sentinel init
sentinel auth login
```

---

### "Cannot connect to Ollama"

The API container cannot reach Ollama on your host machine.

```bash
# Set the correct endpoint (Docker Desktop on macOS/Windows)
sentinel config set api_endpoint http://host.docker.internal:11434

# Set the model name (must match `ollama list`)
sentinel config set model llama3.2

# Verify
curl http://localhost:8000/config
```

---

### "LLM API key is invalid"

```bash
sentinel config set api-key <your-key>
```

---

### Linux Docker Engine (no `host.docker.internal`)

`host.docker.internal` is only available on Docker Desktop. On Linux, add the host IP manually:

```yaml
# In docker-compose.yml, under both api and worker:
extra_hosts:
  - "host.docker.internal:host-gateway"
```

Then restart and set the endpoint as normal.

---

### Scan returns 0 findings immediately

1. **Empty diff** — if the working tree is clean and `HEAD~1..HEAD` is also empty (new repo with one commit), there's nothing to scan. Make some changes and re-run.
2. **Model is too small** — models under 7B may not produce reliable findings. Try `llama3.2` (3B) at minimum; `qwen3` or a cloud model for better results.
3. **Ollama connectivity** — run `sentinel doctor` to verify the API can reach Ollama.

---

### Database resets after `docker compose down`

The database uses a named volume and persists across normal restarts. It is only wiped with:

```bash
docker compose down -v   # -v removes volumes — use with caution
```

---

## Architecture overview

```
┌─────────────┐     REST      ┌──────────────────┐     SQL      ┌──────────────┐
│  CLI        │ ────────────► │  API (FastAPI)    │ ──────────► │  Postgres    │
│  (Node.js)  │               │  :8000            │              │  :5433       │
└─────────────┘               └──────────────────┘              └──────────────┘
                                       │                                ▲
                               source scan runs                         │
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

- `sentinel source` and `sentinel scan` run **synchronously in the API process** — no queue needed for basic scans. The worker queue is used for pentest jobs and `--queue` mode.
- The dashboard makes **server-side requests** to `http://api:8000` (internal Docker network) for SSR.
- The code graph is stored in **Postgres** and updated incrementally on every diff. `sentinel init` builds it once; subsequent scans only re-parse changed files.
- Findings are **fingerprinted** on `file + vuln_type` so suppressions survive line-number shifts and minor refactors.
- Source snapshots are **encrypted at rest** and deleted after `source_retention_days` (default: 365).
- The CLI is **stateless** — no local DB, no cache. Only `sentinel.config.json` (safe to commit).
- LLM calls enforce **channel separation** — instructions live in the system prompt, analyzed code lives in the user prompt. They never mix.

# Sentinel

LLM-powered application security agent. Finds real vulnerabilities in your codebase — not just pattern matches.

The entire incumbent AppSec stack (SAST, SCA, dependency bots) answers one question: *does this code match a known-bad pattern?* That means it can only find vulns it's already catalogued, and it floods you with false positives — "47 vulnerabilities," 3 of which matter.

Sentinel's answer is contextual reasoning over exploitability. Pattern matching is a cheap prior that tells you *where to look* — it's an input, not the product. The product is the layer that reasons about whether a finding is actually reachable and exploitable *in this specific codebase, on this specific diff*. That kills the false positives signatures over-flag and surfaces novel vulns no signature describes.

**Your source code never leaves your machine.** Diffs are computed locally, read locally, and analyzed by an LLM you configure with your own API key (or a local Ollama model) — the call happens on your machine, not ours. Only the code graph (file/line pointers and short semantic labels — never source text) and findings sync to the cloud, so your team shares one graph and one finding history without ever uploading a source file.

---

## Table of contents

- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [Install the CLI](#install-the-cli)
- [Self-host the backend](#self-host-the-backend)
- [Running a scan](#running-a-scan)
- [Pentest (cloud)](#pentest-cloud)
- [CI integration](#ci-integration)
- [Using an LLM provider](#using-an-llm-provider)
- [sentinel.config.json reference](#sentinelconfigjson-reference)
- [CLI reference](#cli-reference)
- [Troubleshooting](#troubleshooting)
- [Architecture overview](#architecture-overview)

---

## Quickstart

```bash
# 1. Install the CLI and the local analysis engine
npm install -g sentineldev
pip install sentinel-worker   # or: pip install ./worker if installing from source

# 2. Point the CLI at a backend for the shared graph + findings (hosted, or self-hosted — see below)
sentinel auth login

# 3. Configure your own LLM key — used locally, never sent to the server
sentinel config set provider anthropic
sentinel config set model claude-sonnet-4-6
sentinel config set api-key sk-ant-...

# 4. Initialize your repo and run your first scan — all analysis runs on this machine
cd /path/to/your-repo
sentinel init
sentinel scan
```

## Install

```bash
npm install -g sentineldev
pip install sentinel-worker
```

Then:

```bash
sentinel auth login     # browser device-code login — for the shared graph/findings backend, not for AI calls
cd your-repo && sentinel init
sentinel source         # scan your diff, entirely on this machine
```

`sentinel source` and `sentinel scan` run the whole pipeline locally: the diff is computed and read on your machine, the LLM call happens on your machine with your own key, and only the resulting code graph (file/line pointers and short labels — never source text) and findings sync to the backend. Bring your own model key:

```bash
sentinel config set api-key sk-ant-...
```

The key is stored in your system keychain (or `~/.sentinel/keychain.json` as a 0600 fallback) and is read directly by the local engine — it is never transmitted to the backend. See [Using an LLM provider](#using-an-llm-provider).

**Pin in your project** (recommended for CI):

```bash
npm install --save-dev sentineldev
pip install sentinel-worker
```

```yaml
# .github/workflows/pr.yml
- run: npx sentinel source
  env:
    SENTINEL_LLM_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

Or use the [GitHub Action](#github-action-ci-native-scanning) below, which needs no separate `pip install` step.

---

## How it works

Every command below runs its analysis — diff parsing, graph construction, the LLM call itself — locally, on your machine. Only the resulting code graph (pointers + short labels, never source) and findings sync to the backend, so a team shares one graph and one finding history.

**Setup (once per repo):**
- **`sentinel init`** — parse the full codebase locally into a persistent code graph: call edges, data-flow edges, route/middleware chains, semantic intent per node. Pushes the graph (not the source) to the backend.
- **`sentinel auth login`** — authenticate the CLI against the backend that stores the shared graph and findings.

**On every diff:**
- **`sentinel source`** — update the graph incrementally and run SAST, SCA, and secret scanning in parallel, all locally. Exits `1` if findings are returned, making it a drop-in CI gate.
- **`sentinel scan`** — run `source` locally, then enqueue a **cloud** pentest for each finding. SAST stays on your machine; pentest execution happens on the cloud worker.

**Deep investigation:**
- **`sentinel pentest`** — enqueue a cloud pentest to confirm a finding with runtime oracle evidence — an HTTP/behavioral proof or sanitizer output, not just agent judgment. The **cloud worker** runs it against your configured staging URL; the CLI enqueues the job and polls until it's done. See [Pentest (cloud)](#pentest-cloud).
- **`sentinel plan`** — review a design doc for security issues before any code is written.

**Managing findings:**
- **`sentinel list`** — list findings, filterable by status and severity.
- **`sentinel pull <id>`** — fetch full remediation context for a finding.
- **`sentinel suppress <id>`** — suppress a finding with a required reason.

---

## Install the CLI

```bash
npm install -g sentineldev
```

The npm package is named **`sentineldev`**; it installs the `sentinel` command. Requires Node.js v20 or later. Verify with `node --version`.

To install from source instead:

```bash
git clone https://github.com/your-org/sentinel
cd sentinel/cli
npm install && npm run build && npm link
```

---

## Self-host the backend

Sentinel's backend (API, worker, database, dashboard) runs in Docker. It only ever stores the code graph (pointers + short labels, never source text) and findings — no source code or diffs are ever sent to it, whether you self-host it or use the hosted default. Self-hosting is about controlling where the *graph and findings* live, not about keeping source local — that's already true no matter which backend you point the CLI at.

### Prerequisites

| Requirement | Version | Install |
|---|---|---|
| Docker Desktop | Latest | [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) |
| Ollama (optional, for a local LLM) | Latest | [ollama.com](https://ollama.com) |

Ollama is installed and used **locally**, alongside the CLI — it's not part of the backend. See [Using an LLM provider](#using-an-llm-provider).

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

Then tell the local engine where Ollama lives — this is read directly by the CLI's local engine process on your machine, not by anything in Docker:

```bash
sentinel config set provider local
sentinel config set model llama3.2
sentinel config set api_endpoint http://localhost:11434
```

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

## Pentest (cloud)

SAST tells you a finding *looks* exploitable. Pentest *proves* it. Unlike everything else in Sentinel, **pentest runs on the cloud worker, not on your machine** — the worker needs to reach a running instance of your app, generate payloads, and observe the app's behavior for a runtime oracle.

`sentinel pentest` never spawns a local pentest: it enqueues a `kind=pentest` task and polls until the run is terminal.

```
sentinel pentest [id]
  └─ POST /pentest ──────────────► cloud worker claims the task
  └─ sentinel runs watch ───────► worker sends HTTP payloads to your staging URL
                                   → confirms finding only on HTTP/behavioral proof
                                     or sanitizer output (never agent judgment alone)
```

### Reachability: two modes

The worker needs to reach your app. Configure this **per repo** — on the dashboard **Team → Pentest Configuration**, or with `sentinel config set` (synced to the cloud repo):

| Mode | When | Config |
|---|---|---|
| **`staging`** (default) | Hosted worker (Vercel/Railway). The worker sends HTTP probes to a URL it can reach. | `staging_base_url`, `healthcheck_path` |
| **`local_worker`** | Self-hosted `docker compose` worker. The worker boots the app itself in a subprocess sandbox on the worker host. | `boot`, `healthcheck`, `egress_allowlist` |

```bash
# Staging mode (hosted): point the worker at a reachable deployment
sentinel config set pentest_mode staging
sentinel config set staging_base_url https://staging.your-app.com
sentinel config set healthcheck_path /health

# Self-hosted worker: let the worker boot the app
sentinel config set pentest_mode local_worker
sentinel config set boot "docker compose up -d"
sentinel config set healthcheck "curl -sf http://localhost:3000/health"
```

The hosted worker cannot reach `localhost` on your machine — use `staging` mode against a deployed environment, or run a self-hosted worker for `local_worker` mode.

### Pentest LLM credential

The pentest agent's LLM key lives **on the worker**, not on your machine — set `SENTINEL_PENTEST_LLM_API_KEY` in the worker environment (or an admin can set an encrypted `pentest_api_key` on the account from the dashboard). This is deliberately **separate** from your local SAST key: the worker never sees your SAST key, and your machine never sees the pentest key.

### Confirmation

A finding is marked `confirmed` **only** with a runtime oracle: an HTTP/behavioral proof (data exfiltrated, auth bypassed, command executed) or a sanitizer stack trace. The agent asserting "this is exploitable" is not sufficient. The worker writes the confirmation and a `CONFIRMED_EXPLOIT` edge directly; evidence text is visible in the dashboard finding detail and via `sentinel pull <id>`.

Phase 1 pentest is HTTP-only and uses the cloud graph plus finding metadata for context — **no source is uploaded for pentest.**

---

## CI integration

Drop this into your GitHub Actions workflow. `sentinel source` runs the whole pipeline in the runner — the LLM call happens there, using the key you provide via env, never uploaded anywhere:

```yaml
- name: Install Sentinel
  run: |
    npm install -g sentineldev
    pip install sentinel-worker

- name: Scan PR diff
  run: sentinel source --base ${{ github.event.pull_request.base.sha }}
  env:
    SENTINEL_TOKEN: ${{ secrets.SENTINEL_TOKEN }}          # auth for the graph/findings backend
    SENTINEL_LLM_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }} # your LLM key, used only in this job
```

`sentinel source` exits `1` if findings are returned — use it as a blocking gate. See [`examples/github-actions.yml`](examples/github-actions.yml) for a full workflow, or [`examples/gitlab-ci.yml`](examples/gitlab-ci.yml) for GitLab.

If you'd rather not install the CLI + engine separately in CI, use the [GitHub Action](#github-action-ci-native-scanning) below — it's self-contained.

---

## GitHub Action (CI-native scanning)

Sentinel ships a composite GitHub Action that runs the **entire** scan inside your
own CI runner. The pipeline (diff → tree-sitter graph → SCA + secret scan + SAST)
executes locally against an ephemeral SQLite database, so **your source code never
leaves the runner**. Only finding metadata is produced: a SARIF report (uploaded to
GitHub code scanning) and, optionally, findings POSTed to your Sentinel cloud via
`ingest-url`. No Docker image or published package is required — the action installs
the scanner straight from its own checkout.

### Required permissions

The action uploads SARIF to GitHub code scanning, which needs `security-events: write`.
A GitHub Action cannot grant itself permissions, so set them in your workflow:

```yaml
permissions:
  contents: read
  security-events: write
```

(Set `upload-sarif: false` if you don't want code-scanning uploads — then only
`contents: read` is needed.)

### Usage — zero-config (secrets + SCA only, no API key)

```yaml
name: Sentinel
on: pull_request
permissions:
  contents: read
  security-events: write
jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: angadjosan/sentinel@v0.1.0
        with:
          provider: mock      # secrets + dependency (SCA) scan, no LLM
          fail-on: high
```

### Usage — full LLM-powered scan

```yaml
name: Sentinel
on: pull_request
permissions:
  contents: read
  security-events: write
jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: angadjosan/sentinel@v0.1.0
        with:
          provider: anthropic
          model: claude-sonnet-4-6
          api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          fail-on: high
          # Optional: ship findings (never source) to your Sentinel cloud
          # ingest-url: ${{ secrets.SENTINEL_API_URL }}
          # ingest-token: ${{ secrets.SENTINEL_TOKEN }}
```

Always check out with `fetch-depth: 0` so the action can compute an accurate PR diff
against the base branch.

### Inputs

| Input | Default | Description |
| --- | --- | --- |
| `repo-name` | `${{ github.repository }}` | Logical repo name recorded with findings. |
| `provider` | `mock` | `anthropic` \| `openai` \| `local` \| `mock`. `mock` = secrets + SCA only (no LLM). |
| `model` | `""` | Model name; empty uses the provider default. |
| `api-key` | `""` | LLM API key (passed via env; never logged). |
| `llm-endpoint` | `""` | Custom LLM endpoint, e.g. an Ollama URL for `provider: local`. |
| `base-ref` | `""` | Base ref for the diff. Empty auto-detects: PR base sha, push `before`, else `origin/<default-branch>`. |
| `fail-on` | `high` | Fail the job at/above this severity: `info`\|`low`\|`medium`\|`high`\|`critical`\|`none`. |
| `sarif` | `sentinel.sarif` | Path for the SARIF 2.1.0 report. |
| `upload-sarif` | `true` | Upload SARIF to GitHub code scanning (needs `security-events: write`). |
| `ingest-url` | `""` | Sentinel cloud base URL. Findings (not source) POSTed to `{url}/findings/ingest`. |
| `ingest-token` | `""` | Bearer token for `ingest-url` (passed via env; never logged). |
| `python-version` | `3.12` | Python used to run the scanner (3.12+). |
| `working-directory` | `.` | Path to the git checkout to scan. |

The action exits non-zero (failing the PR check) when findings reach the `fail-on`
threshold; the SARIF upload still runs first so results appear in the Security tab.
See [`examples/github-actions.yml`](examples/github-actions.yml) for a complete workflow.

---

## Using an LLM provider

Sentinel supports Anthropic, OpenAI, and local models (Ollama) — the LLM call always happens locally, on the machine running the CLI, regardless of which provider you pick:

```bash
# Anthropic
sentinel config set provider anthropic
sentinel config set model claude-sonnet-4-6
sentinel config set api-key sk-ant-...

# OpenAI
sentinel config set provider openai
sentinel config set model gpt-4o
sentinel config set api-key sk-...

# Local (Ollama) — see "Pull an Ollama model" above
sentinel config set provider local
sentinel config set model llama3.2
```

`provider` and `model` are synced to the backend as metadata (so the dashboard can show what a run used) — but `api-key` is **not**: it's stored only in your system keychain (or `~/.sentinel/keychain.json`, mode `0600`, as a fallback) and read directly by the local engine process. The server rejects any attempt to set it and never stores one. In CI, set `SENTINEL_LLM_API_KEY` (or the provider-specific `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`) as an env var instead of running `config set api-key`.

You do **not** need to set `api_endpoint` for Anthropic or OpenAI — only for a custom endpoint (e.g. an Ollama server not on `localhost:11434`).

---

## sentinel.config.json reference

Written by `sentinel init` into your repo root. Commit this file — it contains no secrets.

| Field | Type | Default | Description |
|---|---|---|---|
| `apiUrl` | string | hosted backend | Backend URL for the shared code graph + findings (not used for AI calls) |
| `repoName` | string | directory name | Display name for this repo |
| `provider` | string | `local` | LLM provider: `local` (Ollama), `anthropic`, `openai` — the SAST call always runs on this machine |
| `model` | string | — | Model name |
| `pentest_mode` | string | `staging` | Where the **cloud** worker reaches your app: `staging` (HTTP probe) or `local_worker` (self-hosted worker boots the app). Synced to the cloud repo. |
| `staging_base_url` | string | — | (`staging` mode) Base URL the cloud worker sends pentest payloads to. |
| `healthcheck_path` | string | — | (`staging` mode) Path the worker probes to confirm the app is up, e.g. `/health`. |
| `boot` | string | — | (`local_worker` mode) Command the **worker host** runs to start the app. |
| `healthcheck` | string | — | (`local_worker` mode) Command that exits 0 when the app is ready. |
| `egress_allowlist` | string[] | `[]` | (`local_worker` mode) Hosts the worker sandbox may contact. |

These pentest fields are **synced to the cloud repo** (`sentinel init` / `sentinel config set`) because the cloud worker — not your machine — runs the pentest. See [Pentest (cloud)](#pentest-cloud).

Example (`staging` mode, the hosted default):

```json
{
  "apiUrl": "https://sentinel-steel-xi.vercel.app",
  "repoName": "my-app",
  "provider": "local",
  "model": "llama3.2",
  "pentest_mode": "staging",
  "staging_base_url": "https://staging.my-app.com",
  "healthcheck_path": "/health"
}
```

---

## CLI reference

### `sentinel doctor`

Check that everything is set up correctly. Run this first if something isn't working.

```bash
sentinel doctor
```

Checks: git repo present · config file · backend reachable · authenticated · LLM configured (provider/model/key resolvable locally) · Node.js version · local engine (`sentinel_worker`) installed.

---

### `sentinel init`

Initialize Sentinel for this repository. Run once from your repo root.

```bash
sentinel init [--api-url <url>] [--repo-name <name>]
```

Writes `sentinel.config.json` and parses your codebase **locally** to build the initial code graph — source is read from disk and never leaves this machine; only the resulting nodes/edges (file/line pointers and short semantic labels) are pushed to the backend. The first init can take 30–120 seconds depending on repo size and model speed.

---

### `sentinel auth login`

Authenticate the CLI. Run after `init`. Re-run after resetting the database.

```bash
sentinel auth login
```

Prints a verification URL. With `SENTINEL_DEV_MODE=1` (default in `docker-compose.yml`) it auto-approves with no browser step. Otherwise the URL opens the dashboard's device-approval page (`SENTINEL_DASHBOARD_URL` on the API), where you log in (or sign up) and approve the device to finish. The issued token is long-lived (~90 days), stored in the system keychain, and never written to disk.

---

### `sentinel auth logout`

Revoke the stored credential, both locally and on the server.

```bash
sentinel auth logout
```

---

### `sentinel auth whoami`

Show the currently authenticated user, role, and account.

```bash
sentinel auth whoami
```

---

### `sentinel source [paths...]`

Scan the current git diff — entirely locally. Runs SAST, SCA, and secret scanning, with the LLM call made on this machine using your configured key; only the graph delta and findings are pushed to the backend. Exits `1` if findings are found.

```bash
sentinel source [--staged] [--base <ref>] [paths...]
```

---

### `sentinel scan [paths...]`

Full scan: runs `source` **locally**, then enqueues a **cloud** pentest for each ingested finding and polls until they finish. SAST stays on your machine; pentest runs on the cloud worker (see [Pentest (cloud)](#pentest-cloud)).

```bash
sentinel scan [--staged] [--base <ref>] [--no-pentest] [--pentest-concurrency <n>] [paths...]
```

`--no-pentest` scans locally and skips the cloud pentest step entirely.

---

### `sentinel pentest [target...]`

Confirm a finding with runtime oracle evidence. Unlike SAST, **pentest runs on the cloud worker, not on your machine.** `sentinel pentest` enqueues a `kind=pentest` task (`POST /pentest`) and then polls (`sentinel runs watch`) until the run reaches a terminal state, printing the finding status and evidence. The worker sends HTTP payloads to your configured staging URL and confirms only on an HTTP/behavioral proof or sanitizer output — never on agent judgment alone.

```bash
sentinel pentest                                         # auto-select
sentinel pentest abc123ef-...                            # by finding ID
sentinel pentest "SQL injection in user login handler"   # by description
```

Requires the repo's **pentest reachability** to be configured — a reachable `staging_base_url` (hosted worker, the default), or `boot`/`healthcheck` for a self-hosted `local_worker`. See [Pentest (cloud)](#pentest-cloud). The worker's LLM credential is server-side (`SENTINEL_PENTEST_LLM_API_KEY`) — separate from your local SAST key, which the worker never sees.

---

### `sentinel plan [input...]`

Review a design doc or inline text for security issues before implementation — locally, same as `source`. Exits `1` if issues are found.

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
sentinel runs show <id>         # trace + token breakdown
sentinel runs watch <id>        # stream live events from a running scan
sentinel runs cancel <id>       # cancel an in-progress run
```

`runs show <id>` reads the **full local trace** (every prompt, every tool call) from `~/.sentinel/runs/<id>.jsonl` when the run originated on this machine — that file never leaves it. If no local trace exists for the ID (e.g. it came from a teammate's run, or CI), it falls back to the backend's **redacted summary trace** — token spend and event kinds only, never prompts or tool payloads.

---

### `sentinel config`

```bash
sentinel config show               # display current config
sentinel config set <key> <value>  # update a value
```

Keys synced to the backend (metadata only, for the dashboard): `provider`, `model`, `api_endpoint`
Keys synced to the cloud **repo** (the worker needs them to run pentest): `pentest_mode`, `staging_base_url`, `healthcheck_path`, `boot`, `healthcheck`, `egress_allowlist`
Keys stored **only** in the system keychain, never sent anywhere: `api-key`
Local-only keys: `apiUrl`, `repoName`

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

The local engine (running directly on your machine, not in Docker) can't reach Ollama.

```bash
# Ollama must actually be running
ollama serve &   # or: open the Ollama app

# Set the provider, model, and endpoint the local engine will use
sentinel config set provider local
sentinel config set model llama3.2      # must match `ollama list`
sentinel config set api_endpoint http://localhost:11434

# Verify
sentinel doctor
```

---

### "LLM API key is invalid"

```bash
sentinel config set api-key <your-key>
```

This is stored in your system keychain and read directly by the local engine — it's never sent to the backend, so an invalid key won't show up as a server-side config problem; re-run `sentinel doctor` after setting it.

---

### Scan returns 0 findings immediately

1. **Empty diff** — if the working tree is clean and `HEAD~1..HEAD` is also empty (new repo with one commit), there's nothing to scan. Make some changes and re-run.
2. **Model is too small** — models under 7B may not produce reliable findings. Try `llama3.2` (3B) at minimum; `qwen3` or a cloud model for better results.
3. **Ollama connectivity** — run `sentinel doctor` to verify the local engine can reach Ollama.

---

### Database resets after `docker compose down`

The database uses a named volume and persists across normal restarts. It is only wiped with:

```bash
docker compose down -v   # -v removes volumes — use with caution
```

---

## Architecture overview

```
On your machine (or a CI runner):

┌──────────────┐  spawns  ┌───────────────────────┐  reads   ┌──────────────┐
│  CLI         │ ───────► │  Local engine          │ ───────►│  Your repo   │
│  (Node.js)   │          │  (Python, sentinel_    │          │  (git diff,  │
│              │◄──────── │  worker.local_cli)     │          │   working    │
└──────────────┘  stdout  └───────────────────────┘          │   tree)      │
      │  JSON                    │        ▲                  └──────────────┘
      │                          │        │ your key, via keychain/env
      │                          ▼        │
      │                 ┌──────────────────┐
      │                 │  LLM provider     │   Anthropic / OpenAI / local Ollama —
      │                 │  (your account)   │   the call happens here, not on the backend
      │                 └──────────────────┘
      │
      │  graph delta (pointers + labels, never source) + findings
      │  + POST /pentest (enqueue) ; sentinel runs watch (poll)
      ▼
┌─────────────────────┐   SQL   ┌──────────────┐
│  Backend API          │ ─────► │  Postgres    │
│  (FastAPI) — graph,   │        │  (graph,     │
│  findings, auth,      │        │  findings,   │
│  pentest enqueue      │        │  runs)       │
└─────────────────────┘         └──────────────┘
      ▲    │                          ▲
      │    │ claims kind=pentest       │ writes confirmation
      │    ▼                          │ + CONFIRMED_EXPLOIT
      │  ┌──────────────────────┐      │
      │  │  Cloud Worker          │──────┘
      │  │  runs pentest:         │   HTTP payloads
      │  │  SENTINEL_PENTEST_     │ ─────────────────► ┌──────────────┐
      │  │  LLM_API_KEY           │                    │  Your staging │
      │  └──────────────────────┘                     │  URL (app)    │
      │                                                └──────────────┘
      │  SSR fetches (findings, graph, run summaries — never source)
┌──────────────────┐
│  Dashboard         │
│  (Next.js)         │
└──────────────────┘
```

**Key design decisions:**

- **Source never leaves your machine for SAST.** `sentinel init`/`source`/`scan`/`plan` all run their analysis — diff parsing, graph construction, the SAST LLM call itself — in the local engine process. The CLI spawns it, pipes the diff over stdin, and parses one JSON result line from stdout.
- **The SAST LLM call happens locally**, with a key you configure (`sentinel config set api-key`) that lives only in your system keychain. The backend cannot see it, store it, or make a call on your behalf — `PATCH /config` rejects an `api_key` field outright.
- **Only the code graph and findings sync to the backend.** Graph nodes store pointers (`file`, `line_start`, `line_end`) and short LLM-written labels — never source text. `POST /graph/upsert` and `POST /findings/ingest` are the only write paths for the scan; there is no endpoint that accepts a diff or file contents.
- **Pentest runs in the cloud** — not on your machine. `sentinel pentest` enqueues a `kind=pentest` task (`POST /pentest`); the cloud worker sends HTTP payloads to your configured staging URL, applies a runtime oracle, and writes the confirmation directly. Its LLM credential (`SENTINEL_PENTEST_LLM_API_KEY`) lives on the worker, separate from your local SAST key. See [Pentest (cloud)](#pentest-cloud).
- **Run traces stay local for local runs.** A SAST run's full trace (every prompt, every tool call) is written to `~/.sentinel/runs/<id>.jsonl` and never uploaded; the backend only sees a redacted summary (token spend, event kinds). Cloud pentest runs are traced on the worker, with the same scrubbed-summary discipline.
- The code graph is stored in **Postgres**, keyed by account/repo. `sentinel init` builds it once locally and pushes it; subsequent scans push only the delta for changed nodes.
- Findings are **fingerprinted** on `file + vuln_type` so suppressions survive line-number shifts and minor refactors.
- LLM calls enforce **channel separation** — instructions live in the system prompt, analyzed code lives in the user prompt. They never mix.
- The CLI itself is **stateless** — no local database, no cache. Only `sentinel.config.json` (safe to commit) and the keychain entry for your LLM key.

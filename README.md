# Sentinel

Sentinel is an open source application security agent harness. It integrates with any model provider to find real vulnerabilities in your codebase — not just pattern matches.

The entire incumbent AppSec stack (SAST, SCA, dependency bots) answers one question: *does this code match a known-bad pattern?* That means it can only find vulns it's already catalogued. It misses business-logic flaws, auth gaps unique to your architecture, and anything that doesn't look like an existing CVE. It also floods you with false positives — "47 vulnerabilities," 3 of which matter.

Sentinel's fix is contextual reasoning over exploitability. Pattern matching is a cheap prior that tells you *where to look* — it's an input, not the product. The product is the layer that reasons about whether a finding is actually reachable and exploitable in *this* codebase, on *this* diff. That kills the false positives signatures over-flag and surfaces novel vulns no signature describes.

A raw LLM can't do this either — no persistent architectural context, stale CVE data, no way to verify its own hunches. Sentinel is the harness that supplies all three: a persistent code graph updated on every diff, live CVE feeds at scan time, and a pentest tier that confirms findings with runtime oracle evidence.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/angadjosan/sentinel/main/install.sh | bash
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

---

## How it works

**Setup (once per repo):**
- **`sentinel init`** — parse the full codebase into a cloud-backed code graph: call edges, data-flow edges, route/middleware chains, semantic intent per node.
- **`sentinel auth login`** — authenticate the CLI via a browser-based device code flow.

**Scanning:**
- **`sentinel source`** — on every diff, update the graph incrementally and run SAST, SCA, and secret scanning in parallel. Exits `1` if findings are returned, making it a drop-in CI gate.
- **`sentinel scan`** — run `source` + `pentest` in one shot.
- **`sentinel pentest`** — attempt to actually exploit a finding in a replica of your app. Confirmation requires runtime oracle evidence — sanitizer output or behavioral proof, not just agent judgment.
- **`sentinel plan`** — review a design doc or plan text for security issues before any code is written.

**Managing findings:**
- **`sentinel list`** — list findings, filterable by status and severity.
- **`sentinel pull <id>`** — fetch full remediation context for a finding: description, step-by-step fix plan, and the graph node it's anchored to.
- **`sentinel suppress <id>`** — suppress a finding with a required reason. Suppressions are fingerprint-keyed on file + vuln type so they survive line-number shifts.

**Observability:**
- **`sentinel runs list / show / watch / cancel`** — inspect run traces, stream live events, view per-component token breakdowns, or cancel an in-progress run.
- **`sentinel config show / set`** — read or update local config (API URL, model, provider, Firecracker settings, etc.).

---

## Running locally

### Prerequisites

- Docker + Docker Compose
- Node.js 20+

### 1. Start the backend

```bash
docker compose up -d
```

This starts:

| Service | Port | Description |
|---|---|---|
| `postgres` | 5433 | Graph and findings database |
| `api` | 8000 | REST API + auth |
| `worker` | — | Background scan/pentest job processor |
| `dashboard` | 3000 | Web UI |

### 2. Build the CLI

```bash
cd cli
npm install
npm run build
```

Use it directly:

```bash
node dist/index.js --help
```

Or link globally:

```bash
npm link
sentinel --help
```

### 3. Configure your repo

Copy the example config into your repo root and edit it:

```bash
cp /path/to/sentinel/sentinel.config.json.example sentinel.config.json
```

Minimum required fields:

```json
{
  "apiUrl": "http://localhost:8000",
  "repoName": "your-repo-name",
  "provider": "local",
  "model": "ollama"
}
```

`apiUrl` points at your local API. No cloud dependency — fully self-hostable.

### 4. Authenticate

```bash
sentinel auth login
```

Prints a URL and device code. Open the dashboard at `http://localhost:3000` to approve it. In dev mode (`SENTINEL_DEV_MODE=1`, already set in docker-compose), auth may be auto-approved.

### 5. Initialize the repo

Run once per repo, from the repo root:

```bash
sentinel init
```

Sends your full codebase to the worker, which builds the code graph in five passes: parse → symbol resolution → framework adapters → taint analysis → semantic enrichment. This is the only slow step — all subsequent operations are incremental.

### 6. Scan

```bash
sentinel source        # scan full git diff (staged + unstaged)
sentinel source --staged              # staged changes only
sentinel source src/auth.ts           # scope to specific files
sentinel scan                         # source scan + pentest findings
```

Findings stream to the CLI and are recorded in the dashboard.

---

## CI integration

Add to your pipeline after checkout:

```bash
sentinel source --base ${{ github.event.pull_request.base.sha }}
```

`sentinel source` exits with code `1` if any findings are returned, `0` if clean. The `--base` ref sets the diff target (defaults to merge-base detection from PR metadata when `CI=true`).

To queue scans asynchronously instead of blocking CI:

```bash
sentinel source --queue
```

---

## sentinel.config.json reference

| Field | Type | Default | Description |
|---|---|---|---|
| `apiUrl` | string | `http://localhost:8000` | Sentinel API endpoint |
| `repoName` | string | — | Required. Display name for this repo |
| `provider` | string | `local` | Model provider (`local`, `anthropic`, `openai`, etc.) |
| `model` | string | `ollama` | Model identifier |
| `boot` | string | — | Shell command to start your app for pentesting |
| `healthcheck` | string | — | Shell command that exits 0 when app is ready |
| `env.from` | string | — | Path to env file loaded into the pentest environment |
| `egress_allowlist` | string[] | `[]` | Hosts the pentest runner may reach |
| `variants` | object | — | Named build variants (e.g. `asan`, `ubsan`) |
| `firecracker.enabled` | boolean | `false` | Run pentest sandbox in Firecracker microVM |

Full example:

```json
{
  "apiUrl": "http://localhost:8000",
  "repoName": "my-app",
  "provider": "local",
  "model": "ollama",
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

Initialize Sentinel for this repository. Run once per repo; the graph is shared across the whole team.

```
sentinel init [options]

Options:
  --api-url <url>      Sentinel API URL (default: http://localhost:8000)
  --repo-name <name>   Repository name (default: current directory name)
```

Writes `sentinel.config.json` to the repo root if it doesn't exist, then sends the full codebase to the cloud worker to build the initial code graph.

---

### `sentinel auth login`

Authorize the CLI via a browser-based device code flow.

```
sentinel auth login [options]

Options:
  --poll-interval <seconds>   How often to poll for approval (default: 2)
```

Prints a verification URL and a short code. Open the URL, enter the code, and approve the request. The access token is stored in the system keychain.

---

### `sentinel source [paths...]`

Scan the current git diff for vulnerabilities. Runs SAST, SCA, and secret scanning against the diff. Exits `1` if findings are returned.

```
sentinel source [paths...] [options]

Arguments:
  paths   One or more file paths to scope the scan (optional)

Options:
  --staged          Scan staged changes only (default: staged + unstaged)
  --base <ref>      Diff against this git ref
  --queue           Queue for async worker execution instead of blocking
```

Examples:

```bash
sentinel source                          # full working tree diff
sentinel source --staged                 # staged only
sentinel source src/api/routes.ts        # scope to one file
sentinel source --base origin/main       # diff vs remote main
sentinel source --queue                  # fire and forget
```

---

### `sentinel scan [paths...]`

Run a full source scan, then pentest each finding. The combined command for local development.

```
sentinel scan [paths...] [options]

Arguments:
  paths   One or more file paths to scope the diff (optional)

Options:
  --staged                     Scan staged changes only
  --base <ref>                 Diff against this git ref
  --no-pentest                 Skip the pentest phase
  --pentest-concurrency <n>    Max concurrent pentest jobs (default: 4)
```

---

### `sentinel pentest [target...]`

Attempt to confirm a finding with runtime oracle evidence. Pass a finding ID, a natural-language description of what to test, or nothing to auto-select.

```
sentinel pentest [target...] [options]

Arguments:
  target   Finding UUID, description, or empty to auto-select

Options:
  --sanitizer-output <text>    Sanitizer output to attach as oracle evidence
  --behavioral-proof <kind>    Kind of behavioral proof
  --proof-detail <text>        Additional detail for the behavioral proof
```

Examples:

```bash
sentinel pentest                                    # auto-select a finding
sentinel pentest abc123ef-...                       # by finding ID
sentinel pentest "SQL injection in login handler"   # by description
```

---

### `sentinel list`

List findings for this repo.

```
sentinel list [options]

Options:
  --status <status>      Filter by status (open, suppressed, confirmed, etc.)
  --severity <severity>  Filter by severity (critical, high, medium, low)
```

Output columns: `ID  STATUS  SEVERITY  TYPE  FILE  UPDATED  TITLE`

---

### `sentinel pull <id>`

Fetch full remediation context for a finding — description, step-by-step remediation plan, and the graph node the finding is anchored to.

```
sentinel pull <id>

Arguments:
  id   Finding UUID
```

---

### `sentinel plan [input...]`

Review a design doc, plan file, or inline text for security issues before implementation.

```
sentinel plan [input...] [options]

Arguments:
  input   File path, inline text, or empty to read from stdin

Options:
  --with-retry   Run additional retry review passes
```

Examples:

```bash
sentinel plan DESIGN.md
sentinel plan "users can reset passwords via a link sent to their email"
cat plan.txt | sentinel plan
```

Exits `1` if issues are found.

---

### `sentinel suppress`

Suppress a finding, remove a suppression, or approve/reject a pending suppression.

```
sentinel suppress <id> --reason <reason>
sentinel suppress remove <id> --reason <reason>
sentinel suppress approve <id> --reason <reason>
sentinel suppress reject <id> --reason <reason>

Arguments:
  id   Finding UUID

Options:
  --reason <reason>   Required. Explanation for the action.
```

Suppressions are fingerprint-keyed on file + vuln type (not line number), so they survive refactors that shift line numbers.

---

### `sentinel runs`

Manage run traces.

```
sentinel runs list                 # list all runs
sentinel runs show <id>            # print full JSONL trace + token summary
sentinel runs watch <id>           # stream a run's events live
sentinel runs cancel <id>          # cancel an in-progress run
```

`runs show` also prints a per-component token breakdown for cost attribution.

---

### `sentinel config`

Read and write local config.

```
sentinel config show               # print current config as JSON
sentinel config set <key> <value>  # set a config value
```

Settable keys: `apiUrl`, `repoName`, `provider`, `model`, `boot`, `healthcheck`, `api_endpoint`, `repo_id`, `api-key` (stored in system keychain), and any `firecracker.*` sub-key.

Examples:

```bash
sentinel config show
sentinel config set apiUrl http://sentinel.internal:8000
sentinel config set model claude-opus-4-8
sentinel config set api-key sk-ant-...
sentinel config set firecracker.enabled true
sentinel config set firecracker.mem_size_mib 1024
```

---

## Findings lifecycle

```
open → confirmed (pentest passed) → suppressed (manually ignored)
                                  → suppression pending review → approved / rejected
```

Suppressions require an explicit `--reason`. Approved suppressions carry forward on the graph and are not re-surfaced on subsequent scans unless the fingerprint changes.

---

## Architecture overview

```
CLI  ──►  API (FastAPI)  ──►  Worker  ──►  Code graph (Postgres)
                │                              ▲
                ▼                              │
           Dashboard (Next.js)            sentinel init / source diffs
```

The worker handles all graph construction and agent execution. The API is a thin job queue + findings store. The CLI talks only to the API. Nothing is stored locally beyond `sentinel.config.json` and the keychain entry.

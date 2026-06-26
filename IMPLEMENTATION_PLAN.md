# Sentinel Production-Readiness Implementation Plan

This plan captures the full audit findings and exact changes needed to make Sentinel production-ready. Each task includes file paths, line numbers, what to change, and why. Tasks are ordered by dependency.

---

## Pre-existing state (what's already done)

- `worker/tests/__init__.py` — created (empty file). Fixes `from tests.conftest import MockLLMClient` collection errors.
- `worker/pyproject.toml` — added `[tool.pytest.ini_options]` with `pythonpath = ["."]`, `asyncio_mode = "auto"`, `testpaths = ["tests"]`.
- Baseline: CLI 36/36 pass, API 34/34 pass, Worker 354/360 pass (6 fail due to ollama model misconfiguration — expected).

---

## Task 1: Reliability — model/parse errors return clean 4xx, not 500

### Root cause

The default model id is `"ollama"` (the provider name, not a real model). Ollama returns HTTP 404 for unknown models. In `agent.py:593-603`, the `_local_agentic_loop` catches `httpx.ConnectError`/`ConnectTimeout` as `RuntimeError` but catches all other exceptions with a bare `except Exception: break` — silently swallowing the 404. In `_call_local` (line 330-353), the 400/422 fallback path has no `except` for connect errors on the retry. The `/source` handler (`main.py:342`) only catches `LLMNotConfiguredError | RuntimeError`, so any other exception becomes a raw 500.

### Changes

#### 1a. `worker/src/sentinel_worker/agent.py`

Add a new exception class near the top (after `ChannelViolationError` at line 19):

```python
class ModelNotFoundError(RuntimeError):
    """Raised when the configured model is not available on the provider."""
    pass
```

In `_call_local` (lines 295-353), after `resp.raise_for_status()` at line 318, wrap the `except httpx.HTTPStatusError` block to detect model-not-found:

```python
except httpx.HTTPStatusError as exc:
    if exc.response.status_code == 404:
        raise ModelNotFoundError(
            f"Model '{self.model}' not found on Ollama at {endpoint}. "
            f"Run `ollama pull <model>` or set a valid model: "
            f"`sentinel config set model <model-name>`"
        ) from exc
    # existing 400/422 tool-fallback logic stays
    if tools and exc.response.status_code in (400, 422):
        ...  # existing fallback, but wrap the retry in try/except too
    raise RuntimeError(f"Ollama returned {exc.response.status_code}: {exc.response.text[:200]}") from exc
```

In `_local_agentic_loop` (lines 564-640), change `except Exception: break` at line 602-603 to:

```python
except (httpx.ConnectError, httpx.ConnectTimeout):
    raise RuntimeError(
        f"Cannot connect to Ollama at {endpoint}. "
        "Either start Ollama or configure a cloud provider."
    )
except httpx.HTTPStatusError as exc:
    if exc.response.status_code == 404:
        raise ModelNotFoundError(
            f"Model '{self.model}' not found on Ollama at {endpoint}. "
            f"Run `ollama pull <model>` or set a valid model."
        ) from exc
    log.warning("ollama_error", status=exc.response.status_code, detail=exc.response.text[:200])
    break
except Exception:
    log.warning("local_agentic_loop_error", exc_info=True)
    break
```

In `_call_openai` (around line 284), wrap `response.choices[0]` access:

```python
if not response.choices:
    return LLMCallResult(content="", input_tokens=0, output_tokens=0, model=self.model, provider="openai")
```

In the OpenAI agentic loop (around line 533), wrap `json.loads(tc.function.arguments)`:

```python
try:
    args = json.loads(tc.function.arguments or "{}")
except (json.JSONDecodeError, TypeError):
    args = {}
```

#### 1b. `worker/src/sentinel_worker/sast.py`

Export `ModelNotFoundError` alongside `LLMNotConfiguredError` so the API handler can catch it. At line 1 area, add:

```python
from .agent import ModelNotFoundError  # re-export for API handler convenience
```

#### 1c. `api/src/sentinel_api/main.py`

**Global exception handler** — add after the CORS middleware setup (~line 79):

```python
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    log.error("unhandled_exception", path=request.url.path, error=str(exc), exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})
```

(Add `from starlette.responses import JSONResponse` to imports if not already present.)

**`/source` handler** (line 342) — broaden the except:

```python
except (LLMNotConfiguredError, RuntimeError) as exc:
    raise HTTPException(status_code=422, detail=str(exc)) from exc
```

Change to:

```python
except (LLMNotConfiguredError, RuntimeError, ValueError) as exc:
    raise HTTPException(status_code=422, detail=str(exc)) from exc
except Exception as exc:
    log.error("source_scan_failed", error=str(exc), exc_info=exc)
    raise HTTPException(status_code=500, detail="Scan failed unexpectedly. Check server logs.") from exc
```

**`/plan` handler** (around line 413-415) — same pattern, broaden the except.

**`/pentest` handler** (around line 699-716) — currently has NO try/except. Wrap `run_pentest` call:

```python
try:
    # existing run_pentest call
except (LLMNotConfiguredError, RuntimeError, ValueError) as exc:
    raise HTTPException(status_code=422, detail=str(exc)) from exc
except Exception as exc:
    log.error("pentest_failed", error=str(exc), exc_info=exc)
    raise HTTPException(status_code=500, detail="Pentest failed unexpectedly.") from exc
```

**Replace `assert` with HTTPException** — find all `assert ... is not None` in main.py (lines ~289, 297, 359) and repos.py (~104, 124, 145, 165, 185). Replace with:

```python
if account is None:
    raise HTTPException(status_code=404, detail="account not found")
```

#### 1d. Verify

Run: `cd worker && python -m pytest -q` — should still have 354+ pass.
Run: `cd api && python -m pytest -q` — should still have 34 pass.
Start the API and run `node cli/dist/index.js source README.md` — should get a 422 with a "Model 'ollama' not found" message instead of a 500.

---

## Task 2: Performance — keep scans within budget

### Problem

`execute_source_scan` runs SAST (50 iterations x 120s timeout), graph enrichment (1 LLM call per 15-node cluster), and serial OSV lookups all synchronously inside the `/source` request. `review_plan` with `--with-retry` runs SAST 3 times.

### Changes

#### 2a. `worker/src/sentinel_worker/agent.py`

Lower per-call httpx timeout from 120s to 30s in `_call_local` (line 317) and `_local_agentic_loop` (line 593):

```python
timeout=30  # was 120
```

#### 2b. `worker/src/sentinel_worker/sast.py`

At line 63, change `max_iterations=50` to `max_iterations=5`. The SAST loop rarely needs more than 2-3 tool calls to produce findings. 50 is wildly excessive for a sync path.

#### 2c. `worker/src/sentinel_worker/scan.py`

**Move enrichment off the sync path.** In `execute_source_scan` (lines 243-245), make enrichment async-optional:

```python
# Only enrich in the background worker path, not the synchronous /source path
if run_context != "local-sync":
    await enrich_graph_nodes(db, graph_id=graph.id, run_id=run.id, source_by_file={f.path: f.content for f in files}, only_new=True, llm=llm)
    from .enrichment import validate_enrichment_labels
    await validate_enrichment_labels(db, graph_id=graph.id, run_id=run.id, llm=llm, source_by_file={f.path: f.content for f in files})
```

Pass `run_context` through to `execute_source_scan` — it's already a parameter (line 151).

**Make SCA concurrent with a short aggregate timeout.** Replace the serial loop at lines 212-215:

```python
import asyncio

sca_tasks = [scan_dependencies(db, graph.id, repo.id, run.id, f.path, f.content) for f in files if _is_manifest(f.path)]
if sca_tasks:
    try:
        sca_results = await asyncio.wait_for(asyncio.gather(*sca_tasks, return_exceptions=True), timeout=8.0)
        sca_count = sum(r for r in sca_results if isinstance(r, int))
    except asyncio.TimeoutError:
        log.warning("sca_timeout", run_id=run.id)
        sca_count = 0
```

Wait — `scan_dependencies` takes a shared `db` session which is NOT safe to use concurrently in SQLAlchemy. Instead, just add a per-dependency timeout in `sca.py` (the `httpx` call at `sca.py:63` already has `timeout=10` which is fine) and skip files that aren't manifests early. The bigger win is the enrichment removal above.

Simpler approach: just add a wall-clock deadline around the whole SAST call at lines 230-241:

```python
try:
    sast_findings = await asyncio.wait_for(run_sast(
        diff=diff,
        bootstrap_context=bootstrap_context,
        run_id=run.id,
        suppressed_fps=suppressed_fps,
        graph=graph,
        repo_id=str(repo.id),
        db=db,
        llm=llm,
    ), timeout=15.0)
except asyncio.TimeoutError:
    log.warning("sast_timeout", run_id=run.id)
    sast_findings = []
```

Add `import asyncio` at the top of scan.py if not present.

**Cap `review_plan` retry passes.** In `review_plan` (around line 292), change `max_passes = 3` to `max_passes = 1` for the synchronous path. Keep `max_passes = 3` only when called from the worker (add a `max_passes` param defaulting to 1).

#### 2d. Verify

Timing: `time node cli/dist/index.js source README.md` — should complete in ~15s or less (model-dependent, but the enrichment removal alone saves multiple LLM calls; the iteration cap from 50 to 5 prevents runaway loops).

---

## Task 3: CLI fetch timeouts + friendly error messages

### Changes

#### 3a. `cli/src/api/client.ts`

Add a timeout helper and apply it to `request()` (line 58):

```typescript
private requestTimeout(): number {
  return (this.config as any).requestTimeoutMs ?? 10_000;
}

async request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), this.requestTimeout());
  try {
    const response = await fetch(`${this.config.apiUrl}${path}`, {
      ...init,
      signal: controller.signal,
      headers: {
        "Content-Type": "application/json",
        ...(await this.authHeaders()),
        ...(init.headers ?? {}),
      },
    });
    if (!response.ok) {
      const detail = await response.text();
      throw new Error(`${response.status} ${response.statusText}: ${detail}`);
    }
    return response.json() as Promise<T>;
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error(
        `Request to ${this.config.apiUrl}${path} timed out after ${this.requestTimeout() / 1000}s. ` +
        `Is the backend running? Start it with 'sentinel up'.`
      );
    }
    if (error instanceof TypeError && (error as any).cause?.code === "ECONNREFUSED") {
      throw new Error(
        `Cannot reach Sentinel backend at ${this.config.apiUrl}. ` +
        `Start it with 'sentinel up' or set a different URL: 'sentinel config set apiUrl <url>'.`
      );
    }
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
```

Apply the same AbortController pattern to `deviceAuthToken` (line 86), `trace` (line 200), and `runEvents` (line 210). For `runEvents`, use a longer timeout on the initial fetch (30s) and add an idle-read watchdog.

#### 3b. `cli/src/index.ts` (line 331-334)

Improve the top-level error handler:

```typescript
program.parseAsync().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(chalk.red(`Error: ${message}`));
  if (process.env.DEBUG && error instanceof Error && error.stack) {
    console.error(error.stack);
  }
  if (error instanceof Error && error.cause) {
    console.error(chalk.dim(`Cause: ${(error.cause as any).code ?? error.cause}`));
  }
  process.exitCode = 2;
});
```

#### 3c. `cli/src/diff/git.ts`

Add `maxBuffer` and wrap errors. Read the current file first — it uses `execFileSync`. Add:

```typescript
function git(...args: string[]): string {
  try {
    return execFileSync("git", args, {
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024, // 64 MB for large diffs
    }).trimEnd();
  } catch (error: any) {
    if (error.code === "ENOENT") {
      throw new Error("git is not installed or not on PATH.");
    }
    if (error.stderr?.includes("not a git repository")) {
      throw new Error("Not a git repository. Run sentinel commands from inside your repo.");
    }
    throw error;
  }
}
```

#### 3d. Rebuild and verify

```bash
cd cli && npm run build && npm test
```

Test against dead backend: `node dist/index.js list` — should print friendly "Cannot reach Sentinel backend" message.
Test against live backend: `time node dist/index.js list` — should complete in < 1s.

---

## Task 4: Backend always running — ensureBackend + sentinel up/down/status

### Design

- `ensureBackend()` — shared helper called before any API-touching command.
  - GET `{apiUrl}/health` with 500ms timeout.
  - If healthy, return immediately.
  - If `apiUrl` points to localhost and health fails, spawn backend automatically.
  - If non-localhost, throw with a "backend not reachable" error.
- Spawn: fork `uvicorn sentinel_api.main:app --port 8000` + `sentinel-worker` as detached child processes. Store PIDs in `~/.sentinel/pids/`. Redirect stdout/stderr to `~/.sentinel/logs/`.
- `sentinel up` — explicit start (same logic but always spawns even if healthy).
- `sentinel down` — read PIDs from `~/.sentinel/pids/`, send SIGTERM, clean up PID files.
- `sentinel status` — check PID files, verify processes are alive, hit /health.

### Changes

#### 4a. New file: `cli/src/backend/ensure.ts`

```typescript
import { existsSync, mkdirSync, readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const SENTINEL_DIR = join(homedir(), ".sentinel");
const PID_DIR = join(SENTINEL_DIR, "pids");
const LOG_DIR = join(SENTINEL_DIR, "logs");

function ensureDirs() {
  mkdirSync(PID_DIR, { recursive: true });
  mkdirSync(LOG_DIR, { recursive: true });
}

async function isHealthy(apiUrl: string, timeoutMs = 500): Promise<boolean> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(`${apiUrl}/health`, { signal: controller.signal });
    return resp.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

function isLocalhost(apiUrl: string): boolean {
  try {
    const url = new URL(apiUrl);
    return ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
  } catch {
    return false;
  }
}

function readPid(name: string): number | null {
  try {
    const pid = parseInt(readFileSync(join(PID_DIR, `${name}.pid`), "utf8").trim(), 10);
    // Check if process is alive
    process.kill(pid, 0);
    return pid;
  } catch {
    return null;
  }
}

function writePid(name: string, pid: number) {
  writeFileSync(join(PID_DIR, `${name}.pid`), String(pid));
}

function removePid(name: string) {
  try { unlinkSync(join(PID_DIR, `${name}.pid`)); } catch {}
}

export async function startBackend(apiUrl: string): Promise<void> {
  ensureDirs();
  const port = new URL(apiUrl).port || "8000";

  // Find python with sentinel_api installed
  // Try common locations
  const pythonCandidates = ["python3", "python", process.env.SENTINEL_PYTHON ?? ""];
  // For simplicity, use whichever python has sentinel_api
  const pythonBin = "python3"; // Could be smarter, but keep it simple

  if (!readPid("api")) {
    const apiOut = require("fs").openSync(join(LOG_DIR, "api.log"), "a");
    const apiErr = require("fs").openSync(join(LOG_DIR, "api.log"), "a");
    const apiProc = spawn(pythonBin, [
      "-m", "uvicorn", "sentinel_api.main:app", "--host", "0.0.0.0", "--port", port,
    ], {
      detached: true,
      stdio: ["ignore", apiOut, apiErr],
      env: { ...process.env, SENTINEL_DEV_MODE: "1" },
    });
    apiProc.unref();
    writePid("api", apiProc.pid!);
  }

  if (!readPid("worker")) {
    const workerOut = require("fs").openSync(join(LOG_DIR, "worker.log"), "a");
    const workerErr = require("fs").openSync(join(LOG_DIR, "worker.log"), "a");
    const workerProc = spawn(pythonBin, ["-m", "sentinel_worker.worker_main"], {
      detached: true,
      stdio: ["ignore", workerOut, workerErr],
      env: { ...process.env },
    });
    workerProc.unref();
    writePid("worker", workerProc.pid!);
  }

  // Poll /health until ready (max ~8s)
  for (let i = 0; i < 16; i++) {
    if (await isHealthy(apiUrl, 500)) return;
    await sleep(500);
  }
  throw new Error(`Backend failed to start. Check logs: ${LOG_DIR}/api.log`);
}

export async function stopBackend(): Promise<void> {
  for (const name of ["api", "worker"]) {
    const pid = readPid(name);
    if (pid) {
      try { process.kill(pid, "SIGTERM"); } catch {}
      removePid(name);
    }
  }
}

export async function backendStatus(apiUrl: string): Promise<{ api: string; worker: string; healthy: boolean }> {
  const apiPid = readPid("api");
  const workerPid = readPid("worker");
  const healthy = await isHealthy(apiUrl);
  return {
    api: apiPid ? `running (PID ${apiPid})` : "stopped",
    worker: workerPid ? `running (PID ${workerPid})` : "stopped",
    healthy,
  };
}

export async function ensureBackend(apiUrl: string): Promise<void> {
  if (await isHealthy(apiUrl)) return;
  if (!isLocalhost(apiUrl)) {
    throw new Error(
      `Cannot reach Sentinel backend at ${apiUrl}. ` +
      `The backend must be running at this URL. If running locally, use 'sentinel up'.`
    );
  }
  console.log("Backend not running. Starting...");
  await startBackend(apiUrl);
  console.log("Backend ready.");
}
```

#### 4b. `cli/src/index.ts`

Add commands and wire `ensureBackend` into API-touching commands.

After imports, add:
```typescript
import { ensureBackend, startBackend, stopBackend, backendStatus } from "./backend/ensure.js";
```

Add new commands before `program.parseAsync()`:

```typescript
program
  .command("up")
  .description("Start the Sentinel backend (API + worker)")
  .action(async () => {
    const config = loadConfig();
    await startBackend(config.apiUrl);
    console.log("Sentinel backend started.");
  });

program
  .command("down")
  .description("Stop the Sentinel backend")
  .action(async () => {
    await stopBackend();
    console.log("Sentinel backend stopped.");
  });

program
  .command("status")
  .description("Show backend status")
  .action(async () => {
    const config = loadConfig();
    const s = await backendStatus(config.apiUrl);
    console.log(`API:     ${s.api}`);
    console.log(`Worker:  ${s.worker}`);
    console.log(`Healthy: ${s.healthy ? "yes" : "no"}`);
  });
```

Add `await ensureBackend(config.apiUrl)` as the first line inside every command action that uses `SentinelApiClient`. These are: `init`, `source`, `scan`, `list`, `pull`, `plan`, `pentest`, all `suppress` sub-commands, all `runs` sub-commands, and `config set` (when it calls `patchConfig`). Example pattern:

```typescript
.action(async (options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);  // <-- add this
    const client = new SentinelApiClient(config);
    // ... rest of handler
});
```

For `config show` and `--version`, do NOT add ensureBackend (they're local-only).

#### 4c. Rebuild and verify

```bash
cd cli && npm run build
sentinel down  # stop any existing
sentinel status  # should show stopped
sentinel up  # should start
sentinel list  # should auto-start if needed, then return results
```

---

## Task 5: Async scans — source/scan enqueue + live-stream by default

### Design

Change `sentinel source`/`scan` from synchronous (POST /source, wait for full response) to: POST /source/enqueue (returns immediately with run_id), then stream findings via SSE from `/runs/{id}/events`. This makes the CLI return first output within ~2s while the scan runs in the worker.

### Changes

#### 5a. `cli/src/index.ts` — `source` command (lines 76-102)

Replace the current synchronous flow:

```typescript
.action(async (paths: string[], options) => {
    const config = loadConfig();
    validateConfigForScan(config);
    await ensureBackend(config.apiUrl);
    const diff = currentDiff({ staged: options.staged, base: options.base, paths });
    const client = new SentinelApiClient(config);
    const scope = { baseRef: options.base, paths };
    const runContext = process.env.CI ? "ci" : "local";

    if (options.queue) {
      const queued = await client.enqueueSource(diff, runContext, scope);
      console.log(`queued task ${queued.task_id}; run ${queued.run.id}`);
      return;
    }

    // Default: enqueue + stream
    const queued = await client.enqueueSource(diff, runContext, scope);
    console.log(`run ${queued.run.id} started`);

    let findingCount = 0;
    const deadline = Date.now() + 120_000; // 2 min max wait
    try {
      for await (const event of client.runEvents(queued.run.id)) {
        try {
          const parsed = JSON.parse(event);
          if (parsed.vuln_type) {
            findingCount++;
            console.log(`${chalk.red((parsed.severity || "unknown").toUpperCase())} ${parsed.vuln_type} ${parsed.id || ""}`);
            console.log(`  ${parsed.title || ""}`);
            if (parsed.remediation) console.log(`  fix: ${parsed.remediation}`);
          }
          if (parsed.kind === "complete" || parsed.kind === "run.completed" ||
              parsed.status === "failed" || parsed.status === "cancelled" ||
              parsed.kind === "scan.completed") {
            if (parsed.finding_count !== undefined) findingCount = parsed.finding_count;
            break;
          }
        } catch { /* non-JSON lines are trace output, ignore */ }
        if (Date.now() > deadline) break;
      }
    } catch (err) {
      // Stream interrupted — fall back to polling the run
      const run = await client.run(queued.run.id);
      findingCount = run.finding_count;
    }
    console.log(`run ${queued.run.id} completed with ${findingCount} finding(s)`);
    process.exitCode = findingCount > 0 ? 1 : 0;
});
```

Apply the same pattern to `scan`.

#### 5b. SSE terminal event standardization

In `api/src/sentinel_api/main.py`, the `/source/stream` handler (line 363-372) emits `{"kind": "complete"}`. The dashboard's `LiveFindingCards.tsx` checks `data.kind === "run.completed"`. Standardize: always emit `{"kind": "run.completed", ...}` as the terminal event.

In `main.py` line 370:
```python
yield f"data: {json.dumps({'kind': 'run.completed', 'run_id': result.run.id, 'finding_count': len(result.findings)})}\n\n"
```

In `cli/src/index.ts` line 271, add `parsed.kind === "run.completed"` to the break condition (or just check both for backward compat).

#### 5c. Worker must be running for async to work

This is handled by Task 4 (`ensureBackend` starts the worker). But also: the API's `/source/enqueue` should return a clear error if no worker has claimed a task within a reasonable time. The current task_queue already handles this, and the SSE stream will show the run as "queued" until claimed.

#### 5d. Verify

```bash
cd cli && npm run build
time node dist/index.js source README.md  # should return within seconds, stream findings
```

---

## Task 6: Security hardening

### 6a. Fail-closed auth — `api/src/sentinel_api/auth.py`

Change `auth_required()` (line 25-26):

```python
def auth_required() -> bool:
    if os.getenv("SENTINEL_DEV_MODE", "0") == "1":
        return False
    return True
```

This means: auth is always required UNLESS dev mode is explicitly enabled. Remove or ignore `SENTINEL_REQUIRE_AUTH`.

### 6b. No default JWT secret — `api/src/sentinel_api/auth.py`

Change `jwt_secret()` (line 21-22):

```python
def jwt_secret() -> str:
    secret = os.getenv("SENTINEL_JWT_SECRET", "")
    if not secret:
        if os.getenv("SENTINEL_DEV_MODE", "0") == "1":
            return "dev-secret-not-for-production"
        raise RuntimeError(
            "SENTINEL_JWT_SECRET must be set in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
        )
    return secret
```

### 6c. Remove `account_id == "dev"` tenant bypass — `api/src/sentinel_api/main.py`

Search for every `if ... == "dev"` or `account_id == "dev"` pattern in main.py. These appear in helper functions like `_graph_account_id`, `_finding_for_principal`, `_run_for_principal`, and all the analytics/graph endpoints.

The pattern is:
```python
if principal.account_id == "dev":
    # no tenant filter
else:
    query = query.where(... .account_id == principal.account_id)
```

Change to:
```python
def _is_dev_mode() -> bool:
    return os.getenv("SENTINEL_DEV_MODE", "0") == "1"
```

Then replace `principal.account_id == "dev"` checks with `_is_dev_mode()`. This way the bypass is controlled by a server-side env var, not a client-supplied token value.

### 6d. CORS from env — `api/src/sentinel_api/main.py` (lines 73-79)

```python
import os

_cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:3001").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _cors_origins],
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
```

### 6e. Require auth on `/metrics` — `api/src/sentinel_api/main.py` (line 206-208)

```python
@app.get("/metrics")
async def metrics(principal: Principal = Depends(require_admin)) -> PlainTextResponse:
    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)
```

### 6f. Validate path traversal in `read_source_file` — `api/src/sentinel_api/main.py`

Find the `read_source_file` endpoint (around line 796-808). Add validation:

```python
import re

COMMIT_HASH_RE = re.compile(r"^[0-9a-f]{7,64}$")

@app.get("/source/{commit_hash}/{file_path:path}")
async def read_source_file(commit_hash: str, file_path: str, ...):
    if not COMMIT_HASH_RE.match(commit_hash):
        raise HTTPException(status_code=400, detail="invalid commit hash")
    normalized = os.path.normpath(file_path)
    if normalized.startswith("..") or normalized.startswith("/"):
        raise HTTPException(status_code=400, detail="invalid file path")
    # ... rest of handler using normalized path
```

### 6g. Pentest: refuse local executor in prod — `worker/src/sentinel_worker/vm.py`

In `_pentest_executor` or wherever `LocalSubprocessSandboxExecutor` is chosen as fallback, add:

```python
if not os.getenv("SENTINEL_DEV_MODE") == "1":
    raise RuntimeError(
        "Pentest requires Firecracker sandbox in production. "
        "Set firecracker.enabled=true or enable SENTINEL_DEV_MODE for local testing."
    )
```

### 6h. Verify

```bash
cd api && python -m pytest -q  # all tests should pass (tests set SENTINEL_DEV_MODE=1)
```

Test: start API without SENTINEL_DEV_MODE → auth should be required. Start with SENTINEL_DEV_MODE=1 → dev mode works as before.

---

## Task 7: Ops — docker, dashboard, default model

### 7a. `docker-compose.yml`

Add healthchecks and restart policies:

```yaml
services:
  postgres:
    # ... existing
    restart: unless-stopped

  api:
    # ... existing
    restart: unless-stopped
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:8000/health || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 3
    environment:
      DATABASE_URL: postgresql+asyncpg://sentinel:sentinel@postgres:5432/sentinel
      SENTINEL_JWT_SECRET: "${SENTINEL_JWT_SECRET:-dev-secret-not-for-production}"
      SENTINEL_DEV_MODE: "${SENTINEL_DEV_MODE:-1}"
      CORS_ORIGINS: "${CORS_ORIGINS:-http://localhost:3000,http://localhost:3001}"

  worker:
    # ... existing
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy

  dashboard:
    # ... existing
    restart: unless-stopped
    depends_on:
      api:
        condition: service_healthy
```

### 7b. Dashboard error boundary — `dashboard/src/app/error.tsx`

Create new file:

```tsx
"use client";

export default function Error({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <div style={{ padding: "2rem", textAlign: "center" }}>
      <h2>Something went wrong</h2>
      <p>{error.message.includes("fetch") ? "Cannot reach the Sentinel backend." : error.message}</p>
      <button onClick={reset} style={{ marginTop: "1rem", padding: "0.5rem 1rem" }}>
        Try again
      </button>
    </div>
  );
}
```

### 7c. Dashboard loading state — `dashboard/src/app/loading.tsx`

Create new file:

```tsx
export default function Loading() {
  return (
    <div style={{ padding: "2rem", textAlign: "center" }}>
      <p>Loading...</p>
    </div>
  );
}
```

### 7d. Pulse keyframes — `dashboard/src/app/globals.css`

Add at the end:

```css
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.35; }
}
```

### 7e. Default model guidance

In `cli/src/config/sentinel.config.ts`, change the default model from `"ollama"` to something meaningful. At line 37:

```typescript
model: z.string().default("llama3.2"),
```

This way `sentinel init` writes a real model name. The user still needs to `ollama pull llama3.2`, but the error message from Task 1 will tell them that.

Also update `sentinel.config.json.example`:

```json
{
  "apiUrl": "http://localhost:8000",
  "repoName": "your-repo-name",
  "provider": "local",
  "model": "llama3.2"
}
```

### 7f. Verify

```bash
cd cli && npm run build && npm test
cd ../api && python -m pytest -q
cd ../worker && python -m pytest -q
```

---

## Task 8: Final verification

After all changes:

1. `cd cli && npm run build && npm test` — 36+ tests pass
2. `cd api && python -m pytest -q` — 34+ tests pass
3. `cd worker && python -m pytest -q` — 354+ tests pass
4. Kill any existing backend: `sentinel down`
5. `sentinel status` — shows stopped
6. `sentinel list` — should auto-start backend, then list (empty) findings in < 10s
7. `sentinel source README.md` — should enqueue, stream, complete
8. `sentinel config show` — instant, no backend needed
9. `sentinel --version` — instant

---

## Summary of all files to modify

| File | Changes |
|------|---------|
| `worker/src/sentinel_worker/agent.py` | Add `ModelNotFoundError`; fix error handling in `_call_local`, `_local_agentic_loop`, OpenAI path; lower timeouts to 30s |
| `worker/src/sentinel_worker/sast.py` | Re-export `ModelNotFoundError`; cap `max_iterations` to 5 |
| `worker/src/sentinel_worker/scan.py` | Move enrichment off sync path; add SAST wall-clock deadline; cap review_plan passes |
| `worker/src/sentinel_worker/vm.py` | Refuse local executor outside dev mode |
| `api/src/sentinel_api/main.py` | Global exception handler; broaden /source /plan /pentest error handling; replace asserts; CORS from env; auth on /metrics; path traversal validation; standardize SSE events; `_is_dev_mode()` helper replacing `account_id=="dev"` checks |
| `api/src/sentinel_api/auth.py` | Fail-closed auth; no default JWT secret outside dev |
| `cli/src/api/client.ts` | AbortController timeout on all fetches; friendly connection-refused errors |
| `cli/src/index.ts` | Wire `ensureBackend`; add `up`/`down`/`status` commands; async source/scan with SSE streaming; better top-level error handler |
| `cli/src/backend/ensure.ts` | **NEW** — health check, auto-spawn, stop, status helpers |
| `cli/src/diff/git.ts` | Add maxBuffer, wrap git-missing/not-a-repo errors |
| `cli/src/config/sentinel.config.ts` | Change default model from `"ollama"` to `"llama3.2"` |
| `docker-compose.yml` | Healthchecks, restart policies, env var templating |
| `dashboard/src/app/error.tsx` | **NEW** — error boundary |
| `dashboard/src/app/loading.tsx` | **NEW** — loading state |
| `dashboard/src/app/globals.css` | Add `@keyframes pulse` |
| `sentinel.config.json.example` | Update default model |
| `worker/pyproject.toml` | Already done — pytest config |
| `worker/tests/__init__.py` | Already done — empty file |

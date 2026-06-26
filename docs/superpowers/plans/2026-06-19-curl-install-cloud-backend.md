# Sentinel: One-Line Curl Install + Costless Cloud Backend — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let anyone install Sentinel with a single `curl … | bash`, getting a self-contained `sentinel` CLI that points at a free, always-on cloud backend — while all resource-intensive work (graph construction, LLM agent runs, pentest) executes locally on the user's machine.

**Architecture:** Invert today's topology. The **cloud** (Vercel + Neon, both free tiers) is a *thin* coordination/storage layer: the FastAPI app as Vercel Python serverless functions, the Next.js dashboard, and Neon Postgres as the shared findings/graph store. It runs **no heavy compute and holds no LLM keys**, so it is costless to host. The **local machine** runs the Python worker (shipped as a Docker image the CLI launches on demand) which does graph construction, agent execution, and pentest using the user's own LLM key. The worker connects to Neon to claim and complete jobs, scoped to its account. The CLI is compiled to a standalone per-platform binary (Bun) and installed via a hosted `install.sh`, mirroring Claude Code's installer.

**Tech Stack:** Bun (compile CLI → binary), bash (`install.sh`), GitHub Actions (release pipeline), Vercel (`@vercel/python` ASGI + Next.js), Neon (serverless Postgres), Docker/GHCR (worker image), FastAPI, SQLAlchemy/asyncpg.

---

## Key Architectural Decisions (read before starting)

1. **Cloud never runs heavy work.** The inline endpoints `/source`, `/init`, `/plan`, `/pentest` in `api/src/sentinel_api/main.py` currently import and run `scan_diff`/`run_pentest`/`review_plan` in-process. On Vercel serverless these would time out, cost money, and defeat the "heavy work local" goal. **All heavy operations become enqueue-only** in the cloud; the local worker processes the queue.

2. **Worker runs locally via Docker.** Replace `cli/src/backend/ensure.ts`'s `uvicorn`/`python3` spawning with a `docker run` of a published worker image (`ghcr.io/sentineldev/sentinel-worker`). Docker is the only local prerequisite for scanning/pentest. The CLI passes the user's LLM key and the Neon connection (obtained at login) into the container via env.

3. **SSE → polling.** The `/runs/{id}/events` SSE endpoint uses Postgres `LISTEN/NOTIFY` (asyncpg), which does not work over Neon's pooled connection or serverless. The CLI's `runEvents` is changed to **poll** `/runs/{id}` for status + trace deltas until the run reaches a terminal state. No server LISTEN/NOTIFY needed.

4. **CLI is a self-contained binary.** Bun `--compile` produces a single executable per platform. `keytar` (native) is dropped from the compiled build; `keychain.ts` already has a working `~/.sentinel/keychain.json` file fallback, which the binary uses.

5. **Self-hosted-per-team trust model (v1).** "Anyone can run the curl command" refers to the CLI install UX. The backend is hosted once per team. The local worker reaches Neon using a connection string issued at `sentinel auth login`, and task claims are scoped by `account_id` so one team's worker never claims another's job. Routing the worker's DB access through the API (so no DB creds leave the cloud) is a documented follow-up, **out of scope** for this plan.

### Files created / modified (map)

**Phase A — CLI packaging & install (headline):**
- Create: `cli/build.ts` (Bun compile driver), `cli/tests/build.test.ts`
- Create: `install.sh` (repo root), `cli/tests/install.test.ts`
- Create: `.github/workflows/release.yml`
- Modify: `cli/package.json` (build scripts, drop keytar from bundle), `cli/src/config/sentinel.config.ts` (default `apiUrl`), `cli/src/backend/ensure.ts` (Docker worker + no-spawn for remote)
- Modify: `cli/src/api/client.ts` (`runEvents` → polling)

**Phase B — Cloud backend (Vercel + Neon):**
- Create: `api/index.py` (Vercel ASGI entrypoint), `vercel.json` (repo root), `api/requirements.txt`
- Create: `worker/Dockerfile`
- Modify: `api/src/sentinel_api/main.py` (make heavy endpoints enqueue-only), `worker/src/sentinel_worker/task_queue.py` (account-scoped claim), `api/src/sentinel_api/sse.py` / `main.py` (drop LISTEN/NOTIFY events route or make it polling-safe)
- Create: `docs/DEPLOY.md`

**Phase C — Docs & config:**
- Modify: `README.md` (install via curl), `sentinel.config.json.example` (hosted default)

---

## Phase A — CLI Packaging & One-Line Install (headline deliverable)

### Task A1: Default the CLI at the hosted backend

**Files:**
- Modify: `cli/src/config/sentinel.config.ts:36` (the `apiUrl` default)
- Test: `cli/tests/config.test.ts`

- [ ] **Step 1: Write the failing test**

Add to `cli/tests/config.test.ts` (create the file if absent; use Node's built-in test runner, matching `package.json`'s `node --test dist/tests/*.test.js`):

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { ConfigSchema } from "../src/config/sentinel.config.js";

test("apiUrl defaults to the hosted backend", () => {
  const cfg = ConfigSchema.parse({ repoName: "demo" });
  assert.equal(cfg.apiUrl, "https://sentinel-api.vercel.app");
});
```

- [ ] **Step 2: Run it and confirm failure**

Run: `cd cli && npm run build && node --test dist/tests/config.test.js`
Expected: FAIL — default is still `http://localhost:8000`.

- [ ] **Step 3: Change the default**

In `cli/src/config/sentinel.config.ts`, change:

```ts
  apiUrl: z.string().url().default("http://localhost:8000"),
```
to:
```ts
  apiUrl: z.string().url().default("https://sentinel-api.vercel.app"),
```

(Replace `sentinel-api.vercel.app` with the real deployment URL produced in Phase B, Task B5. Until then this is the agreed placeholder hostname.)

- [ ] **Step 4: Run the test, confirm pass**

Run: `cd cli && npm run build && node --test dist/tests/config.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cli/src/config/sentinel.config.ts cli/tests/config.test.ts
git commit -m "feat(cli): default apiUrl to hosted backend"
```

---

### Task A2: `ensureBackend` — don't spawn for remote, run worker via Docker for local

**Files:**
- Modify: `cli/src/backend/ensure.ts`
- Test: `cli/tests/ensure.test.ts` (create)

Today `ensureBackend` health-checks `apiUrl`; if unhealthy and localhost, it spawns `uvicorn` + the Python worker. With a hosted default, scanning commands must (a) confirm the cloud API is reachable, and (b) ensure a **local worker** is running to process the user's jobs. The worker now runs as a Docker container, not a spawned Python process.

- [ ] **Step 1: Write the failing test**

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { workerDockerArgs } from "../src/backend/ensure.js";

test("workerDockerArgs wires Neon + LLM env into the container", () => {
  const argv = workerDockerArgs({
    image: "ghcr.io/sentineldev/sentinel-worker:latest",
    databaseUrl: "postgresql+asyncpg://u:p@ep.neon.tech/db",
    accountId: "acct_123",
    anthropicKey: "sk-ant-xxx",
  });
  assert.ok(argv.includes("--rm"));
  assert.ok(argv.includes("ghcr.io/sentineldev/sentinel-worker:latest"));
  assert.ok(argv.some((a) => a.startsWith("DATABASE_URL=")));
  assert.ok(argv.some((a) => a === "SENTINEL_ACCOUNT_ID=acct_123"));
  assert.ok(argv.some((a) => a === "ANTHROPIC_API_KEY=sk-ant-xxx"));
});
```

- [ ] **Step 2: Run it, confirm failure**

Run: `cd cli && npm run build && node --test dist/tests/ensure.test.js`
Expected: FAIL — `workerDockerArgs` not exported.

- [ ] **Step 3: Implement `workerDockerArgs` and rework `ensureBackend`**

In `cli/src/backend/ensure.ts`, add:

```ts
export function workerDockerArgs(opts: {
  image: string;
  databaseUrl: string;
  accountId: string;
  anthropicKey?: string;
  openaiKey?: string;
}): string[] {
  const env: string[] = [
    `DATABASE_URL=${opts.databaseUrl}`,
    `SENTINEL_ACCOUNT_ID=${opts.accountId}`,
    `SENTINEL_WORKER_ID=local-${opts.accountId}`,
  ];
  if (opts.anthropicKey) env.push(`ANTHROPIC_API_KEY=${opts.anthropicKey}`);
  if (opts.openaiKey) env.push(`OPENAI_API_KEY=${opts.openaiKey}`);
  const argv = ["run", "--rm", "--name", "sentinel-worker", "-d"];
  for (const e of env) argv.push("-e", e);
  argv.push(opts.image);
  return argv;
}
```

Then change `ensureBackend` so that for a **remote** (non-localhost) `apiUrl` it (1) calls `isHealthy(apiUrl)` and throws a clear error if the cloud API is unreachable, and (2) starts the local worker container if not already running:

```ts
export async function ensureBackend(apiUrl: string): Promise<void> {
  if (!isLocalhost(apiUrl)) {
    if (!(await isHealthy(apiUrl, 4000))) {
      throw new Error(
        `Cannot reach Sentinel cloud backend at ${apiUrl}. ` +
          `Check your network or run \`sentinel config set apiUrl <url>\`.`
      );
    }
    await ensureWorkerContainer(apiUrl);
    return;
  }
  // localhost path unchanged (existing startBackend logic)
  if (await isHealthy(apiUrl)) return;
  console.log("Backend not running. Starting...");
  await startBackend(apiUrl);
  console.log("Backend ready.");
}
```

Implement `ensureWorkerContainer(apiUrl)`: it reads the Neon URL + account id + LLM key from config/keychain (added in Phase B login flow), checks `docker ps --filter name=sentinel-worker` for an existing container, and if absent runs `spawn("docker", workerDockerArgs({...}))`. If `docker` is not found, throw: `"Docker is required to run scans locally. Install Docker Desktop, or set apiUrl to a backend that runs its own worker."`

> Note for implementer: `ensureWorkerContainer` needs the Neon URL and account id. These are stored at login (Phase B, Task B3). If not yet present, throw `"Run \`sentinel auth login\` first."`. Keep `ensureWorkerContainer` reading from the same keychain/config helpers used elsewhere.

- [ ] **Step 4: Run the test, confirm pass**

Run: `cd cli && npm run build && node --test dist/tests/ensure.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cli/src/backend/ensure.ts cli/tests/ensure.test.ts
git commit -m "feat(cli): run local worker via Docker; verify reachability for remote backend"
```

---

### Task A3: Switch `runEvents` from SSE to polling

**Files:**
- Modify: `cli/src/api/client.ts:318-375`
- Test: `cli/tests/client-poll.test.ts` (create)

- [ ] **Step 1: Write the failing test** — stub `fetch` to return two `/runs/{id}` snapshots (running then completed) and assert `runEvents` yields the new trace lines and stops at terminal status:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { SentinelApiClient } from "../src/api/client.js";

test("runEvents polls run trace until terminal", async () => {
  const snapshots = [
    { id: "r1", status: "running", trace: "task.queued\ntask.claimed" },
    { id: "r1", status: "completed", trace: "task.queued\ntask.claimed\ntask.completed" },
  ];
  let call = 0;
  globalThis.fetch = (async () => ({
    ok: true,
    status: 200,
    json: async () => snapshots[Math.min(call++, snapshots.length - 1)],
  })) as unknown as typeof fetch;

  const client = new SentinelApiClient({ apiUrl: "https://x", repoName: "d" } as any);
  const seen: string[] = [];
  for await (const line of client.runEvents("r1", 5000)) seen.push(line);
  assert.deepEqual(seen, ["task.queued", "task.claimed", "task.completed"]);
});
```

- [ ] **Step 2: Run, confirm failure**

Run: `cd cli && npm run build && node --test dist/tests/client-poll.test.js`
Expected: FAIL — current `runEvents` hits the streaming `/events` endpoint.

- [ ] **Step 3: Reimplement `runEvents` as a poller** — replace lines 318-375 with a loop that GETs `/runs/${id}` every ~1s, diffs `trace` against the last emitted line set, yields new non-empty lines, and returns when `status` is one of `completed|failed|cancelled` or the wall-clock `timeoutMs` elapses:

```ts
  async *runEvents(id: string, timeoutMs = 120_000): AsyncGenerator<string> {
    const deadline = Date.now() + timeoutMs;
    const emitted = new Set<string>();
    const terminal = new Set(["completed", "failed", "cancelled"]);
    while (Date.now() < deadline) {
      const run = await this.run(id); // existing GET /runs/{id}
      for (const line of (run.trace ?? "").split("\n")) {
        const t = line.trim();
        if (t && !emitted.has(t)) {
          emitted.add(t);
          yield t;
        }
      }
      if (terminal.has(run.status)) return;
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
```

(Confirm `this.run(id)` returns an object with `status` and `trace`; it is already used at `index.ts` line 129. If its type lacks `trace`, widen the response type.)

- [ ] **Step 4: Run, confirm pass**

Run: `cd cli && npm run build && node --test dist/tests/client-poll.test.js`
Expected: PASS.

- [ ] **Step 5: Remove now-dead SSE plumbing** — delete the `eventsource` dependency from `cli/package.json` if unused elsewhere (`grep -rn eventsource cli/src`), and run the full CLI test suite:

Run: `cd cli && npm run build && node --test dist/tests/*.test.js`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add cli/src/api/client.ts cli/package.json cli/tests/client-poll.test.js
git commit -m "feat(cli): poll run trace instead of SSE for serverless compatibility"
```

---

### Task A4: Bun compile driver — build standalone binaries

**Files:**
- Create: `cli/build.ts`
- Modify: `cli/package.json` (add `build:binaries` script; mark `keytar` external)
- Test: `cli/tests/build.test.ts` (create)

Bun compiles the ESM/TS CLI into a single executable per target. `keytar` is native and cannot be embedded — mark it external so Bun's loader treats the dynamic `import("keytar")` as a runtime-optional that fails gracefully into the existing file fallback.

- [ ] **Step 1: Write the failing test** — assert the target matrix is correct:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { BUILD_TARGETS } from "../build.js";

test("build targets cover mac + linux on both arches", () => {
  const triples = BUILD_TARGETS.map((t) => t.bunTarget);
  assert.deepEqual(new Set(triples), new Set([
    "bun-darwin-arm64",
    "bun-darwin-x64",
    "bun-linux-x64",
    "bun-linux-arm64",
  ]));
});
```

- [ ] **Step 2: Run, confirm failure**

Run: `cd cli && bun build.ts --list` (expect module/exports missing → FAIL). If Bun is unavailable in the dev env, run `node --test` against a compiled `build.js`; the test only inspects the exported constant.

- [ ] **Step 3: Implement `cli/build.ts`**

```ts
// Bun build driver: produces ./binaries/sentinel-<os>-<arch>
import { mkdir } from "node:fs/promises";

export const BUILD_TARGETS = [
  { bunTarget: "bun-darwin-arm64", asset: "sentinel-darwin-arm64" },
  { bunTarget: "bun-darwin-x64", asset: "sentinel-darwin-x64" },
  { bunTarget: "bun-linux-x64", asset: "sentinel-linux-x64" },
  { bunTarget: "bun-linux-arm64", asset: "sentinel-linux-arm64" },
] as const;

if (import.meta.main) {
  await mkdir("binaries", { recursive: true });
  for (const t of BUILD_TARGETS) {
    const proc = Bun.spawnSync([
      "bun", "build", "src/index.ts",
      "--compile",
      "--target", t.bunTarget,
      "--external", "keytar",
      "--outfile", `binaries/${t.asset}`,
    ], { stdout: "inherit", stderr: "inherit" });
    if (proc.exitCode !== 0) throw new Error(`build failed for ${t.bunTarget}`);
  }
}
```

Add to `cli/package.json` scripts: `"build:binaries": "bun build.ts"`.

- [ ] **Step 4: Build for the host platform and smoke-test**

Run:
```bash
cd cli && bun build.ts
./binaries/sentinel-$(uname -s | tr 'A-Z' 'a-z')-$(uname -m | sed 's/x86_64/x64/;s/aarch64/arm64/') --version
```
Expected: prints `0.1.0`.

- [ ] **Step 5: Commit** (binaries are build artifacts — gitignore them)

```bash
echo "cli/binaries/" >> .gitignore
git add cli/build.ts cli/package.json cli/tests/build.test.ts .gitignore
git commit -m "build(cli): compile standalone per-platform binaries with Bun"
```

---

### Task A5: `install.sh` — the curl entrypoint

**Files:**
- Create: `install.sh` (repo root)
- Test: `cli/tests/install.test.ts` (create — shells out to `bash` with a stubbed `curl`)

Mirrors Claude's installer: detect OS/arch, download the matching binary from the GitHub Releases `latest` tag, verify SHA-256, install to `${SENTINEL_INSTALL_DIR:-$HOME/.local/bin}/sentinel`, `chmod +x`, and print a PATH hint if needed.

- [ ] **Step 1: Write the failing test** — invoke `install.sh` with `SENTINEL_NO_DOWNLOAD=1` (a dry-run flag the script supports) and assert it resolves the right asset name for a faked platform:

```ts
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

test("install.sh resolves the darwin-arm64 asset in dry-run", () => {
  const out = execFileSync("bash", ["../install.sh"], {
    env: { ...process.env, SENTINEL_NO_DOWNLOAD: "1", SENTINEL_FAKE_UNAME: "Darwin arm64" },
    encoding: "utf8",
  });
  assert.match(out, /sentinel-darwin-arm64/);
});
```

- [ ] **Step 2: Run, confirm failure**

Run: `cd cli && node --test dist/tests/install.test.js` (or `node --test` after build)
Expected: FAIL — `install.sh` does not exist.

- [ ] **Step 3: Write `install.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail

REPO="sentineldev/sentinel"
INSTALL_DIR="${SENTINEL_INSTALL_DIR:-$HOME/.local/bin}"
BIN="$INSTALL_DIR/sentinel"

detect_platform() {
  local uname_out="${SENTINEL_FAKE_UNAME:-$(uname -s) $(uname -m)}"
  local os arch
  case "$uname_out" in
    Darwin*) os="darwin" ;;
    Linux*)  os="linux" ;;
    *) echo "Unsupported OS: $uname_out" >&2; exit 1 ;;
  esac
  case "$uname_out" in
    *arm64*|*aarch64*) arch="arm64" ;;
    *x86_64*|*x64*)    arch="x64" ;;
    *) echo "Unsupported arch: $uname_out" >&2; exit 1 ;;
  esac
  echo "sentinel-${os}-${arch}"
}

main() {
  local asset url
  asset="$(detect_platform)"
  url="https://github.com/${REPO}/releases/latest/download/${asset}"
  echo "Installing Sentinel ($asset)…"
  echo "  from: $url"

  if [ "${SENTINEL_NO_DOWNLOAD:-0}" = "1" ]; then
    echo "[dry-run] would download $asset to $BIN"
    return 0
  fi

  mkdir -p "$INSTALL_DIR"
  curl -fsSL "$url" -o "$BIN.tmp"
  curl -fsSL "$url.sha256" -o "$BIN.sha256" || true
  if [ -f "$BIN.sha256" ]; then
    (cd "$INSTALL_DIR" && shasum -a 256 -c "$(basename "$BIN").sha256" 2>/dev/null) \
      || { echo "Checksum verification failed" >&2; exit 1; }
    rm -f "$BIN.sha256"
  fi
  mv "$BIN.tmp" "$BIN"
  chmod +x "$BIN"
  echo "Installed to $BIN"

  case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) echo; echo "Add to PATH:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
  esac
  echo "Run: sentinel --help"
}

main "$@"
```

- [ ] **Step 4: Run, confirm pass**

Run: `cd cli && node --test dist/tests/install.test.js`
Expected: PASS — output contains `sentinel-darwin-arm64`.

- [ ] **Step 5: Commit**

```bash
git add install.sh cli/tests/install.test.ts
git commit -m "feat: add curl-pipe install.sh installer"
```

---

### Task A6: Release pipeline (GitHub Actions)

**Files:**
- Create: `.github/workflows/release.yml`

On a `v*` tag push: install Bun, build all four binaries, generate `.sha256` sidecars, and publish a GitHub Release with the binaries + checksums attached. This makes `releases/latest/download/<asset>` (used by `install.sh`) resolve.

- [ ] **Step 1: Write the workflow**

```yaml
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
jobs:
  build-cli:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v2
        with: { bun-version: latest }
      - name: Build binaries
        working-directory: cli
        run: |
          bun install
          bun build.ts
      - name: Checksums
        working-directory: cli/binaries
        run: for f in sentinel-*; do shasum -a 256 "$f" > "$f.sha256"; done
      - name: Release
        uses: softprops/action-gh-release@v2
        with:
          files: cli/binaries/*
```

- [ ] **Step 2: Validate locally** — lint the YAML and confirm the build step matches Task A4:

Run: `python3 -c "import yaml,sys; yaml.safe_load(open('.github/workflows/release.yml'))" && echo OK`
Expected: `OK`.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: build and release CLI binaries on tag"
```

> Manual verification (post-merge, not a code step): push a tag `v0.1.0`, confirm the release has all four binaries + `.sha256`, then run the real curl command on a clean machine.

---

## Phase B — Costless Cloud Backend (Vercel + Neon)

### Task B1: Make heavy API endpoints enqueue-only

**Files:**
- Modify: `api/src/sentinel_api/main.py` (the `/source`, `/init`, `/plan`, `/pentest` handlers around lines 347-460, 737)
- Test: `api/tests/test_enqueue_only.py` (create)

The cloud must not run `scan_diff`/`run_pentest`/`review_plan` in-process. Each heavy endpoint should enqueue a task and return the `Run`/`EnqueueResponse`, identical to the existing `/source/enqueue` path. The local worker does the work.

- [ ] **Step 1: Write the failing test** — POST `/source` and assert it returns a queued run without invoking the scanner. Use the existing test client/fixtures in `api/tests/conftest.py`; monkeypatch `scan_diff` to raise if called:

```python
import pytest

async def test_source_endpoint_enqueues_not_runs(client, monkeypatch):
    import sentinel_worker.scan as scan
    monkeypatch.setattr(scan, "scan_diff", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran inline")))
    resp = await client.post("/source", json={"repo_name": "demo", "diff": "diff --git a b"})
    assert resp.status_code == 200
    assert resp.json()["run"]["status"] in ("queued", "running")
```

- [ ] **Step 2: Run, confirm failure**

Run: `cd api && python -m pytest tests/test_enqueue_only.py -v`
Expected: FAIL — current `/source` calls `scan_diff` inline.

- [ ] **Step 3: Rewrite the handlers to enqueue** — in `main.py`, change the `/source`, `/init`, `/plan`, `/pentest` handlers to call `enqueue_task(db, repo_name=..., kind="source|init|plan|pentest", payload=...)` (already imported) and return the run, mirroring `/source/enqueue` (lines 382-398). Remove the direct `scan_diff`/`review_plan`/`run_pentest` calls and their imports if no longer used anywhere in the file.

- [ ] **Step 4: Run, confirm pass + full API suite**

Run: `cd api && python -m pytest -v`
Expected: PASS (update any existing tests that asserted inline behavior; note the change in the commit).

- [ ] **Step 5: Commit**

```bash
git add api/src/sentinel_api/main.py api/tests/test_enqueue_only.py
git commit -m "refactor(api): make scan/pentest/plan endpoints enqueue-only for serverless"
```

---

### Task B2: Account-scoped task claiming

**Files:**
- Modify: `worker/src/sentinel_worker/task_queue.py` (`claim_next_task` + `_claimable_task_stmt`)
- Modify: `worker/src/sentinel_worker/worker_main.py` (pass account id)
- Test: `worker/tests/test_claim_scope.py` (create)

A local worker must only claim its own account's tasks.

- [ ] **Step 1: Write the failing test** — enqueue tasks for accounts A and B; a worker scoped to A claims only A's task:

```python
async def test_claim_scoped_to_account(session):
    from sentinel_worker.task_queue import enqueue_task, claim_next_task
    await enqueue_task(session, repo_name="ra", kind="source", payload={}, account_id="A")
    await enqueue_task(session, repo_name="rb", kind="source", payload={}, account_id="B")
    claimed = await claim_next_task(session, worker_id="w", account_id="A")
    assert claimed is not None and claimed.task.account_id == "A"
```

- [ ] **Step 2: Run, confirm failure**

Run: `cd worker && python -m pytest tests/test_claim_scope.py -v`
Expected: FAIL — `claim_next_task` has no `account_id` parameter.

- [ ] **Step 3: Add the scope** — give `claim_next_task` and `_claimable_task_stmt` an optional `account_id: str | None = None`; when set, add `.where(Task.account_id == account_id)` to the select. In `worker_main.py`, read `SENTINEL_ACCOUNT_ID` from env and thread it into `run_one_task` → `claim_next_task`.

- [ ] **Step 4: Run, confirm pass**

Run: `cd worker && python -m pytest tests/test_claim_scope.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add worker/src/sentinel_worker/task_queue.py worker/src/sentinel_worker/worker_main.py worker/tests/test_claim_scope.py
git commit -m "feat(worker): scope task claiming to account id"
```

---

### Task B3: Login issues Neon connection + stores it locally

**Files:**
- Modify: `api/src/sentinel_api/main.py` (`/auth/device/token` response includes `database_url`)
- Modify: `api/src/sentinel_api/schemas.py` (`DeviceTokenResponse` add `database_url`, `account_id`)
- Modify: `cli/src/index.ts` (auth login action ~lines 24-50) + `cli/src/auth/keychain.ts` (store db url)
- Test: `api/tests/test_auth.py` (extend)

For the local worker to reach Neon, the CLI must learn the connection string at login. The cloud API returns the Neon URL (read from its own `DATABASE_URL` env, optionally a read/write-scoped role) alongside the token.

- [ ] **Step 1: Write the failing test** (API) — approved device token response carries `database_url` and `account_id`:

```python
async def test_device_token_includes_database_url(client, monkeypatch):
    monkeypatch.setenv("SENTINEL_WORKER_DATABASE_URL", "postgresql+asyncpg://u:p@ep.neon.tech/db")
    # ... start + approve device flow via existing helpers ...
    token = await client.get("/auth/device/token", params={"device_code": code})
    body = token.json()
    assert body["status"] == "approved"
    assert body["database_url"].startswith("postgresql")
    assert body["account_id"]
```

- [ ] **Step 2: Run, confirm failure**

Run: `cd api && python -m pytest tests/test_auth.py -k database_url -v`
Expected: FAIL.

- [ ] **Step 3: Implement** — add `database_url: str | None` and `account_id: str | None` to `DeviceTokenResponse`; in the `/auth/device/token` handler, on approval set `database_url=os.getenv("SENTINEL_WORKER_DATABASE_URL")` and the principal's `account_id`. In the CLI `auth login` action, after `writeApiKey`, also persist the returned `database_url` + `account_id` via new keychain helpers `writeWorkerConn(config, {databaseUrl, accountId})` (file store, mode 600). `ensureWorkerContainer` (Task A2) reads these.

- [ ] **Step 4: Run, confirm pass**

Run: `cd api && python -m pytest tests/test_auth.py -v` then `cd cli && npm run build && node --test dist/tests/*.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/src/sentinel_api/main.py api/src/sentinel_api/schemas.py cli/src/index.ts cli/src/auth/keychain.ts api/tests/test_auth.py
git commit -m "feat: issue worker DB connection to CLI at login"
```

---

### Task B4: Worker Docker image + GHCR publish

**Files:**
- Create: `worker/Dockerfile`
- Modify: `.github/workflows/release.yml` (add a `build-worker` job)

- [ ] **Step 1: Write `worker/Dockerfile`**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY worker /app/worker
RUN pip install --no-cache-dir -e /app/worker
ENV PYTHONPATH=/app/worker/src
CMD ["sentinel-worker"]
```

- [ ] **Step 2: Build locally, confirm it starts and exits cleanly without a DB**

Run:
```bash
docker build -f worker/Dockerfile -t sentinel-worker:dev .
docker run --rm sentinel-worker:dev python -c "import sentinel_worker.worker_main; print('ok')"
```
Expected: prints `ok`.

- [ ] **Step 3: Add GHCR publish job** to `.github/workflows/release.yml`:

```yaml
  build-worker:
    runs-on: ubuntu-latest
    permissions: { contents: read, packages: write }
    steps:
      - uses: actions/checkout@v4
      - uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}
      - uses: docker/build-push-action@v6
        with:
          context: .
          file: worker/Dockerfile
          push: true
          tags: |
            ghcr.io/sentineldev/sentinel-worker:latest
            ghcr.io/sentineldev/sentinel-worker:${{ github.ref_name }}
```

- [ ] **Step 4: Commit**

```bash
git add worker/Dockerfile .github/workflows/release.yml
git commit -m "build(worker): publish worker image to GHCR on release"
```

---

### Task B5: Vercel deployment of API + dashboard, Neon Postgres

**Files:**
- Create: `api/index.py` (Vercel ASGI entrypoint)
- Create: `api/requirements.txt`
- Create: `vercel.json` (repo root)
- Create: `docs/DEPLOY.md`

The API ships as a Vercel Python serverless function exposing the existing FastAPI ASGI app; the dashboard ships as the existing Next.js project. Neon provides Postgres.

- [ ] **Step 1: Create the ASGI entrypoint** `api/index.py`:

```python
# Vercel Python serverless entrypoint — exposes the FastAPI ASGI app.
from sentinel_api.main import app  # noqa: F401
```

- [ ] **Step 2: Pin runtime deps** `api/requirements.txt` — mirror `api/pyproject.toml` + the lightweight subset of `worker` the API imports (models, task_queue, scan signatures). Generate and verify it imports without tree-sitter at module load:

```
fastapi>=0.111,<1
uvicorn[standard]>=0.30,<1
pydantic>=2,<3
python-jose[cryptography]>=3.3,<4
sqlalchemy>=2,<3
asyncpg>=0.29,<1
aiosqlite>=0.20,<1
structlog>=25,<26
prometheus-client>=0.20,<1
```

> If `sentinel_api.main` imports modules that pull in `tree_sitter`/`anthropic` at import time (e.g. via `sentinel_worker.scan`), make those imports lazy (import inside the worker-only functions) so the serverless cold start stays light. Verify with: `cd api && python -c "import sentinel_api.main"` in a venv that has ONLY `requirements.txt` installed — it must succeed.

- [ ] **Step 3: `vercel.json`** routing API under `/` (functions) and building the dashboard:

```json
{
  "functions": { "api/index.py": { "runtime": "@vercel/python@4.3.0" } },
  "rewrites": [{ "source": "/(.*)", "destination": "/api/index" }]
}
```

> The dashboard is a separate Vercel project (its own `dashboard/` root) to keep concerns clean; or use a monorepo project per `vercel.json` build settings. `docs/DEPLOY.md` documents both projects.

- [ ] **Step 4: Provision Neon + env** — document in `docs/DEPLOY.md`:
  - Create a free Neon project; copy the pooled connection string.
  - Set Vercel env on the API project: `DATABASE_URL` (Neon, `postgresql+asyncpg://…`), `SENTINEL_WORKER_DATABASE_URL` (same or a scoped role), `SENTINEL_JWT_SECRET`, `SENTINEL_DEV_MODE=0`, `CORS_ORIGINS=<dashboard url>`.
  - Run migrations once against Neon: `DATABASE_URL=… python -m sentinel_worker.migrations` (or the worker's `apply_migrations` invoked by the first local worker run).
  - Set dashboard env: `NEXT_PUBLIC_SENTINEL_API_URL=<api url>`.

- [ ] **Step 5: Deploy and capture the URL**

Run:
```bash
vercel --prod    # API project
```
Record the production URL and **back-fill it into `cli/src/config/sentinel.config.ts` (Task A1) and `sentinel.config.json.example`**.

- [ ] **Step 6: Smoke-test the live API**

Run: `curl -fsSL https://<your-api>.vercel.app/health`
Expected: `200` with health JSON.

- [ ] **Step 7: Commit**

```bash
git add api/index.py api/requirements.txt vercel.json docs/DEPLOY.md
git commit -m "feat: deploy API to Vercel serverless + Neon, document deploy"
```

---

## Phase C — Docs & Config

### Task C1: README + example config for the curl install

**Files:**
- Modify: `README.md` (add a top-of-file Quickstart), `sentinel.config.json.example`

- [ ] **Step 1: Add Quickstart to `README.md`** directly under the intro:

```markdown
## Install

```bash
curl -fsSL https://raw.githubusercontent.com/sentineldev/sentinel/main/install.sh | bash
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
```

- [ ] **Step 2: Update `sentinel.config.json.example`** so `apiUrl` is the hosted URL and add a comment that local Docker runs the worker.

- [ ] **Step 3: Verify the curl command shape matches `install.sh`'s `REPO` + branch.**

Run: `grep -n "raw.githubusercontent.com/sentineldev/sentinel" README.md`
Expected: one match, branch `main`.

- [ ] **Step 4: Commit**

```bash
git add README.md sentinel.config.json.example
git commit -m "docs: curl install quickstart and hosted config defaults"
```

---

## Self-Review Notes

- **Spec coverage:** curl install (A5), Claude-like single binary (A4), hosted+costless backend (B5 Vercel free + Neon free, no LLM keys in cloud), heavy work local (A2 Docker worker, B1 enqueue-only, B2 account-scoped claims), commit at end of every task. ✅
- **Cross-task type consistency:** `workerDockerArgs` (A2) consumes `databaseUrl`/`accountId` issued by B3 and stored via keychain helpers; `BUILD_TARGETS` assets (A4) match `install.sh` `detect_platform` names (A5) and release upload (A6). `SENTINEL_WORKER_DATABASE_URL` is the cloud env (B5) surfaced through B3. ✅
- **Open risk flagged in Decision #5:** distributing a Neon connection string to local workers is acceptable for self-hosted-per-team v1; routing worker DB access through the API is a follow-up, intentionally out of scope.
- **Verification that needs real infra (call out, don't fake):** A6 release tag, B5 Vercel deploy + Neon migrations, end-to-end curl install on a clean machine. These are manual post-merge steps, noted as such.

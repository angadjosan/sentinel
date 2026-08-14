import { existsSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const SENTINEL_DIR = join(homedir(), ".sentinel");
const PID_DIR = join(SENTINEL_DIR, "pids");
const LOG_DIR = join(SENTINEL_DIR, "logs");
const WORKER_CONN_FILE = join(SENTINEL_DIR, "worker-conn.json");
const DASHBOARD_PORT = process.env.SENTINEL_DASHBOARD_PORT || "3000";
const DASHBOARD_URL = `http://localhost:${DASHBOARD_PORT}`;

function ensureDirs(): void {
  mkdirSync(PID_DIR, { recursive: true });
  mkdirSync(LOG_DIR, { recursive: true });
}

export async function isHealthy(apiUrl: string, timeoutMs = 500): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(`${apiUrl}/health`, { signal: controller.signal });
    return resp.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
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
    const raw = readFileSync(join(PID_DIR, `${name}.pid`), "utf8").trim();
    const pid = parseInt(raw, 10);
    if (!Number.isFinite(pid)) return null;
    process.kill(pid, 0);
    return pid;
  } catch {
    return null;
  }
}

function writePid(name: string, pid: number): void {
  writeFileSync(join(PID_DIR, `${name}.pid`), String(pid));
}

function removePid(name: string): void {
  try {
    unlinkSync(join(PID_DIR, `${name}.pid`));
  } catch {}
}

// ── Worker connection info (written at login; consumed by self-hosted worker setup) ──

export interface WorkerConn {
  databaseUrl: string;
  accountId: string;
  anthropicKey?: string;
  openaiKey?: string;
}

export function writeWorkerConn(conn: WorkerConn): void {
  mkdirSync(SENTINEL_DIR, { recursive: true });
  writeFileSync(WORKER_CONN_FILE, JSON.stringify(conn, null, 2), { mode: 0o600 });
}

export function readWorkerConn(): WorkerConn | null {
  try {
    return JSON.parse(readFileSync(WORKER_CONN_FILE, "utf8")) as WorkerConn;
  } catch {
    return null;
  }
}

// NOTE: There is no separate worker process anymore. The CLI runs SAST and
// pentest locally in-process (see local_engine.py / execute_full_pentest), and
// the backend is a results-only store. `sentinel up` spawns a local Python API
// and, when the dashboard source is resolvable, the Next.js dashboard too — no
// worker daemon, no Docker container image.

// ── Localhost spawning (self-hosted local dev via `sentinel up`) ────────────────

export function resolveVenvPython(): string {
  // Prefer explicit override, then walk up from cwd looking for a .venv.
  if (process.env.SENTINEL_PYTHON) return process.env.SENTINEL_PYTHON;
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = join(dir, ".venv", "bin", "python3");
    if (existsSync(candidate)) return candidate;
    const parent = join(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  return "python3"; // fall back to PATH
}

/**
 * Locate the Next.js dashboard source so `sentinel up` can launch the frontend.
 * Explicit `SENTINEL_DASHBOARD_DIR` wins; otherwise walk up from cwd looking for
 * a `dashboard/package.json` (a Sentinel source checkout / self-host). Returns
 * null when not found — the CLI then starts the API only (an npm-global install
 * doesn't ship the dashboard; use docker-compose for the full stack there).
 */
export function resolveDashboardDir(): string | null {
  const override = process.env.SENTINEL_DASHBOARD_DIR;
  if (override) return existsSync(join(override, "package.json")) ? override : null;
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = join(dir, "dashboard");
    if (existsSync(join(candidate, "package.json"))) return candidate;
    const parent = join(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/** True if something is serving HTTP at the given URL (any response counts). */
async function isPortResponding(url: string, timeoutMs = 500): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    await fetch(url, { signal: controller.signal });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

function startApi(apiUrl: string): void {
  const port = new URL(apiUrl).port || "8000";
  if (readPid("api")) return;
  const fd = openSync(join(LOG_DIR, "api.log"), "a");
  const apiProc = spawn(
    resolveVenvPython(),
    ["-m", "uvicorn", "sentinel_api.main:app", "--host", "0.0.0.0", "--port", port],
    { detached: true, stdio: ["ignore", fd, fd], env: { ...process.env, SENTINEL_DEV_MODE: "1" } }
  );
  apiProc.unref();
  if (apiProc.pid !== undefined) writePid("api", apiProc.pid);
}

/** Best-effort: launch the Next.js dashboard against the local API. Non-fatal —
 *  a missing/failed dashboard must never block the API-backed workflow. */
function startDashboard(apiUrl: string): "started" | "running" | "unavailable" {
  if (readPid("dashboard")) return "running";
  const dir = resolveDashboardDir();
  if (!dir) return "unavailable";
  const fd = openSync(join(LOG_DIR, "dashboard.log"), "a");
  const proc = spawn("npm", ["run", "dev"], {
    cwd: dir,
    detached: true,
    stdio: ["ignore", fd, fd],
    env: {
      ...process.env,
      PORT: DASHBOARD_PORT,
      NEXT_PUBLIC_SENTINEL_API_URL: apiUrl,
      SENTINEL_API_INTERNAL_URL: apiUrl,
      SENTINEL_DEV_MODE: "1",
    },
  });
  proc.unref();
  if (proc.pid !== undefined) writePid("dashboard", proc.pid);
  return "started";
}

export async function startBackend(apiUrl: string): Promise<void> {
  ensureDirs();
  const port = new URL(apiUrl).port || "8000";

  startApi(apiUrl);
  const dashboard = startDashboard(apiUrl);

  let apiReady = false;
  for (let i = 0; i < 16; i++) {
    if (await isHealthy(apiUrl, 500)) { apiReady = true; break; }
    await sleep(500);
  }
  if (!apiReady) {
    throw new Error(
      `Backend failed to start within 8s. Check logs: ${join(LOG_DIR, "api.log")}\n` +
      `You can also start it manually with: uvicorn sentinel_api.main:app --port ${port}`
    );
  }

  if (dashboard === "unavailable") {
    console.log(
      "Dashboard source not found — started the API only. " +
      "Run `sentinel up` from a Sentinel checkout, or set SENTINEL_DASHBOARD_DIR, to launch the dashboard too."
    );
  } else {
    // Give Next a moment; it compiles on first request, so don't fail if slow.
    for (let i = 0; i < 20; i++) {
      if (await isPortResponding(DASHBOARD_URL, 500)) break;
      await sleep(500);
    }
    console.log(`Dashboard: ${DASHBOARD_URL} (logs: ${join(LOG_DIR, "dashboard.log")})`);
  }
}

export async function stopBackend(): Promise<void> {
  for (const name of ["dashboard", "api"]) {
    const pid = readPid(name);
    if (pid) {
      try {
        process.kill(pid, "SIGTERM");
      } catch {}
      removePid(name);
    }
  }
}

export async function backendStatus(
  apiUrl: string
): Promise<{ api: string; dashboard: string; healthy: boolean }> {
  const apiPid = readPid("api");
  const dashPid = readPid("dashboard");
  const healthy = await isHealthy(apiUrl);
  return {
    api: apiPid ? `running (PID ${apiPid})` : "stopped",
    dashboard: dashPid ? `running (PID ${dashPid}) at ${DASHBOARD_URL}` : "stopped",
    healthy,
  };
}

export async function ensureBackend(apiUrl: string): Promise<void> {
  if (!isLocalhost(apiUrl)) {
    // Remote (cloud) backend: just verify reachability. It is a results-only
    // store — scans and pentests run locally in the CLI, so there is no remote
    // worker or task processing to wait on.
    for (let attempt = 0; attempt < 3; attempt++) {
      if (await isHealthy(apiUrl, 8000)) return;
    }
    throw new Error(
      `Cannot reach Sentinel cloud backend at ${apiUrl}. ` +
        `Check your network or run \`sentinel config set apiUrl <url>\`.`
    );
  }
  // Localhost path: spawn API + worker via Python (self-hosted dev)
  if (await isHealthy(apiUrl)) return;
  console.log("Backend not running. Starting...");
  await startBackend(apiUrl);
  console.log("Backend ready.");
}

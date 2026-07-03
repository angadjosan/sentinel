import { existsSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const SENTINEL_DIR = join(homedir(), ".sentinel");
const PID_DIR = join(SENTINEL_DIR, "pids");
const LOG_DIR = join(SENTINEL_DIR, "logs");
const WORKER_CONN_FILE = join(SENTINEL_DIR, "worker-conn.json");

const WORKER_IMAGE = "ghcr.io/sentineldev/sentinel-worker:latest";
const WORKER_CONTAINER_NAME = "sentinel-worker";

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

// ── Worker connection info (written at login, read by ensureWorkerContainer) ──

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

// ── Docker worker ─────────────────────────────────────────────────────────────

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
  const argv = ["run", "--rm", `--name=${WORKER_CONTAINER_NAME}`, "-d"];
  for (const e of env) argv.push("-e", e);
  argv.push(opts.image);
  return argv;
}

function isWorkerContainerRunning(): boolean {
  const result = spawnSync("docker", [
    "ps", "--filter", `name=${WORKER_CONTAINER_NAME}`, "--format", "{{.Names}}",
  ], { encoding: "utf8" });
  return result.stdout?.includes(WORKER_CONTAINER_NAME) ?? false;
}

async function ensureWorkerContainer(): Promise<void> {
  if (isWorkerContainerRunning()) return;

  const conn = readWorkerConn();
  if (!conn) {
    throw new Error('Run `sentinel auth login` first to configure your worker connection.');
  }

  const dockerResult = spawnSync("docker", ["version"], { encoding: "utf8" });
  if (dockerResult.error || dockerResult.status !== 0) {
    throw new Error(
      "Docker is required to run scans locally. " +
        "Install Docker Desktop, or set apiUrl to a backend that runs its own worker."
    );
  }

  const argv = workerDockerArgs({
    image: WORKER_IMAGE,
    databaseUrl: conn.databaseUrl,
    accountId: conn.accountId,
    anthropicKey: conn.anthropicKey,
    openaiKey: conn.openaiKey,
  });
  const proc = spawnSync("docker", argv, { encoding: "utf8" });
  if (proc.status !== 0) {
    throw new Error(`Failed to start worker container: ${proc.stderr}`);
  }
}

// ── Legacy localhost spawning (kept for self-hosted local dev) ─────────────────

function resolveVenvPython(): string {
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

export async function startBackend(apiUrl: string): Promise<void> {
  ensureDirs();
  const port = new URL(apiUrl).port || "8000";
  const pythonBin = resolveVenvPython();

  if (!readPid("api")) {
    const fd = openSync(join(LOG_DIR, "api.log"), "a");
    const apiProc = spawn(
      pythonBin,
      ["-m", "uvicorn", "sentinel_api.main:app", "--host", "0.0.0.0", "--port", port],
      {
        detached: true,
        stdio: ["ignore", fd, fd],
        env: { ...process.env, SENTINEL_DEV_MODE: "1" },
      }
    );
    apiProc.unref();
    if (apiProc.pid !== undefined) {
      writePid("api", apiProc.pid);
    }
  }

  if (!readPid("worker")) {
    const fd = openSync(join(LOG_DIR, "worker.log"), "a");
    const workerProc = spawn(
      pythonBin,
      ["-m", "sentinel_worker.worker_main"],
      {
        detached: true,
        stdio: ["ignore", fd, fd],
        env: { ...process.env },
      }
    );
    workerProc.unref();
    if (workerProc.pid !== undefined) {
      writePid("worker", workerProc.pid);
    }
  }

  for (let i = 0; i < 16; i++) {
    if (await isHealthy(apiUrl, 500)) return;
    await sleep(500);
  }
  throw new Error(
    `Backend failed to start within 8s. Check logs: ${join(LOG_DIR, "api.log")}\n` +
    `You can also start it manually with: uvicorn sentinel_api.main:app --port ${port}`
  );
}

export async function stopBackend(): Promise<void> {
  for (const name of ["api", "worker"]) {
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
): Promise<{ api: string; worker: string; healthy: boolean }> {
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
  if (!isLocalhost(apiUrl)) {
    // Remote (cloud) backend: just verify reachability. The hosted worker on Railway
    // handles task processing — no local Docker container needed.
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

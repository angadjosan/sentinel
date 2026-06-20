import { mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const SENTINEL_DIR = join(homedir(), ".sentinel");
const PID_DIR = join(SENTINEL_DIR, "pids");
const LOG_DIR = join(SENTINEL_DIR, "logs");

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
    // Verify the process is still alive
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

export async function startBackend(apiUrl: string): Promise<void> {
  ensureDirs();
  const port = new URL(apiUrl).port || "8000";
  const pythonBin = process.env.SENTINEL_PYTHON ?? "python3";

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

  // Poll /health until ready (max ~8s)
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

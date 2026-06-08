import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import type { SentinelConfig } from "../config/sentinel.config.js";

const SERVICE = "sentinel";

type KeytarModule = {
  getPassword(service: string, account: string): Promise<string | null>;
  setPassword(service: string, account: string, password: string): Promise<void>;
};

function accountName(config: SentinelConfig): string {
  return `${config.apiUrl}:${config.repoName}`;
}

// ── File-based fallback ───────────────────────────────────────────────────────
// Used when the system keychain (keytar) is unavailable or its native bindings
// are not functional. Tokens are stored in ~/.sentinel/keychain.json (mode 600).

function fallbackPath(): string {
  return join(homedir(), ".sentinel", "keychain.json");
}

function readFallback(): Record<string, string> {
  try {
    return JSON.parse(readFileSync(fallbackPath(), "utf8")) as Record<string, string>;
  } catch {
    return {};
  }
}

function writeFallback(data: Record<string, string>): void {
  const dir = join(homedir(), ".sentinel");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(fallbackPath(), JSON.stringify(data), { mode: 0o600 });
}

function fallbackKey(service: string, account: string): string {
  return `${service}:${account}`;
}

// ── Keytar loader ─────────────────────────────────────────────────────────────

async function loadKeytar(): Promise<KeytarModule | null> {
  try {
    const mod = await import("keytar") as KeytarModule;
    // Verify native bindings are actually functional before trusting the module.
    if (typeof mod.setPassword !== "function" || typeof mod.getPassword !== "function") {
      return null;
    }
    return mod;
  } catch {
    return null;
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

export async function readApiKey(config: SentinelConfig): Promise<string | undefined> {
  if (process.env.SENTINEL_API_TOKEN) return process.env.SENTINEL_API_TOKEN;
  const key = accountName(config);
  try {
    const keytar = await loadKeytar();
    if (keytar) {
      const value = await keytar.getPassword(SERVICE, key);
      if (value) return value;
    }
  } catch {
    // fall through to file fallback
  }
  return readFallback()[fallbackKey(SERVICE, key)] ?? undefined;
}

export async function writeApiKey(config: SentinelConfig, apiKey: string): Promise<void> {
  const key = accountName(config);
  try {
    const keytar = await loadKeytar();
    if (keytar) {
      await keytar.setPassword(SERVICE, key, apiKey);
      return;
    }
  } catch {
    // fall through to file fallback
  }
  const data = readFallback();
  data[fallbackKey(SERVICE, key)] = apiKey;
  writeFallback(data);
}

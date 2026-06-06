import type { SentinelConfig } from "../config/sentinel.config.js";

const SERVICE = "sentinel";

type KeytarModule = {
  getPassword(service: string, account: string): Promise<string | null>;
  setPassword(service: string, account: string, password: string): Promise<void>;
};

function accountName(config: SentinelConfig): string {
  return `${config.apiUrl}:${config.repoName}`;
}

async function loadKeytar(): Promise<KeytarModule> {
  try {
    return await import("keytar");
  } catch (error) {
    throw new Error("keytar is not installed or the system keychain is unavailable.");
  }
}

export async function readApiKey(config: SentinelConfig): Promise<string | undefined> {
  if (process.env.SENTINEL_API_TOKEN) return process.env.SENTINEL_API_TOKEN;
  try {
    const keytar = await loadKeytar();
    return (await keytar.getPassword(SERVICE, accountName(config))) ?? undefined;
  } catch {
    return undefined;
  }
}

export async function writeApiKey(config: SentinelConfig, apiKey: string): Promise<void> {
  const keytar = await loadKeytar();
  await keytar.setPassword(SERVICE, accountName(config), apiKey);
}

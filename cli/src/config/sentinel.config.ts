import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { z } from "zod";

export const ConfigSchema = z.object({
  apiUrl: z.string().url().default("http://localhost:8000"),
  repoName: z.string().min(1),
  provider: z.string().default("local"),
  model: z.string().default("ollama"),
  boot: z.string().optional(),
  healthcheck: z.string().optional(),
  env: z.object({ from: z.string() }).optional(),
  variants: z.record(z.object({ build: z.string(), requires: z.string().optional() })).default({})
});

export type SentinelConfig = z.infer<typeof ConfigSchema>;

export function findRepoRoot(start = process.cwd()): string {
  let current = resolve(start);
  while (true) {
    if (existsSync(join(current, ".git")) || existsSync(join(current, "sentinel.config.json"))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) return resolve(start);
    current = parent;
  }
}

export function configPath(root = findRepoRoot()): string {
  return join(root, "sentinel.config.json");
}

export function loadConfig(root = findRepoRoot()): SentinelConfig {
  const path = configPath(root);
  if (!existsSync(path)) {
    throw new Error("sentinel.config.json not found. Run `sentinel init` first.");
  }
  return ConfigSchema.parse(JSON.parse(readFileSync(path, "utf8")));
}

export function writeConfig(config: SentinelConfig, root = findRepoRoot()): void {
  writeFileSync(configPath(root), `${JSON.stringify(config, null, 2)}\n`);
}

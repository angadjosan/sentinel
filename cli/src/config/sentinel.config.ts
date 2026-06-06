import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { z } from "zod";

const SAFE_COMMAND_RE = /^[A-Za-z0-9_./:@%+=,\-\s]+$/;

const VariantSchema = z.object({
  build: z.string(),
  requires: z.string().optional()
});

export const ConfigSchema = z.object({
  $schema: z.string().optional(),
  repo_id: z.string().optional(),
  api_endpoint: z.string().url().optional(),
  apiUrl: z.string().url().default("http://localhost:8000"),
  repoName: z.string().min(1),
  provider: z.string().default("local"),
  model: z.string().default("ollama"),
  boot: z.string().optional(),
  healthcheck: z.string().optional(),
  env: z.object({ from: z.string() }).optional(),
  variants: z.record(VariantSchema).default({}),
  egress_allowlist: z.array(z.string().min(1)).default([]),
  pentest: z
    .object({
      max_wall_clock_seconds: z.number().int().positive().default(1800),
      memory_mb: z.number().int().positive().default(2048),
      fuzzing_budget_seconds: z.number().int().positive().default(300)
    })
    .default({}),
  graph: z
    .object({
      trust_levels: z.array(z.string()).default(["untrusted", "validated", "trusted", "internal"]),
      edge_kinds: z.array(z.string()).default(["CALLS", "IMPORTS", "FLOWS_TO", "GUARDED_BY", "DEPENDS_ON", "SANITIZED_BY", "CONFIRMED_EXPLOIT"]),
      node_props: z.record(z.unknown()).default({}),
      custom_adapters: z.array(z.string()).default([])
    })
    .default({})
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
  const raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
  return ConfigSchema.parse(raw.api_endpoint && !raw.apiUrl ? { ...raw, apiUrl: raw.api_endpoint } : raw);
}

export function writeConfig(config: SentinelConfig, root = findRepoRoot()): void {
  writeFileSync(configPath(root), `${JSON.stringify(config, null, 2)}\n`);
}

export function validateConfigForScan(config: SentinelConfig): void {
  validateSafeCommand("boot", config.boot);
  validateSafeCommand("healthcheck", config.healthcheck);
  for (const [name, variant] of Object.entries(config.variants)) {
    validateSafeCommand(`variants.${name}.build`, variant.build);
  }
}

function validateSafeCommand(field: string, command: string | undefined): void {
  if (!command) return;
  if (!SAFE_COMMAND_RE.test(command)) {
    throw new Error(`${field} contains shell metacharacters; use a simple argv-style command without pipes, redirection, command substitution, or backgrounding.`);
  }
}

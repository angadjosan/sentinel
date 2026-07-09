import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { z } from "zod";

const SAFE_COMMAND_RE = /^[A-Za-z0-9_./:@%+=,\-\s]+$/;

// gVisor sandbox target (rec #2/#3). Support both units: a hermetic OCI image
// (recommended, pin by @sha256 digest) or the compose/boot tier.
const TargetSchema = z.object({
  image: z.string().optional(),
  entrypoint: z.array(z.string()).default([]),
  compose: z.string().optional(),
  boot: z.string().optional()
});

const ResourcesSchema = z
  .object({
    vcpus: z.number().positive().default(1),
    memory_mb: z.number().int().positive().default(2048),
    pids_max: z.number().int().positive().default(256), // anti-fork-bomb
    wall_clock_seconds: z.number().int().positive().default(1800)
  })
  .default({});

const SandboxSchema = z.object({
  runtime: z.enum(["gvisor"]).default("gvisor"),
  target: TargetSchema.optional(),
  healthcheck: z.string().optional(),
  resources: ResourcesSchema
});

// Default-deny, token-scoped egress (rec #7 — cuts the exfiltration leg).
const EgressSchema = z.object({
  default: z.enum(["deny", "allow"]).default("deny"),
  allow: z.array(z.string().min(1)).default([]),
  proxy: z.object({ mode: z.enum(["token_scoped", "open"]).default("token_scoped") }).default({})
});

// Real upstream creds go through the broker (agent never holds them); synthetic
// decoys go into the target env (rec #4).
const SecretsSchema = z.object({
  synthetic_env: z.string().optional(),
  broker: z
    .object({
      enabled: z.boolean().default(false),
      upstreams: z
        .array(
          z.object({
            host: z.string(),
            credential_ref: z.string(),
            header: z.string().default("Authorization"),
            scheme: z.string().default("Bearer")
          })
        )
        .default([])
    })
    .optional()
});

const CanarySchema = z.object({
  enabled: z.boolean().default(false),
  provider: z.string().default("deterministic"),
  count: z.number().int().positive().default(3),
  seed_into: z.array(z.string()).default(["env"])
});

// Attack-safety controls (rec #7): scope + destructive exclusion + budget + auth.
const AttackSafetySchema = z.object({
  scope: z.array(z.string()).default([]),
  exclude_paths: z.array(z.string()).default([]),
  exclude_methods: z.array(z.string()).default(["DELETE"]),
  max_requests: z.number().int().positive().default(500),
  max_attack_duration_seconds: z.number().int().positive().default(600),
  auth: z
    .object({
      method: z.string().default("POST"),
      path: z.string().default("/login"),
      body: z.record(z.unknown()).default({}),
      logged_in_indicator: z.string().optional()
    })
    .optional()
});

export const ConfigSchema = z.object({
  $schema: z.string().optional(),
  repo_id: z.string().optional(),
  api_endpoint: z.string().url().optional(),
  apiUrl: z.string().url().default("https://sentinel-steel-xi.vercel.app"),
  repoName: z.string().min(1).default("unnamed-repo"),
  provider: z.string().default("local"),
  model: z.string().default("llama3.2"),
  boot: z.string().optional(),
  healthcheck: z.string().optional(),
  // AUDIT.md §3 D1 — pentest reachability config, synced to the cloud Repo so
  // the worker knows how to reach the target app. `staging` (default, hosted)
  // probes staging_base_url over HTTP; `local_worker` (self-hosted) boots the
  // app on the worker host.
  pentest_mode: z.enum(["staging", "local_worker"]).optional(),
  staging_base_url: z.string().url().optional(),
  healthcheck_path: z.string().optional(),
  env: z.object({ from: z.string() }).optional(),
  egress_allowlist: z.array(z.string().min(1)).default([]),
  // gVisor sandbox + its controls (rec #2/#4/#7). Synced to the cloud Repo as a
  // single `pentest_config` blob the worker reads at pentest time.
  sandbox: SandboxSchema.optional(),
  egress: EgressSchema.optional(),
  secrets: SecretsSchema.optional(),
  canary: CanarySchema.optional(),
  attack_safety: AttackSafetySchema.optional(),
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
    // No config file — use defaults so sentinel works on any repo without init.
    return ConfigSchema.parse({ repoName: basename(root) });
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
  // The gVisor sandbox's boot/compose/healthcheck must be argv-safe too (no
  // shell metacharacters) — they are executed as argv arrays, never via a shell.
  validateSafeCommand("sandbox.target.boot", config.sandbox?.target?.boot);
  validateSafeCommand("sandbox.healthcheck", config.sandbox?.healthcheck);
}

function validateSafeCommand(field: string, command: string | undefined): void {
  if (!command) return;
  if (!SAFE_COMMAND_RE.test(command)) {
    throw new Error(`${field} contains shell metacharacters; use a simple argv-style command without pipes, redirection, command substitution, or backgrounding.`);
  }
}

// Invokes the local Python analysis engine (worker/sentinel_worker/local_cli.py)
// as a subprocess. This is the mechanism that keeps source code and diffs on
// this machine: the CLI computes the diff locally (diff/git.ts), hands it to
// this engine over stdin, and the engine reads any additional source it needs
// straight from --repo-dir on disk. Only the JSON summary (findings + graph
// push counts) crosses back over stdout; the LLM API key crosses over env,
// never argv or a file.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { accessSync, constants as fsConstants } from "node:fs";
import type { SentinelConfig } from "../config/sentinel.config.js";
import { resolveVenvPython } from "../backend/ensure.js";

/**
 * Resolve how to invoke the Python analysis engine, in priority order:
 *
 *   a. A bundled, frozen (PyInstaller) binary shipped as an optionalDependency
 *      `@sentineldev/engine-<platform>-<arch>`. npm installs only the package
 *      matching the host os/cpu (mirrors how esbuild/swc/turbo ship natives).
 *      When present + executable → run it directly, no Python needed.
 *   b. `SENTINEL_ENGINE_BIN` env override → a caller-provided frozen binary.
 *   c. Fallback (dev / source checkout): the historical behavior —
 *      `<venv python> -m sentinel_worker.local_cli`.
 *
 * `prefixArgs` are prepended before the subcommand ("source", "pentest", …):
 * empty for a frozen binary (its entry point IS local_cli:main), and
 * `["-m", "sentinel_worker.local_cli"]` for the Python fallback.
 */
export function resolveEngineCommand(): { cmd: string; prefixArgs: string[] } {
  // (a) Bundled frozen binary via optionalDependency.
  const pkg = `@sentineldev/engine-${process.platform}-${process.arch}`;
  try {
    // import.meta.url works both in the built dist and under ts-node/tsx.
    const req = createRequire(import.meta.url);
    // Resolve a known file inside the platform package. The frozen onedir bundle
    // exposes its launcher at bin/sentinel-local (bin/sentinel-local.exe on win32).
    const binName = process.platform === "win32" ? "sentinel-local.exe" : "sentinel-local";
    const bin = req.resolve(`${pkg}/bin/${binName}`);
    accessSync(bin, fsConstants.X_OK);
    return { cmd: bin, prefixArgs: [] };
  } catch {
    // Package not installed for this platform, or its binary isn't executable —
    // fall through to the env override / Python fallback.
  }

  // (b) Explicit binary override.
  if (process.env.SENTINEL_ENGINE_BIN) {
    return { cmd: process.env.SENTINEL_ENGINE_BIN, prefixArgs: [] };
  }

  // (c) Dev / source fallback: run the module through a Python interpreter.
  return { cmd: resolveVenvPython(), prefixArgs: ["-m", "sentinel_worker.local_cli"] };
}

export interface LocalFinding {
  vuln_type: string;
  severity: string;
  title: string;
  description: string;
  remediation: string;
  fingerprint: string;
  node_id?: string | null;
  file?: string | null;
  line?: number | null;
  evidence?: string | null;
}

export interface IngestPushResponse {
  run_id: string;
  created: number;
  updated: number;
  total: number;
  finding_ids: string[];
}

export interface GraphPushResponse {
  graph_id: string;
  nodes_upserted: number;
  edges_upserted: number;
}

export interface PushResult {
  graph?: GraphPushResponse;
  findings?: IngestPushResponse;
}

export interface LocalSourceResult {
  findings: LocalFinding[];
  finding_count: number;
  graph_nodes_pushed: number;
  graph_edges_pushed: number;
  // Changed files that no framework adapter matched (AUDIT.md §6 W4 P5.4).
  // Surfaced to the user on stderr after a scan; absent on older engines.
  adapter_unmatched_files?: string[];
  local_run_id?: string;
  local_trace_path?: string;
  push: PushResult;
}

export interface LocalPlanResult {
  findings: LocalFinding[];
  finding_count: number;
  local_run_id?: string;
  local_trace_path?: string;
  push: PushResult;
}

export interface LocalInitResult {
  nodes: number;
  edges: number;
  local_run_id?: string;
  local_trace_path?: string;
  push: PushResult;
}

interface RawRunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

function runLocalEngine(args: string[], opts: { llmApiKey?: string; stdin?: string } = {}): Promise<RawRunResult> {
  return new Promise((resolve, reject) => {
    const { cmd, prefixArgs } = resolveEngineCommand();
    const child = spawn(cmd, [...prefixArgs, ...args], {
      env: {
        ...process.env,
        // Passed via env, never argv (argv is visible to other processes via `ps`).
        ...(opts.llmApiKey ? { SENTINEL_LLM_API_KEY: opts.llmApiKey } : {}),
      },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
      process.stderr.write(chunk); // stream scan progress live
    });
    child.on("error", (err) => {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        reject(
          new Error(
            `Could not run the local Sentinel engine (${cmd}${prefixArgs.length ? " " + prefixArgs.join(" ") : ""}). ` +
              `Install the bundled engine (it ships automatically as the optionalDependency ` +
              `@sentineldev/engine-${process.platform}-${process.arch}), or for a source checkout ` +
              `run 'pip install ./worker' / set SENTINEL_PYTHON to a Python with sentinel-worker installed, ` +
              `or point SENTINEL_ENGINE_BIN at a frozen engine binary.`
          )
        );
        return;
      }
      reject(err);
    });
    child.on("close", (code) => resolve({ stdout, stderr, exitCode: code ?? 1 }));
    if (opts.stdin !== undefined) {
      child.stdin.write(opts.stdin);
    }
    child.stdin.end();
  });
}

function parseJsonStdout<T>(stdout: string, context: string): T {
  const line = stdout.trim().split("\n").filter(Boolean).pop() ?? "";
  try {
    return JSON.parse(line) as T;
  } catch {
    throw new Error(`${context}: could not parse local engine output.\n${stdout.slice(0, 1000)}`);
  }
}

interface CommonEngineOpts {
  config: SentinelConfig;
  repoDir: string;
  llmApiKey?: string;
  apiToken?: string;
}

export async function runLocalInit(opts: CommonEngineOpts): Promise<LocalInitResult> {
  const args = [
    "init",
    "--repo-name", opts.config.repoName,
    "--repo-dir", opts.repoDir,
    "--provider", opts.config.provider,
    "--model", opts.config.model,
    "--api-url", opts.config.apiUrl,
  ];
  if (opts.config.api_endpoint) args.push("--llm-endpoint", opts.config.api_endpoint);
  if (opts.apiToken) args.push("--api-token", opts.apiToken);
  const { stdout, exitCode, stderr } = await runLocalEngine(args, { llmApiKey: opts.llmApiKey });
  if (exitCode !== 0) throw new Error(`local init failed (exit ${exitCode}): ${stderr.slice(-2000)}`);
  return parseJsonStdout<LocalInitResult>(stdout, "sentinel init");
}

export async function runLocalSourceScan(
  opts: CommonEngineOpts & { diff: string; baseRef?: string; runContext: string }
): Promise<{ result: LocalSourceResult; exitCode: number }> {
  const args = [
    "source",
    "--repo-name", opts.config.repoName,
    "--repo-dir", opts.repoDir,
    "--diff-file", "-",
    "--base", opts.baseRef ?? "HEAD",
    "--run-context", opts.runContext,
    "--provider", opts.config.provider,
    "--model", opts.config.model,
    "--api-url", opts.config.apiUrl,
  ];
  if (opts.config.api_endpoint) args.push("--llm-endpoint", opts.config.api_endpoint);
  if (opts.apiToken) args.push("--api-token", opts.apiToken);
  const { stdout, exitCode } = await runLocalEngine(args, { llmApiKey: opts.llmApiKey, stdin: opts.diff });
  return { result: parseJsonStdout<LocalSourceResult>(stdout, "sentinel source"), exitCode };
}

export async function runLocalPlanReview(
  opts: CommonEngineOpts & { content: string; withRetry: boolean }
): Promise<{ result: LocalPlanResult; exitCode: number }> {
  const args = [
    "plan",
    "--repo-name", opts.config.repoName,
    "--repo-dir", opts.repoDir,
    "--content-file", "-",
    "--provider", opts.config.provider,
    "--model", opts.config.model,
    "--api-url", opts.config.apiUrl,
  ];
  if (opts.withRetry) args.push("--with-retry");
  if (opts.config.api_endpoint) args.push("--llm-endpoint", opts.config.api_endpoint);
  if (opts.apiToken) args.push("--api-token", opts.apiToken);
  const { stdout, exitCode } = await runLocalEngine(args, { llmApiKey: opts.llmApiKey, stdin: opts.content });
  return { result: parseJsonStdout<LocalPlanResult>(stdout, "sentinel plan"), exitCode };
}

export interface LocalPentestResult {
  finding_id: string;
  confirmed: boolean;
  status: string;
  evidence?: string | null;
  payloads: string[];
  local_run_id?: string;
  local_trace_path?: string;
  push: Record<string, unknown>;
}

// Run the FULL hardened pentest stack (gVisor sandbox + egress proxy + canary +
// broker + attack-safety + oracle) on THIS machine, mirroring runLocalSourceScan.
// The finding lives in the cloud, so --api-url is required; the outcome is pushed
// back by the Python engine via POST /findings/{id}/confirm. Source, payloads,
// and boot secrets never leave this process.
export async function runLocalPentest(
  opts: CommonEngineOpts & {
    findingId: string;
    repoId?: string;
    sanitizerOutput?: string;
    behavioralProof?: string;
    proofDetail?: string;
    boot?: string;
    healthcheck?: string;
    egressAllowlist?: string[];
    noSandbox?: boolean;
  }
): Promise<LocalPentestResult> {
  const args = [
    "pentest",
    "--repo-name", opts.config.repoName,
    "--repo-dir", opts.repoDir,
    "--finding-id", opts.findingId,
    "--provider", opts.config.provider,
    "--model", opts.config.model,
    "--api-url", opts.config.apiUrl,
  ];
  if (opts.repoId) args.push("--repo-id", opts.repoId);
  if (opts.sanitizerOutput) args.push("--sanitizer-output", opts.sanitizerOutput);
  if (opts.behavioralProof) args.push("--behavioral-proof", opts.behavioralProof);
  if (opts.proofDetail) args.push("--proof-detail", opts.proofDetail);
  if (opts.boot) args.push("--boot", opts.boot);
  if (opts.healthcheck) args.push("--healthcheck", opts.healthcheck);
  for (const entry of opts.egressAllowlist ?? []) args.push("--egress-allowlist", entry);
  if (opts.noSandbox) args.push("--no-sandbox");
  if (opts.config.api_endpoint) args.push("--llm-endpoint", opts.config.api_endpoint);
  if (opts.apiToken) args.push("--api-token", opts.apiToken);
  const { stdout, exitCode, stderr } = await runLocalEngine(args, { llmApiKey: opts.llmApiKey });
  if (exitCode !== 0) throw new Error(`local pentest failed (exit ${exitCode}): ${stderr.slice(-2000)}`);
  return parseJsonStdout<LocalPentestResult>(stdout, "sentinel pentest");
}

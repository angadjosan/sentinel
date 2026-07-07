#!/usr/bin/env node
import { readFileSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import chalk from "chalk";
import { Command } from "commander";

import { SentinelApiClient } from "./api/client.js";
import { readApiKey, readLlmApiKey, writeApiKey, writeLlmApiKey } from "./auth/keychain.js";
import { writeWorkerConn } from "./backend/ensure.js";
import { ConfigSchema, configPath, findRepoRoot, loadConfig, validateConfigForScan, writeConfig } from "./config/sentinel.config.js";
import { currentDiff } from "./diff/git.js";
import { ensureBackend, startBackend, stopBackend, backendStatus } from "./backend/ensure.js";
import { runLocalInit, runLocalPentest, runLocalPlanReview, runLocalSourceScan } from "./engine/localEngine.js";

const program = new Command();

program.name("sentinel").description("LLM-powered application security scanner — scans run locally, only the code graph and findings sync to the cloud").version("0.1.0");

const auth = program.command("auth").description("Manage Sentinel authentication");
auth
  .command("login")
  .description("Authorize this CLI with a browser-based device code")
  .option("--poll-interval <seconds>", "Polling interval while waiting for approval", "2")
  .action(async (options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const client = new SentinelApiClient(config);
    const started = await client.startDeviceAuth();
    const verificationUrl = absoluteUrl(config.apiUrl, started.verification_url);
    const pollIntervalMs = Math.max(250, Math.floor(Number(options.pollInterval) * 1000));
    if (!Number.isFinite(pollIntervalMs)) {
      throw new Error("poll interval must be a number of seconds");
    }

    console.log(`Verification URL: ${verificationUrl}`);
    console.log(`User code:        ${started.user_code}`);
    console.log(`Polling for approval (dev mode auto-approves)...`);

    const deadline = Date.now() + started.expires_in * 1000;
    while (Date.now() < deadline) {
      const token = await client.deviceAuthToken(started.device_code);
      if (token.status === "approved") {
        await writeApiKey(config, token.access_token);
        if (token.database_url) {
          writeWorkerConn({ databaseUrl: token.database_url, accountId: token.account_id });
        }
        console.log(`logged in as ${token.user_id} for account ${token.account_id}`);
        return;
      }
      await sleep(Math.min(pollIntervalMs, Math.max(0, deadline - Date.now())));
    }
    throw new Error("device code expired before approval");
  });

program
  .command("init")
  .description("Initialize Sentinel for this repository")
  .option("--api-url <url>", "Sentinel API URL", "https://sentinel-steel-xi.vercel.app")
  .option("--repo-name <name>", "Repository name")
  .action(async (options) => {
    const root = findRepoRoot();
    const path = configPath(root);
    const repoName = options.repoName ?? basename(root);
    if (!existsSync(path)) {
      writeConfig(ConfigSchema.parse({ apiUrl: options.apiUrl, repoName, provider: "local", model: "llama3.2" }), root);
      console.log(`wrote ${path}`);
    }
    const config = loadConfig(root);
    await ensureBackend(config.apiUrl);
    // The codebase is parsed into a graph entirely on this machine; only the
    // resulting nodes/edges (pointers + short labels, never source text) are
    // sent to the cloud. See non-code/README.md's local-AI-calls model.
    const [apiToken, llmApiKey] = await Promise.all([readApiKey(config), readLlmApiKey(config)]);
    const result = await runLocalInit({ config, repoDir: root, apiToken, llmApiKey });
    console.log(`initialized ${repoName}: ${result.nodes} graph nodes, ${result.edges} edges pushed`);
    if (result.local_trace_path) console.log(`trace saved locally: ${result.local_trace_path}`);
  });

program
  .command("source")
  .description("Scan the current git diff — locally. Source and diffs never leave this machine.")
  .argument("[paths...]", "Optional paths to scope the diff")
  .option("--staged", "Scan staged changes only")
  .option("--base <ref>", "Diff against this base ref")
  .action(async (paths: string[], options) => {
    const config = loadConfig();
    validateConfigForScan(config);
    await ensureBackend(config.apiUrl);
    const root = findRepoRoot();
    const diff = currentDiff({ staged: options.staged, base: options.base, paths });
    if (!diff.trim()) {
      console.log("no changes to scan");
      process.exitCode = 0;
      return;
    }
    const runContext = process.env.CI ? "ci" : "local";
    const [apiToken, llmApiKey] = await Promise.all([readApiKey(config), readLlmApiKey(config)]);

    const { result, exitCode } = await runLocalSourceScan({
      config,
      repoDir: root,
      diff,
      baseRef: options.base,
      runContext,
      apiToken,
      llmApiKey,
    });
    for (const finding of result.findings) {
      console.log(`${chalk.red(finding.severity.toUpperCase())} ${finding.vuln_type} ${finding.fingerprint.slice(0, 8)}`);
      console.log(`  ${finding.title}`);
      if (finding.remediation) console.log(`  fix: ${finding.remediation}`);
    }
    console.log(`${result.finding_count} finding(s) · pushed ${result.graph_nodes_pushed} graph node(s), ${result.graph_edges_pushed} edge(s)`);
    if (result.local_trace_path) console.log(`trace saved locally: ${result.local_trace_path}`);
    process.exitCode = exitCode;
  });

program
  .command("scan")
  .description("Run source scan locally, then pentest each finding unless skipped")
  .argument("[paths...]", "Optional paths to scope the diff")
  .option("--staged", "Scan staged changes only")
  .option("--base <ref>", "Diff against this base ref")
  .option("--no-pentest", "Skip pentest")
  .option("--pentest-concurrency <count>", "Maximum concurrent pentest jobs", "4")
  .action(async (paths: string[], options) => {
    const config = loadConfig();
    validateConfigForScan(config);
    await ensureBackend(config.apiUrl);
    const root = findRepoRoot();
    const diff = currentDiff({ staged: options.staged, base: options.base, paths });
    const runContext = process.env.CI ? "ci" : "local";
    const [apiToken, llmApiKey] = await Promise.all([readApiKey(config), readLlmApiKey(config)]);

    if (!diff.trim()) {
      console.log("no changes to scan");
      process.exitCode = 0;
      return;
    }

    const { result, exitCode } = await runLocalSourceScan({
      config,
      repoDir: root,
      diff,
      baseRef: options.base,
      runContext,
      apiToken,
      llmApiKey,
    });
    for (const finding of result.findings) {
      console.log(`${chalk.red(finding.severity.toUpperCase())} ${finding.vuln_type} ${finding.fingerprint.slice(0, 8)}`);
      console.log(`  ${finding.title}`);
    }

    const findingIds = result.push.findings?.finding_ids ?? [];
    if (options.pentest && findingIds.length > 0) {
      const concurrency = parsePositiveInt(options.pentestConcurrency, "pentest concurrency");
      const pentestResults = await runLimited(findingIds, concurrency, async (findingId) =>
        runLocalPentest({
          config, repoDir: root, apiToken, llmApiKey, findingId,
          boot: config.boot, healthcheck: config.healthcheck, egressAllowlist: config.egress_allowlist,
        })
      );
      for (const r of pentestResults) {
        console.log(`pentest ${r.finding_id}: ${r.status} confirmed=${r.confirmed}`);
      }
    } else if (options.pentest && result.findings.length > 0) {
      console.log("(pentest skipped: findings were not pushed to the cloud, so no finding IDs are available — check network/auth)");
    }
    console.log(`scan: ${result.finding_count} finding(s)`);
    if (result.local_trace_path) console.log(`trace saved locally: ${result.local_trace_path}`);
    process.exitCode = exitCode;
  });

program
  .command("list")
  .description("List findings")
  .option("--status <status>", "Filter by finding status")
  .option("--severity <severity>", "Filter by severity")
  .action(async (options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const findings = await new SentinelApiClient(config).findings({ status: options.status, severity: options.severity });
    console.log("ID\tSTATUS\tSEVERITY\tTYPE\tFILE\tUPDATED\tTITLE");
    for (const finding of findings) {
      const file = finding.file ? `${finding.file}${finding.line_start ? `:${finding.line_start}` : ""}` : "n/a";
      console.log(`${finding.id}\t${finding.status}\t${finding.severity}\t${finding.vuln_type}\t${file}\t${finding.updated_at}\t${finding.title}`);
    }
  });

program
  .command("pull")
  .description("Fetch remediation context for a finding")
  .argument("<id>", "Finding ID")
  .action(async (id: string) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const result = await new SentinelApiClient(config).pull(id);
    console.log(`${result.finding.severity.toUpperCase()} ${result.finding.vuln_type}: ${result.finding.title}`);
    console.log(result.finding.description);
    console.log("\nRemediation plan:");
    for (const item of result.remediation_plan) {
      console.log(`- ${item}`);
    }
    if (result.node) {
      console.log(`\nGraph node: ${JSON.stringify(result.node, null, 2)}`);
    }
  });

program
  .command("plan")
  .description("Review a plan file, stdin, or inline text for security issues")
  .argument("[input...]", "File path or inline text")
  .option("--with-retry", "Run retry review passes")
  .action(async (input: string[], options) => {
    const joined = input.join(" ");
    let content = joined;
    if (joined && existsSync(joined)) {
      content = readFileSync(joined, "utf8");
    } else if (!joined && !process.stdin.isTTY) {
      content = await new Promise<string>((resolve) => {
        let data = "";
        process.stdin.setEncoding("utf8");
        process.stdin.on("data", (chunk) => {
          data += chunk;
        });
        process.stdin.on("end", () => resolve(data));
      });
    }
    if (!content.trim()) {
      throw new Error("Provide a plan file, inline plan text, or stdin content.");
    }
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const root = findRepoRoot();
    const [apiToken, llmApiKey] = await Promise.all([readApiKey(config), readLlmApiKey(config)]);
    const { result, exitCode } = await runLocalPlanReview({
      config,
      repoDir: root,
      content,
      withRetry: Boolean(options.withRetry),
      apiToken,
      llmApiKey,
    });
    for (const finding of result.findings) {
      console.log(`${chalk.red(finding.severity.toUpperCase())} ${finding.vuln_type}: ${finding.title}`);
      console.log(`  ${finding.description}`);
      console.log(`  fix: ${finding.remediation}`);
    }
    console.log(`plan review completed with ${result.finding_count} issue(s)`);
    if (result.local_trace_path) console.log(`trace saved locally: ${result.local_trace_path}`);
    process.exitCode = exitCode;
  });

program
  .command("pentest")
  .description("Attempt to confirm a finding by attacking the app booted on this machine")
  .argument("[target...]", "Finding ID, natural-language target, or empty to auto-select")
  .option("--sanitizer-output <text>", "Sanitizer output")
  .option("--behavioral-proof <kind>", "Behavioral proof kind")
  .option("--proof-detail <text>", "Behavioral proof detail", "")
  .action(async (targetParts: string[], options) => {
    const config = loadConfig();
    validateConfigForScan(config);
    await ensureBackend(config.apiUrl);
    const root = findRepoRoot();
    const client = new SentinelApiClient(config);
    const target = parsePentestTarget(targetParts);
    const findingId = target.findingId ?? (await resolvePentestTargetId(client, target.description));
    if (!findingId) {
      throw new Error("No open finding matched. Run `sentinel list` to see finding IDs.");
    }
    const [apiToken, llmApiKey] = await Promise.all([readApiKey(config), readLlmApiKey(config)]);
    const result = await runLocalPentest({
      config,
      repoDir: root,
      apiToken,
      llmApiKey,
      findingId,
      sanitizerOutput: options.sanitizerOutput,
      behavioralProof: options.behavioralProof,
      proofDetail: options.proofDetail,
      boot: config.boot,
      healthcheck: config.healthcheck,
      egressAllowlist: config.egress_allowlist,
    });
    console.log(`${result.finding_id}\t${result.status}\tconfirmed=${result.confirmed}`);
    if (result.evidence) console.log(result.evidence);
    if (result.local_trace_path) console.log(`trace saved locally: ${result.local_trace_path}`);
  });

const suppress = program.command("suppress").description("Suppress or remove suppressions");
suppress
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Suppression reason")
  .action(async (id: string, options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const finding = await new SentinelApiClient(config).suppress(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("remove")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Unsuppression reason")
  .action(async (id: string, options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const finding = await new SentinelApiClient(config).unsuppress(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("approve")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Approval reason")
  .action(async (id: string, options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const finding = await new SentinelApiClient(config).approveSuppression(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });
suppress
  .command("reject")
  .argument("<id>", "Finding ID")
  .requiredOption("--reason <reason>", "Rejection reason")
  .action(async (id: string, options) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const finding = await new SentinelApiClient(config).rejectSuppression(id, options.reason);
    console.log(`${finding.id}\t${finding.status}`);
  });

const runs = program.command("runs").description("Manage run traces");
runs
  .command("list")
  .action(async () => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const rows = await new SentinelApiClient(config).runs();
    console.log("ID\tKIND\tSTATUS\tFINDINGS\tTOKENS\tMODEL\tCREATED");
    for (const run of rows) {
      console.log(`${run.id}\t${run.kind}\t${run.status}\t${run.finding_count}\t${run.token_spend}\t${run.model_used ?? "n/a"}\t${run.created_at}`);
    }
  });
runs
  .command("show")
  .argument("<id>", "Run ID (a local run ID from `sentinel source/scan/plan/pentest`, or a cloud run ID)")
  .action(async (id: string) => {
    const config = loadConfig();
    const localTracePath = join(homedir(), ".sentinel", "runs", `${id}.jsonl`);
    let trace: string;
    if (existsSync(localTracePath)) {
      // Full local traces (every prompt, every tool call) never leave this
      // machine — the cloud only ever gets a redacted run summary.
      trace = readFileSync(localTracePath, "utf8");
      console.log(`(reading full trace from local file: ${localTracePath})\n`);
    } else {
      await ensureBackend(config.apiUrl);
      trace = await new SentinelApiClient(config).trace(id);
      console.log("(no local trace found for this ID — showing the cloud's redacted run summary)\n");
    }
    console.log(trace);
    const summary = summarizeTokens(trace);
    if (summary.totalInput + summary.totalOutput > 0) {
      console.log("\n--- Token Summary ---");
      for (const row of summary.rows) {
        console.log(`  ${row.component}: ${row.input.toLocaleString()} in + ${row.output.toLocaleString()} out = ${(row.input + row.output).toLocaleString()}`);
      }
      console.log(`  Total: ${summary.totalInput.toLocaleString()} in + ${summary.totalOutput.toLocaleString()} out = ${(summary.totalInput + summary.totalOutput).toLocaleString()}`);
    }
  });
runs
  .command("watch")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const client = new SentinelApiClient(config);
    for await (const event of client.runEvents(id)) {
      console.log(event);
      try {
        const parsed = JSON.parse(event) as { kind?: string; status?: string };
        if (parsed.kind === "run.completed" || parsed.kind === "complete" || parsed.status === "failed" || parsed.status === "cancelled") break;
      } catch {
        // Non-JSON trace lines are still useful to display.
      }
    }
  });
runs
  .command("cancel")
  .argument("<id>", "Run ID")
  .action(async (id: string) => {
    const config = loadConfig();
    await ensureBackend(config.apiUrl);
    const run = await new SentinelApiClient(config).cancelRun(id);
    console.log(`${run.id}\t${run.status}`);
  });

const config = program.command("config").description("Manage local Sentinel config");
config.command("show").action(() => {
  console.log(JSON.stringify(loadConfig(), null, 2));
});
config
  .command("set")
  .argument("<key>", "Config key")
  .argument("<value>", "Config value")
  .action(async (key: string, value: string) => {
    const root = findRepoRoot();
    const current = loadConfig(root) as Record<string, unknown>;
    const client = new SentinelApiClient();

    if (key === "api-key") {
      // The LLM provider key is used locally by the scan engine and never
      // sent to the Sentinel cloud — stored in the system keychain (or the
      // ~/.sentinel fallback), same mechanism as the Sentinel auth token.
      await writeLlmApiKey(loadConfig(root), value);
      console.log("api-key stored locally (never sent to the Sentinel cloud)");
      return;
    }

    const serverSyncKeys = new Set(["provider", "model", "api_endpoint"]);
    const allowed = new Set(["apiUrl", "repoName", "provider", "model", "boot", "healthcheck", "api_endpoint", "repo_id"]);

    if (key.startsWith("firecracker.")) {
      setFirecrackerConfigValue(current, key.slice("firecracker.".length), value);
      writeConfig(ConfigSchema.parse(current), root);
      console.log(`set ${key}`);
      return;
    }
    if (!allowed.has(key)) {
      throw new Error(`Unsupported config key ${key}`);
    }
    current[key] = value;
    writeConfig(ConfigSchema.parse(current), root);

    if (serverSyncKeys.has(key)) {
      await ensureBackend(loadConfig(root).apiUrl);
      const patch: Record<string, string | null> = {};
      patch[key] = value;
      await client.patchConfig(patch as { provider?: string; model?: string; api_endpoint?: string | null });
      console.log(`set ${key} (local + server)`);
    } else {
      console.log(`set ${key}`);
    }
  });

// Backend lifecycle commands
program
  .command("up")
  .description("Start the Sentinel backend (API + worker)")
  .action(async () => {
    const config = loadConfig();
    await startBackend(config.apiUrl);
    console.log("Sentinel backend started.");
  });

program
  .command("down")
  .description("Stop the Sentinel backend")
  .action(async () => {
    await stopBackend();
    console.log("Sentinel backend stopped.");
  });

program
  .command("status")
  .description("Show Sentinel backend status")
  .action(async () => {
    const config = loadConfig();
    const s = await backendStatus(config.apiUrl);
    console.log(`API:     ${s.api}`);
    console.log(`Worker:  ${s.worker}`);
    console.log(`Healthy: ${s.healthy ? "yes" : "no"}`);
  });

program.parseAsync().catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(chalk.red(`Error: ${message}`));
  if (process.env.DEBUG && error instanceof Error && error.stack) {
    console.error(error.stack);
  }
  if (error instanceof Error && (error as NodeJS.ErrnoException).cause) {
    const cause = (error as NodeJS.ErrnoException).cause as any;
    const causeStr = cause?.code ?? String(cause);
    if (causeStr !== message) {
      console.error(chalk.dim(`Cause: ${causeStr}`));
    }
  }
  process.exitCode = 2;
});

function summarizeTokens(trace: string): { rows: Array<{ component: string; input: number; output: number }>; totalInput: number; totalOutput: number } {
  const totals = new Map<string, { input: number; output: number }>();
  for (const line of trace.split("\n")) {
    if (!line.trim()) continue;
    try {
      const event = JSON.parse(line) as { kind?: string; component?: string; input_tokens?: number; output_tokens?: number };
      if (event.kind !== "token_event" || !event.component) continue;
      const current = totals.get(event.component) ?? { input: 0, output: 0 };
      current.input += event.input_tokens ?? 0;
      current.output += event.output_tokens ?? 0;
      totals.set(event.component, current);
    } catch {
      continue;
    }
  }
  const rows = Array.from(totals.entries()).map(([component, counts]) => ({ component, input: counts.input, output: counts.output }));
  return {
    rows,
    totalInput: rows.reduce((sum, row) => sum + row.input, 0),
    totalOutput: rows.reduce((sum, row) => sum + row.output, 0)
  };
}

function absoluteUrl(apiUrl: string, pathOrUrl: string): string {
  return new URL(pathOrUrl, apiUrl).toString();
}

async function runLimited<T, R>(items: T[], concurrency: number, task: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await task(items[index]);
    }
  });
  await Promise.all(workers);
  return results;
}

function parsePositiveInt(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function parsePentestTarget(parts: string[]): { findingId?: string; description?: string } {
  const target = parts.join(" ").trim();
  if (!target) return {};
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(target)) {
    return { findingId: target };
  }
  return { description: target };
}

const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Client-side mirror of the server's retired /pentest description-matching:
// term-overlap score against title+description+vuln_type, else just the
// highest-severity open finding. No source is involved — just finding metadata.
async function resolvePentestTargetId(client: SentinelApiClient, description?: string): Promise<string | undefined> {
  const findings = await client.findings({ status: "open" });
  if (findings.length === 0) return undefined;
  if (!description) {
    return [...findings].sort((a, b) => (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5))[0]?.id;
  }
  const terms = description
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 2);
  const scored = findings
    .map((f) => {
      const haystack = `${f.id} ${f.vuln_type} ${f.title} ${f.description} ${f.file ?? ""}`.toLowerCase();
      const score = terms.reduce((n, term) => n + (haystack.includes(term) ? 1 : 0), 0);
      return { finding: f, score };
    })
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score || (SEVERITY_RANK[a.finding.severity] ?? 5) - (SEVERITY_RANK[b.finding.severity] ?? 5));
  return scored[0]?.finding.id;
}

function setFirecrackerConfigValue(config: Record<string, unknown>, key: string, value: string): void {
  const current = (config.firecracker && typeof config.firecracker === "object" ? config.firecracker : {}) as Record<string, unknown>;
  if (key === "enabled" || key === "smt") {
    current[key] = value === "true";
  } else if (key === "vcpu_count" || key === "mem_size_mib") {
    current[key] = Number(value);
  } else if (key === "guest_runner_argv") {
    current[key] = value.split(/\s+/).filter(Boolean);
  } else if (
    [
      "kernel_image",
      "rootfs_image",
      "api_socket",
      "firecracker_bin",
      "boot_args",
      "network_interface_id",
      "host_dev_name",
      "guest_mac"
    ].includes(key)
  ) {
    current[key] = value;
  } else {
    throw new Error(`Unsupported firecracker config key ${key}`);
  }
  config.firecracker = current;
}
